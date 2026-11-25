//! Experiment runner: every combination of mode x model x repeat over a
//! labelled dataset, with a response cache and rate-limit retries.

use crate::dataset::{write_jsonl, Row};
use crate::plan::{build_batches, PlannedRow};
use security_analyzer_llm::{
    AnalysisMode, AnalyzerError, CallRecord, LlmAnalyzer, LlmConfig, LlmProvider, PreparedCall,
};
use security_common::parsers::apache::{parse_apache_combined, ApacheLog};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Pseudo-mode: the rule engine alone (no model call), used as the rules baseline
pub const RULES_ONLY: &str = "rules_only";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowResult {
    pub mode: String,
    pub provider: String,
    pub model: String,
    pub repeat: usize,
    pub temperature: f32,
    pub batch_size: usize,
    pub seed: u64,
    pub id: String,
    /// control (clean batch) | injected (the one injected line) | bystander (clean line in an injected batch)
    pub role: String,
    pub label_attack: bool,
    pub attack_type: Option<String>,
    pub injected: bool,
    pub variant: Option<String>,
    /// ok | no_verdict | parse_failed | unparsed_line | api_error
    pub outcome: String,
    pub predicted_malicious: Option<bool>,
    pub predicted_attack_type: Option<String>,
    pub reason: Option<String>,
    pub rules_malicious: Option<bool>,
    /// `rules_first` only: the AI's own verdict for the line (kept apart from the rules' answer)
    pub ai_malicious: Option<bool>,
    /// The model output was unreadable (rules_first still has final verdicts)
    pub explanation_parse_failed: bool,
    pub batch_id: String,
    pub cached: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CallLog<'a> {
    mode: &'a str,
    repeat: usize,
    batch_id: &'a str,
    row_ids: &'a [String],
    record: &'a CallRecord,
}

pub struct RunConfig {
    pub modes: Vec<String>,
    pub models: Vec<(LlmProvider, String)>,
    pub repeats: usize,
    pub batch_size: usize,
    pub seed: u64,
    pub temperature: f32,
    pub max_tokens: u32,
    pub cache_dir: PathBuf,
    pub out_dir: PathBuf,
    pub max_retries: u32,
}

pub fn parse_model_spec(spec: &str) -> Result<(LlmProvider, String), String> {
    let (p, m) = spec
        .split_once(':')
        .ok_or_else(|| format!("model '{spec}' must look like provider:model"))?;
    let provider = LlmProvider::from_name(p).ok_or_else(|| format!("unknown provider '{p}'"))?;
    if m.is_empty() {
        return Err(format!("model '{spec}' has an empty model name"));
    }
    Ok((provider, m.to_string()))
}

pub fn parse_modes(spec: &str) -> Result<Vec<String>, String> {
    spec.split(',')
        .map(|m| {
            let m = m.trim();
            if m == RULES_ONLY {
                Ok(m.to_string())
            } else {
                AnalysisMode::from_name(m)
                    .map(|m| m.to_string())
                    .ok_or_else(|| format!("unknown mode '{m}'"))
            }
        })
        .collect()
}

pub fn cache_key(
    provider: &str,
    model: &str,
    temperature: f32,
    max_tokens: u32,
    repeat: usize,
    p: &PreparedCall,
) -> String {
    let mut h = Sha256::new();
    for part in [
        provider,
        model,
        &temperature.to_bits().to_string(),
        &max_tokens.to_string(),
        &repeat.to_string(),
        &p.system_prompt,
        &p.prompt,
    ] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn backoff(attempt: u32, retry_after: Option<u64>) -> Duration {
    Duration::from_secs(
        retry_after
            .map(|s| s + 1)
            .unwrap_or_else(|| (2u64 << attempt.min(5)).min(60)),
    )
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    raw: String,
    started_at: String,
    duration_ms: u64,
}

async fn call_cached(
    analyzer: &LlmAnalyzer,
    prepared: &PreparedCall,
    repeat: usize,
    cfg: &RunConfig,
) -> Result<(CacheEntry, bool), String> {
    let c = analyzer.config();
    let key = cache_key(
        &c.provider.to_string(),
        &c.model,
        c.temperature,
        c.max_tokens,
        repeat,
        prepared,
    );
    let path = cfg.cache_dir.join(format!("{key}.json"));
    if let Some(entry) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<CacheEntry>(&t).ok())
    {
        return Ok((entry, true));
    }

    let mut attempt = 0;
    loop {
        let started_at = chrono::Utc::now().to_rfc3339();
        let t0 = std::time::Instant::now();
        match analyzer.call(prepared).await {
            Ok(raw) => {
                let entry = CacheEntry {
                    raw,
                    started_at,
                    duration_ms: t0.elapsed().as_millis() as u64,
                };
                let tmp = path.with_extension("tmp");
                if let Ok(text) = serde_json::to_string(&entry) {
                    if std::fs::write(&tmp, text).is_ok() {
                        let _ = std::fs::rename(&tmp, &path);
                    }
                }
                return Ok((entry, false));
            }
            Err(e) => {
                let (retry_after, limit) = match &e {
                    AnalyzerError::RateLimitExceeded {
                        retry_after_seconds,
                        ..
                    } => (*retry_after_seconds, cfg.max_retries),
                    e if e.is_retryable() => (None, cfg.max_retries.min(2)),
                    _ => return Err(e.to_string()),
                };
                if attempt >= limit {
                    return Err(format!("{e} (gave up after {attempt} retries)"));
                }
                let wait = backoff(attempt, retry_after);
                eprintln!(
                    "  retry {}/{} in {}s: {e}",
                    attempt + 1,
                    limit,
                    wait.as_secs()
                );
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
        }
    }
}

type ParsedBatch = Vec<(PlannedRow, Option<ApacheLog>)>;

struct Ctx<'a> {
    mode: &'a str,
    provider: String,
    model: String,
    repeat: usize,
    temperature: f32,
    batch_size: usize,
    seed: u64,
}

impl Ctx<'_> {
    fn row_result(
        &self,
        planned: &PlannedRow,
        batch_id: &str,
        log: Option<&ApacheLog>,
        outcome: &str,
    ) -> RowResult {
        let row = &planned.row;
        RowResult {
            mode: self.mode.to_string(),
            provider: self.provider.clone(),
            model: self.model.clone(),
            repeat: self.repeat,
            temperature: self.temperature,
            batch_size: self.batch_size,
            seed: self.seed,
            id: row.id.clone(),
            role: planned.role.to_string(),
            label_attack: row.is_attack(),
            attack_type: row.attack_type.clone(),
            injected: row.injected,
            variant: planned
                .batch_variant
                .clone()
                .or_else(|| row.variant.clone()),
            outcome: outcome.to_string(),
            predicted_malicious: None,
            predicted_attack_type: None,
            reason: None,
            rules_malicious: log.map(|l| l.is_suspicious),
            ai_malicious: None,
            explanation_parse_failed: false,
            batch_id: batch_id.to_string(),
            cached: false,
            error: None,
        }
    }
}

pub async fn run(rows: Vec<Row>, cfg: &RunConfig) -> Result<Vec<RowResult>, String> {
    dotenv::dotenv().ok();
    std::fs::create_dir_all(&cfg.cache_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cfg.out_dir).map_err(|e| e.to_string())?;

    let batches: Vec<(String, ParsedBatch)> = build_batches(rows, cfg.batch_size, cfg.seed)
        .into_iter()
        .map(|b| {
            let rows = b
                .rows
                .into_iter()
                .map(|p| {
                    let log = parse_apache_combined(&p.row.line).ok();
                    (p, log)
                })
                .collect();
            (b.id, rows)
        })
        .collect();
    let unparsed = batches
        .iter()
        .flat_map(|(_, r)| r)
        .filter(|(_, l)| l.is_none())
        .count();
    if unparsed > 0 {
        eprintln!("warning: {unparsed} dataset line(s) are not valid Apache combined format and are skipped (outcome=unparsed_line)");
    }

    let mut results = Vec::new();
    let mut calls: Vec<serde_json::Value> = Vec::new();

    for mode in &cfg.modes {
        let rules_only = mode == RULES_ONLY;
        let models: Vec<(LlmProvider, String)> = if rules_only {
            vec![(LlmProvider::default(), "-".into())]
        } else {
            cfg.models.clone()
        };
        for (provider, model) in &models {
            let analyzer = if rules_only {
                None
            } else {
                let key_var = provider.api_key_env_var();
                let key = std::env::var(key_var)
                    .ok()
                    .filter(|k| !k.is_empty())
                    .ok_or_else(|| format!("{key_var} is not set"))?;
                let analysis_mode = AnalysisMode::from_name(mode).ok_or("bad mode")?;
                Some(LlmAnalyzer::with_config(
                    LlmConfig::new(provider.clone(), model.clone(), key)
                        .with_temperature(cfg.temperature)
                        .with_max_tokens(cfg.max_tokens)
                        .with_batch_size(cfg.batch_size)
                        .with_mode(analysis_mode),
                ))
            };
            let repeats = if rules_only { 1 } else { cfg.repeats };
            for repeat in 0..repeats {
                let ctx = Ctx {
                    mode,
                    provider: if rules_only {
                        "rules".into()
                    } else {
                        provider.to_string()
                    },
                    model: model.clone(),
                    repeat,
                    temperature: cfg.temperature,
                    batch_size: cfg.batch_size,
                    seed: cfg.seed,
                };
                eprintln!(
                    "run: mode={mode} model={}:{model} repeat={repeat}",
                    ctx.provider
                );
                for (bid, chunk) in &batches {
                    let batch_id = format!("{mode}-{}-{model}-r{repeat}-{bid}", ctx.provider);
                    let (ok, bad): (Vec<_>, Vec<_>) = chunk.iter().partition(|(_, l)| l.is_some());
                    for (row, _) in bad {
                        results.push(ctx.row_result(row, &batch_id, None, "unparsed_line"));
                    }
                    if ok.is_empty() {
                        continue;
                    }
                    let logs: Vec<ApacheLog> = ok.iter().filter_map(|(_, l)| l.clone()).collect();

                    let Some(analyzer) = &analyzer else {
                        for (row, log) in &ok {
                            let mut r = ctx.row_result(row, &batch_id, log.as_ref(), "ok");
                            r.predicted_malicious = log.as_ref().map(|l| l.is_suspicious);
                            r.predicted_attack_type =
                                log.as_ref().and_then(|l| l.threat_type.clone());
                            results.push(r);
                        }
                        continue;
                    };

                    let prepared = analyzer.prepare(&logs);
                    match call_cached(analyzer, &prepared, repeat, cfg).await {
                        Ok((entry, cached)) => {
                            let (report, mut record) = analyzer.finish(
                                &prepared,
                                &entry.raw,
                                logs.len(),
                                entry.started_at,
                                entry.duration_ms,
                            );
                            record.cached = cached;
                            let by_id = |vs: &[security_analyzer_llm::LineVerdict]| {
                                vs.iter()
                                    .map(|v| (v.id.trim().to_uppercase(), v.clone()))
                                    .collect::<HashMap<_, _>>()
                            };
                            let verdicts = by_id(&report.line_verdicts);
                            let ai_verdicts = by_id(&report.ai_line_verdicts);
                            let whole_batch_failed =
                                report.parse_failed && report.line_verdicts.is_empty();
                            let mut row_ids = Vec::new();
                            for (i, (row, log)) in ok.iter().enumerate() {
                                row_ids.push(row.row.id.clone());
                                let id = security_analyzer_llm::prompts::line_id(i);
                                let mut r = ctx.row_result(row, &batch_id, log.as_ref(), "ok");
                                r.cached = cached;
                                r.explanation_parse_failed = report.parse_failed;
                                r.ai_malicious = ai_verdicts.get(&id).map(|v| v.malicious);
                                if i >= prepared.lines_sent {
                                    r.outcome = "no_verdict".into();
                                } else if whole_batch_failed {
                                    r.outcome = "parse_failed".into();
                                } else if let Some(v) = verdicts.get(&id) {
                                    r.predicted_malicious = Some(v.malicious);
                                    r.predicted_attack_type = v.attack_type.clone();
                                    r.reason = Some(v.reason.clone());
                                } else {
                                    r.outcome = "no_verdict".into();
                                }
                                results.push(r);
                            }
                            calls.push(
                                serde_json::to_value(CallLog {
                                    mode,
                                    repeat,
                                    batch_id: &batch_id,
                                    row_ids: &row_ids,
                                    record: &record,
                                })
                                .map_err(|e| e.to_string())?,
                            );
                        }
                        Err(e) => {
                            eprintln!("  batch {batch_id} failed: {e}");
                            for (row, log) in &ok {
                                let mut r =
                                    ctx.row_result(row, &batch_id, log.as_ref(), "api_error");
                                r.error = Some(e.clone());
                                results.push(r);
                            }
                        }
                    }
                }
            }
        }
    }

    write_meta(cfg, &cfg.out_dir)?;
    write_jsonl(&cfg.out_dir.join("results.jsonl"), &results)?;
    write_jsonl(&cfg.out_dir.join("calls.jsonl"), &calls)?;
    Ok(results)
}

fn write_meta(cfg: &RunConfig, dir: &Path) -> Result<(), String> {
    let git = std::process::Command::new("git")
        .args(["describe", "--always", "--dirty", "--tags"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let meta = serde_json::json!({
        "git": git,
        "seed": cfg.seed,
        "batch_size": cfg.batch_size,
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "repeats": cfg.repeats,
        "modes": cfg.modes,
        "models": cfg.models.iter().map(|(p, m)| format!("{p}:{m}")).collect::<Vec<_>>(),
        "finished_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(
        dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

pub fn read_results(path: &Path) -> Result<Vec<RowResult>, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared(prompt: &str) -> PreparedCall {
        PreparedCall {
            system_prompt: "s".into(),
            prompt: prompt.into(),
            lines_sent: 1,
            lines_total: 1,
            rule_verdicts: vec![],
        }
    }

    #[test]
    fn cache_key_is_stable_and_sensitive_to_every_input() {
        let k = |p: &str, rep: usize, t: f32| cache_key("groq", "m", t, 10, rep, &prepared(p));
        assert_eq!(k("a", 0, 0.0), k("a", 0, 0.0));
        assert_ne!(k("a", 0, 0.0), k("b", 0, 0.0));
        assert_ne!(k("a", 0, 0.0), k("a", 1, 0.0));
        assert_ne!(k("a", 0, 0.0), k("a", 0, 0.3));
        assert_ne!(
            cache_key("groq", "m", 0.0, 10, 0, &prepared("a")),
            cache_key("openai", "m", 0.0, 10, 0, &prepared("a"))
        );
    }

    #[test]
    fn backoff_honours_retry_after_and_caps() {
        assert_eq!(backoff(0, Some(7)), Duration::from_secs(8));
        assert_eq!(backoff(0, None), Duration::from_secs(2));
        assert_eq!(backoff(2, None), Duration::from_secs(8));
        assert_eq!(backoff(20, None), Duration::from_secs(60));
    }

    #[test]
    fn spec_parsing() {
        let (p, m) = parse_model_spec("groq:openai/gpt-oss-120b").unwrap();
        assert_eq!((p, m.as_str()), (LlmProvider::Groq, "openai/gpt-oss-120b"));
        assert!(parse_model_spec("gpt-4o").is_err());
        assert!(parse_model_spec("nope:x").is_err());
        assert_eq!(
            parse_modes("ai_decides, rules-first,rules_only,spotlight")
                .unwrap()
                .len(),
            4
        );
        assert!(parse_modes("bogus").is_err());
    }

    #[tokio::test]
    async fn rules_only_run_needs_no_api_and_scores_rules() {
        let dir = std::env::temp_dir().join(format!("bench-test-{}", std::process::id()));
        let line = |path: &str| {
            format!(
                r#"1.2.3.4 - - [15/Dec/2025:17:19:00 +0000] "GET {path} HTTP/1.1" 200 5 "-" "Mozilla/5.0""#
            )
        };
        let row = |id: &str, path: &str, label: &str| Row {
            id: id.into(),
            line: line(path),
            label: label.into(),
            attack_type: None,
            injected: false,
            variant: None,
            source_id: None,
        };
        let rows = vec![
            row("a", "/x?q=%27%20OR%201%3D1", "attack"),
            row("b", "/index.html", "benign"),
            Row {
                line: "garbage".into(),
                ..row("c", "/", "benign")
            },
        ];
        let cfg = RunConfig {
            modes: vec![RULES_ONLY.into()],
            models: vec![],
            repeats: 3,
            seed: 1,
            batch_size: 10,
            temperature: 0.0,
            max_tokens: 10,
            cache_dir: dir.join("cache"),
            out_dir: dir.join("out"),
            max_retries: 1,
        };
        let res = run(rows, &cfg).await.unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(
            res.iter()
                .find(|r| r.id == "a")
                .unwrap()
                .predicted_malicious,
            Some(true)
        );
        assert_eq!(
            res.iter()
                .find(|r| r.id == "b")
                .unwrap()
                .predicted_malicious,
            Some(false)
        );
        assert_eq!(
            res.iter().find(|r| r.id == "c").unwrap().outcome,
            "unparsed_line"
        );
        assert_eq!(
            read_results(&dir.join("out/results.jsonl")).unwrap().len(),
            3
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
