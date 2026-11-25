//! `bench`: prompt-injection experiment tooling for the log analyzer.
//!
//! - `bench inject`: make injected copies of the attack lines in a dataset
//! - `bench run`:    run every mode x model x repeat and write results
//! - `bench score`:  report missed attacks, false alarms and parse failures

mod dataset;
mod inject;
mod plan;
mod run;
mod score;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bench", about = "Prompt-injection experiment tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate injected copies of the attack lines in a dataset
    Inject {
        /// Input dataset (JSONL: id, line, label, attack_type, injected, variant)
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Where the text goes: ua, path
        #[arg(long, value_delimiter = ',', default_values_t = inject::LOCATIONS.map(String::from))]
        locations: Vec<String>,
        /// Wording names: ignore_prev, system_override, authorized_test, json_forgery, marker_escape
        #[arg(long, value_delimiter = ',', default_values_t = inject::WORDINGS.map(|(n, _)| n.to_string()))]
        wordings: Vec<String>,
        /// plain, url
        #[arg(long, value_delimiter = ',', default_values_t = inject::ENCODINGS.map(String::from))]
        encodings: Vec<String>,
        /// Also write the original (uninjected) attack lines
        #[arg(long)]
        with_originals: bool,
    },
    /// Run every combination of mode, model and repeat over a dataset
    Run {
        /// Clean labelled dataset (benign + attack lines)
        #[arg(long)]
        dataset: PathBuf,
        /// Injected rows from `bench inject` (without --with-originals). Rows with
        /// injected=true in --dataset are treated the same way.
        #[arg(long)]
        injected: Option<PathBuf>,
        /// Seed for the batch shuffle (recorded in every result)
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long, default_value = "bench_out")]
        out: PathBuf,
        /// Comma list: ai_decides, rules_first, spotlight, rules_only (no model call)
        #[arg(long, default_value = "ai_decides,rules_first,spotlight")]
        modes: String,
        /// Comma list of provider:model, e.g. groq:openai/gpt-oss-120b,openai:gpt-4o
        #[arg(long, default_value = "")]
        models: String,
        #[arg(long, default_value_t = 3)]
        repeats: usize,
        /// Log lines per request (recorded with every result)
        #[arg(long, default_value_t = 20)]
        batch_size: usize,
        #[arg(long, default_value_t = 0.0)]
        temperature: f32,
        #[arg(long, default_value_t = 16384)]
        max_tokens: u32,
        #[arg(long, default_value = ".bench_cache")]
        cache_dir: PathBuf,
        /// Retries on rate limits (exponential backoff, honours Retry-After)
        #[arg(long, default_value_t = 6)]
        max_retries: u32,
    },
    /// Score a results file
    Score {
        #[arg(long, default_value = "bench_out/results.jsonl")]
        results: PathBuf,
        /// Split injected rows by variant (location/wording/encoding)
        #[arg(long)]
        by_variant: bool,
        /// Also write the summary as CSV
        #[arg(long)]
        csv: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Inject {
            input,
            output,
            locations,
            wordings,
            encodings,
            with_originals,
        } => {
            let valid = |name: &str, vals: &[String], ok: Vec<&str>| {
                vals.iter()
                    .find(|v| !ok.contains(&v.as_str()))
                    .map_or(Ok(()), |v| {
                        Err(format!("unknown {name} '{v}' (valid: {})", ok.join(", ")))
                    })
            };
            valid("location", &locations, inject::LOCATIONS.to_vec())?;
            valid(
                "wording",
                &wordings,
                inject::WORDINGS.iter().map(|(n, _)| *n).collect(),
            )?;
            valid("encoding", &encodings, inject::ENCODINGS.to_vec())?;
            let rows = dataset::read_rows(&input)?;
            let out = inject::generate(
                &rows,
                &inject::Options {
                    locations,
                    wordings,
                    encodings,
                    with_originals,
                },
            );
            dataset::write_jsonl(&output, &out)?;
            eprintln!("wrote {} rows to {}", out.len(), output.display());
        }
        Cmd::Run {
            dataset,
            injected,
            seed,
            out,
            modes,
            models,
            repeats,
            batch_size,
            temperature,
            max_tokens,
            cache_dir,
            max_retries,
        } => {
            let modes = run::parse_modes(&modes)?;
            let models = models
                .split(',')
                .filter(|m| !m.trim().is_empty())
                .map(|m| run::parse_model_spec(m.trim()))
                .collect::<Result<Vec<_>, _>>()?;
            if models.is_empty() && modes.iter().any(|m| m != run::RULES_ONLY) {
                return Err("--models is required unless --modes is rules_only".into());
            }
            let mut rows = dataset::read_rows(&dataset)?;
            if let Some(path) = &injected {
                rows.extend(dataset::read_rows(path)?);
            }
            dataset::ensure_unique_ids(&rows)?;
            let cfg = run::RunConfig {
                modes,
                models,
                repeats: repeats.max(1),
                batch_size: batch_size.max(1),
                seed,
                temperature,
                max_tokens,
                cache_dir,
                out_dir: out.clone(),
                max_retries,
            };
            let results = run::run(rows, &cfg).await?;
            eprintln!("wrote {} results to {}", results.len(), out.display());
            println!(
                "{}",
                score::render_table(&score::summarize(&results, false))
            );
        }
        Cmd::Score {
            results,
            by_variant,
            csv,
        } => {
            let summaries = score::summarize(&run::read_results(&results)?, by_variant);
            println!("{}", score::render_table(&summaries));
            if let Some(path) = csv {
                std::fs::write(&path, score::render_csv(&summaries))
                    .map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
    }
    Ok(())
}
