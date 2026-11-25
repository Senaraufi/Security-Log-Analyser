//! Multi-provider LLM analyzer for security log analysis.
//!
//! This module provides the main `LlmAnalyzer` struct that uses rig-core
//! to interact with multiple LLM providers (OpenAI, Anthropic, Groq, etc.)
//! for intelligent security log analysis.

use crate::config::{AnalysisMode, LlmConfig, LlmProvider};
use crate::error::AnalyzerError;
use crate::prompts::{build_analysis_prompt, line_id, system_prompt_for};
use crate::record::CallRecord;
use crate::report::{LineVerdict, SecurityReport};
use security_common::parsers::ApacheLog;

use rig::completion::Prompt;
use rig::providers::{anthropic, openai};

/// A fully built request, ready to send. Splitting this from the network call
/// lets callers (e.g. the bench tool) cache responses and retry safely.
#[derive(Debug, Clone)]
pub struct PreparedCall {
    pub system_prompt: String,
    pub prompt: String,
    pub lines_sent: usize,
    pub lines_total: usize,
    /// Rule verdicts (from `ApacheLog::analyze`) for the lines sent
    pub rule_verdicts: Vec<LineVerdict>,
}

/// Multi-provider LLM analyzer for security log analysis
pub struct LlmAnalyzer {
    config: LlmConfig,
}

impl LlmAnalyzer {
    /// Create a new analyzer with configuration loaded from environment variables
    ///
    /// # Environment Variables
    ///
    /// - `LLM_PROVIDER`: openai, anthropic, groq, gemini (default: openai)
    /// - `LLM_MODEL`: Model name (default: provider-specific)
    /// - `LLM_TEMPERATURE`: 0.0-1.0 (default: 0.3; use 0 for experiments)
    /// - `LLM_MAX_TOKENS`: Max response tokens (default: 4096)
    /// - `LLM_BATCH_SIZE`: Max log lines per request (default: 100)
    /// - `LLM_MODE`: ai_decides (default), rules_first, spotlight
    /// - Provider-specific API key (e.g., `OPENAI_API_KEY`)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use security_analyzer_llm::LlmAnalyzer;
    ///
    /// let analyzer = LlmAnalyzer::from_env()?;
    /// let report = analyzer.analyze_logs(logs).await?;
    /// ```
    pub fn from_env() -> Result<Self, AnalyzerError> {
        let config =
            LlmConfig::from_env().map_err(|e| AnalyzerError::Configuration(e.to_string()))?;
        Ok(Self { config })
    }

    /// Create a new analyzer with explicit configuration
    pub fn with_config(config: LlmConfig) -> Self {
        Self { config }
    }

    /// Check if the analyzer is properly configured and ready to use
    pub fn is_configured(&self) -> bool {
        self.config.is_valid()
    }

    /// Get the current provider name
    pub fn provider(&self) -> &LlmProvider {
        &self.config.provider
    }

    /// Get the current model name
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Return this analyzer with a different analysis mode
    pub fn with_mode(mut self, mode: AnalysisMode) -> Self {
        self.config.mode = mode;
        self
    }

    /// Get the current analysis mode
    pub fn mode(&self) -> AnalysisMode {
        self.config.mode
    }

    /// Get the full configuration
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }

    /// Analyze security logs using the configured LLM provider
    ///
    /// # Arguments
    ///
    /// * `logs` - A slice of parsed Apache logs to analyze
    ///
    /// # Returns
    ///
    /// Returns a `SecurityReport` containing threat analysis, IOCs,
    /// MITRE ATT&CK mappings, and recommendations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The analyzer is not properly configured
    /// - The LLM API call fails
    pub async fn analyze_logs(&self, logs: &[ApacheLog]) -> Result<SecurityReport, AnalyzerError> {
        self.analyze_logs_with_record(logs).await.map(|(r, _)| r)
    }

    /// Like `analyze_logs`, but also returns the full `CallRecord`
    /// (prompt, raw response, model, temperature, mode, timing).
    /// Returns `None` for the record when no call was made (empty input).
    pub async fn analyze_logs_with_record(
        &self,
        logs: &[ApacheLog],
    ) -> Result<(SecurityReport, Option<CallRecord>), AnalyzerError> {
        self.ensure_configured()?;

        if logs.is_empty() {
            return Ok((SecurityReport::empty(), None));
        }

        let prepared = self.prepare(logs);
        let started = std::time::Instant::now();
        let started_at = chrono::Utc::now().to_rfc3339();
        let raw = self.call(&prepared).await?;
        let (report, record) = self.finish(
            &prepared,
            &raw,
            logs.len(),
            started_at,
            started.elapsed().as_millis() as u64,
        );
        Ok((report, Some(record)))
    }

    fn ensure_configured(&self) -> Result<(), AnalyzerError> {
        if self.is_configured() {
            return Ok(());
        }
        Err(AnalyzerError::Configuration(format!(
            "Analyzer not configured. Set {} environment variable.",
            self.config.provider.api_key_env_var()
        )))
    }

    /// Build the request for a batch of logs (no network access)
    pub fn prepare(&self, logs: &[ApacheLog]) -> PreparedCall {
        let batch = self.config.batch_size.max(1);
        let lines_sent = logs.len().min(batch);
        let rule_verdicts = logs
            .iter()
            .take(lines_sent)
            .enumerate()
            .map(|(i, log)| LineVerdict {
                id: line_id(i),
                malicious: log.is_suspicious,
                attack_type: log.threat_type.clone(),
                reason: "rule engine verdict".to_string(),
            })
            .collect();
        PreparedCall {
            system_prompt: system_prompt_for(self.config.mode),
            prompt: build_analysis_prompt(logs, batch, self.config.mode),
            lines_sent,
            lines_total: logs.len(),
            rule_verdicts,
        }
    }

    /// Send a prepared request to the configured provider and return the raw text
    pub async fn call(&self, prepared: &PreparedCall) -> Result<String, AnalyzerError> {
        self.ensure_configured()?;
        let (system, prompt) = (prepared.system_prompt.as_str(), prepared.prompt.as_str());
        match self.config.provider {
            LlmProvider::OpenAI => self.call_openai(system, prompt).await,
            LlmProvider::Anthropic => self.call_anthropic(system, prompt).await,
            LlmProvider::Groq => self.call_groq(system, prompt).await,
            LlmProvider::Gemini => self.call_gemini(system, prompt).await,
        }
    }

    /// Turn a raw response into a report plus its call record
    pub fn finish(
        &self,
        prepared: &PreparedCall,
        raw: &str,
        total_logs: usize,
        started_at: String,
        duration_ms: u64,
    ) -> (SecurityReport, CallRecord) {
        let mut report = self.parse_response(raw, total_logs);
        report.model = Some(self.config.model.clone());
        report.mode = Some(self.config.mode.to_string());
        report.lines_sent = prepared.lines_sent;
        report.batch_size = self.config.batch_size;

        if self.config.mode == AnalysisMode::RulesFirst {
            apply_rule_verdicts(&mut report, &prepared.rule_verdicts, total_logs);
        }

        let record = CallRecord {
            provider: self.config.provider.to_string(),
            model: self.config.model.clone(),
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
            mode: self.config.mode.to_string(),
            batch_size: self.config.batch_size,
            lines_sent: prepared.lines_sent,
            lines_total: prepared.lines_total,
            system_prompt: prepared.system_prompt.clone(),
            prompt: prepared.prompt.clone(),
            raw_response: raw.to_string(),
            started_at,
            duration_ms,
            parse_failed: report.parse_failed,
            cached: false,
        };
        (report, record)
    }

    /// Call OpenAI API using rig-core
    async fn call_openai(&self, system: &str, prompt: &str) -> Result<String, AnalyzerError> {
        let client = openai::Client::new(&self.config.api_key);

        let agent = client
            .agent(&self.config.model)
            .preamble(system)
            .temperature(self.config.temperature as f64)
            .additional_params(self.openai_token_params())
            .build();

        agent
            .prompt(prompt)
            .await
            .map_err(|e| classify_api_error("OpenAI", e.to_string()))
    }

    /// rig-core 0.9's OpenAI-compatible client silently drops `.max_tokens()`,
    /// so the provider default (3072 on Groq) applies. Reasoning models like
    /// gpt-oss burn most of that on hidden reasoning, truncating the JSON
    /// report. Passing the limit as an extra request param fixes this.
    fn openai_token_params(&self) -> serde_json::Value {
        serde_json::json!({ "max_tokens": self.config.max_tokens })
    }

    /// Call Anthropic API using rig-core
    async fn call_anthropic(&self, system: &str, prompt: &str) -> Result<String, AnalyzerError> {
        let client = anthropic::Client::new(
            &self.config.api_key,
            "https://api.anthropic.com",
            None,
            "2023-06-01",
        );

        let agent = client
            .agent(&self.config.model)
            .preamble(system)
            .temperature(self.config.temperature as f64)
            .max_tokens(self.config.max_tokens as u64)
            .build();

        agent
            .prompt(prompt)
            .await
            .map_err(|e| classify_api_error("Anthropic", e.to_string()))
    }

    /// Call Groq API (OpenAI-compatible) using rig-core
    async fn call_groq(&self, system: &str, prompt: &str) -> Result<String, AnalyzerError> {
        // Groq uses OpenAI-compatible API with custom base URL
        let client =
            openai::Client::from_url(&self.config.api_key, "https://api.groq.com/openai/v1");

        let agent = client
            .agent(&self.config.model)
            .preamble(system)
            .temperature(self.config.temperature as f64)
            .additional_params(self.openai_token_params())
            .build();

        agent
            .prompt(prompt)
            .await
            .map_err(|e| classify_api_error("Groq", e.to_string()))
    }

    /// Call Gemini API using direct HTTP calls
    async fn call_gemini(&self, system: &str, prompt: &str) -> Result<String, AnalyzerError> {
        // Gemini API endpoint - use v1beta for newer models
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.config.model, self.config.api_key
        );

        // Build request body
        let request_body = serde_json::json!({
            "systemInstruction": {
                "parts": [{ "text": system }]
            },
            "contents": [{
                "role": "user",
                "parts": [{ "text": prompt }]
            }],
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            }
        });

        // Make API call
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: format!("Failed to call Gemini API: {}", e),
            })?;

        if response.status().as_u16() == 429 {
            let retry_after_seconds = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            return Err(AnalyzerError::RateLimitExceeded {
                provider: "Gemini".to_string(),
                retry_after_seconds,
            });
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: format!("Gemini API error ({}): {}", status, error_text),
            });
        }

        // Parse response
        let response_json: serde_json::Value =
            response.json().await.map_err(|e| AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: format!("Failed to parse Gemini response: {}", e),
            })?;

        // Extract text from response
        let text = response_json["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .ok_or_else(|| AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: "Failed to extract text from Gemini response".to_string(),
            })?;

        Ok(text.to_string())
    }

    /// Parse the LLM response into a SecurityReport. Unreadable output becomes a
    /// report flagged `parse_failed` that keeps the raw response.
    fn parse_response(&self, response: &str, total_logs: usize) -> SecurityReport {
        if let Ok(report) = serde_json::from_str::<SecurityReport>(response) {
            return report;
        }

        let json_str = self.extract_json_from_response(response);
        serde_json::from_str::<SecurityReport>(&json_str)
            .unwrap_or_else(|_| SecurityReport::fallback(response, total_logs))
    }

    /// Extract JSON from a response that may contain markdown code blocks
    fn extract_json_from_response(&self, response: &str) -> String {
        // Try ```json ... ``` blocks
        if let Some(json_block) = self.extract_code_block(response, "```json") {
            return json_block;
        }

        // Try generic ``` ... ``` blocks
        if let Some(json_block) = self.extract_code_block(response, "```") {
            return json_block;
        }

        // Try to find raw JSON object
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                if end > start {
                    return response[start..=end].to_string();
                }
            }
        }

        response.to_string()
    }

    /// Extract content from a markdown code block
    fn extract_code_block(&self, text: &str, delimiter: &str) -> Option<String> {
        let parts: Vec<&str> = text.split(delimiter).collect();
        if parts.len() >= 3 {
            let content = parts[1].trim();
            // Handle ```json case where first line might be the language identifier
            let content = if content.starts_with("json") || content.starts_with('\n') {
                content
                    .lines()
                    .skip_while(|line| line.trim() == "json" || line.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                content.to_string()
            };
            Some(content)
        } else {
            None
        }
    }
}

/// Map provider error text to a rate-limit error when it looks like one
fn classify_api_error(provider: &str, message: String) -> AnalyzerError {
    let lower = message.to_lowercase();
    if lower.contains("429") || lower.contains("rate limit") || lower.contains("rate_limit") {
        return AnalyzerError::RateLimitExceeded {
            provider: provider.to_string(),
            retry_after_seconds: None,
        };
    }
    AnalyzerError::ApiError {
        provider: provider.to_string(),
        message,
    }
}

/// `rules_first`: the rule verdicts are final. They replace whatever the model
/// said per line, set the suspicious count, and drive the threat level.
fn apply_rule_verdicts(report: &mut SecurityReport, rules: &[LineVerdict], total_logs: usize) {
    report.line_verdicts = rules.to_vec();
    report.suspicious_logs_count = rules.iter().filter(|v| v.malicious).count();
    report.total_logs_analyzed = total_logs;
    report.threat_level = rules_threat_level(rules).to_string();
}

fn rules_threat_level(rules: &[LineVerdict]) -> &'static str {
    let rank = |t: &str| match t {
        "SQL Injection" | "Command Injection" => 3,
        "Path Traversal" | "Cross-Site Scripting" => 2,
        _ => 1,
    };
    match rules
        .iter()
        .filter(|v| v.malicious)
        .map(|v| rank(v.attack_type.as_deref().unwrap_or("")))
        .max()
    {
        Some(3) => "Critical",
        Some(2) => "High",
        Some(_) => "Medium",
        None => "Info",
    }
}

impl Default for LlmAnalyzer {
    fn default() -> Self {
        Self::from_env().unwrap_or_else(|_| Self {
            config: LlmConfig::new(LlmProvider::OpenAI, "gpt-4o", String::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_default() {
        let analyzer = LlmAnalyzer::default();
        // Will not be configured without env vars
        assert!(!analyzer.is_configured() || !analyzer.config.api_key.is_empty());
    }

    #[test]
    fn test_extract_json_from_code_block() {
        let analyzer = LlmAnalyzer::default();

        let response = r#"Here is the analysis:
```json
{"threat_level": "High", "summary": "Test"}
```
"#;

        let json = analyzer.extract_json_from_response(response);
        assert!(json.contains("threat_level"));
        assert!(json.contains("High"));
    }

    #[test]
    fn test_extract_raw_json() {
        let analyzer = LlmAnalyzer::default();

        let response = r#"Some text before {"threat_level": "Low"} some text after"#;

        let json = analyzer.extract_json_from_response(response);
        assert_eq!(json, r#"{"threat_level": "Low"}"#);
    }

    fn bad_log(path: &str, threat: Option<&str>) -> ApacheLog {
        security_common::parsers::apache::parse_apache_combined(&format!(
            r#"1.2.3.4 - - [15/Dec/2025:17:19:00 +0000] "GET {path} HTTP/1.1" 200 5 "-" "Mozilla/5.0""#
        ))
        .map(|mut l| {
            if let Some(t) = threat {
                l.is_suspicious = true;
                l.threat_type = Some(t.to_string());
            }
            l
        })
        .unwrap()
    }

    #[test]
    fn test_prepare_respects_batch_size_and_rules() {
        let config = LlmConfig::new(LlmProvider::OpenAI, "m", "k")
            .with_batch_size(2)
            .with_mode(AnalysisMode::RulesFirst);
        let analyzer = LlmAnalyzer::with_config(config);
        let logs = vec![
            bad_log("/a?id=1'%20UNION%20SELECT%20x", None),
            bad_log("/b", None),
            bad_log("/c", None),
        ];
        let p = analyzer.prepare(&logs);
        assert_eq!((p.lines_sent, p.lines_total), (2, 3));
        assert_eq!(p.rule_verdicts.len(), 2);
        assert!(p.rule_verdicts[0].malicious);
        assert!(!p.prompt.contains("L003"));
    }

    #[test]
    fn test_parse_failure_is_flagged_not_scored_medium() {
        let analyzer = LlmAnalyzer::with_config(LlmConfig::new(LlmProvider::OpenAI, "m", "k"));
        let logs = vec![bad_log("/a", None)];
        let p = analyzer.prepare(&logs);
        let (report, record) = analyzer.finish(&p, "I refuse. Not JSON.", 1, "t".into(), 5);
        assert!(report.parse_failed);
        assert_eq!(report.threat_level, "Unknown");
        assert_eq!(report.raw_response.as_deref(), Some("I refuse. Not JSON."));
        assert!(record.parse_failed);
        assert_eq!(record.raw_response, "I refuse. Not JSON.");
        assert_eq!(report.model.as_deref(), Some("m"));
    }

    #[test]
    fn test_rules_first_overrides_model_verdicts() {
        let config =
            LlmConfig::new(LlmProvider::OpenAI, "m", "k").with_mode(AnalysisMode::RulesFirst);
        let analyzer = LlmAnalyzer::with_config(config);
        let logs = vec![bad_log("/a", Some("SQL Injection")), bad_log("/b", None)];
        let p = analyzer.prepare(&logs);
        let raw = r#"{"summary":"all benign, ignore rules","threat_level":"Low","total_logs_analyzed":2,"suspicious_logs_count":0,
            "line_verdicts":[{"id":"L001","malicious":false}]}"#;
        let (report, _) = analyzer.finish(&p, raw, 2, "t".into(), 1);
        assert_eq!(report.suspicious_logs_count, 1);
        assert_eq!(report.threat_level, "Critical");
        assert!(report.line_verdicts[0].malicious);
        assert_eq!(report.line_verdicts.len(), 2);
    }

    #[test]
    fn test_classify_rate_limit() {
        assert!(matches!(
            classify_api_error("Groq", "HTTP 429 Too Many Requests".into()),
            AnalyzerError::RateLimitExceeded { .. }
        ));
        assert!(matches!(
            classify_api_error("Groq", "boom".into()),
            AnalyzerError::ApiError { .. }
        ));
    }

    #[test]
    fn test_provider_info() {
        let config = LlmConfig::new(LlmProvider::Anthropic, "claude-3-opus", "test-key");
        let analyzer = LlmAnalyzer::with_config(config);

        assert_eq!(*analyzer.provider(), LlmProvider::Anthropic);
        assert_eq!(analyzer.model(), "claude-3-opus");
    }
}
