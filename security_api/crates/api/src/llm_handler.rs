//! LLM-based log analysis handler using the multi-provider analyzer.
//!
//! This handler uses the `security-analyzer-llm` crate to analyze logs
//! using various LLM providers (OpenAI, Anthropic, Groq, etc.) configured
//! via environment variables.

use axum::{
    extract::Multipart,
    response::{IntoResponse, Json},
};
use security_analyzer_llm::{LlmAnalyzer, AnalyzerError};
use security_common::{geolocation, parsers::apache::parse_apache_combined};

/// Analyze logs using the configured LLM provider
///
/// This endpoint accepts a multipart file upload containing Apache logs
/// and returns a comprehensive security analysis using the LLM configured
/// in environment variables.
///
/// # Environment Variables
///
/// - `LLM_PROVIDER`: openai, anthropic, groq (default: openai)
/// - `LLM_MODEL`: Model name (default: provider-specific)
/// - Provider-specific API key (e.g., `OPENAI_API_KEY`)
///
/// See `LLM_CONFIG.md` in the analyzer-llm crate for full configuration details.
pub async fn analyze_logs_with_llm(
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut content = String::new();
    let mut filename = String::from("unknown");
    let mut provider_override: Option<String> = None;

    // Extract file and optional provider from multipart form
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            filename = field.file_name().unwrap_or("unknown").to_string();
            match field.bytes().await {
                Ok(data) => {
                    content = String::from_utf8_lossy(&data).to_string();
                }
                Err(e) => {
                    return Json(serde_json::json!({
                        "error": format!("Failed to read file: {}", e)
                    }));
                }
            }
        } else if name == "provider" {
            // User-selected provider override
            if let Ok(data) = field.bytes().await {
                provider_override = Some(String::from_utf8_lossy(&data).to_string());
            }
        }
    }

    if content.is_empty() {
        return Json(serde_json::json!({
            "error": "No file content provided"
        }));
    }

    // Convert Kibana/CSV exports (e.g. honeypot data) into analyzable events
    let content = security_common::parsers::normalize_upload(content);

    // Build the analyzer from a per-request provider override or from the
    // environment. Any failure here is non-fatal: we fall back to the key-free
    // standard analysis below so the user always gets real results.
    let analyzer_result = match &provider_override {
        Some(provider_name) => build_override_analyzer(provider_name),
        None => LlmAnalyzer::from_env().map_err(|e| (e.to_string(), get_error_suggestion(&e))),
    };

    let mut ai_error: Option<String> = None;
    let mut ai_suggestion: Option<String> = None;
    let mut provider_str = String::from("none");
    let mut model_str = String::from("none");
    let analyzer_opt = match analyzer_result {
        Ok(a) => {
            provider_str = a.provider().to_string();
            model_str = a.model().to_string();
            println!("[INFO] Processing log file with {} ({}): {}", provider_str, model_str, filename);
            Some(a)
        }
        Err((err, sugg)) => {
            eprintln!("[WARN] LLM unavailable, will use standard analysis: {}", err);
            ai_error = Some(err);
            ai_suggestion = Some(sugg);
            None
        }
    };

    // Parse logs with unified parser (supports Apache, generic, and any text format)
    let mut logs = Vec::new();
    let mut parse_errors = 0;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // Try Apache format first, fall back to generic parsing
        match parse_apache_combined(line) {
            Ok(log) => logs.push(log),
            Err(_) => {
                // Use generic parser to convert any log format to Apache-like structure
                if let Some(entry) = security_common::parsers::parse_log_line_unified(line) {
                    // Convert generic LogEntry to ApacheLog for LLM analysis
                    use security_common::parsers::apache::ApacheLog;
                    use chrono::Utc;
                    
                    let apache_log = ApacheLog {
                        ip: entry.ip_address.clone().unwrap_or_else(|| "unknown".to_string()),
                        timestamp: Utc::now(), // Use current time as fallback
                        method: "GENERIC".to_string(),
                        path: entry.message.clone(),
                        protocol: "LOG/1.0".to_string(),
                        status: match entry.level.as_str() {
                            "CRITICAL" => 500,
                            "ERROR" => 400,
                            "WARN" => 300,
                            _ => 200,
                        },
                        size: 0,
                        referer: "-".to_string(),
                        user_agent: entry.username.clone().unwrap_or_else(|| "-".to_string()),
                        is_suspicious: entry.level == "ERROR" || entry.level == "CRITICAL",
                        threat_type: if entry.level == "CRITICAL" {
                            Some("Critical Alert".to_string())
                        } else if entry.level == "ERROR" {
                            Some("Error Event".to_string())
                        } else {
                            None
                        },
                        severity: Some(entry.level.clone()),
                    };
                    logs.push(apache_log);
                } else {
                    parse_errors += 1;
                }
            }
        }
    }

    if logs.is_empty() {
        return Json(serde_json::json!({
            "error": "No valid logs found in the uploaded file",
            "parse_errors": parse_errors,
            "suggestion": "Ensure the file contains log entries with timestamps and messages"
        }));
    }

    println!(
        "[INFO] Parsed {} logs ({} parse errors), sending to LLM...",
        logs.len(),
        parse_errors
    );

    // Perform LLM analysis if an analyzer is available. On any failure we record
    // the error but continue with the standard analysis below.
    let ai_report = match analyzer_opt {
        Some(analyzer) => match analyzer.analyze_logs(&logs).await {
            Ok(report) => {
                println!("[INFO] AI analysis complete - Threat Level: {}", report.threat_level);
                Some(report)
            }
            Err(e) => {
                eprintln!("[WARN] LLM analysis failed, using standard analysis: {}", e);
                ai_suggestion = Some(get_error_suggestion(&e));
                ai_error = Some(e.to_string());
                None
            }
        },
        None => None,
    };

    // Also get basic analysis for additional context
    let mut basic_result = super::process_logs(&content);

    // Enrich IPs with geolocation data
    let all_ip_strings: Vec<String> = basic_result.ip_analysis.all_ips.iter().map(|ip| ip.ip.clone()).collect();
    if !all_ip_strings.is_empty() {
        println!("[INFO] Looking up geolocation for {} IPs...", all_ip_strings.len());
        let geo_data = geolocation::lookup_batch(&all_ip_strings).await;
        
        for ip_info in &mut basic_result.ip_analysis.all_ips {
            if let Some(geo) = geo_data.get(&ip_info.ip) {
                ip_info.country = geo.country.clone();
                ip_info.city = geo.city.clone();
                ip_info.is_vpn = geo.is_proxy || geo.is_hosting;
            }
        }
        
        for ip_info in &mut basic_result.ip_analysis.high_risk_ips {
            if let Some(geo) = geo_data.get(&ip_info.ip) {
                ip_info.country = geo.country.clone();
                ip_info.city = geo.city.clone();
                ip_info.is_vpn = geo.is_proxy || geo.is_hosting;
            }
        }
    }

    // Build the report object from the AI result when available, otherwise from
    // the key-free standard analysis so the UI always shows real threat data.
    let ai_available = ai_report.is_some();
    let report_json = match &ai_report {
        Some(r) => serde_json::json!({
            "summary": r.summary,
            "threat_level": r.threat_level,
            "attack_chains": r.attack_chains,
            "mitre_attack_techniques": r.mitre_attack_techniques,
            "indicators_of_compromise": r.indicators_of_compromise,
            "recommendations": r.recommendations,
            "confidence_score": r.confidence_score,
        }),
        None => build_basic_report(&basic_result, logs.len()),
    };
    let suspicious_logs = ai_report
        .as_ref()
        .map(|r| r.suspicious_logs_count)
        .unwrap_or(basic_result.risk_assessment.total_threats);

    // Combine results - flatten structure for UI compatibility
    Json(serde_json::json!({
        // Basic analysis data (for threat distribution, IP analysis, parsing stats)
        "threat_statistics": basic_result.threat_statistics,
        "ip_analysis": basic_result.ip_analysis,
        "risk_assessment": basic_result.risk_assessment,
        "parsing_info": basic_result.parsing_info,
        "alerts": basic_result.alerts,

        // AI analysis data (report is AI-derived, or standard-analysis-derived on fallback)
        "ai_report": ai_report,
        "report": report_json,
        "ai_available": ai_available,
        "ai_error": ai_error,
        "ai_suggestion": ai_suggestion,

        // Metadata
        "total_logs": logs.len(),
        "suspicious_logs": suspicious_logs,
        "provider": provider_str,
        "model": model_str,
    }))
}

/// Build an analyzer from a user-selected provider override.
/// Returns `(error_message, suggestion)` on failure so the caller can degrade
/// gracefully to the standard analysis.
fn build_override_analyzer(provider_name: &str) -> Result<LlmAnalyzer, (String, String)> {
    use security_analyzer_llm::{LlmConfig, LlmProvider};

    let provider = LlmProvider::from_str(provider_name).ok_or_else(|| (
        format!("Unsupported provider: {}", provider_name),
        "Valid options: openai, anthropic, groq, gemini".to_string(),
    ))?;

    let model = match provider {
        LlmProvider::Groq => "openai/gpt-oss-120b",
        LlmProvider::Gemini => "gemini-1.5-flash",
        LlmProvider::OpenAI => "gpt-4o",
        LlmProvider::Anthropic => "claude-sonnet-4-20250514",
    };

    let api_key = std::env::var(provider.api_key_env_var())
        .ok()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| (
            format!("API key not configured for provider '{}'", provider_name),
            format!("Set the {} environment variable in your .env file.", provider.api_key_env_var()),
        ))?;

    println!("[INFO] User selected provider: {}", provider_name);
    // Reasoning models (e.g. gpt-oss) spend part of this budget on hidden
    // reasoning tokens, so a small limit truncates the JSON report.
    let config = LlmConfig::new(provider, model, api_key).with_max_tokens(16384);
    Ok(LlmAnalyzer::with_config(config))
}

/// Build a UI report from the key-free standard analysis. Used when the LLM
/// provider is unavailable so the dashboard always shows real threat data
/// instead of an empty "Analysis complete / Unknown" placeholder.
fn build_basic_report(result: &security_common::AnalysisResult, total_logs: usize) -> serde_json::Value {
    let ra = &result.risk_assessment;
    let ts = &result.threat_statistics;

    // Base the displayed threat level on CVSS severity (not raw threat count), so
    // a small number of Critical findings isn't mislabeled as "Low".
    let threat_level = match ra.cvss_severity.to_uppercase().as_str() {
        "CRITICAL" => "Critical",
        "HIGH" => "High",
        "MEDIUM" => "Medium",
        "LOW" => "Low",
        _ => "Info",
    };

    let summary = format!(
        "Standard (non-AI) analysis: {}. Detected {} threat indicator(s) across {} log entries, aggregate CVSS {:.1}.",
        ra.description, ra.total_threats, total_logs, ra.cvss_aggregate_score
    );

    let findings: Vec<String> = ts
        .cvss_scores
        .iter()
        .map(|s| format!("{} ({}x) - {} (CVSS {:.1})", s.threat_type, s.count, s.severity, s.cvss_score))
        .collect();

    let iocs: Vec<String> = result
        .ip_analysis
        .high_risk_ips
        .iter()
        .take(10)
        .map(|ip| format!("Suspicious IP {} ({} requests)", ip.ip, ip.count))
        .collect();

    let mut recs = Vec::new();
    if ts.sql_injection_attempts > 0 { recs.push("Investigate SQL injection attempts; use parameterized queries and deploy a WAF.".to_string()); }
    if ts.suspicious_file_access > 0 { recs.push("Review access to sensitive files (e.g., /etc/passwd) and block path traversal.".to_string()); }
    if ts.failed_logins > 0 { recs.push("Multiple failed logins detected; enforce rate limiting, MFA, and fail2ban.".to_string()); }
    if ts.root_attempts > 0 { recs.push("Privileged/root access attempts detected; audit sudo and disable root SSH login.".to_string()); }
    if ts.port_scanning_attempts > 0 { recs.push("Port scanning observed; block the offending IPs at the firewall.".to_string()); }
    if ts.malware_detections > 0 { recs.push("Possible malware indicators found; isolate affected hosts and run a scan.".to_string()); }
    if recs.is_empty() { recs.push("No high-severity threats detected. Continue monitoring.".to_string()); }

    serde_json::json!({
        "summary": summary,
        "threat_level": threat_level,
        "attack_chains": findings,
        "mitre_attack_techniques": Vec::<String>::new(),
        "indicators_of_compromise": iocs,
        "recommendations": recs,
        "confidence_score": serde_json::Value::Null,
    })
}

/// Get a user-friendly suggestion for fixing an analyzer error
fn get_error_suggestion(error: &AnalyzerError) -> String {
    match error {
        AnalyzerError::Configuration(_) => {
            "Check your .env file and ensure the required API key is set. \
             See LLM_CONFIG.md for configuration details."
                .to_string()
        }
        AnalyzerError::ApiError { provider, .. } => {
            format!(
                "Check your {} API key and network connection. \
                 The provider may be experiencing issues.",
                provider
            )
        }
        AnalyzerError::RateLimitExceeded { retry_after_seconds, .. } => {
            if let Some(seconds) = retry_after_seconds {
                format!("Rate limit exceeded. Try again in {} seconds.", seconds)
            } else {
                "Rate limit exceeded. Please wait and try again.".to_string()
            }
        }
        AnalyzerError::ProviderNotSupported { provider, .. } => {
            format!(
                "Provider '{}' is not supported. Use openai, anthropic, or groq.",
                provider
            )
        }
        _ => error.suggestion().to_string(),
    }
}

/// Health check endpoint for the LLM analyzer
pub async fn llm_health_check() -> impl IntoResponse {
    match LlmAnalyzer::from_env() {
        Ok(analyzer) => Json(serde_json::json!({
            "status": "ok",
            "configured": true,
            "provider": analyzer.provider().to_string(),
            "model": analyzer.model(),
        })),
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "configured": false,
            "error": e.to_string(),
            "suggestion": get_error_suggestion(&e),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_suggestions() {
        let config_error = AnalyzerError::Configuration("test".to_string());
        let suggestion = get_error_suggestion(&config_error);
        assert!(suggestion.contains("env"));

        let api_error = AnalyzerError::ApiError {
            provider: "OpenAI".to_string(),
            message: "test".to_string(),
        };
        let suggestion = get_error_suggestion(&api_error);
        assert!(suggestion.contains("OpenAI"));
    }
}