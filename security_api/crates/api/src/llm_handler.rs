//! LLM-based log analysis handler using the multi-provider analyzer.
//!
//! This handler uses the `security-analyzer-llm` crate to analyze logs
//! using various LLM providers (OpenAI, Anthropic, Groq, etc.) configured
//! via environment variables.

use axum::{
    extract::{Extension, Multipart},
    response::{IntoResponse, Json},
};
use security_analyzer_llm::{LlmAnalyzer, AnalyzerError};
use security_common::{database::DbPool, parsers::apache::parse_apache_combined};

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
    Extension(_db_pool): Extension<DbPool>,
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

    // Create the LLM analyzer from environment configuration or user override
    let analyzer = if let Some(provider) = provider_override {
        // Temporarily set LLM_PROVIDER env var for this request
        // SAFETY: This is safe because we're only modifying the environment for this process
        // and the analyzer will read it immediately after
        unsafe {
            std::env::set_var("LLM_PROVIDER", &provider);
            
            // Set appropriate model for each provider
            match provider.as_str() {
                "groq" => std::env::set_var("LLM_MODEL", "llama-3.3-70b-versatile"),
                "gemini" => std::env::set_var("LLM_MODEL", "gemini-3-flash-preview"),
                "openai" => std::env::set_var("LLM_MODEL", "gpt-4o"),
                "anthropic" => std::env::set_var("LLM_MODEL", "claude-sonnet-4-20250514"),
                _ => {}
            }
        }
        println!("[INFO] User selected provider: {}", provider);
        match LlmAnalyzer::from_env() {
            Ok(a) => a,
            Err(e) => {
                let suggestion = get_error_suggestion(&e);
                eprintln!("[ERROR] LLM Analyzer configuration error: {}", e);
                return Json(serde_json::json!({
                    "error": format!("LLM configuration error: {}", e),
                    "suggestion": suggestion
                }));
            }
        }
    } else {
        // Use default environment configuration
        match LlmAnalyzer::from_env() {
            Ok(a) => a,
            Err(e) => {
                let suggestion = get_error_suggestion(&e);
                eprintln!("[ERROR] LLM Analyzer configuration error: {}", e);
                return Json(serde_json::json!({
                    "error": format!("LLM configuration error: {}", e),
                    "suggestion": suggestion
                }));
            }
        }
    };

    println!(
        "[INFO] Processing log file with {} ({}): {}",
        analyzer.provider(),
        analyzer.model(),
        filename
    );

    // Parse Apache logs
    let mut logs = Vec::new();
    let mut parse_errors = 0;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        match parse_apache_combined(line) {
            Ok(log) => logs.push(log),
            Err(_) => parse_errors += 1,
        }
    }

    if logs.is_empty() {
        return Json(serde_json::json!({
            "error": "No valid Apache logs found in the uploaded file",
            "parse_errors": parse_errors,
            "suggestion": "Ensure the file contains Apache combined log format entries"
        }));
    }

    println!(
        "[INFO] Parsed {} logs ({} parse errors), sending to LLM...",
        logs.len(),
        parse_errors
    );

    // Perform LLM analysis
    let ai_report = match analyzer.analyze_logs(&logs).await {
        Ok(report) => report,
        Err(e) => {
            let suggestion = get_error_suggestion(&e);
            eprintln!("[ERROR] LLM analysis failed: {}", e);
            return Json(serde_json::json!({
                "error": format!("AI analysis failed: {}", e),
                "suggestion": suggestion,
                "provider": analyzer.provider().to_string(),
                "model": analyzer.model()
            }));
        }
    };

    println!(
        "✅ Analysis complete - Threat Level: {}",
        ai_report.threat_level
    );

    // Also get basic analysis for additional context
    let basic_result = super::process_logs(&content);

    // Combine results - flatten structure for UI compatibility
    Json(serde_json::json!({
        // Basic analysis data (for threat distribution, IP analysis, parsing stats)
        "threat_statistics": basic_result.threat_statistics,
        "ip_analysis": basic_result.ip_analysis,
        "risk_assessment": basic_result.risk_assessment,
        "parsing_info": basic_result.parsing_info,
        "alerts": basic_result.alerts,

        // AI analysis data
        "ai_report": ai_report,
        "report": {
            "summary": ai_report.summary,
            "threat_level": ai_report.threat_level,
            "attack_chains": ai_report.attack_chains,
            "mitre_attack_techniques": ai_report.mitre_attack_techniques,
            "indicators_of_compromise": ai_report.indicators_of_compromise,
            "recommendations": ai_report.recommendations,
            "confidence_score": ai_report.confidence_score,
        },

        // Metadata
        "total_logs": logs.len(),
        "suspicious_logs": ai_report.suspicious_logs_count,
        "provider": analyzer.provider().to_string(),
        "model": analyzer.model(),
    }))
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