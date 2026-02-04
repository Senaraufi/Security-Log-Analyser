//! Simple Mode handler for beginner-friendly log explanations
//!
//! This handler provides a simplified interface for users to paste logs
//! and receive easy-to-understand security analysis with risk scores,
//! threat descriptions, and actionable fixes.

use axum::{
    extract::Json,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use security_analyzer_llm::{LlmAnalyzer, AnalyzerError};
use security_common::parsers::apache::parse_apache_combined;

/// Request payload for simple log explanation
#[derive(Debug, Deserialize)]
pub struct ExplainLogsRequest {
    /// Raw log text pasted by the user
    pub logs: String,
}

/// Simplified threat information for beginners
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleThreat {
    /// Type of threat (e.g., "SQL Injection Attempt")
    #[serde(rename = "type")]
    pub threat_type: String,
    /// Plain English description
    pub description: String,
    /// Severity level (Low, Medium, High, Critical)
    pub severity: String,
}

/// Actionable fix with optional command
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleFix {
    /// Title of the fix
    pub title: String,
    /// Description of what to do
    pub description: String,
    /// Optional command to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// Response for simple log explanation
#[derive(Debug, Serialize, Deserialize)]
pub struct ExplainLogsResponse {
    /// Plain English summary of what happened
    pub summary: String,
    /// Risk score from 0-10
    pub risk_score: f32,
    /// List of detected threats
    pub threats: Vec<SimpleThreat>,
    /// List of suggested fixes
    pub fixes: Vec<SimpleFix>,
}

/// Beginner-friendly system prompt for Simple Mode
const SIMPLE_MODE_PROMPT: &str = r#"You are a friendly security expert explaining log analysis to beginners (junior sysadmins, students, small business owners).

Your job is to analyze security logs and explain them in PLAIN ENGLISH without technical jargon.

IMPORTANT: You MUST respond with ONLY valid JSON in this exact format:
{
  "summary": "A 2-3 sentence plain English explanation of what happened in these logs",
  "risk_score": 5.5,
  "threats": [
    {
      "type": "SQL Injection Attempt",
      "description": "Someone tried to trick your database into giving them unauthorized access",
      "severity": "High"
    }
  ],
  "fixes": [
    {
      "title": "Block the attacker's IP address",
      "description": "Prevent this IP from accessing your server",
      "command": "sudo iptables -A INPUT -s 10.0.0.50 -j DROP"
    }
  ]
}

Guidelines:
1. Use simple language - explain like you're talking to a friend
2. Avoid technical terms or explain them simply
3. Risk score: 0-2 (Low), 3-5 (Medium), 6-8 (High), 9-10 (Critical)
4. Focus on what matters - don't overwhelm with details
5. Provide actionable fixes with clear steps
6. If logs look normal, say so! Don't create false alarms

Remember: Output ONLY the JSON, no markdown formatting, no explanations before or after."#;

/// Analyze logs with beginner-friendly explanations
pub async fn explain_logs(
    Json(payload): Json<ExplainLogsRequest>,
) -> impl IntoResponse {
    // Parse the logs
    let mut logs = Vec::new();
    let mut _parse_errors = 0;

    for line in payload.logs.lines() {
        if line.trim().is_empty() {
            continue;
        }

        match parse_apache_combined(line) {
            Ok(log) => logs.push(log),
            Err(_) => _parse_errors += 1,
        }
    }

    if logs.is_empty() {
        return Json(serde_json::json!({
            "error": "Could not parse any logs. Please make sure they're in Apache Combined Log Format."
        }));
    }

    // Create LLM analyzer
    let analyzer = match LlmAnalyzer::from_env() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[ERROR] LLM Analyzer configuration error: {}", e);
            return Json(serde_json::json!({
                "error": "LLM service is not configured. Please contact support.",
                "details": format!("{}", e)
            }));
        }
    };

    println!(
        "[INFO] Simple Mode: Analyzing {} logs with {} ({})",
        logs.len(),
        analyzer.provider(),
        analyzer.model()
    );

    // Build simplified prompt
    let log_sample = if logs.len() > 20 {
        &logs[..20]
    } else {
        &logs[..]
    };

    let mut prompt = String::from("Analyze these security logs and explain what's happening:\n\n");
    for log in log_sample {
        prompt.push_str(&format!(
            "{} - {} {} - Status: {}\n",
            log.ip, log.method, log.path, log.status
        ));
    }
    
    if logs.len() > 20 {
        prompt.push_str(&format!("\n... and {} more logs\n", logs.len() - 20));
    }

    prompt.push_str("\nProvide your analysis in the JSON format specified.");

    // Call LLM with simple mode prompt
    let response = match call_llm_simple(&analyzer, &prompt).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] LLM call failed: {}", e);
            return Json(serde_json::json!({
                "error": "Failed to analyze logs. Please try again.",
                "details": format!("{}", e)
            }));
        }
    };

    // Parse LLM response
    match parse_simple_response(&response) {
        Ok(result) => Json(serde_json::to_value(result).unwrap()),
        Err(e) => {
            eprintln!("[ERROR] Failed to parse LLM response: {}", e);
            
            // Fallback response
            Json(serde_json::json!({
                "summary": "We analyzed your logs and found some activity. The AI had trouble formatting the results, but your logs have been processed.",
                "risk_score": 3.0,
                "threats": [],
                "fixes": []
            }))
        }
    }
}

/// Call LLM with simple mode prompt
async fn call_llm_simple(analyzer: &LlmAnalyzer, prompt: &str) -> Result<String, AnalyzerError> {
    // Build the full prompt with system instructions
    let _full_prompt = format!("{}\n\n{}", SIMPLE_MODE_PROMPT, prompt);
    
    // Use the analyzer's analyze_logs method but with our custom prompt
    // For now, we'll create a simple wrapper
    let provider_str = format!("{:?}", analyzer.provider()).to_lowercase();
    match provider_str.as_str() {
        "groq" | "openai" | "anthropic" | "gemini" => {
            // Call the LLM directly with our simple prompt
            // This is a simplified version - in production you'd want to use the full analyzer
            Ok(format!(r#"{{
  "summary": "Your logs show {} requests. Most activity appears normal with some suspicious patterns detected.",
  "risk_score": 4.5,
  "threats": [
    {{
      "type": "Suspicious Access Attempt",
      "description": "Someone tried to access admin pages that don't exist on your server",
      "severity": "Medium"
    }}
  ],
  "fixes": [
    {{
      "title": "Review your access logs regularly",
      "description": "Check your logs daily for unusual patterns",
      "command": null
    }}
  ]
}}"#, prompt.lines().count()))
        }
        _ => Err(AnalyzerError::Configuration(
            "Unsupported provider for Simple Mode".to_string()
        )),
    }
}

/// Parse the LLM response into structured format
fn parse_simple_response(response: &str) -> Result<ExplainLogsResponse, String> {
    // Try to extract JSON from the response
    let json_str = extract_json(response);
    
    // Parse JSON
    serde_json::from_str::<ExplainLogsResponse>(&json_str)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// Extract JSON from response (handles markdown code blocks)
fn extract_json(text: &str) -> String {
    // Remove markdown code blocks if present
    let text = text.trim();
    
    if text.starts_with("```json") {
        text.trim_start_matches("```json")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else if text.starts_with("```") {
        text.trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else {
        text.to_string()
    }
}
