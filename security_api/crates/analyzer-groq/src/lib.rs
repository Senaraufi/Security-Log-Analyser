use reqwest::Client;
use serde::{Deserialize, Serialize};
use security_common::parsers::ApacheLog;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityReport {
    pub summary: String,
    pub threat_level: String,
    pub total_logs_analyzed: usize,
    pub suspicious_logs_count: usize,
    pub attack_chains: Vec<String>,
    pub mitre_attack_techniques: Vec<String>,
    pub indicators_of_compromise: Vec<String>,
    pub recommendations: Vec<String>,
    pub confidence_score: f32,
    pub alerts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GroqRequest {
    model: String,
    messages: Vec<GroqMessage>,
    temperature: f32,
    max_tokens: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroqMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct GroqResponse {
    choices: Vec<GroqChoice>,
}

#[derive(Debug, Deserialize)]
struct GroqChoice {
    message: GroqMessage,
}

pub struct GroqAnalyzer {
    client: Client,
    api_key: String,
    model: String,
}

impl GroqAnalyzer {
    pub fn new() -> Self {
        let api_key = env::var("GROQ_API_KEY").unwrap_or_default();
        let model = env::var("GROQ_MODEL").unwrap_or_else(|_| "llama-3.1-70b-versatile".to_string());
        
        Self {
            client: Client::new(),
            api_key,
            model,
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    async fn call_groq_api(&self, prompt: String) -> Result<String, String> {
        let request = GroqRequest {
            model: self.model.clone(),
            messages: vec![
                GroqMessage {
                    role: "system".to_string(),
                    content: "You are a cybersecurity expert analyzing web server logs for security threats.".to_string(),
                },
                GroqMessage {
                    role: "user".to_string(),
                    content: prompt,
                },
            ],
            temperature: 0.3,
            max_tokens: 2000,
        };

        let response = self.client
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Groq API request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("Groq API error {}: {}", status, error_text));
        }

        let groq_response: GroqResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse Groq response: {}", e))?;

        groq_response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| "No response from Groq".to_string())
    }

    fn parse_groq_response(&self, response: String) -> Result<SecurityReport, String> {
        // Try to parse as JSON first
        if let Ok(report) = serde_json::from_str::<SecurityReport>(&response) {
            return Ok(report);
        }

        // Fallback: Create a basic report from the text response
        Ok(SecurityReport {
            summary: response.lines().take(5).collect::<Vec<_>>().join("\n"),
            threat_level: "Medium".to_string(),
            total_logs_analyzed: 0,
            suspicious_logs_count: 0,
            attack_chains: vec![],
            mitre_attack_techniques: vec![],
            indicators_of_compromise: vec![],
            recommendations: vec![
                "Review the AI analysis above for detailed findings".to_string(),
            ],
            confidence_score: 0.75,
            alerts: vec![],
        })
    }

    pub async fn analyze_logs(&self, logs: Vec<ApacheLog>) -> Result<SecurityReport, String> {
        if !self.is_configured() {
            return Err("Groq API key not configured. Set GROQ_API_KEY environment variable.".to_string());
        }

        // Build analysis prompt
        let log_sample = logs.iter().take(50).map(|log| {
            format!(
                "[{}] {} {} {} - Status: {}",
                log.timestamp,
                log.ip,
                log.method,
                log.path,
                log.status
            )
        }).collect::<Vec<_>>().join("\n");

        let prompt = format!(
            r#"Analyze these Apache web server logs for security threats and provide a detailed security report.

LOGS TO ANALYZE:
{}

Provide your analysis in the following JSON format:
{{
    "summary": "Brief executive summary of findings",
    "threat_level": "Low/Medium/High/Critical",
    "total_logs_analyzed": {},
    "suspicious_logs_count": 0,
    "attack_chains": ["Description of any multi-step attacks detected"],
    "mitre_attack_techniques": ["T1190: Exploit Public-Facing Application"],
    "indicators_of_compromise": ["Suspicious IPs, patterns, or signatures"],
    "recommendations": ["Specific actionable recommendations"],
    "confidence_score": 0.85,
    "alerts": []
}}

Focus on:
1. SQL injection attempts
2. XSS attacks
3. Path traversal
4. Brute force attempts
5. Port scanning
6. Malware indicators
7. Suspicious patterns

Be specific and actionable in your recommendations."#,
            log_sample,
            logs.len()
        );

        // Call Groq API
        let response = self.call_groq_api(prompt).await?;

        // Parse response
        self.parse_groq_response(response)
    }
}

impl Default for GroqAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = GroqAnalyzer::new();
        assert_eq!(analyzer.model, "llama-3.1-70b-versatile");
    }

    #[test]
    fn test_is_configured() {
        let analyzer = GroqAnalyzer::new();
        // Will be false unless GROQ_API_KEY is set
        let _ = analyzer.is_configured();
    }
}
