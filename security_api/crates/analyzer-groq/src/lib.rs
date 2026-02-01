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

        // Try to extract JSON from markdown code blocks (```json ... ```)
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(&response)
                .trim()
        } else if response.contains("```") {
            // Try generic code block
            response
                .split("```")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(&response)
                .trim()
        } else {
            // Try to find JSON object in text
            if let Some(start) = response.find('{') {
                if let Some(end) = response.rfind('}') {
                    &response[start..=end]
                } else {
                    &response
                }
            } else {
                &response
            }
        };

        // Try parsing the extracted JSON
        if let Ok(report) = serde_json::from_str::<SecurityReport>(json_str) {
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
            r#"You are a senior cybersecurity analyst. Analyze these Apache web server logs and provide a DETAILED security assessment.

LOGS TO ANALYZE ({} total):
{}

CRITICAL INSTRUCTIONS:
1. Count the ACTUAL number of suspicious logs you identify
2. List SPECIFIC attack chains with timestamps and IPs
3. Provide DETAILED MITRE ATT&CK mappings with explanations
4. List ALL malicious IPs found
5. Give SPECIFIC, actionable recommendations

Return ONLY valid JSON in this EXACT format (no markdown, no code blocks):
{{
    "summary": "Detailed 3-4 sentence executive summary describing the specific attacks found, their severity, and immediate concerns",
    "threat_level": "Critical",
    "total_logs_analyzed": {},
    "suspicious_logs_count": <actual count of suspicious entries>,
    "attack_chains": [
        "SQL Injection Attack Chain: IP 10.0.0.50 attempted multiple SQL injection attacks at 14:25:10-14:25:20, targeting /api/users and /api/data endpoints with UNION SELECT and OR 1=1 patterns",
        "Brute Force Attack: IP 192.168.1.100 made 5 failed login attempts to /admin/login.php between 14:23:15-14:23:27",
        "Path Traversal: IP 203.0.113.45 attempted directory traversal at 14:30:00-14:30:10 targeting /etc/passwd and Windows system files"
    ],
    "mitre_attack_techniques": [
        "T1190 - Exploit Public-Facing Application: SQL injection attempts detected",
        "T1110.001 - Brute Force: Password Guessing: Multiple failed authentication attempts",
        "T1083 - File and Directory Discovery: Path traversal attempts to access sensitive files",
        "T1595.002 - Active Scanning: Vulnerability Scanning: Port scanning detected from 198.51.100.88",
        "T1505.003 - Web Shell: Backdoor upload and execution attempts from 45.33.32.156"
    ],
    "indicators_of_compromise": [
        "Malicious IP: 10.0.0.50 - SQL injection source",
        "Malicious IP: 192.168.1.100 - Brute force attacker",
        "Malicious IP: 203.0.113.45 - Path traversal attempts",
        "Malicious IP: 198.51.100.88 - Port scanner (masscan)",
        "Malicious IP: 45.33.32.156 - Web shell deployment",
        "Suspicious User-Agent: python-requests/2.28.0, curl/7.68.0, masscan/1.0, WPScan",
        "Malicious Files: shell.php, backdoor.php accessed",
        "Attack Patterns: SQL UNION SELECT, OR '1'='1, <script> tags, ../../etc/passwd"
    ],
    "recommendations": [
        "IMMEDIATE: Block IPs 10.0.0.50, 192.168.1.100, 203.0.113.45, 198.51.100.88, 45.33.32.156 at firewall level",
        "URGENT: Implement rate limiting on /admin/login.php to prevent brute force attacks (max 3 attempts per 5 minutes)",
        "CRITICAL: Enable parameterized queries/prepared statements to prevent SQL injection on /api/users and /api/data endpoints",
        "HIGH: Implement input validation and sanitization for all user inputs to prevent XSS attacks",
        "HIGH: Restrict file upload functionality and scan all uploads for malware. Remove backdoor.php immediately",
        "MEDIUM: Enable Web Application Firewall (WAF) with OWASP Core Rule Set",
        "MEDIUM: Implement path traversal protection by validating and sanitizing file paths",
        "LOW: Update WordPress installation and plugins (WPScan activity detected)",
        "MONITORING: Set up alerts for failed login attempts > 3 in 5 minutes",
        "MONITORING: Alert on any access to .env, .git, config.bak, or database.sql files"
    ],
    "confidence_score": 0.95,
    "alerts": []
}}

Analyze EVERY log entry. Be thorough and specific. Include actual IPs, timestamps, and attack details."#,
            logs.len(),
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
