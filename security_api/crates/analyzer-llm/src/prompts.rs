//! Security analysis prompt templates for LLM-based log analysis.
//!
//! This module contains carefully crafted prompts that guide the LLM
//! to produce structured, actionable security analysis reports.

use security_common::parsers::ApacheLog;

/// System prompt that establishes the LLM's role as a security analyst
pub const SYSTEM_PROMPT: &str = r#"You are a senior cybersecurity analyst specializing in web server log analysis and threat detection. Your expertise includes:

- Identifying attack patterns (SQL injection, XSS, path traversal, brute force, etc.)
- Mapping attacks to MITRE ATT&CK framework techniques
- Extracting Indicators of Compromise (IOCs)
- Providing actionable security recommendations
- CVSS scoring and risk assessment

You analyze logs methodically, identify attack chains, and provide detailed, actionable intelligence. Your responses are always in valid JSON format."#;

/// Format a collection of Apache logs into a readable string for analysis
pub fn format_logs_for_analysis(logs: &[ApacheLog], max_logs: usize) -> String {
    logs.iter()
        .take(max_logs)
        .map(|log| {
            format!(
                "[{}] {} {} \"{}\" {} {} \"{}\"",
                log.timestamp,
                log.ip,
                log.method,
                log.path,
                log.status,
                log.size,
                log.user_agent
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the main security analysis prompt
pub fn build_analysis_prompt(logs: &[ApacheLog], max_sample_logs: usize) -> String {
    let log_sample = format_logs_for_analysis(logs, max_sample_logs);
    let total_logs = logs.len();

    format!(
        r#"Analyze the following Apache web server logs and provide a comprehensive security assessment.

## LOGS TO ANALYZE ({total_logs} total entries, showing up to {max_sample_logs}):

{log_sample}

## ANALYSIS REQUIREMENTS:

1. **Count Suspicious Activity**: Identify and count all suspicious log entries
2. **Detect Attack Chains**: Group related malicious requests by IP and time
3. **Map to MITRE ATT&CK**: Identify techniques with their T-codes and explanations
4. **Extract IOCs**: List all malicious IPs, user-agents, and attack patterns
5. **Provide Recommendations**: Give specific, actionable remediation steps

## RESPONSE FORMAT:

Return ONLY valid JSON matching this exact schema (no markdown, no code blocks):

{{
    "summary": "A detailed 3-4 sentence executive summary describing the specific attacks found, their severity, and immediate security concerns",
    "threat_level": "Critical|High|Medium|Low|Info",
    "total_logs_analyzed": {total_logs},
    "suspicious_logs_count": <actual count of suspicious entries you identified>,
    "attack_chains": [
        "Detailed description of attack chain 1 with IPs, timestamps, and techniques",
        "Detailed description of attack chain 2..."
    ],
    "mitre_attack_techniques": [
        "T1190 - Exploit Public-Facing Application: Description of how this was observed",
        "T1110.001 - Brute Force: Password Guessing: Description..."
    ],
    "indicators_of_compromise": [
        "Malicious IP: x.x.x.x - Description of activity",
        "Suspicious User-Agent: agent-string - Why it's suspicious",
        "Attack Pattern: pattern - Explanation"
    ],
    "recommendations": [
        "IMMEDIATE: Urgent action with specific details",
        "HIGH: Important action with specifics",
        "MEDIUM: Recommended action",
        "LOW: Best practice suggestion"
    ],
    "confidence_score": 0.95,
    "alerts": [
        "Critical alerts requiring immediate attention"
    ]
}}

## IMPORTANT GUIDELINES:

- Be thorough: analyze EVERY log entry for potential threats
- Be specific: include actual IPs, timestamps, paths, and patterns
- Be actionable: recommendations should be immediately implementable
- Be accurate: only report what you actually observe in the logs
- If no threats are found, report that clearly with appropriate low threat level"#
    )
}

/// Build a prompt for analyzing a specific IP address
pub fn build_ip_analysis_prompt(ip: &str, logs: &[ApacheLog]) -> String {
    let ip_logs: Vec<_> = logs.iter().filter(|log| log.ip == ip).collect();
    let log_sample = ip_logs
        .iter()
        .take(50)
        .map(|log| {
            format!(
                "[{}] {} \"{}\" {} \"{}\"",
                log.timestamp,
                log.method,
                log.path,
                log.status,
                log.user_agent
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"Analyze all activity from IP address {ip} and determine if it's malicious.

## ACTIVITY FROM {ip} ({} total requests):

{log_sample}

## ANALYSIS REQUIREMENTS:

1. Determine if this IP is malicious, suspicious, or benign
2. Identify attack patterns if any
3. Provide risk score (0.0 - 1.0)
4. Recommend actions

## RESPONSE FORMAT (JSON only):

{{
    "ip": "{ip}",
    "classification": "malicious|suspicious|benign",
    "risk_score": 0.85,
    "attack_types": ["SQL Injection", "Brute Force"],
    "request_count": {},
    "suspicious_requests": <count>,
    "first_seen": "timestamp",
    "last_seen": "timestamp",
    "user_agents": ["list of user agents used"],
    "targeted_paths": ["list of attacked paths"],
    "recommendations": ["Block at firewall", "Investigate..."],
    "evidence": "Detailed explanation of why this classification was made"
}}"#,
        ip_logs.len(),
        ip_logs.len()
    )
}

/// Build a prompt for quick threat triage
pub fn build_triage_prompt(logs: &[ApacheLog]) -> String {
    let log_sample = format_logs_for_analysis(logs, 100);
    
    format!(
        r#"Quickly triage these logs and identify the most critical threats.

## LOGS ({} entries):

{log_sample}

## RESPONSE FORMAT (JSON only):

{{
    "threat_level": "Critical|High|Medium|Low|Info",
    "critical_findings": ["List of most critical issues"],
    "top_malicious_ips": ["ip1", "ip2", "ip3"],
    "immediate_actions": ["Action 1", "Action 2"],
    "requires_deep_analysis": true|false
}}"#,
        logs.len()
    )
}

/// Build a prompt for generating security recommendations
pub fn build_recommendations_prompt(threat_summary: &str) -> String {
    format!(
        r#"Based on the following security threat summary, provide detailed remediation recommendations.

## THREAT SUMMARY:

{threat_summary}

## RESPONSE FORMAT (JSON only):

{{
    "immediate_actions": [
        {{
            "priority": 1,
            "action": "Specific action to take",
            "reason": "Why this is important",
            "implementation": "How to implement this"
        }}
    ],
    "short_term_actions": [
        {{
            "priority": 2,
            "action": "Action",
            "reason": "Reason",
            "implementation": "How to implement"
        }}
    ],
    "long_term_improvements": [
        {{
            "priority": 3,
            "action": "Action",
            "reason": "Reason",
            "implementation": "How to implement"
        }}
    ],
    "monitoring_recommendations": [
        "What to monitor going forward"
    ]
}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc, TimeZone};

    fn create_test_log(ip: &str, method: &str, path: &str, status: u16) -> ApacheLog {
        ApacheLog {
            ip: ip.to_string(),
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap(),
            method: method.to_string(),
            path: path.to_string(),
            protocol: "HTTP/1.1".to_string(),
            status,
            size: 1234,
            referer: "-".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            is_suspicious: false,
            threat_type: None,
            severity: None,
        }
    }

    #[test]
    fn test_format_logs_for_analysis() {
        let logs = vec![
            create_test_log("192.168.1.1", "GET", "/index.html", 200),
            create_test_log("10.0.0.1", "POST", "/api/login", 401),
        ];

        let formatted = format_logs_for_analysis(&logs, 10);
        
        assert!(formatted.contains("192.168.1.1"));
        assert!(formatted.contains("10.0.0.1"));
        assert!(formatted.contains("/index.html"));
        assert!(formatted.contains("/api/login"));
    }

    #[test]
    fn test_build_analysis_prompt() {
        let logs = vec![
            create_test_log("192.168.1.1", "GET", "/index.html", 200),
        ];

        let prompt = build_analysis_prompt(&logs, 50);
        
        assert!(prompt.contains("LOGS TO ANALYZE"));
        assert!(prompt.contains("192.168.1.1"));
        assert!(prompt.contains("MITRE ATT&CK"));
        assert!(prompt.contains("threat_level"));
    }

    #[test]
    fn test_build_ip_analysis_prompt() {
        let logs = vec![
            create_test_log("192.168.1.1", "GET", "/admin", 403),
            create_test_log("192.168.1.1", "POST", "/admin/login", 401),
            create_test_log("10.0.0.1", "GET", "/index.html", 200),
        ];

        let prompt = build_ip_analysis_prompt("192.168.1.1", &logs);
        
        assert!(prompt.contains("192.168.1.1"));
        assert!(prompt.contains("/admin"));
        assert!(prompt.contains("2 total requests"));
        // Should not include the other IP's logs
        assert!(!prompt.contains("10.0.0.1"));
    }

    #[test]
    fn test_system_prompt_content() {
        assert!(SYSTEM_PROMPT.contains("cybersecurity"));
        assert!(SYSTEM_PROMPT.contains("MITRE ATT&CK"));
        assert!(SYSTEM_PROMPT.contains("JSON"));
    }
}