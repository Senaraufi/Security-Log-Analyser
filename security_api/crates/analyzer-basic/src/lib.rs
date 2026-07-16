// Basic threat detection using regex patterns
// Fast, synchronous analysis without AI

use security_common::{LogEntry, ThreatCVSS};
use std::collections::HashMap;

/// Detect threats in parsed log entries
pub struct BasicAnalyzer;

impl BasicAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze log entries and return threat statistics
    pub fn analyze(&self, entries: &[LogEntry]) -> BasicAnalysisResult {
        let mut failed_logins = 0;
        let mut root_attempts = 0;
        let mut suspicious_file_access = 0;
        let mut critical_alerts = 0;
        let mut sql_injection_attempts = 0;
        let mut port_scanning_attempts = 0;
        let mut malware_detections = 0;
        let mut ip_frequency: HashMap<String, usize> = HashMap::new();

        for entry in entries {
            // Track IP addresses
            if let Some(ip) = &entry.ip_address {
                ip_frequency.entry(ip.clone())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
            }

            // Detect failed logins across common auth formats:
            // - Apache/app logs:   "Failed login"
            // - sshd/auth.log:     "Failed password", "authentication failure", "Invalid user"
            // - Windows events:    "an account failed to log on", audit failure 4625
            let login_msg = entry.message.to_lowercase();
            if login_msg.contains("failed login")
                || login_msg.contains("failed password")
                || login_msg.contains("authentication failure")
                || login_msg.contains("invalid user")
                || login_msg.contains("failed to log on")
                || login_msg.contains("login failed")
            {
                failed_logins += 1;
            }

            // Detect root access attempts
            if entry.message.contains("user: root") || 
               entry.message.contains("root access") ||
               entry.message.contains("Root access") {
                root_attempts += 1;
            }

            // Detect suspicious file access
            if entry.message.contains("/etc/passwd") || 
               entry.message.contains("/etc/shadow") ||
               entry.message.contains("Suspicious file") {
                suspicious_file_access += 1;
            }

            // Detect critical alerts
            if entry.level == "CRITICAL" {
                critical_alerts += 1;
            }

            let message_lower = entry.message.to_lowercase();

            // Detect SQL injection: require actual injection markers, not just
            // the word "SELECT" (which appears in legitimate query logs).
            if message_lower.contains("union select") ||
               message_lower.contains("drop table") ||
               message_lower.contains("'; drop") ||
               message_lower.contains("or 1=1") ||
               message_lower.contains("' or '1'='1") ||
               message_lower.contains("sql injection") {
                sql_injection_attempts += 1;
            }

            // Detect port scanning
            if message_lower.contains("port scan") ||
               message_lower.contains("nmap") {
                port_scanning_attempts += 1;
            }

            // Detect malware (avoid matching benign strings like "antivirus")
            if message_lower.contains("malware") ||
               message_lower.contains("trojan") ||
               message_lower.contains("ransomware") ||
               (message_lower.contains("virus") && !message_lower.contains("antivirus")) {
                malware_detections += 1;
            }
        }

        BasicAnalysisResult {
            failed_logins,
            root_attempts,
            suspicious_file_access,
            critical_alerts,
            sql_injection_attempts,
            port_scanning_attempts,
            malware_detections,
            ip_frequency,
        }
    }

    /// Generate CVSS scores for detected threats
    pub fn generate_cvss_scores(&self, result: &BasicAnalysisResult) -> Vec<ThreatCVSS> {
        use security_common::cvss::ThreatType;
        
        let mut cvss_scores = Vec::new();

        if result.sql_injection_attempts > 0 {
            let cvss = ThreatType::SQLInjection.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "SQL Injection".to_string(),
                count: result.sql_injection_attempts,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        if result.failed_logins > 0 {
            let cvss = ThreatType::FailedLogin.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "Failed Login".to_string(),
                count: result.failed_logins,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        if result.root_attempts > 0 {
            let cvss = ThreatType::RootAccess.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "Root Access Attempt".to_string(),
                count: result.root_attempts,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        if result.suspicious_file_access > 0 {
            let cvss = ThreatType::SuspiciousFileAccess.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "Suspicious File Access".to_string(),
                count: result.suspicious_file_access,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        if result.port_scanning_attempts > 0 {
            let cvss = ThreatType::PortScanning.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "Port Scanning".to_string(),
                count: result.port_scanning_attempts,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        if result.malware_detections > 0 {
            let cvss = ThreatType::Malware.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "Malware".to_string(),
                count: result.malware_detections,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        if result.critical_alerts > 0 {
            let cvss = ThreatType::CriticalAlert.cvss_score();
            cvss_scores.push(ThreatCVSS {
                threat_type: "Critical Alert".to_string(),
                count: result.critical_alerts,
                cvss_score: cvss.base_score,
                severity: cvss.severity.as_str().to_string(),
                vector_string: cvss.vector_string.clone(),
                explanation: cvss.explanation.clone(),
            });
        }

        cvss_scores
    }
}

/// Result of basic threat analysis
pub struct BasicAnalysisResult {
    pub failed_logins: usize,
    pub root_attempts: usize,
    pub suspicious_file_access: usize,
    pub critical_alerts: usize,
    pub sql_injection_attempts: usize,
    pub port_scanning_attempts: usize,
    pub malware_detections: usize,
    pub ip_frequency: HashMap<String, usize>,
}

impl Default for BasicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp: "2025-12-15T17:19:00Z".to_string(),
            level: level.to_string(),
            ip_address: Some("10.0.0.1".to_string()),
            username: None,
            message: message.to_string(),
        }
    }

    #[test]
    fn detects_real_sql_injection() {
        let entries = vec![entry("INFO", "GET /api?id=1 UNION SELECT password FROM users")];
        let result = BasicAnalyzer::new().analyze(&entries);
        assert_eq!(result.sql_injection_attempts, 1);
    }

    #[test]
    fn ignores_benign_select_in_message() {
        // A legitimate query log mentioning SELECT must not be flagged.
        let entries = vec![entry("INFO", "Executed query: SELECT * FROM products WHERE active = 1")];
        let result = BasicAnalyzer::new().analyze(&entries);
        assert_eq!(result.sql_injection_attempts, 0);
    }

    #[test]
    fn antivirus_is_not_malware() {
        let entries = vec![entry("INFO", "Antivirus definitions updated successfully")];
        let result = BasicAnalyzer::new().analyze(&entries);
        assert_eq!(result.malware_detections, 0);
    }

    #[test]
    fn detects_malware_keyword() {
        let entries = vec![entry("WARN", "Detected trojan in uploaded file")];
        let result = BasicAnalyzer::new().analyze(&entries);
        assert_eq!(result.malware_detections, 1);
    }

    #[test]
    fn detects_failed_logins_across_formats() {
        let entries = vec![
            entry("ERROR", "Failed login for admin from 10.0.0.1"),
            entry("INFO", "Failed password for invalid user root from 203.0.113.5 port 22 ssh2"),
            entry("INFO", "pam_unix(sshd:auth): authentication failure; rhost=203.0.113.9"),
            entry("INFO", "An account failed to log on. Account Name: bob"),
        ];
        let result = BasicAnalyzer::new().analyze(&entries);
        // "Failed password for invalid user" matches two patterns but counts once per entry.
        assert_eq!(result.failed_logins, 4);
    }
}
