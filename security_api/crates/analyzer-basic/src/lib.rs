// Basic threat detection using regex patterns
// Fast, synchronous analysis without AI

use regex::Regex;
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

            // Detect failed logins
            if entry.level == "ERROR" && entry.message.contains("Failed login") {
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

            // Detect SQL injection
            if entry.message.contains("SELECT") ||
               entry.message.contains("DROP TABLE") ||
               entry.message.contains("UNION SELECT") ||
               entry.message.contains("SQL Injection") ||
               entry.message.contains("' OR '1'='1") {
                sql_injection_attempts += 1;
            }

            // Detect port scanning
            if entry.message.contains("port scan") ||
               entry.message.contains("nmap") ||
               entry.message.contains("Port scan") {
                port_scanning_attempts += 1;
            }

            // Detect malware
            if entry.message.contains("malware") ||
               entry.message.contains("trojan") ||
               entry.message.contains("virus") ||
               entry.message.contains("ransomware") ||
               entry.message.contains("Malware") {
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
