use async_trait::async_trait;
use crate::llm::analyzer::{
    LLMAnalyzer, SecurityReport, ThreatLevel, Finding, AttackChain, IOC
};
use security_common::parsers::apache::ApacheLog;

/// Mock LLM analyzer for testing without API key for development 
/// Generates realistic-looking reports based on parsed log data
pub struct MockAnalyzer;

impl MockAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    fn generate_mock_report(&self, logs: &[ApacheLog]) -> SecurityReport {
        let suspicious_logs: Vec<&ApacheLog> = logs.iter()
            .filter(|l| l.is_suspicious)
            .collect();
        
        // Generate summary
        let summary = if suspicious_logs.is_empty() {
            format!(
                "Analysis of {} log entries revealed no significant security threats. \
                All requests appear to be legitimate traffic with normal patterns. \
                Continue monitoring for anomalies.",
                logs.len()
            )
        } else {
            format!(
                "Analysis of {} log entries identified {} suspicious activities requiring attention. \
                Detected attack patterns include {}. Immediate investigation recommended for high-severity findings.",
                logs.len(),
                suspicious_logs.len(),
                self.summarize_threat_types(&suspicious_logs)
            )
        };
        
        // Determine threat level
        let threat_level = self.calculate_threat_level(&suspicious_logs);
        
        // Generate findings
        let findings = self.generate_findings(&suspicious_logs);
        
        // Generate attack chains
        let attack_chains = self.generate_attack_chains(&suspicious_logs);
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&suspicious_logs);
        
        // Generate IOCs
        let iocs = self.generate_iocs(&suspicious_logs);
        
        SecurityReport {
            summary,
            threat_level,
            findings,
            attack_chains,
            recommendations,
            iocs,
        }
    }
    
    fn summarize_threat_types(&self, logs: &[&ApacheLog]) -> String {
        let mut threat_types: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        for log in logs {
            if let Some(threat_type) = &log.threat_type {
                threat_types.insert(threat_type.to_string());
            }
        }
        
        let types: Vec<String> = threat_types.into_iter().collect();
        
        if types.is_empty() {
            "various attack patterns".to_string()
        } else if types.len() == 1 {
            types[0].clone()
        } else if types.len() == 2 {
            format!("{} and {}", types[0], types[1])
        } else {
            let last = types.last().unwrap();
            let others = &types[..types.len() - 1];
            format!("{}, and {}", others.join(", "), last)
        }
    }
    
    fn calculate_threat_level(&self, logs: &[&ApacheLog]) -> ThreatLevel {
        if logs.is_empty() {
            return ThreatLevel::None;
        }
        
        let has_critical = logs.iter().any(|l| {
            l.severity.as_ref().map_or(false, |s| s == "Critical")
        });
        
        let has_high = logs.iter().any(|l| {
            l.severity.as_ref().map_or(false, |s| s == "High")
        });
        
        if has_critical {
            ThreatLevel::Critical
        } else if has_high {
            ThreatLevel::High
        } else if logs.len() > 5 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        }
    }
    
    fn generate_findings(&self, logs: &[&ApacheLog]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Group by threat type
        let mut by_threat: std::collections::HashMap<String, Vec<&ApacheLog>> = 
            std::collections::HashMap::new();
        
        for log in logs {
            if let Some(threat_type) = &log.threat_type {
                by_threat.entry(threat_type.to_string())
                    .or_insert_with(Vec::new)
                    .push(log);
            }
        }
        
        for (threat_type, threat_logs) in by_threat.iter() {
            let severity = threat_logs.first()
                .and_then(|l| l.severity.clone())
                .unwrap_or_else(|| "Medium".to_string());
            
            let affected_resources: Vec<String> = threat_logs.iter()
                .map(|l| format!("{} {}", l.method, l.path))
                .collect();
            
            let description = self.generate_finding_description(threat_type, threat_logs);
            
            findings.push(Finding {
                severity: severity.clone(),
                attack_type: threat_type.to_string(),
                description,
                affected_resources,
                confidence: self.calculate_confidence(threat_type, threat_logs.len()),
            });
        }
        
        findings
    }
    
    fn generate_finding_description(&self, threat_type: &str, logs: &[&ApacheLog]) -> String {
        let count = logs.len();
        let ips: std::collections::HashSet<String> = logs.iter()
            .map(|l| l.ip.clone())
            .collect();
        
        match threat_type {
            "SQL Injection" => format!(
                "Detected {} SQL injection attempt(s) from {} unique IP address(es). \
                Attack patterns include UNION SELECT statements, OR 1=1 conditions, and comment sequences. \
                These attempts target database queries and could lead to unauthorized data access or modification. \
                MITRE ATT&CK: T1190 (Exploit Public-Facing Application).",
                count, ips.len()
            ),
            "Path Traversal" => format!(
                "Identified {} path traversal attempt(s) from {} source(s). \
                Attackers are attempting to access files outside the web root using ../ sequences. \
                Successful exploitation could expose sensitive system files. \
                MITRE ATT&CK: T1005 (Data from Local System).",
                count, ips.len()
            ),
            "Cross-Site Scripting" => format!(
                "Found {} XSS attempt(s) from {} IP(s). \
                Attack vectors include <script> tags and JavaScript event handlers. \
                Could be used to steal user sessions or perform actions on behalf of victims. \
                OWASP: A03:2021 - Injection.",
                count, ips.len()
            ),
            "Command Injection" => format!(
                "Detected {} command injection attempt(s) from {} attacker(s). \
                Patterns indicate attempts to execute system commands through application inputs. \
                Critical risk of remote code execution and system compromise. \
                MITRE ATT&CK: T1059 (Command and Scripting Interpreter).",
                count, ips.len()
            ),
            "Security Scanner" => format!(
                "Identified {} automated security scanning activities from {} source(s). \
                Tools detected include Nmap, Nikto, SQLMap, and other reconnaissance tools. \
                Indicates reconnaissance phase of potential attack. \
                MITRE ATT&CK: T1046 (Network Service Scanning).",
                count, ips.len()
            ),
            "Unauthorized Access Attempt" => format!(
                "Recorded {} unauthorized access attempt(s) from {} IP(s). \
                Multiple authentication failures or forbidden resource access attempts. \
                Could indicate credential stuffing, brute force, or privilege escalation attempts. \
                OWASP: A07:2021 - Identification and Authentication Failures.",
                count, ips.len()
            ),
            _ => format!(
                "Detected {} suspicious activities of type '{}' from {} source(s). \
                Further investigation recommended to determine intent and impact.",
                count, threat_type, ips.len()
            ),
        }
    }
    
    fn calculate_confidence(&self, threat_type: &str, count: usize) -> f32 {
        // Higher confidence for well-known patterns and multiple occurrences
        let base_confidence = match threat_type {
            "SQL Injection" => 0.95,
            "Command Injection" => 0.95,
            "Path Traversal" => 0.90,
            "Cross-Site Scripting" => 0.85,
            "Security Scanner" => 0.98,
            "Unauthorized Access Attempt" => 0.80,
            _ => 0.70,
        };
        
        // Increase confidence with more occurrences
        let count_factor = (count as f32).log10() * 0.05;
        
        (base_confidence + count_factor).min(1.0)
    }
    
    fn generate_attack_chains(&self, logs: &[&ApacheLog]) -> Vec<AttackChain> {
        let mut chains = Vec::new();
        
        // Group by IP to find attack chains
        let mut by_ip: std::collections::HashMap<String, Vec<&ApacheLog>> = 
            std::collections::HashMap::new();
        
        for log in logs {
            by_ip.entry(log.ip.clone())
                .or_insert_with(Vec::new)
                .push(log);
        }
        
        // Find IPs with multiple attack types
        for (ip, ip_logs) in by_ip {
            if ip_logs.len() < 2 {
                continue;
            }
            
            let threat_types: std::collections::HashSet<String> = ip_logs.iter()
                .filter_map(|l| l.threat_type.clone())
                .collect();
            
            if threat_types.len() > 1 {
                let events: Vec<String> = ip_logs.iter()
                    .map(|l| format!("{} {} - {}", 
                        l.method, 
                        l.path, 
                        l.threat_type.as_ref().unwrap_or(&"Unknown".to_string())
                    ))
                    .collect();
                
                let timeline: Vec<String> = ip_logs.iter()
                    .map(|l| l.timestamp.to_rfc3339())
                    .collect();
                
                chains.push(AttackChain {
                    name: format!("Multi-vector attack from {}", ip),
                    description: format!(
                        "Source {} performed {} different types of attacks in sequence. \
                        This indicates a sophisticated attacker performing reconnaissance \
                        and exploitation attempts. Pattern suggests automated attack tool usage.",
                        ip, threat_types.len()
                    ),
                    events,
                    timeline,
                    source_ips: vec![ip.clone()],
                });
            }
        }
        
        chains
    }
    
    fn generate_recommendations(&self, logs: &[&ApacheLog]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if logs.is_empty() {
            recommendations.push("Continue monitoring for anomalous patterns.".to_string());
            recommendations.push("Ensure logging is comprehensive and retained for forensic analysis.".to_string());
            recommendations.push("Review and update WAF rules regularly.".to_string());
            return recommendations;
        }
        
        // Immediate actions
        recommendations.push("**IMMEDIATE ACTIONS (0-24 hours)**".to_string());
        
        let critical_count = logs.iter()
            .filter(|l| l.severity.as_ref().map_or(false, |s| s == "Critical"))
            .count();
        
        if critical_count > 0 {
            recommendations.push(format!(
                "Block {} critical threat source IP(s) at firewall/WAF level immediately.",
                logs.iter().map(|l| l.ip.as_str()).collect::<std::collections::HashSet<_>>().len()
            ));
        }
        
        recommendations.push("Review application logs for successful exploitation indicators.".to_string());
        recommendations.push("Verify data integrity and check for unauthorized modifications.".to_string());
        
        // Threat-specific recommendations
        let threat_types: std::collections::HashSet<String> = logs.iter()
            .filter_map(|l| l.threat_type.clone())
            .collect();
        
        recommendations.push("\n**SHORT-TERM ACTIONS (1-7 days)**".to_string());
        
        if threat_types.contains("SQL Injection") {
            recommendations.push("Implement parameterized queries and input validation for all database interactions.".to_string());
            recommendations.push("Deploy or update WAF rules to block SQL injection patterns.".to_string());
        }
        
        if threat_types.contains("Path Traversal") {
            recommendations.push("Implement strict input validation and path canonicalization.".to_string());
            recommendations.push("Use chroot jails or containerization to limit file system access.".to_string());
        }
        
        if threat_types.contains("Cross-Site Scripting") {
            recommendations.push("Implement Content Security Policy (CSP) headers.".to_string());
            recommendations.push("Enable output encoding for all user-controlled data.".to_string());
        }
        
        if threat_types.contains("Security Scanner") {
            recommendations.push("Implement rate limiting and CAPTCHA for suspicious traffic patterns.".to_string());
            recommendations.push("Consider using honeypots to detect and track reconnaissance activities.".to_string());
        }
        
        recommendations.push("\n**LONG-TERM IMPROVEMENTS (1-3 months)**".to_string());
        recommendations.push("Conduct security code review and penetration testing.".to_string());
        recommendations.push("Implement Security Information and Event Management (SIEM) for real-time correlation.".to_string());
        recommendations.push("Establish incident response playbooks for common attack scenarios.".to_string());
        recommendations.push("Provide security awareness training for development and operations teams.".to_string());
        
        recommendations
    }
    
    fn generate_iocs(&self, logs: &[&ApacheLog]) -> Vec<IOC> {
        let mut iocs = Vec::new();
        
        // Malicious IPs
        let malicious_ips: std::collections::HashSet<String> = logs.iter()
            .map(|l| l.ip.clone())
            .collect();
        
        for ip in malicious_ips {
            let ip_logs: Vec<&&ApacheLog> = logs.iter()
                .filter(|l| l.ip == ip)
                .collect();
            
            let threat_types: Vec<String> = ip_logs.iter()
                .filter_map(|l| l.threat_type.clone())
                .collect();
            
            iocs.push(IOC {
                ioc_type: "ip".to_string(),
                value: ip.clone(),
                description: format!("Source of {} attack(s): {}", 
                    ip_logs.len(), 
                    threat_types.join(", ")
                ),
            });
        }
        
        // Suspicious user agents
        let suspicious_uas: std::collections::HashSet<String> = logs.iter()
            .map(|l| l.user_agent.clone())
            .collect();
        
        for ua in suspicious_uas {
            if ua.to_lowercase().contains("sqlmap") 
                || ua.to_lowercase().contains("nmap")
                || ua.to_lowercase().contains("nikto")
                || ua.to_lowercase().contains("burp") {
                iocs.push(IOC {
                    ioc_type: "user_agent".to_string(),
                    value: ua.clone(),
                    description: "Security scanning tool detected".to_string(),
                });
            }
        }
        
        // Attack patterns in paths
        let attack_paths: std::collections::HashSet<String> = logs.iter()
            .map(|l| l.path.clone())
            .collect();
        
        for path in attack_paths {
            if path.contains("union") || path.contains("select") {
                iocs.push(IOC {
                    ioc_type: "pattern".to_string(),
                    value: path.clone(),
                    description: "SQL injection pattern".to_string(),
                });
            } else if path.contains("../") {
                iocs.push(IOC {
                    ioc_type: "pattern".to_string(),
                    value: path.clone(),
                    description: "Path traversal pattern".to_string(),
                });
            } else if path.contains("<script>") {
                iocs.push(IOC {
                    ioc_type: "pattern".to_string(),
                    value: path.clone(),
                    description: "XSS pattern".to_string(),
                });
            }
        }
        
        iocs
    }
}

#[async_trait]
impl LLMAnalyzer for MockAnalyzer {
    async fn analyze_logs(&self, logs: Vec<ApacheLog>) -> Result<SecurityReport, String> {
        // Simulate API delay
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        Ok(self.generate_mock_report(&logs))
    }
}

impl Default for MockAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
