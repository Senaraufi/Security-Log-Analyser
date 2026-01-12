/// CVSS 3.1 (Common Vulnerability Scoring System) Implementation
/// 
/// This module provides CVSS scoring for detected security threats.
/// CVSS is the industry-standard framework for rating vulnerability severity.
/// 
/// Score Range: 0.0 - 10.0
/// - None: 0.0
/// - Low: 0.1-3.9
/// - Medium: 4.0-6.9
/// - High: 7.0-8.9
/// - Critical: 9.0-10.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s == 0.0 => Severity::None,
            s if s < 4.0 => Severity::Low,
            s if s < 7.0 => Severity::Medium,
            s if s < 9.0 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Severity::None => "None",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            Severity::None => "#94a3b8",      // Gray
            Severity::Low => "#10b981",       // Green
            Severity::Medium => "#f59e0b",    // Yellow/Orange
            Severity::High => "#ef4444",      // Red
            Severity::Critical => "#dc2626",  // Dark Red
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVSSScore {
    /// Base score (0.0 - 10.0)
    pub base_score: f32,
    
    /// Severity rating based on score
    pub severity: Severity,
    
    /// CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    pub vector_string: String,
    
    /// Human-readable explanation
    pub explanation: String,
}

impl CVSSScore {
    pub fn new(base_score: f32, vector_string: String, explanation: String) -> Self {
        Self {
            base_score,
            severity: Severity::from_score(base_score),
            vector_string,
            explanation,
        }
    }
}

/// Threat types that can be detected in logs
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    SQLInjection,
    XSS,
    PathTraversal,
    CommandInjection,
    FailedLogin,
    RootAccess,
    SuspiciousFileAccess,
    PortScanning,
    Malware,
    CriticalAlert,
}

impl ThreatType {
    /// Get CVSS score for this threat type
    pub fn cvss_score(&self) -> CVSSScore {
        match self {
            ThreatType::SQLInjection => CVSSScore::new(
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                "Network-accessible SQL injection with no authentication required. \
                 High impact on confidentiality, integrity, and availability. \
                 Attacker can read, modify, or delete database contents.".to_string(),
            ),
            
            ThreatType::XSS => CVSSScore::new(
                6.1,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string(),
                "Network-accessible cross-site scripting requiring user interaction. \
                 Can steal session cookies, redirect users, or deface pages. \
                 Scope changed as attack affects other users.".to_string(),
            ),
            
            ThreatType::PathTraversal => CVSSScore::new(
                7.5,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                "Network-accessible path traversal allowing unauthorized file access. \
                 High confidentiality impact as attacker can read sensitive files \
                 like /etc/passwd or application configs.".to_string(),
            ),
            
            ThreatType::CommandInjection => CVSSScore::new(
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                "Network-accessible command injection with no authentication. \
                 Attacker can execute arbitrary system commands, leading to \
                 complete system compromise.".to_string(),
            ),
            
            ThreatType::FailedLogin => CVSSScore::new(
                5.3,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L".to_string(),
                "Failed login attempts indicate potential brute force attack. \
                 Low availability impact from resource consumption. \
                 Becomes critical if successful or repeated from same IP.".to_string(),
            ),
            
            ThreatType::RootAccess => CVSSScore::new(
                8.8,
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string(),
                "Attempt to access root/admin account. If successful, \
                 grants complete system control with high impact on all \
                 security properties.".to_string(),
            ),
            
            ThreatType::SuspiciousFileAccess => CVSSScore::new(
                7.5,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                "Access to sensitive system files (/etc/passwd, /etc/shadow). \
                 High confidentiality impact as these files contain user \
                 credentials and system information.".to_string(),
            ),
            
            ThreatType::PortScanning => CVSSScore::new(
                5.3,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                "Port scanning indicates reconnaissance activity. \
                 Low confidentiality impact from service discovery. \
                 Often precedes more serious attacks.".to_string(),
            ),
            
            ThreatType::Malware => CVSSScore::new(
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                "Malware detection indicates system compromise. \
                 High impact on all security properties. \
                 Can lead to data theft, system damage, or ransomware.".to_string(),
            ),
            
            ThreatType::CriticalAlert => CVSSScore::new(
                8.0,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string(),
                "Critical severity event requiring immediate attention. \
                 Specific impact depends on alert type but generally \
                 indicates serious security incident.".to_string(),
            ),
        }
    }
    
    /// Get threat type from string name
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "sql_injection" | "sql injection" => Some(ThreatType::SQLInjection),
            "xss" | "cross-site scripting" => Some(ThreatType::XSS),
            "path_traversal" | "path traversal" => Some(ThreatType::PathTraversal),
            "command_injection" | "command injection" => Some(ThreatType::CommandInjection),
            "failed_login" | "failed login" => Some(ThreatType::FailedLogin),
            "root_access" | "root access" => Some(ThreatType::RootAccess),
            "suspicious_file_access" | "suspicious file access" => Some(ThreatType::SuspiciousFileAccess),
            "port_scanning" | "port scanning" => Some(ThreatType::PortScanning),
            "malware" => Some(ThreatType::Malware),
            "critical_alert" | "critical alert" => Some(ThreatType::CriticalAlert),
            _ => None,
        }
    }
}

/// Calculate aggregate CVSS score for multiple threats
pub fn calculate_aggregate_score(threats: &[(ThreatType, usize)]) -> CVSSScore {
    if threats.is_empty() {
        return CVSSScore::new(
            0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N".to_string(),
            "No threats detected".to_string(),
        );
    }
    
    // Find highest severity threat
    let max_score = threats
        .iter()
        .map(|(threat_type, _)| threat_type.cvss_score().base_score)
        .fold(0.0_f32, f32::max);
    
    // Count total threat instances
    let total_instances: usize = threats.iter().map(|(_, count)| count).sum();
    
    // Apply multiplier based on threat volume
    let volume_multiplier = match total_instances {
        0 => 0.0,
        1..=2 => 1.0,
        3..=5 => 1.1,
        6..=10 => 1.15,
        11..=20 => 1.2,
        _ => 1.25,
    };
    
    let aggregate_score = (max_score * volume_multiplier).min(10.0);
    
    let explanation = format!(
        "Aggregate score based on {} threat type(s) with {} total instance(s). \
         Highest individual threat score: {:.1}. Volume multiplier: {:.2}x",
        threats.len(),
        total_instances,
        max_score,
        volume_multiplier
    );
    
    CVSSScore::new(
        aggregate_score,
        format!("CVSS:3.1/AGGREGATE"),
        explanation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(0.0), Severity::None);
        assert_eq!(Severity::from_score(3.9), Severity::Low);
        assert_eq!(Severity::from_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_score(8.9), Severity::High);
        assert_eq!(Severity::from_score(10.0), Severity::Critical);
    }

    #[test]
    fn test_sql_injection_score() {
        let score = ThreatType::SQLInjection.cvss_score();
        assert_eq!(score.base_score, 9.8);
        assert_eq!(score.severity, Severity::Critical);
    }

    #[test]
    fn test_aggregate_score() {
        let threats = vec![
            (ThreatType::SQLInjection, 2),
            (ThreatType::XSS, 1),
        ];
        let score = calculate_aggregate_score(&threats);
        assert!(score.base_score >= 9.8); // Should be at least the max score
        assert!(score.base_score <= 10.0); // But capped at 10.0
    }

    #[test]
    fn test_threat_type_from_name() {
        assert_eq!(
            ThreatType::from_name("sql_injection"),
            Some(ThreatType::SQLInjection)
        );
        assert_eq!(
            ThreatType::from_name("XSS"),
            Some(ThreatType::XSS)
        );
        assert_eq!(ThreatType::from_name("unknown"), None);
    }
}
