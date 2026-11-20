//! Shared log analysis pipeline.
//!
//! Both the web API (`security-api`) and the CLI (`logr`) need the same
//! parse → detect → score → aggregate flow. This module provides a single
//! [`analyze`] function that encapsulates it, eliminating the previous code
//! duplication between the two binaries.

use crate::BasicAnalyzer;
use security_common::{
    AnalysisResult, FormatQuality, IpAnalysis, IpInfo, ParseError, ParsingInfo, RiskAssessment,
    ThreatStats, cvss,
    parsers::{parse_apache_combined, parse_log_line_unified},
};

/// Run the full basic-analysis pipeline on raw log text.
///
/// 1. Parses every line using the unified multi-format parser.
/// 2. Runs pattern-based threat detection.
/// 3. Generates CVSS 3.1 scores for each threat category.
/// 4. Computes an aggregate risk assessment.
///
/// The returned [`AnalysisResult`] is ready to serialize as JSON for the API
/// response or to feed into the CLI's output formatters.
pub fn analyze(content: &str) -> AnalysisResult {
    // ── Parse ──────────────────────────────────────────────────────────
    let mut entries = Vec::new();
    let mut total_lines: usize = 0;
    let mut parsed_lines: usize = 0;
    let mut parse_errors: Vec<ParseError> = Vec::new();
    let mut perfect_format: usize = 0;
    let mut alternative_format: usize = 0;
    let mut fallback_format: usize = 0;

    for line in content.lines() {
        total_lines += 1;

        if line.trim().is_empty() {
            continue;
        }

        if let Some(entry) = parse_log_line_unified(line) {
            parsed_lines += 1;

            // Track format quality
            if parse_apache_combined(line).is_ok() {
                perfect_format += 1;
            } else if entry.timestamp.contains('-') && !entry.level.is_empty() {
                alternative_format += 1;
            } else {
                fallback_format += 1;
            }

            entries.push(entry);
        } else if parse_errors.len() < 10 {
            parse_errors.push(ParseError {
                line_number: total_lines,
                line_content: if line.len() > 100 {
                    format!("{}...", &line[..100])
                } else {
                    line.to_string()
                },
                error_type: "Parse failed".to_string(),
                suggestion: "Line was empty or invalid".to_string(),
            });
        }
    }

    // ── Detect ─────────────────────────────────────────────────────────
    let analyzer = BasicAnalyzer::new();
    let analysis = analyzer.analyze(&entries);
    let cvss_scores = analyzer.generate_cvss_scores(&analysis);

    // ── IP aggregation ─────────────────────────────────────────────────
    let mut ip_vec: Vec<_> = analysis.ip_frequency.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));

    let high_risk_ips: Vec<IpInfo> = ip_vec
        .iter()
        .filter(|(_, count)| **count >= 3)
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: "high".to_string(),
            country: None,
            city: None,
            is_vpn: false,
        })
        .collect();

    let all_ips: Vec<IpInfo> = ip_vec
        .iter()
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: if **count >= 3 { "high" } else { "low" }.to_string(),
            country: None,
            city: None,
            is_vpn: false,
        })
        .collect();

    // ── Aggregate scoring ──────────────────────────────────────────────
    let total_threats = analysis.failed_logins
        + analysis.root_attempts
        + analysis.suspicious_file_access
        + analysis.critical_alerts
        + analysis.sql_injection_attempts
        + analysis.port_scanning_attempts
        + analysis.malware_detections;

    let mut threat_types_for_aggregate = Vec::new();
    if analysis.sql_injection_attempts > 0 {
        threat_types_for_aggregate.push((
            cvss::ThreatType::SQLInjection,
            analysis.sql_injection_attempts,
        ));
    }
    if analysis.failed_logins > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::FailedLogin, analysis.failed_logins));
    }
    if analysis.root_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::RootAccess, analysis.root_attempts));
    }
    if analysis.suspicious_file_access > 0 {
        threat_types_for_aggregate.push((
            cvss::ThreatType::SuspiciousFileAccess,
            analysis.suspicious_file_access,
        ));
    }
    if analysis.port_scanning_attempts > 0 {
        threat_types_for_aggregate.push((
            cvss::ThreatType::PortScanning,
            analysis.port_scanning_attempts,
        ));
    }
    if analysis.malware_detections > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::Malware, analysis.malware_detections));
    }
    if analysis.critical_alerts > 0 {
        threat_types_for_aggregate
            .push((cvss::ThreatType::CriticalAlert, analysis.critical_alerts));
    }

    let aggregate_cvss = cvss::calculate_aggregate_score(&threat_types_for_aggregate);

    let (level, description) = if total_threats > 20 {
        ("CRITICAL", "Immediate action required")
    } else if total_threats > 10 {
        ("HIGH", "Urgent attention needed")
    } else if total_threats > 5 {
        ("MEDIUM", "Review recommended")
    } else {
        ("LOW", "Normal activity")
    };

    // ── Build result ───────────────────────────────────────────────────
    AnalysisResult {
        threat_statistics: ThreatStats {
            failed_logins: analysis.failed_logins,
            root_attempts: analysis.root_attempts,
            suspicious_file_access: analysis.suspicious_file_access,
            critical_alerts: analysis.critical_alerts,
            sql_injection_attempts: analysis.sql_injection_attempts,
            port_scanning_attempts: analysis.port_scanning_attempts,
            malware_detections: analysis.malware_detections,
            cvss_scores,
        },
        ip_analysis: IpAnalysis {
            high_risk_ips,
            all_ips,
        },
        risk_assessment: RiskAssessment {
            level: level.to_string(),
            total_threats,
            description: description.to_string(),
            cvss_aggregate_score: aggregate_cvss.base_score,
            cvss_severity: aggregate_cvss.severity.as_str().to_string(),
        },
        parsing_info: ParsingInfo {
            total_lines,
            parsed_lines,
            skipped_lines: total_lines - parsed_lines,
            errors: parse_errors,
            format_quality: FormatQuality {
                perfect_format,
                alternative_format,
                fallback_format,
            },
        },
        alerts: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_empty_input() {
        let result = analyze("");
        assert_eq!(result.risk_assessment.total_threats, 0);
        assert_eq!(result.parsing_info.total_lines, 0);
    }

    #[test]
    fn analyze_mixed_formats() {
        let content = "\
2025-02-20 10:30:45 [ERROR] Failed login from 192.168.1.100
2025-02-20 10:30:46 [INFO] User logged in successfully
";
        let result = analyze(content);
        assert_eq!(result.parsing_info.parsed_lines, 2);
        assert_eq!(result.threat_statistics.failed_logins, 1);
    }

    #[test]
    fn analyze_apache_logs() {
        let content = r#"203.0.113.10 - - [15/Dec/2025:17:19:00 +0000] "GET /api/health HTTP/1.1" 200 15 "-" "kube-probe/1.28"
10.0.0.1 - - [15/Dec/2025:17:19:01 +0000] "GET /api/users?id=1' UNION SELECT * FROM passwords-- HTTP/1.1" 200 0 "-" "curl/7.68.0"
"#;
        let result = analyze(content);
        assert_eq!(result.parsing_info.parsed_lines, 2);
        assert!(result.threat_statistics.sql_injection_attempts > 0);
    }
}
