use std::fs;
use std::io::{self, Read};
use std::process;

use clap::{Parser, ValueEnum};
use colored::Colorize;

use security_common::{
    AnalysisResult, ThreatStats, IpAnalysis, IpInfo,
    RiskAssessment, ParsingInfo, FormatQuality, ParseError,
    cvss,
};
use security_analyzer_basic::BasicAnalyzer;

mod output;

#[derive(Parser)]
#[command(
    name = "logr",
    about = "Security log analyzer — detect threats, score risks, and audit logs from the terminal",
    version,
    after_help = "EXAMPLES:\n  logr analyze access.log\n  logr analyze /var/log/auth.log --format json\n  cat syslog | logr analyze -\n  logr analyze access.log --severity high --ci"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Analyze a log file for security threats
    Analyze {
        /// Path to the log file, or '-' to read from stdin
        file: String,

        /// Output format
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,

        /// Minimum severity to display (low, medium, high, critical)
        #[arg(short, long)]
        severity: Option<SeverityFilter>,

        /// CI mode — exit with code 1 if threats above severity threshold are found
        #[arg(long)]
        ci: bool,

        /// Show full details including all IPs and parse errors
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum OutputFormat {
    /// Human-readable table output with colors
    Table,
    /// Machine-readable JSON output
    Json,
    /// Compact single-line summary
    Summary,
}

#[derive(ValueEnum, Clone, Copy)]
enum SeverityFilter {
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    fn min_score(&self) -> f32 {
        match self {
            SeverityFilter::Low => 0.0,
            SeverityFilter::Medium => 4.0,
            SeverityFilter::High => 7.0,
            SeverityFilter::Critical => 9.0,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            file,
            format,
            severity,
            ci,
            verbose,
        } => {
            let content = read_input(&file);
            let result = analyze_content(&content);

            match format {
                OutputFormat::Table => output::print_table(&result, &file, severity, verbose),
                OutputFormat::Json => output::print_json(&result),
                OutputFormat::Summary => output::print_summary(&result, &file),
            }

            if ci {
                let min = severity.unwrap_or(SeverityFilter::Low).min_score();
                let has_threats = result
                    .threat_statistics
                    .cvss_scores
                    .iter()
                    .any(|t| t.cvss_score >= min);

                if has_threats {
                    process::exit(1);
                }
            }
        }
    }
}

fn read_input(file: &str) -> String {
    if file == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| {
                eprintln!("{} Failed to read stdin: {}", "error:".red().bold(), e);
                process::exit(2);
            });
        buf
    } else {
        fs::read_to_string(file).unwrap_or_else(|e| {
            eprintln!("{} {}: {}", "error:".red().bold(), file, e);
            process::exit(2);
        })
    }
}

fn analyze_content(content: &str) -> AnalysisResult {
    use security_common::parsers::{parse_log_line_unified, parse_apache_combined};

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

    let analyzer = BasicAnalyzer::new();
    let analysis = analyzer.analyze(&entries);
    let cvss_scores = analyzer.generate_cvss_scores(&analysis);

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

    let total_threats = analysis.failed_logins
        + analysis.root_attempts
        + analysis.suspicious_file_access
        + analysis.critical_alerts
        + analysis.sql_injection_attempts
        + analysis.port_scanning_attempts
        + analysis.malware_detections;

    let mut threat_types_for_aggregate = Vec::new();
    if analysis.sql_injection_attempts > 0 {
        threat_types_for_aggregate
            .push((cvss::ThreatType::SQLInjection, analysis.sql_injection_attempts));
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
        threat_types_for_aggregate
            .push((cvss::ThreatType::PortScanning, analysis.port_scanning_attempts));
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
