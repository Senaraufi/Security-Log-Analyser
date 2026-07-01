use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color as TableColor,
    ContentArrangement, Table,
};

use security_common::AnalysisResult;

use crate::SeverityFilter;

pub fn print_table(
    result: &AnalysisResult,
    file: &str,
    severity: Option<SeverityFilter>,
    verbose: bool,
) {
    let version = env!("CARGO_PKG_VERSION");

    println!();
    println!(
        "  {} {}",
        "Logr".bold().white(),
        format!("v{}", version).dimmed()
    );
    println!();

    // File info
    let display_file = if file == "-" { "stdin" } else { file };
    println!("  {}  {}", "FILE".dimmed(), display_file.white());
    println!(
        "  {}  {} parsed {} {} skipped",
        "LINES".dimmed(),
        result.parsing_info.parsed_lines.to_string().white(),
        "·".dimmed(),
        result.parsing_info.skipped_lines.to_string().dimmed()
    );

    // Risk level with color
    let risk_colored = color_severity(&result.risk_assessment.level);
    println!(
        "  {}   {} (CVSS {})",
        "RISK".dimmed(),
        risk_colored,
        format!("{:.1}", result.risk_assessment.cvss_aggregate_score).white()
    );
    println!();

    // Threats table
    let scores = &result.threat_statistics.cvss_scores;
    let min_score = severity.map(|s| s.min_score()).unwrap_or(0.0);

    let filtered: Vec<_> = scores
        .iter()
        .filter(|t| t.cvss_score >= min_score)
        .collect();

    if filtered.is_empty() {
        println!(
            "  {} {}",
            "✓".green().bold(),
            "No threats detected".green()
        );
    } else {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Threat").fg(TableColor::White),
                Cell::new("Count").fg(TableColor::White),
                Cell::new("CVSS").fg(TableColor::White),
                Cell::new("Severity").fg(TableColor::White),
            ]);

        for threat in &filtered {
            let sev_color = match threat.severity.as_str() {
                "CRITICAL" => TableColor::Red,
                "HIGH" => TableColor::Red,
                "MEDIUM" => TableColor::Yellow,
                _ => TableColor::Green,
            };

            table.add_row(vec![
                Cell::new(&threat.threat_type),
                Cell::new(threat.count),
                Cell::new(format!("{:.1}", threat.cvss_score)),
                Cell::new(&threat.severity).fg(sev_color),
            ]);
        }

        println!("  {}", "THREATS".dimmed());
        for line in table.to_string().lines() {
            println!("  {}", line);
        }
    }

    // High risk IPs
    if !result.ip_analysis.high_risk_ips.is_empty() {
        println!();
        println!("  {}", "HIGH RISK IPs".dimmed());

        let show_count = if verbose {
            result.ip_analysis.high_risk_ips.len()
        } else {
            10
        };

        for ip in result.ip_analysis.high_risk_ips.iter().take(show_count) {
            println!(
                "  {}  {}",
                ip.ip.white(),
                format!("({} requests)", ip.count).dimmed()
            );
        }

        let remaining = result
            .ip_analysis
            .high_risk_ips
            .len()
            .saturating_sub(show_count);
        if remaining > 0 {
            println!("  {}", format!("  ... and {} more", remaining).dimmed());
        }
    }

    // Parse errors (verbose only)
    if verbose && !result.parsing_info.errors.is_empty() {
        println!();
        println!("  {}", "PARSE ERRORS".dimmed());
        for err in &result.parsing_info.errors {
            println!(
                "  {} {}",
                format!("L{}:", err.line_number).dimmed(),
                err.line_content.dimmed()
            );
        }
    }

    // Footer
    println!();
    let total = result.risk_assessment.total_threats;
    if total > 0 {
        println!(
            "  {} {}",
            "✗".red().bold(),
            format!(
                "{} threat{} detected",
                total,
                if total == 1 { "" } else { "s" }
            )
            .red()
        );
    } else {
        println!(
            "  {} {}",
            "✓".green().bold(),
            "No threats detected".green()
        );
    }
    println!();
}

pub fn print_json(result: &AnalysisResult) {
    let json = serde_json::to_string_pretty(result).unwrap_or_else(|e| {
        eprintln!("{} Failed to serialize: {}", "error:".red().bold(), e);
        std::process::exit(2);
    });
    println!("{}", json);
}

pub fn print_summary(result: &AnalysisResult, file: &str) {
    let display_file = if file == "-" { "stdin" } else { file };
    let threats = result.risk_assessment.total_threats;
    let level = &result.risk_assessment.level;
    let cvss = result.risk_assessment.cvss_aggregate_score;
    let parsed = result.parsing_info.parsed_lines;

    println!(
        "{}: {} lines, {} threats, risk={} cvss={:.1}",
        display_file, parsed, threats, level, cvss
    );
}

fn color_severity(level: &str) -> String {
    match level {
        "CRITICAL" => level.red().bold().to_string(),
        "HIGH" => level.red().to_string(),
        "MEDIUM" => level.yellow().to_string(),
        "LOW" => level.green().to_string(),
        _ => level.white().to_string(),
    }
}
