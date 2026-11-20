use std::fs;
use std::io::{self, Read};
use std::process;

use clap::{Parser, ValueEnum};
use colored::Colorize;

use security_common::AnalysisResult;

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
        io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
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
    security_analyzer_basic::analyze::analyze(content)
}
