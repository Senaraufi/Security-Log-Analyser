use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;

#[derive(Debug)]
struct LogEntry {
    timestamp: String,
    level: String,
    ip_address: Option<String>,
    username: Option<String>,
    message: String,
}

fn main() {
    println!("Security Log Parser - Starting Analysis\n");
    
    let file = File::open("sample_logs.txt").expect("Failed to open log file");
    let reader = BufReader::new(file);
    
    let mut failed_logins = 0;
    let mut root_attempts = 0;
    let mut suspicious_file_access = 0;
    let mut critical_alerts = 0;
    let mut ip_frequency: HashMap<String, usize> = HashMap::new();
    
    for line in reader.lines() {
        if let Ok(log_line) = line {
            if let Some(entry) = parse_log_line(&log_line) {
                println!("Parsed: {:?}", entry);
                
                if let Some(ip) = &entry.ip_address {
                    ip_frequency.entry(ip.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
                
                if entry.level == "ERROR" && entry.message.contains("Failed login") {
                    failed_logins += 1;
                }
                
                if entry.message.contains("user: root") {
                    root_attempts += 1;
                    println!(" Root access attempt detected: {}", entry.message);
                }
                
                if entry.message.contains("/etc/passwd") || 
                   entry.message.contains("/etc/shadow") ||
                   entry.message.contains("Suspicious file") {
                    suspicious_file_access += 1;
                    println!("Suspicious file access: {}", entry.message);
                }
                
                if entry.level == "CRITICAL" {
                    critical_alerts += 1;
                    println!("CRITICAL ALERT: {}", entry.message);
                }
            }
        }
    }
    
    println!("\n{}", "=".repeat(60));
    println!("SECURITY ANALYSIS SUMMARY");
    println!("{}", "=".repeat(60));
    
    println!("\nThreat Statistics:");
    println!("   Failed login attempts: {}", failed_logins);
    println!("   Root user attempts: {}", root_attempts);
    println!("   Suspicious file access: {}", suspicious_file_access);
    println!("   Critical alerts: {}", critical_alerts);
    
    println!("\nIP Address Analysis:");
    
    let mut ip_vec: Vec<_> = ip_frequency.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));
    
    let high_risk_ips: Vec<_> = ip_vec.iter()
        .filter(|(_, count)| **count >= 3)
        .collect();
    
    if high_risk_ips.is_empty() {
        println!("  No high-risk IPs detected (3+ occurrences)");
    } else {
        println!("  High-Risk IPs (3+ occurrences):");
        for (ip, count) in high_risk_ips {
            println!("      {} - {} occurrences", ip, count);
        }
    }
    
    println!("\n   All IP Activity:");
    for (ip, count) in ip_vec {
        let risk_indicator = if *count >= 3 { "🔴" } else { "🟢" };
        println!("      {} {} - {} occurrences", risk_indicator, ip, count);
    }
    
    println!("\n⚖️  Overall Risk Level:");
    let total_threats = failed_logins + root_attempts + suspicious_file_access + critical_alerts;
    let risk_level = if total_threats >= 10 {
        "🔴 HIGH - Immediate action required"
    } else if total_threats >= 5 {
        "🟡 MEDIUM - Monitor closely"
    } else {
        "🟢 LOW - Normal activity"
    };
    println!("   {}", risk_level);
    println!("   Total threat indicators: {}", total_threats);
    
    println!("\n{}", "=".repeat(60));
}

fn parse_log_line(line: &str) -> Option<LogEntry> {
    let re = Regex::new(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)"
    ).ok()?;
    
    let caps = re.captures(line)?;
    let message = caps.name("message")?.as_str();
    
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?;
    let ip_address = ip_re.find(message).map(|m| m.as_str().to_string());
    
    let user_re = Regex::new(r"user: (\S+)").ok()?;
    let username = user_re.captures(message)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    
    Some(LogEntry {
        timestamp: caps.name("timestamp")?.as_str().to_string(),
        level: caps.name("level")?.as_str().to_string(),
        ip_address,
        username,
        message: message.to_string(),
    })
}
