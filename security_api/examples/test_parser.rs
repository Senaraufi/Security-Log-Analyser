// Test the Apache parser with real logs
use std::fs;

// Include the parsers module
#[path = "../src/parsers/mod.rs"]
mod parsers;

fn main() {
    println!(" Testing Apache Log Parser\n");
    println!("{}", "=".repeat(60));
    
    // Read the sample log file
    let log_content = fs::read_to_string("apache_combined_test.log")
        .expect("Failed to read apache_combined_test.log");
    
    let lines: Vec<&str> = log_content.lines().collect();
    let total_lines = lines.len();
    
    println!(" Total lines: {}", total_lines);
    println!("{}", "=".repeat(60));
    
    let mut parsed_count = 0;
    let mut failed_count = 0;
    let mut suspicious_count = 0;
    
    let mut threats_by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    
    // Parse all lines
    for (i, line) in lines.iter().enumerate() {
        match parsers::apache::parse_apache_combined(line) {
            Ok(log) => {
                parsed_count += 1;
                
                if log.is_suspicious {
                    suspicious_count += 1;
                    
                    if let Some(ref threat_type) = log.threat_type {
                        *threats_by_type.entry(threat_type.clone()).or_insert(0) += 1;
                        
                        println!("\n THREAT DETECTED (Line {}):", i + 1);
                        println!("   Type: {}", threat_type);
                        println!("   Severity: {}", log.severity.as_ref().unwrap_or(&"Unknown".to_string()));
                        println!("   IP: {}", log.ip);
                        println!("   Method: {} {}", log.method, log.path);
                        println!("   Status: {}", log.status);
                        println!("   User-Agent: {}", log.user_agent);
                    }
                }
            }
            Err(e) => {
                failed_count += 1;
                if failed_count <= 3 {
                    println!("\n Parse error (Line {}): {}", i + 1, e);
                    println!("   Line: {}", line);
                }
            }
        }
    }
    
    println!("\n");
    println!("{}", "=".repeat(60));
    println!("PARSING SUMMARY");
    println!("{}", "=".repeat(60));
    println!(" Successfully parsed: {}/{}", parsed_count, total_lines);
    println!(" Failed to parse: {}/{}", failed_count, total_lines);
    println!(" Suspicious entries: {}", suspicious_count);
    
    if !threats_by_type.is_empty() {
        println!("\n THREATS BY TYPE:");
        for (threat_type, count) in threats_by_type.iter() {
            println!("   {} - {} occurrences", threat_type, count);
        }
    }
    
    println!("\n{}", "=".repeat(60));
    println!(" Parser test complete!");
}
