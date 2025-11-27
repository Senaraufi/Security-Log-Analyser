// Regex library for pattern matching in strings
// to search for patterns like IP addresses, timestamps...
use regex::Regex;
use std::fs::File;

// efficient line-by-line reading reads in chunks (safer than byte-by-byte)
use std::io::{BufRead, BufReader};

// HashMap to count IP occurrences (key-value pairs)
use std::collections::HashMap;

// STRUCT DEFINITION: LogEntry
// data structure that holds all the important parts of a log line
// template or blueprint for storing log information
#[derive(Debug)] // automatically creates a way to print this struct for debugging
struct LogEntry {
    timestamp: String,
    level: String,
    // The IP address involved (if any exists in the log)
    // Option<String> means it can be Some("192.168.1.1") or None (if no IP found)
    ip_address: Option<String>,
    
    // The username involved (if any exists in the log)
    // Option<String> means it might not always be present
    username: Option<String>,

    message: String,
}

// MAIN FUNCTION: Entry point of the program
fn main() {
    // Print a header message to show the program is starting
    println!("Security Log Parser - Starting Analysis\n");
    
    // STEP 1: Open and prepare the log file for reading
    
    // File::open() tries to open "sample_logs.txt"
    // .expect() means: if it fails, crash the program with this error message
    // In production code, you'd handle this error more gracefully
    let file = File::open("sample_logs.txt").expect("Failed to open log file");
    
    // Wrap the file in a BufReader for efficient line-by-line reading
    // BufReader reads data in chunks (buffers) instead of one byte at a time
    // This is MUCH faster for large files
    let reader = BufReader::new(file);
    
    // STEP 2: Initialize counters and storage for our analysis
    
    let mut failed_logins = 0;
    let mut root_attempts = 0;  // Track attempts to access root user
    let mut suspicious_file_access = 0;  // Track suspicious file operations
    let mut critical_alerts = 0;
    
    // HashMap to count how many times each IP appears
    // Key: IP address (String), Value: count (usize)
    let mut ip_frequency: HashMap<String, usize> = HashMap::new();
    
    // ========================================================================
    // STEP 3: Process each line of the log file
    // ========================================================================
    
    // reader.lines() returns an iterator over each line in the file
    // Each line is wrapped in a Result type (Ok or Err)
    for line in reader.lines() {
        
        // Try to unwrap the line from the Result
        // if let Ok(log_line) = line means:
        // "If the line was read successfully, store it in log_line and continue"
        // If there was an error reading the line, skip it
        if let Ok(log_line) = line {
            
            // Try to parse the log line into a LogEntry struct
            // parse_log_line() returns Option<LogEntry>
            // if let Some(entry) = ... means:
            // "If parsing succeeded, store the result in entry and continue"
            // If parsing failed (returned None), skip this line
            if let Some(entry) = parse_log_line(&log_line) {
                
                // Print the parsed entry so we can see what was extracted
                // {:?} is the Debug format - it prints the whole struct
                println!("📋 Parsed: {:?}", entry);
                
                // THREAT DETECTION LOGIC
                
                // Track IP frequency for all entries
                if let Some(ip) = &entry.ip_address {
                    // .entry() gets or creates the HashMap entry for this IP
                    // .and_modify() updates if exists, .or_insert() creates if new
                    ip_frequency.entry(ip.clone())
                        .and_modify(|count| *count += 1)  // Increment if exists
                        .or_insert(1);  // Set to 1 if new
                }
                
                // DETECTION RULE 1: Failed login attempts
                if entry.level == "ERROR" && entry.message.contains("Failed login") {
                    failed_logins += 1;
                }
                
                // DETECTION RULE 2: Root user access attempts (high risk)
                if entry.message.contains("user: root") {
                    root_attempts += 1;
                    println!(" Root access attempt detected: {}", entry.message);
                }
                
                // DETECTION RULE 3: Suspicious file access
                if entry.message.contains("/etc/passwd") || 
                   entry.message.contains("/etc/shadow") ||
                   entry.message.contains("Suspicious file") {
                    suspicious_file_access += 1;
                    println!("🔍 Suspicious file access: {}", entry.message);
                }
                
                // DETECTION RULE 4: Critical alerts
                if entry.level == "CRITICAL" {
                    critical_alerts += 1;
                    println!("🚨 CRITICAL ALERT: {}", entry.message);
                }
            }
        }
    }
    
    // STEP 4: Print the analysis summary
    
    println!("\n{}", "=".repeat(60));
    println!("📊 SECURITY ANALYSIS SUMMARY");
    println!("{}", "=".repeat(60));
    
    // Overall threat counts
    println!("\nThreat Statistics:");
    println!("   Failed login attempts: {}", failed_logins);
    println!("   Root user attempts: {}", root_attempts);
    println!("   Suspicious file access: {}", suspicious_file_access);
    println!("   Critical alerts: {}", critical_alerts);
    
    // Find IPs with multiple failed attempts (potential attackers)
    println!("\n🎯 IP Address Analysis:");
    
    // Create a vector of (IP, count) pairs and sort by count (highest first)
    let mut ip_vec: Vec<_> = ip_frequency.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));  // Sort by count, descending
    
    // Flag IPs with 3+ occurrences as high risk
    let high_risk_ips: Vec<_> = ip_vec.iter()
        .filter(|(_, count)| **count >= 3)
        .collect();
    
    if high_risk_ips.is_empty() {
        println!("   ✅ No high-risk IPs detected (3+ occurrences)");
    } else {
        println!("   🚨 High-Risk IPs (3+ occurrences):");
        for (ip, count) in high_risk_ips {
            println!("      {} - {} occurrences", ip, count);
        }
    }
    
    // Show all IPs with their counts
    println!("\n   All IP Activity:");
    for (ip, count) in ip_vec {
        let risk_indicator = if *count >= 3 { "🔴" } else { "🟢" };
        println!("      {} {} - {} occurrences", risk_indicator, ip, count);
    }
    
    // Risk assessment
    println!("\n⚖️  Overall Risk Level:");
    let total_threats = failed_logins + root_attempts + suspicious_file_access + critical_alerts;
    let risk_level = if total_threats >= 10 {
        "HIGH - Immediate action required"
    } else if total_threats >= 5 {
        "MEDIUM - Monitor closely"
    } else {
        "LOW - Normal activity"
    };
    println!("   {}", risk_level);
    println!("   Total threat indicators: {}", total_threats);
    
    println!("\n{}", "=".repeat(60));
}

// ============================================================================
// PARSING FUNCTION: Extracts structured data from a raw log line
// ============================================================================
// This function takes a string (a line from the log file) and tries to
// extract all the useful information from it
//
// Parameters:
//   line: &str - A borrowed string reference (we don't take ownership)
//
// Returns:
//   Option<LogEntry> - Either Some(LogEntry) if parsing succeeded,
//                      or None if parsing failed
fn parse_log_line(line: &str) -> Option<LogEntry> {
    
    // ========================================================================
    // STEP 1: Extract the main components (timestamp, level, message)
    // ========================================================================
    
    // Create a regex pattern to match the log format:
    // Example: "2024-01-15 10:30:45 [ERROR] Failed login attempt..."
    //
    // Pattern breakdown:
    // (?P<timestamp>...) - Named capture group for the timestamp
    // \d{4}-\d{2}-\d{2}  - Matches YYYY-MM-DD (4 digits, dash, 2 digits, etc.)
    // \d{2}:\d{2}:\d{2}  - Matches HH:MM:SS
    // \[(?P<level>\w+)\] - Matches [ERROR] or [INFO] etc. (word characters in brackets)
    // (?P<message>.*)    - Matches everything after as the message
    let re = Regex::new(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)"
    ).ok()?;
    // .ok()? converts Result to Option and returns None if regex creation failed
    // The ? operator means "if this is None, return None from the whole function"
    
    // Try to match the regex pattern against our log line
    // .captures() returns Option<Captures> - Some if matched, None if not
    let caps = re.captures(line)?;
    // The ? means "if no match, return None from the function"
    
    // Extract the message part from the captures
    // .name("message") gets the named capture group
    // ? returns None if the group doesn't exist
    // .as_str() converts it to a string slice
    let message = caps.name("message")?.as_str();
    
    // ========================================================================
    // STEP 2: Extract IP address from the message (if present)
    // ========================================================================
    
    // Create a regex to match IP addresses
    // Pattern breakdown:
    // \b                    - Word boundary (ensures we match whole IPs)
    // (?:\d{1,3}\.){3}      - Match 1-3 digits followed by a dot, three times
    //                         (?: ...) is a non-capturing group
    // \d{1,3}               - Match 1-3 digits for the last octet
    // \b                    - Word boundary
    // Example matches: 192.168.1.100, 10.0.0.50
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?;
    
    // Try to find an IP address in the message
    // .find() returns Option<Match> - Some if found, None if not
    // .map() transforms the Match into a String if found
    // If no IP is found, ip_address will be None
    let ip_address = ip_re.find(message).map(|m| m.as_str().to_string());
    
    // ========================================================================
    // STEP 3: Extract username from the message (if present)
    // ========================================================================
    
    // Create a regex to match "user: <username>"
    // Pattern breakdown:
    // user:  - Literal text "user:"
    // (\S+)  - Capture group: one or more non-whitespace characters
    //          \S means any character that's NOT a space, tab, or newline
    // Example matches: "user: admin", "user: john.doe"
    let user_re = Regex::new(r"user: (\S+)").ok()?;
    
    // Try to extract the username using a chain of operations:
    let username = user_re.captures(message)  // Try to match the pattern
        .and_then(|c| c.get(1))               // If matched, get capture group 1 (the username)
        .map(|m| m.as_str().to_string());     // If found, convert to String
    // If any step fails, username will be None
    
    // ========================================================================
    // STEP 4: Build and return the LogEntry struct
    // ========================================================================
    
    // Create a new LogEntry with all the data we extracted
    // Some(...) wraps it in an Option to indicate success
    Some(LogEntry {
        // Extract timestamp from named capture group and convert to String
        timestamp: caps.name("timestamp")?.as_str().to_string(),
        
        // Extract level from named capture group and convert to String
        level: caps.name("level")?.as_str().to_string(),
        
        // Use the IP address we found (or None if not found)
        ip_address,
        
        // Use the username we found (or None if not found)
        username,
        
        // Convert the message to a String
        message: message.to_string(),
    })
    // If any of the ? operators above fail, the function returns None
    // Otherwise, it returns Some(LogEntry) with all the parsed data
}
