// Interactive demo showing how the analyzer works step-by-step
use std::fs;

#[path = "../src/parsers/mod.rs"]
mod parsers;

#[path = "../src/llm/mod.rs"]
mod llm;

use llm::{LLMAnalyzer, mock::MockAnalyzer};

#[tokio::main]
async fn main() {
    println!("\n{}", "=".repeat(80));
    println!("SECURITY LOG ANALYZER - INTERACTIVE DEMO");
    println!("{}\n", "=".repeat(80));
    
    // Step 1: Show what we're starting with
    println!("STEP 1: RAW LOG DATA");
    println!("{}", "-".repeat(80));
    
    let log_content = fs::read_to_string("apache_combined_test.log")
        .expect("Failed to read apache_combined_test.log");
    
    let lines: Vec<&str> = log_content.lines().collect();
    
    println!("Here are 3 example raw log lines:\n");
    for (i, line) in lines.iter().take(3).enumerate() {
        println!("{}. {}\n", i + 1, line);
    }
    
    println!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    
    // Step 2: Parse the logs
    println!("\n{}", "=".repeat(80));
    println!("STEP 2: PARSING LOGS");
    println!("{}", "-".repeat(80));
    
    let mut logs = Vec::new();
    let mut suspicious_logs = Vec::new();
    
    for line in &lines {
        match parsers::apache::parse_apache_combined(line) {
            Ok(log) => {
                if log.is_suspicious {
                    suspicious_logs.push(log.clone());
                }
                logs.push(log);
            }
            Err(_) => {}
        }
    }
    
    println!("Parsed {} total logs", logs.len());
    println!("Found {} suspicious logs\n", suspicious_logs.len());
    
    println!("Here's what ONE parsed log looks like:\n");
    if let Some(log) = suspicious_logs.first() {
        println!("Raw line:");
        println!("{}\n", lines[3]); // The SQL injection one
        
        println!("Parsed into structured data:");
        println!("  IP Address: {}", log.ip);
        println!("  Timestamp: {}", log.timestamp);
        println!("  Method: {}", log.method);
        println!("  Path: {}", log.path);
        println!("  Status: {}", log.status);
        println!("  User-Agent: {}", log.user_agent);
        println!("\n  THREAT DETECTED:");
        println!("  - Is Suspicious: {}", log.is_suspicious);
        println!("  - Threat Type: {}", log.threat_type.as_ref().unwrap());
        println!("  - Severity: {}", log.severity.as_ref().unwrap());
    }
    
    println!("\nPress Enter to continue...");
    input.clear();
    std::io::stdin().read_line(&mut input).unwrap();
    
    // Step 3: Show all suspicious logs
    println!("\n{}", "=".repeat(80));
    println!("STEP 3: ALL SUSPICIOUS LOGS DETECTED");
    println!("{}", "-".repeat(80));
    
    for (i, log) in suspicious_logs.iter().enumerate() {
        println!("\n{}. {} from {}", 
            i + 1, 
            log.threat_type.as_ref().unwrap(),
            log.ip
        );
        println!("   Severity: {}", log.severity.as_ref().unwrap());
        println!("   Request: {} {}", log.method, log.path);
        println!("   Status: {}", log.status);
    }
    
    println!("\nPress Enter to run the Mock Analyzer...");
    input.clear();
    std::io::stdin().read_line(&mut input).unwrap();
    
    // Step 4: Run the analyzer
    println!("\n{}", "=".repeat(80));
    println!("STEP 4: RUNNING MOCK ANALYZER");
    println!("{}", "-".repeat(80));
    println!("Analyzing {} logs...\n", logs.len());
    
    let analyzer = MockAnalyzer::new();
    
    println!("(Simulating API call delay...)\n");
    
    match analyzer.analyze_logs(logs).await {
        Ok(report) => {
            // Step 5: Show the report
            println!("{}", "=".repeat(80));
            println!("STEP 5: SECURITY REPORT GENERATED");
            println!("{}", "=".repeat(80));
            
            println!("\n>>> EXECUTIVE SUMMARY <<<");
            println!("{}", "-".repeat(80));
            println!("{}\n", report.summary);
            
            println!(">>> OVERALL THREAT LEVEL <<<");
            println!("{}", "-".repeat(80));
            println!("{:?}\n", report.threat_level);
            
            println!("Press Enter to see detailed findings...");
            input.clear();
            std::io::stdin().read_line(&mut input).unwrap();
            
            println!("\n>>> KEY FINDINGS ({} total) <<<", report.findings.len());
            println!("{}", "-".repeat(80));
            
            for (i, finding) in report.findings.iter().enumerate() {
                println!("\n{}. {} - Severity: {}", 
                    i + 1, 
                    finding.attack_type,
                    finding.severity
                );
                println!("   Confidence: {:.0}%", finding.confidence * 100.0);
                println!("\n   Description:");
                println!("   {}\n", finding.description);
                
                if !finding.affected_resources.is_empty() {
                    println!("   Affected Resources:");
                    for resource in finding.affected_resources.iter().take(2) {
                        println!("     - {}", resource);
                    }
                    if finding.affected_resources.len() > 2 {
                        println!("     ... and {} more", finding.affected_resources.len() - 2);
                    }
                }
                
                if i < report.findings.len() - 1 {
                    println!("\n   Press Enter for next finding...");
                    input.clear();
                    std::io::stdin().read_line(&mut input).unwrap();
                }
            }
            
            if !report.attack_chains.is_empty() {
                println!("\n\n>>> ATTACK CHAINS DETECTED <<<");
                println!("{}", "-".repeat(80));
                
                for chain in &report.attack_chains {
                    println!("\n{}", chain.name);
                    println!("{}", chain.description);
                    println!("Source IPs: {}", chain.source_ips.join(", "));
                }
            }
            
            println!("\n\nPress Enter to see IOCs...");
            input.clear();
            std::io::stdin().read_line(&mut input).unwrap();
            
            println!("\n>>> INDICATORS OF COMPROMISE ({} total) <<<", report.iocs.len());
            println!("{}", "-".repeat(80));
            
            let mut by_type: std::collections::HashMap<String, Vec<&llm::analyzer::IOC>> = 
                std::collections::HashMap::new();
            
            for ioc in &report.iocs {
                by_type.entry(ioc.ioc_type.clone())
                    .or_insert_with(Vec::new)
                    .push(ioc);
            }
            
            for (ioc_type, iocs) in by_type {
                println!("\n{} ({} items):", ioc_type.to_uppercase(), iocs.len());
                for ioc in iocs.iter().take(3) {
                    println!("  - {} ({})", ioc.value, ioc.description);
                }
                if iocs.len() > 3 {
                    println!("  ... and {} more", iocs.len() - 3);
                }
            }
            
            println!("\n\nPress Enter to see recommendations...");
            input.clear();
            std::io::stdin().read_line(&mut input).unwrap();
            
            println!("\n>>> RECOMMENDATIONS <<<");
            println!("{}", "-".repeat(80));
            
            for rec in &report.recommendations {
                if rec.starts_with("**") {
                    println!("\n{}", rec);
                } else {
                    println!("  {}", rec);
                }
            }
            
            println!("\n\n{}", "=".repeat(80));
            println!("DEMO COMPLETE!");
            println!("{}", "=".repeat(80));
            
            println!("\nWHAT JUST HAPPENED:");
            println!("1. We read raw Apache log lines (just text)");
            println!("2. Parser converted them to structured data (IP, timestamp, etc.)");
            println!("3. Parser detected threats (SQL injection, XSS, etc.)");
            println!("4. Mock Analyzer took that data and generated a full report");
            println!("5. Report includes: summary, findings, IOCs, recommendations");
            println!("\nWith REAL Claude API:");
            println!("- Step 4 would send logs to Claude");
            println!("- Claude would do DEEPER analysis");
            println!("- Would catch things the parser missed");
            println!("- Would explain WHY things are threats");
            println!("- Would correlate events better");
            println!("\nBut the OUTPUT FORMAT is identical!");
            
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
