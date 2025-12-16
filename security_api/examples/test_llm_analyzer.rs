// Test the LLM analyzer with mock mode (no API key required)
use std::fs;

// Include the modules
#[path = "../src/parsers/mod.rs"]
mod parsers;

#[path = "../src/llm/mod.rs"]
mod llm;

use llm::{LLMAnalyzer, mock::MockAnalyzer};

#[tokio::main]
async fn main() {
    println!("🤖 Testing LLM Security Analyzer (Mock Mode)\n");
    println!("{}", "=".repeat(70));
    
    // Read the sample log file
    let log_content = fs::read_to_string("apache_combined_test.log")
        .expect("Failed to read apache_combined_test.log");
    
    println!("📄 Parsing Apache logs...\n");
    
    // Parse all logs
    let mut logs = Vec::new();
    let mut parse_errors = 0;
    
    for line in log_content.lines() {
        match parsers::apache::parse_apache_combined(line) {
            Ok(log) => logs.push(log),
            Err(_) => parse_errors += 1,
        }
    }
    
    println!("✅ Parsed {} logs successfully", logs.len());
    if parse_errors > 0 {
        println!("⚠️  {} parse errors", parse_errors);
    }
    
    let suspicious_count = logs.iter().filter(|l| l.is_suspicious).count();
    println!("🚨 {} suspicious entries detected\n", suspicious_count);
    
    println!("{}", "=".repeat(70));
    println!("🔍 Running LLM Security Analysis (Mock Mode)...\n");
    println!("⏳ Analyzing...\n");
    
    // Create mock analyzer (works without API key)
    let analyzer = MockAnalyzer::new();
    
    // Analyze logs
    match analyzer.analyze_logs(logs).await {
        Ok(report) => {
            println!("{}", "=".repeat(70));
            println!("📊 SECURITY ANALYSIS REPORT");
            println!("{}", "=".repeat(70));
            
            // Executive Summary
            println!("\n📋 EXECUTIVE SUMMARY");
            println!("{}", "-".repeat(70));
            println!("{}\n", report.summary);
            
            // Threat Level
            println!("🎯 OVERALL THREAT LEVEL: {:?}", report.threat_level);
            println!("{}", "=".repeat(70));
            
            // Key Findings
            if !report.findings.is_empty() {
                println!("\n🔍 KEY FINDINGS ({} total)", report.findings.len());
                println!("{}", "-".repeat(70));
                
                for (i, finding) in report.findings.iter().enumerate() {
                    println!("\n{}. {} - Severity: {}", 
                        i + 1, 
                        finding.attack_type, 
                        finding.severity
                    );
                    println!("   Confidence: {:.0}%", finding.confidence * 100.0);
                    println!("   Description: {}", finding.description);
                    
                    if !finding.affected_resources.is_empty() {
                        println!("   Affected Resources:");
                        for resource in finding.affected_resources.iter().take(3) {
                            println!("     - {}", resource);
                        }
                        if finding.affected_resources.len() > 3 {
                            println!("     ... and {} more", finding.affected_resources.len() - 3);
                        }
                    }
                }
            }
            
            // Attack Chains
            if !report.attack_chains.is_empty() {
                println!("\n{}", "=".repeat(70));
                println!("🔗 ATTACK CHAINS DETECTED ({} total)", report.attack_chains.len());
                println!("{}", "-".repeat(70));
                
                for (i, chain) in report.attack_chains.iter().enumerate() {
                    println!("\n{}. {}", i + 1, chain.name);
                    println!("   {}", chain.description);
                    println!("   Source IPs: {}", chain.source_ips.join(", "));
                    println!("   Events in chain: {}", chain.events.len());
                }
            }
            
            // IOCs
            if !report.iocs.is_empty() {
                println!("\n{}", "=".repeat(70));
                println!("🎯 INDICATORS OF COMPROMISE ({} total)", report.iocs.len());
                println!("{}", "-".repeat(70));
                
                let mut by_type: std::collections::HashMap<String, Vec<&llm::analyzer::IOC>> = 
                    std::collections::HashMap::new();
                
                for ioc in &report.iocs {
                    by_type.entry(ioc.ioc_type.clone())
                        .or_insert_with(Vec::new)
                        .push(ioc);
                }
                
                for (ioc_type, iocs) in by_type {
                    println!("\n   {} ({} items):", ioc_type.to_uppercase(), iocs.len());
                    for ioc in iocs.iter().take(5) {
                        println!("     - {} ({})", ioc.value, ioc.description);
                    }
                    if iocs.len() > 5 {
                        println!("     ... and {} more", iocs.len() - 5);
                    }
                }
            }
            
            // Recommendations
            if !report.recommendations.is_empty() {
                println!("\n{}", "=".repeat(70));
                println!("💡 RECOMMENDATIONS");
                println!("{}", "-".repeat(70));
                
                for rec in &report.recommendations {
                    if rec.starts_with("**") {
                        println!("\n{}", rec);
                    } else {
                        println!("   • {}", rec);
                    }
                }
            }
            
            println!("\n{}", "=".repeat(70));
            println!("✨ Analysis complete!\n");
            
            println!("💡 NOTE: This is a MOCK analysis for testing.");
            println!("   To use real Claude API:");
            println!("   1. Get API key from https://console.anthropic.com");
            println!("   2. Set ANTHROPIC_API_KEY environment variable");
            println!("   3. The analyzer will automatically use real API");
            
        }
        Err(e) => {
            println!("❌ Analysis failed: {}", e);
        }
    }
}
