/// Example demonstrating CVSS 3.1 scoring for detected threats
/// 
/// This shows how the system assigns industry-standard CVSS scores
/// to different threat types and calculates aggregate risk scores.

// Include the cvss module
#[path = "../src/cvss.rs"]
mod cvss;

fn main() {
    println!("\n🎯 CVSS 3.1 Scoring Demonstration\n");
    println!("{}", "=".repeat(70));
    
    // Show individual threat scores
    println!("\n📊 Individual Threat Type Scores:\n");
    
    let threats = vec![
        cvss::ThreatType::SQLInjection,
        cvss::ThreatType::XSS,
        cvss::ThreatType::PathTraversal,
        cvss::ThreatType::CommandInjection,
        cvss::ThreatType::FailedLogin,
        cvss::ThreatType::RootAccess,
        cvss::ThreatType::SuspiciousFileAccess,
        cvss::ThreatType::PortScanning,
        cvss::ThreatType::Malware,
        cvss::ThreatType::CriticalAlert,
    ];
    
    for threat in threats {
        let cvss = threat.cvss_score();
        println!("┌─ {:?}", threat);
        println!("│  CVSS Score: {:.1} ({})", cvss.base_score, cvss.severity.as_str());
        println!("│  Vector: {}", cvss.vector_string);
        println!("│  {}", cvss.explanation);
        println!("└─");
        println!();
    }
    
    // Demonstrate aggregate scoring
    println!("\n{}", "=".repeat(70));
    println!("\n📈 Aggregate Score Calculation:\n");
    
    // Scenario 1: Single high-severity threat
    println!("Scenario 1: Single SQL Injection");
    let threats_1 = vec![(cvss::ThreatType::SQLInjection, 1)];
    let aggregate_1 = cvss::calculate_aggregate_score(&threats_1);
    println!("  Aggregate Score: {:.1} ({})", aggregate_1.base_score, aggregate_1.severity.as_str());
    println!("  {}", aggregate_1.explanation);
    println!();
    
    // Scenario 2: Multiple instances of same threat
    println!("Scenario 2: 5 SQL Injection attempts");
    let threats_2 = vec![(cvss::ThreatType::SQLInjection, 5)];
    let aggregate_2 = cvss::calculate_aggregate_score(&threats_2);
    println!("  Aggregate Score: {:.1} ({})", aggregate_2.base_score, aggregate_2.severity.as_str());
    println!("  {}", aggregate_2.explanation);
    println!();
    
    // Scenario 3: Mixed threat types
    println!("Scenario 3: Mixed threats (realistic attack)");
    let threats_3 = vec![
        (cvss::ThreatType::SQLInjection, 3),
        (cvss::ThreatType::XSS, 2),
        (cvss::ThreatType::FailedLogin, 10),
        (cvss::ThreatType::PortScanning, 1),
    ];
    let aggregate_3 = cvss::calculate_aggregate_score(&threats_3);
    println!("  Threats:");
    println!("    - 3 SQL Injection (CVSS 9.8)");
    println!("    - 2 XSS (CVSS 6.1)");
    println!("    - 10 Failed Logins (CVSS 5.3)");
    println!("    - 1 Port Scan (CVSS 5.3)");
    println!("  Aggregate Score: {:.1} ({})", aggregate_3.base_score, aggregate_3.severity.as_str());
    println!("  {}", aggregate_3.explanation);
    println!();
    
    // Scenario 4: Low-severity only
    println!("Scenario 4: Only low-severity threats");
    let threats_4 = vec![
        (cvss::ThreatType::FailedLogin, 2),
        (cvss::ThreatType::PortScanning, 1),
    ];
    let aggregate_4 = cvss::calculate_aggregate_score(&threats_4);
    println!("  Aggregate Score: {:.1} ({})", aggregate_4.base_score, aggregate_4.severity.as_str());
    println!("  {}", aggregate_4.explanation);
    println!();
    
    // Show severity color coding
    println!("\n{}", "=".repeat(70));
    println!("\n🎨 Severity Levels & Color Codes:\n");
    
    let severities = vec![
        cvss::Severity::None,
        cvss::Severity::Low,
        cvss::Severity::Medium,
        cvss::Severity::High,
        cvss::Severity::Critical,
    ];
    
    for severity in severities {
        println!("  {} - {} ({})", 
            severity.as_str(),
            match severity {
                cvss::Severity::None => "0.0",
                cvss::Severity::Low => "0.1-3.9",
                cvss::Severity::Medium => "4.0-6.9",
                cvss::Severity::High => "7.0-8.9",
                cvss::Severity::Critical => "9.0-10.0",
            },
            severity.color_code()
        );
    }
    
    println!("\n{}", "=".repeat(70));
    println!("\n✅ CVSS 3.1 scoring provides:");
    println!("   • Industry-standard severity ratings");
    println!("   • Detailed vector strings for each threat");
    println!("   • Aggregate risk assessment");
    println!("   • Consistent, reproducible scores");
    println!("   • Clear guidance for incident response\n");
}
