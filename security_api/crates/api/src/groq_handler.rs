use axum::{
    extract::{Multipart, Extension},
    response::{IntoResponse, Json},
};
use security_common::{database::DbPool, parsers::apache::parse_apache_combined};

pub async fn analyze_logs_with_groq(
    Extension(_db_pool): Extension<DbPool>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    use security_analyzer_groq::GroqAnalyzer;
    
    let mut content = String::new();
    let mut filename = String::from("unknown");
    
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            filename = field.file_name().unwrap_or("unknown").to_string();
            let data = field.bytes().await.unwrap();
            content = String::from_utf8_lossy(&data).to_string();
        }
    }
    
    println!("Processing log file with Groq AI: {}", filename);
    
    // Parse Apache logs
    let mut logs = Vec::new();
    for line in content.lines() {
        if let Ok(log) = parse_apache_combined(line) {
            logs.push(log);
        }
    }
    
    // Get AI analysis using Groq
    let analyzer = GroqAnalyzer::new();
    let ai_report = match analyzer.analyze_logs(logs.clone()).await {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Groq AI analysis failed: {}", e);
            return Json(serde_json::json!({
                "error": format!("AI analysis failed: {}", e)
            }));
        }
    };
    
    // Also get basic analysis
    let basic_result = super::process_logs(&content);
    
    // Combine results - flatten structure for UI compatibility
    Json(serde_json::json!({
        // Basic analysis data (for threat distribution, IP analysis, parsing stats)
        "threat_statistics": basic_result.threat_statistics,
        "ip_analysis": basic_result.ip_analysis,
        "risk_assessment": basic_result.risk_assessment,
        "parsing_info": basic_result.parsing_info,
        "alerts": basic_result.alerts,
        
        // AI analysis data
        "ai_report": ai_report,
        "report": {
            "summary": ai_report.summary,
            "threat_level": ai_report.threat_level,
            "attack_chains": ai_report.attack_chains,
            "recommendations": ai_report.recommendations,
        },
        "total_logs": logs.len(),
        "suspicious_logs": ai_report.suspicious_logs_count,
    }))
}
