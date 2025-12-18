use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Log upload record from database
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogUpload {
    pub id: i32,
    pub filename: String,
    pub upload_date: DateTime<Utc>,
    pub file_size_bytes: Option<i64>,
    pub total_lines: Option<i32>,
    pub parsed_lines: Option<i32>,
    pub failed_lines: Option<i32>,
    pub analysis_mode: String,
    pub processing_time_ms: Option<i32>,
    pub user_ip: Option<String>,
}

/// Analysis result record from database
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AnalysisResult {
    pub id: i32,
    pub upload_id: i32,
    pub risk_level: String,
    pub total_threats: i32,
    pub threat_score: i32,
    pub sql_injection_count: i32,
    pub xss_count: i32,
    pub path_traversal_count: i32,
    pub command_injection_count: i32,
    pub suspicious_patterns_count: i32,
    pub format_quality_percentage: Option<f32>,
    pub perfect_format_count: i32,
    pub minor_issues_count: i32,
    pub major_issues_count: i32,
    pub analysis_date: DateTime<Utc>,
}

/// AI analysis record from database
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AIAnalysis {
    pub id: i32,
    pub upload_id: i32,
    pub threat_level: Option<String>,
    pub summary: Option<String>,
    pub total_logs_analyzed: Option<i32>,
    pub suspicious_logs_count: Option<i32>,
    pub confidence_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_date: Option<DateTime<Utc>>,
    pub processing_time_ms: Option<i32>,
    pub tokens_used: Option<i32>,
}

/// New log upload to insert
#[derive(Debug, Serialize, Deserialize)]
pub struct NewLogUpload {
    pub filename: String,
    pub file_size_bytes: i64,
    pub total_lines: i32,
    pub parsed_lines: i32,
    pub failed_lines: i32,
    pub analysis_mode: String,
    pub processing_time_ms: i32,
    pub user_ip: Option<String>,
}

/// New analysis result to insert
#[derive(Debug, Serialize, Deserialize)]
pub struct NewAnalysisResult {
    pub upload_id: i32,
    pub risk_level: String,
    pub total_threats: i32,
    pub threat_score: i32,
    pub sql_injection_count: i32,
    pub xss_count: i32,
    pub path_traversal_count: i32,
    pub command_injection_count: i32,
    pub suspicious_patterns_count: i32,
    pub format_quality_percentage: f32,
    pub perfect_format_count: i32,
    pub minor_issues_count: i32,
    pub major_issues_count: i32,
}

/// New AI analysis to insert
#[derive(Debug, Serialize, Deserialize)]
pub struct NewAIAnalysis {
    pub upload_id: i32,
    pub threat_level: String,
    pub summary: String,
    pub total_logs_analyzed: i32,
    pub suspicious_logs_count: i32,
    pub confidence_score: f32,
    pub processing_time_ms: i32,
    pub tokens_used: Option<i32>,
}

/// IP analysis record
#[derive(Debug, Serialize, Deserialize)]
pub struct NewIPAnalysis {
    pub analysis_id: i32,
    pub ip_address: String,
    pub request_count: i32,
    pub threat_count: i32,
    pub risk_level: String,
}

/// Detected threat record
#[derive(Debug, Serialize, Deserialize)]
pub struct NewDetectedThreat {
    pub analysis_id: i32,
    pub threat_type: String,
    pub severity: String,
    pub description: Option<String>,
    pub log_line_number: Option<i32>,
    pub log_entry: Option<String>,
}
