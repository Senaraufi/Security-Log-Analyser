use super::models::*;
use super::DbPool;
use sqlx;

/// Save a new log upload to the database
pub async fn save_log_upload(
    pool: &DbPool,
    upload: &NewLogUpload,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO log_uploads 
        (filename, file_size_bytes, total_lines, parsed_lines, failed_lines, 
         analysis_mode, processing_time_ms, user_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        upload.filename,
        upload.file_size_bytes,
        upload.total_lines,
        upload.parsed_lines,
        upload.failed_lines,
        upload.analysis_mode,
        upload.processing_time_ms,
        upload.user_ip
    )
    .execute(pool)
    .await?;
    
    Ok(result.last_insert_id() as i32)
}

/// Save analysis results to the database
pub async fn save_analysis_result(
    pool: &DbPool,
    analysis: &NewAnalysisResult,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO analysis_results 
        (upload_id, risk_level, total_threats, threat_score,
         sql_injection_count, xss_count, path_traversal_count,
         command_injection_count, suspicious_patterns_count,
         format_quality_percentage, perfect_format_count,
         minor_issues_count, major_issues_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        analysis.upload_id,
        analysis.risk_level,
        analysis.total_threats,
        analysis.threat_score,
        analysis.sql_injection_count,
        analysis.xss_count,
        analysis.path_traversal_count,
        analysis.command_injection_count,
        analysis.suspicious_patterns_count,
        analysis.format_quality_percentage,
        analysis.perfect_format_count,
        analysis.minor_issues_count,
        analysis.major_issues_count
    )
    .execute(pool)
    .await?;
    
    Ok(result.last_insert_id() as i32)
}

/// Save AI analysis results to the database
pub async fn save_ai_analysis(
    pool: &DbPool,
    ai_analysis: &NewAIAnalysis,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO ai_analysis 
        (upload_id, threat_level, summary, total_logs_analyzed,
         suspicious_logs_count, confidence_score, processing_time_ms, tokens_used)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        ai_analysis.upload_id,
        ai_analysis.threat_level,
        ai_analysis.summary,
        ai_analysis.total_logs_analyzed,
        ai_analysis.suspicious_logs_count,
        ai_analysis.confidence_score,
        ai_analysis.processing_time_ms,
        ai_analysis.tokens_used
    )
    .execute(pool)
    .await?;
    
    Ok(result.last_insert_id() as i32)
}

/// Save IP analysis data
pub async fn save_ip_analysis(
    pool: &DbPool,
    ip_data: &NewIPAnalysis,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO ip_analysis 
        (analysis_id, ip_address, request_count, threat_count, risk_level)
        VALUES (?, ?, ?, ?, ?)
        "#,
        ip_data.analysis_id,
        ip_data.ip_address,
        ip_data.request_count,
        ip_data.threat_count,
        ip_data.risk_level
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Save detected threat
pub async fn save_detected_threat(
    pool: &DbPool,
    threat: &NewDetectedThreat,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO detected_threats 
        (analysis_id, threat_type, severity, description, log_line_number, log_entry)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
        threat.analysis_id,
        threat.threat_type,
        threat.severity,
        threat.description,
        threat.log_line_number,
        threat.log_entry
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Get recent log uploads
pub async fn get_recent_uploads(
    pool: &DbPool,
    limit: i32,
) -> Result<Vec<LogUpload>, sqlx::Error> {
    let uploads = sqlx::query_as::<_, LogUpload>(
        r#"
        SELECT id, filename, upload_date, file_size_bytes, total_lines,
               parsed_lines, failed_lines, analysis_mode, processing_time_ms, user_ip
        FROM log_uploads
        ORDER BY upload_date DESC
        LIMIT ?
        "#
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    
    Ok(uploads)
}

/// Get analysis result by upload ID
pub async fn get_analysis_by_upload_id(
    pool: &DbPool,
    upload_id: i32,
) -> Result<Option<AnalysisResult>, sqlx::Error> {
    let analysis = sqlx::query_as::<_, AnalysisResult>(
        r#"
        SELECT * FROM analysis_results
        WHERE upload_id = ?
        "#
    )
    .bind(upload_id)
    .fetch_optional(pool)
    .await?;
    
    Ok(analysis)
}

/// Get AI analysis by upload ID
pub async fn get_ai_analysis_by_upload_id(
    pool: &DbPool,
    upload_id: i32,
) -> Result<Option<AIAnalysis>, sqlx::Error> {
    let ai_analysis = sqlx::query_as::<_, AIAnalysis>(
        r#"
        SELECT * FROM ai_analysis
        WHERE upload_id = ?
        "#
    )
    .bind(upload_id)
    .fetch_optional(pool)
    .await?;
    
    Ok(ai_analysis)
}

/// Get threat statistics summary
pub async fn get_threat_statistics(
    pool: &DbPool,
) -> Result<ThreatStatistics, sqlx::Error> {
    use sqlx::Row;
    
    let row = sqlx::query(
        r#"
        SELECT 
            COUNT(DISTINCT upload_id) as total_uploads,
            COALESCE(SUM(total_threats), 0) as total_threats,
            COALESCE(SUM(sql_injection_count), 0) as sql_injections,
            COALESCE(SUM(xss_count), 0) as xss_attacks,
            COALESCE(SUM(path_traversal_count), 0) as path_traversals,
            COALESCE(SUM(command_injection_count), 0) as command_injections
        FROM analysis_results
        "#
    )
    .fetch_one(pool)
    .await?;
    
    Ok(ThreatStatistics {
        total_uploads: row.try_get::<i64, _>("total_uploads").unwrap_or(0) as i32,
        total_threats: row.try_get::<i64, _>("total_threats").unwrap_or(0) as i32,
        sql_injections: row.try_get::<i64, _>("sql_injections").unwrap_or(0) as i32,
        xss_attacks: row.try_get::<i64, _>("xss_attacks").unwrap_or(0) as i32,
        path_traversals: row.try_get::<i64, _>("path_traversals").unwrap_or(0) as i32,
        command_injections: row.try_get::<i64, _>("command_injections").unwrap_or(0) as i32,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct ThreatStatistics {
    pub total_uploads: i32,
    pub total_threats: i32,
    pub sql_injections: i32,
    pub xss_attacks: i32,
    pub path_traversals: i32,
    pub command_injections: i32,
}
