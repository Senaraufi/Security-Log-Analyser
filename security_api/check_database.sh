#!/bin/bash

# Quick Database Check Script
# Shows what's been saved to the database

echo "🔍 Checking Security Logs Database..."
echo ""

# Check uploads
echo "📊 Recent Log Uploads:"
mysql -u root -p security_LogsDB -e "
SELECT 
    id,
    filename,
    DATE_FORMAT(upload_date, '%Y-%m-%d %H:%i:%s') as uploaded,
    analysis_mode as mode,
    total_lines as total_lines,
    CONCAT(ROUND(file_size_bytes/1024, 2), ' KB') as size
FROM log_uploads 
ORDER BY upload_date DESC 
LIMIT 10;
"

echo ""
echo "📈 Analysis Results:"
mysql -u root -p security_LogsDB -e "
SELECT 
    ar.id,
    lu.filename,
    ar.risk_level,
    ar.total_threats,
    ar.sql_injection_count as sql_inj,
    DATE_FORMAT(ar.analysis_date, '%Y-%m-%d %H:%i:%s') as analyzed
FROM analysis_results ar
JOIN log_uploads lu ON ar.upload_id = lu.id
ORDER BY ar.analysis_date DESC 
LIMIT 10;
"

echo ""
echo "🤖 AI Analyses:"
mysql -u root -p security_LogsDB -e "
SELECT 
    ai.id,
    lu.filename,
    ai.threat_level,
    ai.total_logs_analyzed,
    ai.suspicious_logs_count,
    DATE_FORMAT(ai.analysis_date, '%Y-%m-%d %H:%i:%s') as analyzed
FROM ai_analysis ai
JOIN log_uploads lu ON ai.upload_id = lu.id
ORDER BY ai.analysis_date DESC 
LIMIT 10;
"

echo ""
echo "📊 Summary Statistics:"
mysql -u root -p security_LogsDB -e "
SELECT 
    COUNT(*) as total_uploads,
    SUM(total_lines) as total_lines_analyzed,
    COUNT(CASE WHEN analysis_mode = 'standard' THEN 1 END) as standard_analyses,
    COUNT(CASE WHEN analysis_mode = 'ai' THEN 1 END) as ai_analyses,
    MAX(upload_date) as last_upload
FROM log_uploads;
"

echo ""
echo "✅ Database check complete!"
