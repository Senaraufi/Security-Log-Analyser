use axum::{
    extract::Multipart,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    ip_address: Option<String>,
    username: Option<String>,
    message: String,
}

#[derive(Serialize)]
struct AnalysisResult {
    threat_statistics: ThreatStats,
    ip_analysis: IpAnalysis,
    risk_assessment: RiskAssessment,
    parsing_info: ParsingInfo,
}

#[derive(Serialize)]
struct ParsingInfo {
    total_lines: usize,
    parsed_lines: usize,
    skipped_lines: usize,
    errors: Vec<ParseError>,
}

#[derive(Serialize)]
struct ParseError {
    line_number: usize,
    line_content: String,
    error_type: String,
    suggestion: String,
}

#[derive(Serialize)]
struct ThreatStats {
    failed_logins: usize,
    root_attempts: usize,
    suspicious_file_access: usize,
    critical_alerts: usize,
    sql_injection_attempts: usize,
    port_scanning_attempts: usize,
    malware_detections: usize,
}

#[derive(Serialize)]
struct IpAnalysis {
    high_risk_ips: Vec<IpInfo>,
    all_ips: Vec<IpInfo>,
}

#[derive(Serialize)]
struct IpInfo {
    ip: String,
    count: usize,
    risk_level: String,
}

#[derive(Serialize)]
struct RiskAssessment {
    level: String,
    total_threats: usize,
    description: String,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(serve_frontend))
        .route("/api/analyze", post(analyze_logs));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("🚀 Security API Server running on http://localhost:3000");
    println!("📊 Upload logs at: http://localhost:3000");
    
    axum::serve(listener, app).await.unwrap();
}

async fn serve_frontend() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Log Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', 'Consolas', 'Monaco', monospace;
            background: #0a0e27;
            color: #00ff41;
            min-height: 100vh;
            padding: 0;
            overflow-x: hidden;
        }
        
        .header {
            background: #0d1117;
            border-bottom: 2px solid #1f6feb;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(31, 111, 235, 0.3);
        }
        
        .header h1 {
            color: #1f6feb;
            font-size: 1.5em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9em;
            color: #00ff41;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            background: #00ff41;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }
        
        .subtitle {
            color: #8b949e;
            margin-bottom: 30px;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .upload-area {
            border: 2px solid #1f6feb;
            background: #0d1117;
            padding: 40px;
            text-align: center;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .upload-area::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(31, 111, 235, 0.1), transparent);
            transition: 0.5s;
        }
        
        .upload-area:hover::before {
            left: 100%;
        }
        
        input[type="file"] {
            display: none;
        }
        
        .file-label {
            display: inline-block;
            padding: 12px 30px;
            background: #1f6feb;
            color: #ffffff;
            border: 1px solid #1f6feb;
            cursor: pointer;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
        }
        
        .file-label:hover {
            background: transparent;
            color: #1f6feb;
            box-shadow: 0 0 20px rgba(31, 111, 235, 0.5);
        }
        
        .file-name {
            margin-top: 15px;
            color: #00ff41;
            font-size: 0.9em;
        }
        
        button {
            width: 100%;
            padding: 15px;
            background: #238636;
            color: #ffffff;
            border: 1px solid #238636;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 2px;
            font-family: 'Courier New', monospace;
        }
        
        button:hover {
            background: transparent;
            color: #238636;
            box-shadow: 0 0 20px rgba(35, 134, 54, 0.5);
        }
        
        button:disabled {
            background: #21262d;
            border-color: #21262d;
            color: #484f58;
            cursor: not-allowed;
            box-shadow: none;
        }
        
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        
        .spinner {
            border: 3px solid #21262d;
            border-top: 3px solid #1f6feb;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results {
            display: none;
            margin-top: 30px;
        }
        
        .section {
            background: #0d1117;
            border: 1px solid #30363d;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
        }
        
        .section h2 {
            color: #1f6feb;
            margin-bottom: 20px;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 2px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
            font-size: 1.5em;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .stat-box {
            background: #161b22;
            border: 1px solid #30363d;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
        }
        
        .stat-box:hover {
            border-color: #1f6feb;
            box-shadow: 0 0 15px rgba(31, 111, 235, 0.3);
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff41;
            font-family: 'Courier New', monospace;
        }
        
        .stat-label {
            color: #8b949e;
            margin-top: 8px;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .ip-list {
            margin-top: 15px;
        }
        
        .ip-item {
            background: #161b22;
            border: 1px solid #30363d;
            padding: 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: 'Courier New', monospace;
            transition: all 0.3s;
        }
        
        .ip-item:hover {
            border-color: #1f6feb;
            box-shadow: 0 0 10px rgba(31, 111, 235, 0.2);
        }
        
        .risk-high { 
            border-left: 3px solid #da3633;
        }
        .risk-low { 
            border-left: 3px solid #238636;
        }
        
        .risk-badge {
            padding: 6px 16px;
            font-size: 0.85em;
            font-weight: bold;
            border: 1px solid;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: 'Courier New', monospace;
        }
        
        .badge-high {
            background: rgba(218, 54, 51, 0.1);
            color: #ff6b6b;
            border-color: #da3633;
        }
        
        .badge-medium {
            background: rgba(217, 119, 6, 0.1);
            color: #ffa94d;
            border-color: #d97706;
        }
        
        .badge-low {
            background: rgba(35, 134, 54, 0.1);
            color: #51cf66;
            border-color: #238636;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid;
            font-family: 'Courier New', monospace;
        }
        
        .alert-error {
            background: rgba(218, 54, 51, 0.1);
            color: #ff6b6b;
            border-color: #da3633;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ SECURITY LOG ANALYZER</h1>
        <div class="status-indicator">
            <div class="status-dot"></div>
            <span>SYSTEM ONLINE</span>
        </div>
    </div>
    
    <div class="container">
        <p class="subtitle">▸ THREAT DETECTION SYSTEM v0.5.0</p>
        
        <div class="upload-area">
            <label for="file-upload" class="file-label">
                ▸ SELECT LOG FILE
            </label>
            <input id="file-upload" type="file" accept=".txt,.log" />
            <div class="file-name" id="file-name">// NO FILE SELECTED</div>
        </div>
        
        <button id="analyze-btn" disabled>▸ INITIATE THREAT SCAN</button>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 10px; color: #1f6feb; font-family: 'Courier New', monospace;">> SCANNING FOR THREATS...</p>
        </div>
        
        <div id="error-container"></div>
        
        <div class="results" id="results">
            <div class="section">
                <h2>▸ THREAT STATISTICS</h2>
                <div class="stat-grid">
                    <div class="stat-box">
                        <div class="stat-value" id="failed-logins">0</div>
                        <div class="stat-label">Failed Logins</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="root-attempts">0</div>
                        <div class="stat-label">Root Attempts</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="file-access">0</div>
                        <div class="stat-label">File Access</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="critical-alerts">0</div>
                        <div class="stat-label">Critical Alerts</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="sql-injection">0</div>
                        <div class="stat-label">SQL Injection</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="port-scanning">0</div>
                        <div class="stat-label">Port Scanning</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="malware">0</div>
                        <div class="stat-label">Malware</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>▸ IP ADDRESS ANALYSIS</h2>
                <div id="high-risk-ips"></div>
                <div id="all-ips"></div>
            </div>
            
            <div class="section">
                <h2>▸ RISK ASSESSMENT</h2>
                <div id="risk-assessment"></div>
            </div>
            
            <div class="section">
                <h2>▸ PARSING INFORMATION</h2>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #1f6feb; font-family: 'Courier New', monospace;" id="total-lines">0</div>
                        <div style="color: #8b949e; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px;">Total Lines</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #238636; font-family: 'Courier New', monospace;" id="parsed-lines">0</div>
                        <div style="color: #8b949e; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px;">Parsed Successfully</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2em; font-weight: bold; color: #da3633; font-family: 'Courier New', monospace;" id="skipped-lines">0</div>
                        <div style="color: #8b949e; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px;">Skipped/Failed</div>
                    </div>
                </div>
                <div id="parsing-warning" style="margin-top: 15px;"></div>
            </div>
        </div>
    </div>
    
    <script>
        const fileInput = document.getElementById('file-upload');
        const fileName = document.getElementById('file-name');
        const analyzeBtn = document.getElementById('analyze-btn');
        const loading = document.getElementById('loading');
        const results = document.getElementById('results');
        const errorContainer = document.getElementById('error-container');
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                fileName.textContent = e.target.files[0].name;
                analyzeBtn.disabled = false;
            } else {
                fileName.textContent = 'No file selected';
                analyzeBtn.disabled = true;
            }
        });
        
        analyzeBtn.addEventListener('click', async () => {
            const file = fileInput.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            analyzeBtn.disabled = true;
            loading.style.display = 'block';
            results.style.display = 'none';
            errorContainer.innerHTML = '';
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error('Analysis failed');
                }
                
                const data = await response.json();
                displayResults(data);
                
            } catch (error) {
                errorContainer.innerHTML = `
                    <div class="alert alert-error">
                        ▸ ERROR: ${error.message}
                    </div>
                `;
            } finally {
                loading.style.display = 'none';
                analyzeBtn.disabled = false;
            }
        });
        
        function displayResults(data) {
            document.getElementById('failed-logins').textContent = data.threat_statistics.failed_logins;
            document.getElementById('root-attempts').textContent = data.threat_statistics.root_attempts;
            document.getElementById('file-access').textContent = data.threat_statistics.suspicious_file_access;
            document.getElementById('critical-alerts').textContent = data.threat_statistics.critical_alerts;
            document.getElementById('sql-injection').textContent = data.threat_statistics.sql_injection_attempts;
            document.getElementById('port-scanning').textContent = data.threat_statistics.port_scanning_attempts;
            document.getElementById('malware').textContent = data.threat_statistics.malware_detections;
            
            // Display parsing information
            document.getElementById('total-lines').textContent = data.parsing_info.total_lines;
            document.getElementById('parsed-lines').textContent = data.parsing_info.parsed_lines;
            document.getElementById('skipped-lines').textContent = data.parsing_info.skipped_lines;
            
            // Show warning if many lines were skipped
            const warningContainer = document.getElementById('parsing-warning');
            if (data.parsing_info.skipped_lines > 0) {
                const percentage = (data.parsing_info.skipped_lines / data.parsing_info.total_lines * 100).toFixed(1);
                let errorHtml = `
                    <div style="background: rgba(217, 119, 6, 0.1); border: 1px solid #d97706; padding: 12px; margin-bottom: 15px; color: #ffa94d; font-family: 'Courier New', monospace;">
                        <strong>▸ WARNING:</strong> ${data.parsing_info.skipped_lines} lines (${percentage}%) could not be parsed.
                        <br><small style="color: #8b949e;">// Universal parser processed all lines - see details below</small>
                    </div>
                `;
                
                // Display specific errors
                if (data.parsing_info.errors && data.parsing_info.errors.length > 0) {
                    errorHtml += '<div style="margin-top: 15px;"><h4 style="margin-bottom: 10px; color: #1f6feb; text-transform: uppercase; letter-spacing: 1px;">▸ PARSING DETAILS (FIRST 10):</h4>';
                    data.parsing_info.errors.forEach(error => {
                        errorHtml += `
                            <div style="background: #161b22; border: 1px solid #30363d; border-left: 3px solid #da3633; padding: 12px; margin-bottom: 10px; font-size: 0.9em;">
                                <div style="font-weight: bold; color: #ff6b6b; margin-bottom: 8px; font-family: 'Courier New', monospace;">
                                    [LINE ${error.line_number}] ${error.error_type}
                                </div>
                                <div style="background: #0d1117; border: 1px solid #30363d; padding: 10px; margin: 8px 0; font-family: 'Courier New', monospace; font-size: 0.85em; overflow-x: auto; color: #8b949e;">
                                    ${error.line_content}
                                </div>
                                <div style="color: #51cf66; margin-top: 8px; font-family: 'Courier New', monospace;">
                                    ▸ <strong>FIX:</strong> ${error.suggestion}
                                </div>
                            </div>
                        `;
                    });
                    
                    if (data.parsing_info.skipped_lines > data.parsing_info.errors.length) {
                        errorHtml += `<div style="color: #666; font-style: italic; margin-top: 10px;">
                            ... and ${data.parsing_info.skipped_lines - data.parsing_info.errors.length} more errors
                        </div>`;
                    }
                    
                    errorHtml += '</div>';
                }
                
                warningContainer.innerHTML = errorHtml;
            } else {
                warningContainer.innerHTML = '<div style="color: #51cf66; font-family: \'Courier New\', monospace;">▸ ALL LINES PROCESSED SUCCESSFULLY</div>';
            }
            
            const highRiskContainer = document.getElementById('high-risk-ips');
            if (data.ip_analysis.high_risk_ips.length > 0) {
                highRiskContainer.innerHTML = '<h3 style="margin-bottom: 15px; color: #ff6b6b; text-transform: uppercase; letter-spacing: 1px; font-size: 1em;">▸ HIGH-RISK IPS (3+ OCCURRENCES)</h3>';
                data.ip_analysis.high_risk_ips.forEach(ip => {
                    highRiskContainer.innerHTML += `
                        <div class="ip-item risk-high">
                            <span><strong>${ip.ip}</strong> - ${ip.count} occurrences</span>
                            <span class="risk-badge badge-high">HIGH RISK</span>
                        </div>
                    `;
                });
            } else {
                highRiskContainer.innerHTML = '<p style="color: #51cf66; font-family: \'Courier New\', monospace;">▸ NO HIGH-RISK IPS DETECTED</p>';
            }
            
            const allIpsContainer = document.getElementById('all-ips');
            allIpsContainer.innerHTML = '<h3 style="margin: 20px 0 15px 0; color: #1f6feb; text-transform: uppercase; letter-spacing: 1px; font-size: 1em;">▸ ALL IP ACTIVITY</h3>';
            data.ip_analysis.all_ips.forEach(ip => {
                const riskClass = ip.risk_level === 'high' ? 'risk-high' : 'risk-low';
                const indicator = ip.risk_level === 'high' ? '[!]' : '[✓]';
                allIpsContainer.innerHTML += `
                    <div class="ip-item ${riskClass}">
                        <span style="color: ${ip.risk_level === 'high' ? '#ff6b6b' : '#51cf66'}">${indicator}</span>
                        <span style="flex: 1; margin-left: 10px;"><strong>${ip.ip}</strong> - ${ip.count} occurrences</span>
                    </div>
                `;
            });
            
            const riskContainer = document.getElementById('risk-assessment');
            const badgeClass = data.risk_assessment.level === 'HIGH' ? 'badge-high' : 
                               data.risk_assessment.level === 'MEDIUM' ? 'badge-medium' : 'badge-low';
            riskContainer.innerHTML = `
                <div style="text-align: center; padding: 20px;">
                    <div style="margin-bottom: 20px;">
                        <span class="risk-badge ${badgeClass}" style="font-size: 1.5em; padding: 15px 40px;">
                            ${data.risk_assessment.level}
                        </span>
                    </div>
                    <p style="margin-top: 15px; font-size: 1.1em; color: #8b949e; font-family: 'Courier New', monospace;">${data.risk_assessment.description.toUpperCase()}</p>
                    <p style="margin-top: 15px; color: #1f6feb; font-family: 'Courier New', monospace; font-size: 1.2em;">
                        <strong>${data.risk_assessment.total_threats}</strong> THREAT INDICATORS DETECTED
                    </p>
                </div>
            `;
            
            results.style.display = 'block';
        }
    </script>
</body>
</html>
    "#)
}

async fn analyze_logs(mut multipart: Multipart) -> impl IntoResponse {
    let mut log_content = String::new();
    
    while let Some(field) = multipart.next_field().await.unwrap() {
        if field.name() == Some("file") {
            let data = field.bytes().await.unwrap();
            log_content = String::from_utf8_lossy(&data).to_string();
        }
    }
    
    let result = process_logs(&log_content);
    Json(result)
}

fn process_logs(content: &str) -> AnalysisResult {
    let mut failed_logins = 0;
    let mut root_attempts = 0;
    let mut suspicious_file_access = 0;
    let mut critical_alerts = 0;
    let mut sql_injection_attempts = 0;
    let mut port_scanning_attempts = 0;
    let mut malware_detections = 0;
    let mut ip_frequency: HashMap<String, usize> = HashMap::new();
    
    let mut total_lines = 0;
    let mut parsed_lines = 0;
    let mut parse_errors: Vec<ParseError> = Vec::new();
    
    for line in content.lines() {
        total_lines += 1;
        
        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }
        
        if let Some(entry) = parse_log_line(line) {
            parsed_lines += 1;
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
            }
            
            if entry.message.contains("/etc/passwd") || 
               entry.message.contains("/etc/shadow") ||
               entry.message.contains("Suspicious file") {
                suspicious_file_access += 1;
            }
            
            if entry.level == "CRITICAL" {
                critical_alerts += 1;
            }
            
            if entry.message.contains("SELECT") ||
               entry.message.contains("DROP TABLE") ||
               entry.message.contains("UNION SELECT") {
                sql_injection_attempts += 1;
            }
            
            if entry.message.contains("port scan") ||
               entry.message.contains("nmap") {
                port_scanning_attempts += 1;
            }
            
            if entry.message.contains("malware") ||
               entry.message.contains("trojan") ||
               entry.message.contains("virus") ||
               entry.message.contains("ransomware") {
                malware_detections += 1;
            }
        } else {
            // Line failed to parse - diagnose the error
            // Only store first 10 errors to avoid overwhelming the UI
            if parse_errors.len() < 10 {
                let (error_type, suggestion) = diagnose_parse_error(line);
                parse_errors.push(ParseError {
                    line_number: total_lines,
                    line_content: if line.len() > 100 {
                        format!("{}...", &line[..100])
                    } else {
                        line.to_string()
                    },
                    error_type,
                    suggestion,
                });
            }
        }
    }
    
    let mut ip_vec: Vec<_> = ip_frequency.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));
    
    let high_risk_ips: Vec<IpInfo> = ip_vec.iter()
        .filter(|(_, count)| **count >= 3)
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: "high".to_string(),
        })
        .collect();
    
    let all_ips: Vec<IpInfo> = ip_vec.iter()
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: if **count >= 3 { "high" } else { "low" }.to_string(),
        })
        .collect();
    
    let total_threats = failed_logins + root_attempts + suspicious_file_access + critical_alerts + 
                        sql_injection_attempts + port_scanning_attempts + malware_detections;
    let (level, description) = if total_threats >= 10 {
        ("HIGH", "Immediate action required")
    } else if total_threats >= 5 {
        ("MEDIUM", "Monitor closely")
    } else {
        ("LOW", "Normal activity")
    };
    
    AnalysisResult {
        threat_statistics: ThreatStats {
            failed_logins,
            root_attempts,
            suspicious_file_access,
            critical_alerts,
            sql_injection_attempts,
            port_scanning_attempts,
            malware_detections,
        },
        ip_analysis: IpAnalysis {
            high_risk_ips,
            all_ips,
        },
        risk_assessment: RiskAssessment {
            level: level.to_string(),
            total_threats,
            description: description.to_string(),
        },
        parsing_info: ParsingInfo {
            total_lines,
            parsed_lines,
            skipped_lines: total_lines - parsed_lines,
            errors: parse_errors,
        },
    }
}

fn parse_log_line(line: &str) -> Option<LogEntry> {
    // Try multiple common log formats
    
    // Format 1: YYYY-MM-DD HH:MM:SS [LEVEL] message
    let format1 = Regex::new(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)"
    ).ok()?;
    
    // Format 2: [YYYY-MM-DD HH:MM:SS] LEVEL: message
    let format2 = Regex::new(
        r"\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (?P<level>\w+): (?P<message>.*)"
    ).ok()?;
    
    // Format 3: YYYY/MM/DD HH:MM:SS [LEVEL] message
    let format3 = Regex::new(
        r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)"
    ).ok()?;
    
    // Format 4: MM/DD/YYYY HH:MM:SS [LEVEL] message
    let format4 = Regex::new(
        r"(?P<timestamp>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)"
    ).ok()?;
    
    // Format 5: YYYY-MM-DD HH:MM:SS LEVEL message (no brackets)
    let format5 = Regex::new(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>ERROR|WARN|INFO|CRITICAL|DEBUG|FATAL)\s+(?P<message>.*)"
    ).ok()?;
    
    // Format 6: Syslog style - Mon DD HH:MM:SS hostname level: message
    let format6 = Regex::new(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) \S+ (?P<level>\w+): (?P<message>.*)"
    ).ok()?;
    
    // Format 7: Just timestamp and message (extract level from message)
    let format7 = Regex::new(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})"
    ).ok()?;
    
    // Try each format
    let (timestamp, level, message) = if let Some(caps) = format1.captures(line) {
        (
            caps.name("timestamp")?.as_str().to_string(),
            caps.name("level")?.as_str().to_string(),
            caps.name("message")?.as_str().to_string(),
        )
    } else if let Some(caps) = format2.captures(line) {
        (
            caps.name("timestamp")?.as_str().to_string(),
            caps.name("level")?.as_str().to_string(),
            caps.name("message")?.as_str().to_string(),
        )
    } else if let Some(caps) = format3.captures(line) {
        (
            caps.name("timestamp")?.as_str().to_string(),
            caps.name("level")?.as_str().to_string(),
            caps.name("message")?.as_str().to_string(),
        )
    } else if let Some(caps) = format4.captures(line) {
        (
            caps.name("timestamp")?.as_str().to_string(),
            caps.name("level")?.as_str().to_string(),
            caps.name("message")?.as_str().to_string(),
        )
    } else if let Some(caps) = format5.captures(line) {
        (
            caps.name("timestamp")?.as_str().to_string(),
            caps.name("level")?.as_str().to_string(),
            caps.name("message")?.as_str().to_string(),
        )
    } else if let Some(caps) = format6.captures(line) {
        (
            caps.name("timestamp")?.as_str().to_string(),
            caps.name("level")?.as_str().to_string(),
            caps.name("message")?.as_str().to_string(),
        )
    } else if let Some(caps) = format7.captures(line) {
        // Extract level from anywhere in the line
        let level_re = Regex::new(r"\b(ERROR|WARN|INFO|CRITICAL|DEBUG|FATAL)\b").ok()?;
        let level = level_re.find(line)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "INFO".to_string());
        (
            caps.name("timestamp")?.as_str().to_string(),
            level,
            line.to_string(),
        )
    } else {
        // No timestamp found - treat entire line as message
        // Extract level if present
        let level_re = Regex::new(r"\b(ERROR|WARN|INFO|CRITICAL|DEBUG|FATAL)\b").ok()?;
        let level = level_re.find(line)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "INFO".to_string());
        
        return Some(LogEntry {
            timestamp: "Unknown".to_string(),
            level,
            ip_address: extract_ip(line),
            username: extract_username(line),
            message: line.to_string(),
        });
    };
    
    Some(LogEntry {
        timestamp,
        level,
        ip_address: extract_ip(&message),
        username: extract_username(&message),
        message,
    })
}

fn extract_ip(text: &str) -> Option<String> {
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?;
    ip_re.find(text).map(|m| m.as_str().to_string())
}

fn extract_username(text: &str) -> Option<String> {
    // Try multiple username patterns
    let patterns = vec![
        r"user:?\s*(\S+)",
        r"username:?\s*(\S+)",
        r"login:?\s*(\S+)",
        r"account:?\s*(\S+)",
    ];
    
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                if let Some(user) = caps.get(1) {
                    return Some(user.as_str().to_string());
                }
            }
        }
    }
    None
}

fn diagnose_parse_error(line: &str) -> (String, String) {
    // Since we now accept any format, this should rarely be called
    // Only truly unparseable lines (empty, garbage, etc.) will reach here
    
    if line.trim().is_empty() {
        return (
            "Empty line".to_string(),
            "Line contains no content".to_string()
        );
    }
    
    // Check if it looks like it might be a log line
    let has_numbers = line.chars().any(|c| c.is_numeric());
    let has_letters = line.chars().any(|c| c.is_alphabetic());
    
    if !has_numbers && !has_letters {
        return (
            "Invalid content".to_string(),
            "Line contains only special characters or whitespace".to_string()
        );
    }
    
    // If we got here, the line was processed but might lack structure
    // This is now informational rather than an error
    (
        "Unstructured log line".to_string(),
        "Line was processed but may lack timestamp or level. Threats will still be detected.".to_string()
    )
}
