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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 800px;
            width: 100%;
            padding: 40px;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2em;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        
        .upload-area {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            background: #f8f9ff;
            margin-bottom: 20px;
            transition: all 0.3s;
        }
        
        .upload-area:hover {
            border-color: #764ba2;
            background: #f0f1ff;
        }
        
        input[type="file"] {
            display: none;
        }
        
        .file-label {
            display: inline-block;
            padding: 15px 30px;
            background: #667eea;
            color: white;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1.1em;
            transition: all 0.3s;
        }
        
        .file-label:hover {
            background: #764ba2;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .file-name {
            margin-top: 15px;
            color: #666;
            font-style: italic;
        }
        
        button {
            width: 100%;
            padding: 15px;
            background: #10b981;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1.2em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        button:hover {
            background: #059669;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(16, 185, 129, 0.4);
        }
        
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
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
            background: #f8f9ff;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .stat-box {
            background: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            color: #666;
            margin-top: 5px;
            font-size: 0.9em;
        }
        
        .ip-list {
            margin-top: 15px;
        }
        
        .ip-item {
            background: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .risk-high { border-left: 4px solid #ef4444; }
        .risk-low { border-left: 4px solid #10b981; }
        
        .risk-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        
        .badge-high {
            background: #fee2e2;
            color: #dc2626;
        }
        
        .badge-medium {
            background: #fef3c7;
            color: #d97706;
        }
        
        .badge-low {
            background: #d1fae5;
            color: #059669;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .alert-error {
            background: #fee2e2;
            color: #dc2626;
            border: 1px solid #fca5a5;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Log Analyzer</h1>
        <p class="subtitle">Upload your security logs for AI-powered threat analysis</p>
        
        <div class="upload-area">
            <label for="file-upload" class="file-label">
                📁 Choose Log File
            </label>
            <input id="file-upload" type="file" accept=".txt,.log" />
            <div class="file-name" id="file-name">No file selected</div>
        </div>
        
        <button id="analyze-btn" disabled>Analyze Logs</button>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 10px; color: #666;">Analyzing security logs...</p>
        </div>
        
        <div id="error-container"></div>
        
        <div class="results" id="results">
            <div class="section">
                <h2>📊 Threat Statistics</h2>
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
                <h2> IP Address Analysis</h2>
                <div id="high-risk-ips"></div>
                <div id="all-ips"></div>
            </div>
            
            <div class="section">
                <h2>⚖️  Risk Assessment</h2>
                <div id="risk-assessment"></div>
            </div>
            
            <div class="section">
                <h2>📄 Parsing Information</h2>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
                    <div style="text-align: center;">
                        <div style="font-size: 1.5em; font-weight: bold; color: #667eea;" id="total-lines">0</div>
                        <div style="color: #666; font-size: 0.9em;">Total Lines</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 1.5em; font-weight: bold; color: #10b981;" id="parsed-lines">0</div>
                        <div style="color: #666; font-size: 0.9em;">Parsed Successfully</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 1.5em; font-weight: bold; color: #ef4444;" id="skipped-lines">0</div>
                        <div style="color: #666; font-size: 0.9em;">Skipped/Failed</div>
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
                         Error: ${error.message}
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
                    <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 5px; margin-bottom: 15px;">
                        <strong>⚠️ Warning:</strong> ${data.parsing_info.skipped_lines} lines (${percentage}%) could not be parsed.
                        <br><small>Expected format: YYYY-MM-DD HH:MM:SS [LEVEL] message</small>
                    </div>
                `;
                
                // Display specific errors
                if (data.parsing_info.errors && data.parsing_info.errors.length > 0) {
                    errorHtml += '<div style="margin-top: 15px;"><h4 style="margin-bottom: 10px;">🔍 Parsing Errors (showing first 10):</h4>';
                    data.parsing_info.errors.forEach(error => {
                        errorHtml += `
                            <div style="background: #fee; border-left: 3px solid #ef4444; padding: 10px; margin-bottom: 10px; border-radius: 4px; font-size: 0.9em;">
                                <div style="font-weight: bold; color: #dc2626; margin-bottom: 5px;">
                                    Line ${error.line_number}: ${error.error_type}
                                </div>
                                <div style="background: #f5f5f5; padding: 8px; border-radius: 3px; margin: 5px 0; font-family: monospace; font-size: 0.85em; overflow-x: auto;">
                                    ${error.line_content}
                                </div>
                                <div style="color: #059669; margin-top: 5px;">
                                    💡 <strong>Fix:</strong> ${error.suggestion}
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
                warningContainer.innerHTML = '<div style="color: #10b981;">✅ All lines parsed successfully!</div>';
            }
            
            const highRiskContainer = document.getElementById('high-risk-ips');
            if (data.ip_analysis.high_risk_ips.length > 0) {
                highRiskContainer.innerHTML = '<h3 style="margin-bottom: 10px;">🚨 High-Risk IPs (3+ occurrences)</h3>';
                data.ip_analysis.high_risk_ips.forEach(ip => {
                    highRiskContainer.innerHTML += `
                        <div class="ip-item risk-high">
                            <span><strong>${ip.ip}</strong> - ${ip.count} occurrences</span>
                            <span class="risk-badge badge-high">HIGH RISK</span>
                        </div>
                    `;
                });
            } else {
                highRiskContainer.innerHTML = '<p style="color: #10b981;">✅ No high-risk IPs detected</p>';
            }
            
            const allIpsContainer = document.getElementById('all-ips');
            allIpsContainer.innerHTML = '<h3 style="margin: 20px 0 10px 0;">All IP Activity</h3>';
            data.ip_analysis.all_ips.forEach(ip => {
                const riskClass = ip.risk_level === 'high' ? 'risk-high' : 'risk-low';
                allIpsContainer.innerHTML += `
                    <div class="ip-item ${riskClass}">
                        <span>${ip.risk_level === 'high' ? '🔴' : '🟢'} <strong>${ip.ip}</strong> - ${ip.count} occurrences</span>
                    </div>
                `;
            });
            
            const riskContainer = document.getElementById('risk-assessment');
            const badgeClass = data.risk_assessment.level === 'HIGH' ? 'badge-high' : 
                               data.risk_assessment.level === 'MEDIUM' ? 'badge-medium' : 'badge-low';
            riskContainer.innerHTML = `
                <div style="text-align: center;">
                    <span class="risk-badge ${badgeClass}" style="font-size: 1.2em; padding: 10px 30px;">
                        ${data.risk_assessment.level}
                    </span>
                    <p style="margin-top: 15px; font-size: 1.1em;">${data.risk_assessment.description}</p>
                    <p style="margin-top: 10px; color: #666;">Total threat indicators: ${data.risk_assessment.total_threats}</p>
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
