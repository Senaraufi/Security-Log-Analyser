use axum::{
    extract::Multipart,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;

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
    alerts: Vec<Alert>,
}

#[derive(Serialize)]
struct ParsingInfo {
    total_lines: usize,
    parsed_lines: usize,
    skipped_lines: usize,
    errors: Vec<ParseError>,
    format_quality: FormatQuality,
}

#[derive(Serialize)]
struct FormatQuality {
    perfect_format: usize,      // Format 1 (standard)
    alternative_format: usize,  // Formats 2-6 (valid alternatives)
    fallback_format: usize,     // Format 7+ (no timestamp/minimal structure)
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

#[derive(Serialize, Clone)]
struct IpInfo {
    ip: String,
    count: usize,
    risk_level: String,
    country: Option<String>,
    city: Option<String>,
    is_vpn: bool,
}

#[derive(Serialize, Deserialize)]
struct GeoLocation {
    country: String,
    city: String,
    region: String,
    timezone: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Alert {
    id: String,
    severity: String,
    title: String,
    description: String,
    timestamp: String,
    ip_address: Option<String>,
    triggered_by: String,
}

#[derive(Serialize)]
struct AlertRule {
    name: String,
    condition: String,
    threshold: usize,
    timeframe_minutes: u32,
    severity: String,
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
    
    println!("Security API Server running on http://localhost:3000");
    println!("Upload logs at: http://localhost:3000");
    
    axum::serve(listener, app).await.unwrap();
}

async fn serve_frontend() -> Html<&'static str> {
    Html(r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity Analysis Dashboard</title>
        <style>
            :root {
                --neutral-50: #fafafa;
                --neutral-100: #f5f5f5;
                --neutral-200: #e5e5e5;
                --neutral-300: #d4d4d4;
                --neutral-500: #737373;
                --neutral-600: #525252;
                --neutral-700: #404040;
                --neutral-900: #171717;
                --red-50: #fef2f2;
                --red-200: #fecaca;
                --red-700: #b91c1c;
                --orange-50: #fff7ed;
                --orange-200: #fed7aa;
                --orange-700: #c2410c;
                --yellow-50: #fefce8;
                --yellow-200: #fef08a;
                --yellow-700: #a16207;
                --green-50: #f0fdf4;
                --green-200: #bbf7d0;
                --green-700: #15803d;
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: var(--neutral-50);
                color: var(--neutral-900);
                line-height: 1.5;
                font-size: 14px;
                -webkit-font-smoothing: antialiased;
            }
            
            .container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 24px;
            }
            
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
            }
            
            h1 {
                font-size: 1.5rem;
                font-weight: 400;
                color: var(--neutral-900);
            }
            
            .risk-indicator {
                display: none;
                align-items: center;
                gap: 12px;
                padding: 8px 16px;
                border: 1px solid;
            }
            
            .risk-indicator.show {
                display: flex;
            }
            
            .risk-indicator.high {
                background: var(--orange-50);
                border-color: var(--orange-200);
                color: var(--orange-700);
            }
            
            .risk-indicator.medium {
                background: var(--yellow-50);
                border-color: var(--yellow-200);
                color: var(--yellow-700);
            }
            
            .risk-indicator.low {
                background: var(--green-50);
                border-color: var(--green-200);
                color: var(--green-700);
            }
            
            .risk-divider {
                width: 1px;
                height: 16px;
                background: var(--neutral-300);
            }
            
            .file-upload {
                background: white;
                border: 1px solid var(--neutral-200);
                padding: 24px;
                margin-bottom: 16px;
            }
            
            .upload-content {
                display: flex;
                align-items: center;
                gap: 16px;
            }
            
            .upload-button {
                flex: 1;
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 8px 16px;
                border: 1px solid var(--neutral-300);
                background: var(--neutral-50);
                cursor: pointer;
                transition: background 0.15s;
                color: var(--neutral-700);
            }
            
            .upload-button:hover {
                background: var(--neutral-100);
            }
            
            .upload-status {
                display: none;
                align-items: center;
                gap: 8px;
                color: var(--green-700);
            }
            
            .upload-status.show {
                display: flex;
            }
            
            .status-dot {
                width: 8px;
                height: 8px;
                background: var(--green-700);
                border-radius: 50%;
            }
            
            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-bottom: 16px;
            }
            
            .metric-card {
                background: white;
                border: 1px solid var(--neutral-200);
                padding: 16px;
            }
            
            .metric-header {
                display: flex;
                justify-content: space-between;
                align-items: start;
                margin-bottom: 8px;
            }
            
            .metric-icon {
                width: 16px;
                height: 16px;
                color: var(--neutral-500);
            }
            
            .metric-change {
                font-size: 0.75rem;
                color: var(--neutral-600);
                font-variant-numeric: tabular-nums;
            }
            
            .metric-value {
                font-size: 1.5rem;
                font-weight: 400;
                font-variant-numeric: tabular-nums;
                color: var(--neutral-900);
                margin-bottom: 4px;
            }
            
            .metric-label {
                font-size: 0.875rem;
                color: var(--neutral-600);
            }
            
            .section {
                background: white;
                border: 1px solid var(--neutral-200);
                margin-bottom: 16px;
            }
            
            .section-header {
                display: flex;
                align-items: center;
                justify-between;
                padding: 16px;
                cursor: pointer;
                transition: background 0.15s;
            }
            
            .section-header:hover {
                background: var(--neutral-50);
            }
            
            .section-title {
                display: flex;
                align-items: center;
                gap: 12px;
                font-size: 1rem;
                color: var(--neutral-900);
            }
            
            .chevron {
                width: 16px;
                height: 16px;
                color: var(--neutral-600);
                transition: transform 0.2s;
            }
            
            .chevron.expanded {
                transform: rotate(90deg);
            }
            
            .section-count {
                color: var(--neutral-600);
                font-size: 0.875rem;
            }
            
            .section-content {
                display: none;
                border-top: 1px solid var(--neutral-200);
                padding: 16px;
            }
            
            .section-content.show {
                display: block;
            }
            
            .threat-grid {
                display: grid;
                grid-template-columns: repeat(7, 1fr);
                gap: 12px;
                margin-top: 16px;
            }
            
            .threat-box {
                border: 1px solid var(--neutral-200);
                padding: 12px;
            }
            
            .threat-value {
                font-size: 1.25rem;
                font-variant-numeric: tabular-nums;
                color: var(--neutral-900);
                margin-bottom: 4px;
            }
            
            .threat-label {
                font-size: 0.875rem;
                color: var(--neutral-600);
                margin-bottom: 8px;
            }
            
            .threat-severity {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            
            .severity-critical { color: var(--red-700); }
            .severity-high { color: var(--orange-700); }
            .severity-medium { color: var(--yellow-700); }
            
            .ip-table {
                display: grid;
                grid-template-columns: 2fr 1fr 1fr 1fr;
                gap: 1px;
                background: var(--neutral-200);
            }
            
            .ip-table-header {
                background: var(--neutral-100);
                padding: 8px 16px;
                font-size: 0.875rem;
                color: var(--neutral-600);
            }
            
            .ip-table-cell {
                background: white;
                padding: 12px 16px;
                font-size: 0.875rem;
            }
            
            .ip-address {
                font-family: ui-monospace, 'SF Mono', Monaco, monospace;
                color: var(--neutral-900);
            }
            
            .ip-count {
                font-variant-numeric: tabular-nums;
                color: var(--neutral-900);
            }
            
            .status-badge {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            
            .status-blocked { color: var(--red-700); }
            .status-high { color: var(--red-700); }
            .status-low { color: var(--neutral-600); }
            
            .parsing-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 24px;
            }
            
            .donut-container {
                display: flex;
                justify-content: center;
                align-items: center;
            }
            
            .donut-wrapper {
                position: relative;
                width: 200px;
                height: 200px;
            }
            
            .donut-center {
                position: absolute;
                inset: 0;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
            }
            
            .donut-percentage {
                font-size: 1.5rem;
                font-variant-numeric: tabular-nums;
                color: var(--neutral-900);
            }
            
            .donut-label {
                font-size: 0.875rem;
                color: var(--neutral-600);
            }
            
            .stats-list {
                display: flex;
                flex-direction: column;
                gap: 16px;
            }
            
            .stat-item {
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            
            .stat-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .stat-label {
                font-size: 0.875rem;
                color: var(--neutral-700);
            }
            
            .stat-value {
                font-size: 0.875rem;
                font-variant-numeric: tabular-nums;
                color: var(--neutral-900);
            }
            
            .progress-bar {
                width: 100%;
                height: 8px;
                background: var(--neutral-200);
            }
            
            .progress-fill {
                height: 100%;
                background: var(--neutral-900);
                transition: width 0.3s;
            }
            
            .loading {
                display: none;
                text-align: center;
                padding: 40px;
                color: var(--neutral-600);
            }
            
            .loading.show {
                display: block;
            }
            
            .spinner {
                width: 40px;
                height: 40px;
                border: 3px solid var(--neutral-200);
                border-top-color: var(--neutral-900);
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
                margin: 0 auto 16px;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            .hidden {
                display: none;
            }
            
            .bar-chart {
                height: 240px;
                display: flex;
                align-items: flex-end;
                gap: 8px;
                padding: 16px 0;
                margin-bottom: 16px;
            }
            
            .bar {
                flex: 1;
                background: var(--neutral-900);
                position: relative;
                min-height: 4px;
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                align-items: center;
            }
            
            .bar-value {
                position: absolute;
                top: -20px;
                font-size: 0.75rem;
                font-variant-numeric: tabular-nums;
                color: var(--neutral-900);
            }
            
            .bar-labels {
                display: flex;
                gap: 8px;
            }
            
            .bar-label {
                flex: 1;
                text-align: center;
                font-size: 0.75rem;
                color: var(--neutral-600);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Cybersecurity Analysis Dashboard</h1>
                <div class="risk-indicator" id="risk-indicator">
                    <span id="risk-icon">⚠</span>
                    <span id="risk-label">HIGH RISK</span>
                    <div class="risk-divider"></div>
                    <span id="risk-score">78/100</span>
                </div>
            </div>
            
            <div class="file-upload">
                <div class="upload-content">
                    <label class="upload-button">
                        <input type="file" id="file-input" accept=".log,.txt" style="display: none;">
                        <span>↑</span>
                        <span id="file-name">Upload Log File</span>
                    </label>
                    <div class="upload-status" id="upload-status">
                        <div class="status-dot"></div>
                        <span>Analyzed</span>
                    </div>
                </div>
            </div>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing security logs...</p>
            </div>
            
            <div id="results" class="hidden">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-header">
                            <span class="metric-icon">📊</span>
                            <span class="metric-change" id="metric-change-1">+8%</span>
                        </div>
                        <div class="metric-value" id="total-events">0</div>
                        <div class="metric-label">Total Events</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <span class="metric-icon">⚠</span>
                            <span class="metric-change" id="metric-change-2">+12%</span>
                        </div>
                        <div class="metric-value" id="threats-detected">0</div>
                        <div class="metric-label">Threats Detected</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <span class="metric-icon">🛡</span>
                            <span class="metric-change" id="metric-change-3">-3%</span>
                        </div>
                        <div class="metric-value" id="blocked-ips">0</div>
                        <div class="metric-label">Blocked IPs</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <span class="metric-icon">✓</span>
                            <span class="metric-change" id="metric-change-4">+5%</span>
                        </div>
                        <div class="metric-value" id="format-quality">0%</div>
                        <div class="metric-label">Format Quality</div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-header" onclick="toggleSection('threats')">
                        <div class="section-title">
                            <span class="chevron" id="threats-chevron">▶</span>
                            <span>Threat Distribution</span>
                            <span class="section-count" id="threats-count">0 Total</span>
                        </div>
                    </div>
                    <div class="section-content" id="threats-content">
                        <div class="bar-chart" id="threats-chart"></div>
                        <div class="bar-labels" id="threats-labels"></div>
                        <div class="threat-grid">
                            <div class="threat-box">
                                <div class="threat-value" id="failed-logins">0</div>
                                <div class="threat-label">Failed Logins</div>
                                <div class="threat-severity severity-critical">CRITICAL</div>
                            </div>
                            <div class="threat-box">
                                <div class="threat-value" id="root-attempts">0</div>
                                <div class="threat-label">Root Attempts</div>
                                <div class="threat-severity severity-critical">CRITICAL</div>
                            </div>
                            <div class="threat-box">
                                <div class="threat-value" id="file-access">0</div>
                                <div class="threat-label">File Access</div>
                                <div class="threat-severity severity-high">HIGH</div>
                            </div>
                            <div class="threat-box">
                                <div class="threat-value" id="critical-alerts">0</div>
                                <div class="threat-label">Critical</div>
                                <div class="threat-severity severity-critical">CRITICAL</div>
                            </div>
                            <div class="threat-box">
                                <div class="threat-value" id="sql-injection">0</div>
                                <div class="threat-label">SQL Injection</div>
                                <div class="threat-severity severity-critical">CRITICAL</div>
                            </div>
                            <div class="threat-box">
                                <div class="threat-value" id="port-scanning">0</div>
                                <div class="threat-label">Port Scan</div>
                                <div class="threat-severity severity-high">HIGH</div>
                            </div>
                            <div class="threat-box">
                                <div class="threat-value" id="malware">0</div>
                                <div class="threat-label">Malware</div>
                                <div class="threat-severity severity-critical">CRITICAL</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-header" onclick="toggleSection('ips')">
                        <div class="section-title">
                            <span class="chevron" id="ips-chevron">▶</span>
                            <span>IP Analysis</span>
                            <span class="section-count" id="ips-count">0 Blocked</span>
                        </div>
                    </div>
                    <div class="section-content" id="ips-content">
                        <div class="ip-table" id="ip-table"></div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-header" onclick="toggleSection('parsing')">
                        <div class="section-title">
                            <span class="chevron" id="parsing-chevron">▶</span>
                            <span>Parsing Statistics</span>
                        </div>
                    </div>
                    <div class="section-content" id="parsing-content">
                        <div class="parsing-grid">
                            <div class="donut-container">
                                <div class="donut-wrapper">
                                    <canvas id="donut-canvas" width="200" height="200"></canvas>
                                    <div class="donut-center">
                                        <div class="donut-percentage" id="success-rate">0%</div>
                                        <div class="donut-label">Success Rate</div>
                                    </div>
                                </div>
                            </div>
                            <div class="stats-list">
                                <div class="stat-item">
                                    <div class="stat-header">
                                        <span class="stat-label">Perfect Format</span>
                                        <span class="stat-value" id="perfect-format">0</span>
                                    </div>
                                    <div class="progress-bar">
                                        <div class="progress-fill" id="perfect-progress"></div>
                                    </div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-header">
                                        <span class="stat-label">Alternative Format</span>
                                        <span class="stat-value" id="alternative-format">0</span>
                                    </div>
                                    <div class="progress-bar">
                                        <div class="progress-fill" id="alternative-progress"></div>
                                    </div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-header">
                                        <span class="stat-label">Fallback Format</span>
                                        <span class="stat-value" id="fallback-format">0</span>
                                    </div>
                                    <div class="progress-bar">
                                        <div class="progress-fill" id="fallback-progress"></div>
                                    </div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-header">
                                        <span class="stat-label">Total Lines</span>
                                        <span class="stat-value" id="total-lines">0</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            function toggleSection(id) {
                const content = document.getElementById(`${id}-content`);
                const chevron = document.getElementById(`${id}-chevron`);
                
                content.classList.toggle('show');
                chevron.classList.toggle('expanded');
            }
            
            function drawDonut(perfect, alternative, fallback) {
                const canvas = document.getElementById('donut-canvas');
                const ctx = canvas.getContext('2d');
                const total = perfect + alternative + fallback;
                
                if (total === 0) return;
                
                const centerX = 100;
                const centerY = 100;
                const radius = 80;
                const innerRadius = 60;
                
                ctx.clearRect(0, 0, 200, 200);
                
                let currentAngle = -Math.PI / 2;
                
                // Perfect format (green)
                if (perfect > 0) {
                    const angle = (perfect / total) * 2 * Math.PI;
                    ctx.fillStyle = '#15803d';
                    drawDonutSegment(ctx, centerX, centerY, radius, innerRadius, currentAngle, currentAngle + angle);
                    currentAngle += angle;
                }
                
                // Alternative format (neutral)
                if (alternative > 0) {
                    const angle = (alternative / total) * 2 * Math.PI;
                    ctx.fillStyle = '#737373';
                    drawDonutSegment(ctx, centerX, centerY, radius, innerRadius, currentAngle, currentAngle + angle);
                    currentAngle += angle;
                }
                
                // Fallback format (light gray)
                if (fallback > 0) {
                    const angle = (fallback / total) * 2 * Math.PI;
                    ctx.fillStyle = '#e5e5e5';
                    drawDonutSegment(ctx, centerX, centerY, radius, innerRadius, currentAngle, currentAngle + angle);
                }
            }
            
            function drawDonutSegment(ctx, x, y, radius, innerRadius, startAngle, endAngle) {
                ctx.beginPath();
                ctx.arc(x, y, radius, startAngle, endAngle);
                ctx.arc(x, y, innerRadius, endAngle, startAngle, true);
                ctx.closePath();
                ctx.fill();
            }
            
            function drawBarChart(data) {
                const container = document.getElementById('threats-chart');
                const labels = document.getElementById('threats-labels');
                
                const threats = [
                    { value: data.threat_statistics.failed_logins, label: 'Failed Logins' },
                    { value: data.threat_statistics.root_attempts, label: 'Root' },
                    { value: data.threat_statistics.suspicious_file_access, label: 'File Access' },
                    { value: data.threat_statistics.critical_alerts, label: 'Critical' },
                    { value: data.threat_statistics.sql_injection_attempts, label: 'SQL' },
                    { value: data.threat_statistics.port_scanning_attempts, label: 'Port Scan' },
                    { value: data.threat_statistics.malware_detections, label: 'Malware' }
                ];
                
                const maxValue = Math.max(...threats.map(t => t.value), 1);
                
                container.innerHTML = '';
                labels.innerHTML = '';
                
                threats.forEach(threat => {
                    const height = (threat.value / maxValue) * 100;
                    const bar = document.createElement('div');
                    bar.className = 'bar';
                    bar.style.height = `${height}%`;
                    
                    const barValue = document.createElement('div');
                    barValue.className = 'bar-value';
                    barValue.textContent = threat.value;
                    bar.appendChild(barValue);
                    
                    container.appendChild(bar);
                    
                    const label = document.createElement('div');
                    label.className = 'bar-label';
                    label.textContent = threat.label;
                    labels.appendChild(label);
                });
            }
            
            const fileInput = document.getElementById('file-input');
            const fileName = document.getElementById('file-name');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const uploadStatus = document.getElementById('upload-status');
            const riskIndicator = document.getElementById('risk-indicator');
            
            fileInput.addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                
                fileName.textContent = file.name;
                loading.classList.add('show');
                results.classList.add('hidden');
                
                const formData = new FormData();
                formData.append('file', file);
                
                try {
                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    displayResults(data);
                    
                    loading.classList.remove('show');
                    results.classList.remove('hidden');
                    uploadStatus.classList.add('show');
                    riskIndicator.classList.add('show');
                    
                } catch (error) {
                    console.error('Error:', error);
                    loading.classList.remove('show');
                }
            });
            
            function displayResults(data) {
                // Metrics
                document.getElementById('total-events').textContent = data.parsing_info.total_lines.toLocaleString();
                document.getElementById('threats-detected').textContent = data.risk_assessment.total_threats;
                document.getElementById('blocked-ips').textContent = data.ip_analysis.high_risk_ips.length;
                
                const formatQuality = ((data.parsing_info.format_quality.perfect_format / data.parsing_info.total_lines) * 100).toFixed(0);
                document.getElementById('format-quality').textContent = formatQuality + '%';
                
                // Risk indicator
                const riskLevel = data.risk_assessment.level.toLowerCase();
                riskIndicator.className = `risk-indicator show ${riskLevel}`;
                document.getElementById('risk-label').textContent = data.risk_assessment.level + ' RISK';
                document.getElementById('risk-score').textContent = data.risk_assessment.total_threats + '/100';
                
                if (riskLevel === 'high') {
                    document.getElementById('risk-icon').textContent = '⚠';
                } else if (riskLevel === 'medium') {
                    document.getElementById('risk-icon').textContent = '⚠';
                } else {
                    document.getElementById('risk-icon').textContent = '🛡';
                }
                
                // Threats
                document.getElementById('threats-count').textContent = data.risk_assessment.total_threats + ' Total';
                document.getElementById('failed-logins').textContent = data.threat_statistics.failed_logins;
                document.getElementById('root-attempts').textContent = data.threat_statistics.root_attempts;
                document.getElementById('file-access').textContent = data.threat_statistics.suspicious_file_access;
                document.getElementById('critical-alerts').textContent = data.threat_statistics.critical_alerts;
                document.getElementById('sql-injection').textContent = data.threat_statistics.sql_injection_attempts;
                document.getElementById('port-scanning').textContent = data.threat_statistics.port_scanning_attempts;
                document.getElementById('malware').textContent = data.threat_statistics.malware_detections;
                
                drawBarChart(data);
                
                // IPs
                const highRiskCount = data.ip_analysis.high_risk_ips.length;
                document.getElementById('ips-count').textContent = highRiskCount + ' Blocked';
                
                const ipTable = document.getElementById('ip-table');
                ipTable.innerHTML = `
                    <div class="ip-table-header">IP Address</div>
                    <div class="ip-table-header">Attempts</div>
                    <div class="ip-table-header">Risk</div>
                    <div class="ip-table-header">Status</div>
                `;
                
                data.ip_analysis.all_ips.slice(0, 8).forEach(ip => {
                    // IP Address cell
                    const ipCell = document.createElement('div');
                    ipCell.className = 'ip-table-cell ip-address';
                    ipCell.textContent = ip.ip;
                    ipTable.appendChild(ipCell);
                    
                    // Count cell
                    const countCell = document.createElement('div');
                    countCell.className = 'ip-table-cell ip-count';
                    countCell.textContent = ip.count;
                    ipTable.appendChild(countCell);
                    
                    // Risk cell
                    const riskCell = document.createElement('div');
                    riskCell.className = 'ip-table-cell';
                    const riskBadge = document.createElement('span');
                    riskBadge.className = `status-badge status-${ip.risk_level}`;
                    riskBadge.textContent = ip.risk_level.toUpperCase();
                    riskCell.appendChild(riskBadge);
                    ipTable.appendChild(riskCell);
                    
                    // Status cell
                    const statusCell = document.createElement('div');
                    statusCell.className = 'ip-table-cell';
                    const statusBadge = document.createElement('span');
                    statusBadge.className = `status-badge status-${ip.risk_level === 'high' ? 'blocked' : 'low'}`;
                    statusBadge.textContent = ip.risk_level === 'high' ? 'BLOCKED' : 'MONITORED';
                    statusCell.appendChild(statusBadge);
                    ipTable.appendChild(statusCell);
                });
                
                // Parsing stats
                const successRate = ((data.parsing_info.parsed_lines / data.parsing_info.total_lines) * 100).toFixed(1);
                document.getElementById('success-rate').textContent = successRate + '%';
                document.getElementById('perfect-format').textContent = data.parsing_info.format_quality.perfect_format;
                document.getElementById('alternative-format').textContent = data.parsing_info.format_quality.alternative_format;
                document.getElementById('fallback-format').textContent = data.parsing_info.format_quality.fallback_format;
                document.getElementById('total-lines').textContent = data.parsing_info.total_lines;
                
                const total = data.parsing_info.total_lines;
                document.getElementById('perfect-progress').style.width = ((data.parsing_info.format_quality.perfect_format / total) * 100) + '%';
                document.getElementById('alternative-progress').style.width = ((data.parsing_info.format_quality.alternative_format / total) * 100) + '%';
                document.getElementById('fallback-progress').style.width = ((data.parsing_info.format_quality.fallback_format / total) * 100) + '%';
                
                drawDonut(
                    data.parsing_info.format_quality.perfect_format,
                    data.parsing_info.format_quality.alternative_format,
                    data.parsing_info.format_quality.fallback_format
                );
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

// Geolocation lookup using IP-API (free, no API key needed)
async fn get_geolocation(ip: &str) -> Option<(String, String)> {
    // Skip private IPs
    if ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.") {
        return Some(("Local Network".to_string(), "Private IP".to_string()));
    }
    
    let url = format!("http://ip-api.com/json/{}?fields=status,country,city", ip);
    
    match reqwest::get(&url).await {
        Ok(response) => {
            if let Ok(data) = response.json::<serde_json::Value>().await {
                if data["status"] == "success" {
                    let country = data["country"].as_str().unwrap_or("Unknown").to_string();
                    let city = data["city"].as_str().unwrap_or("Unknown").to_string();
                    return Some((country, city));
                }
            }
        }
        Err(_) => {}
    }
    
    None
}

// Check if IP is likely a VPN/Proxy (simple heuristic)
fn is_vpn_ip(ip: &str) -> bool {
    // Simple check: known VPN ranges or patterns
    // In production, use a proper VPN detection service
    ip.starts_with("185.") || // Common VPN range
    ip.starts_with("45.") ||   // Common VPN range
    ip.starts_with("104.")     // Common cloud/VPN range
}

// Alert Rules Engine
fn check_alert_rules(
    threat_stats: &ThreatStats,
    ip_analysis: &IpAnalysis,
    total_threats: usize,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let now = Utc::now().to_rfc3339();
    
    // Rule 1: High number of failed logins
    if threat_stats.failed_logins >= 5 {
        alerts.push(Alert {
            id: format!("ALERT-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            severity: "HIGH".to_string(),
            title: "Multiple Failed Login Attempts".to_string(),
            description: format!("{} failed login attempts detected. Possible brute force attack.", threat_stats.failed_logins),
            timestamp: now.clone(),
            ip_address: None,
            triggered_by: "Failed Login Threshold".to_string(),
        });
    }
    
    // Rule 2: Root access attempts
    if threat_stats.root_attempts >= 3 {
        alerts.push(Alert {
            id: format!("ALERT-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            severity: "CRITICAL".to_string(),
            title: "Root Access Attempts".to_string(),
            description: format!("{} attempts to access root account detected.", threat_stats.root_attempts),
            timestamp: now.clone(),
            ip_address: None,
            triggered_by: "Root Attempt Threshold".to_string(),
        });
    }
    
    // Rule 3: SQL Injection detected
    if threat_stats.sql_injection_attempts > 0 {
        alerts.push(Alert {
            id: format!("ALERT-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            severity: "CRITICAL".to_string(),
            title: "SQL Injection Attempt".to_string(),
            description: format!("{} SQL injection patterns detected in logs.", threat_stats.sql_injection_attempts),
            timestamp: now.clone(),
            ip_address: None,
            triggered_by: "SQL Injection Detection".to_string(),
        });
    }
    
    // Rule 4: Malware detection
    if threat_stats.malware_detections > 0 {
        alerts.push(Alert {
            id: format!("ALERT-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            severity: "CRITICAL".to_string(),
            title: "Malware Detected".to_string(),
            description: format!("{} malware signatures found.", threat_stats.malware_detections),
            timestamp: now.clone(),
            ip_address: None,
            triggered_by: "Malware Signature Match".to_string(),
        });
    }
    
    // Rule 5: High-risk IP with many attempts
    for ip_info in &ip_analysis.high_risk_ips {
        if ip_info.count >= 10 {
            alerts.push(Alert {
                id: format!("ALERT-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
                severity: "HIGH".to_string(),
                title: "Suspicious IP Activity".to_string(),
                description: format!("IP {} made {} requests. Possible attack source.", ip_info.ip, ip_info.count),
                timestamp: now.clone(),
                ip_address: Some(ip_info.ip.clone()),
                triggered_by: "High Request Count".to_string(),
            });
        }
    }
    
    // Rule 6: Overall threat level
    if total_threats >= 15 {
        alerts.push(Alert {
            id: format!("ALERT-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            severity: "CRITICAL".to_string(),
            title: "High Threat Level".to_string(),
            description: format!("Total of {} threats detected. System under attack.", total_threats),
            timestamp: now,
            ip_address: None,
            triggered_by: "Threat Level Threshold".to_string(),
        });
    }
    
    alerts
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
    let mut perfect_format = 0;
    let mut alternative_format = 0;
    let mut fallback_format = 0;
    
    for line in content.lines() {
        total_lines += 1;
        
        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }
        
        // Check format quality
        let format_type = check_format_quality(line);
        match format_type {
            1 => perfect_format += 1,
            2..=6 => alternative_format += 1,
            _ => fallback_format += 1,
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
        .map(|(ip, count)| {
            // Note: Geolocation is async, so we'll add placeholder for now
            // In production, you'd want to batch these or cache results
            IpInfo {
                ip: ip.to_string(),
                count: **count,
                risk_level: "high".to_string(),
                country: None, // Will be populated by frontend or async process
                city: None,
                is_vpn: is_vpn_ip(ip),
            }
        })
        .collect();
    
    let all_ips: Vec<IpInfo> = ip_vec.iter()
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: if **count >= 3 { "high" } else { "low" }.to_string(),
            country: None,
            city: None,
            is_vpn: is_vpn_ip(ip),
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
    
    let threat_stats = ThreatStats {
        failed_logins,
        root_attempts,
        suspicious_file_access,
        critical_alerts,
        sql_injection_attempts,
        port_scanning_attempts,
        malware_detections,
    };
    
    let ip_analysis = IpAnalysis {
        high_risk_ips: high_risk_ips.clone(),
        all_ips,
    };
    
    // Generate alerts based on rules
    let alerts = check_alert_rules(&threat_stats, &ip_analysis, total_threats);
    
    AnalysisResult {
        threat_statistics: threat_stats,
        ip_analysis,
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
            format_quality: FormatQuality {
                perfect_format,
                alternative_format,
                fallback_format,
            },
        },
        alerts,
    }
}

fn check_format_quality(line: &str) -> u8 {
    use regex::Regex;
    
    // Format 1: YYYY-MM-DD HH:MM:SS [LEVEL] message (PERFECT)
    if Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[\w+\] .*").unwrap().is_match(line) {
        return 1;
    }
    
    // Format 2: [YYYY-MM-DD HH:MM:SS] LEVEL: message
    if Regex::new(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \w+: .*").unwrap().is_match(line) {
        return 2;
    }
    
    // Format 3: YYYY/MM/DD HH:MM:SS [LEVEL] message
    if Regex::new(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[\w+\] .*").unwrap().is_match(line) {
        return 3;
    }
    
    // Format 4: MM/DD/YYYY HH:MM:SS [LEVEL] message
    if Regex::new(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} \[\w+\] .*").unwrap().is_match(line) {
        return 4;
    }
    
    // Format 5: YYYY-MM-DD HH:MM:SS LEVEL message (no brackets)
    if Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (ERROR|WARN|INFO|CRITICAL|DEBUG|FATAL)\s+.*").unwrap().is_match(line) {
        return 5;
    }
    
    // Format 6: Syslog style
    if Regex::new(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2} \S+ \w+: .*").unwrap().is_match(line) {
        return 6;
    }
    
    // Format 7: Has timestamp but not perfect format
    if Regex::new(r"\d{4}[-/]\d{2}[-/]\d{2}").unwrap().is_match(line) {
        return 7;
    }
    
    // Format 8+: Fallback (no proper timestamp)
    8
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
