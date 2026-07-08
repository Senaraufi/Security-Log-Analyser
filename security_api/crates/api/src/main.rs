use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Multipart, Request},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tower_http::services::ServeDir;

/// Maximum upload size: 50 MB
const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;

/// Rate limit: max requests per IP within the window
const RATE_LIMIT_MAX_REQUESTS: usize = 30;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

fn rate_limit_store() -> &'static Mutex<HashMap<String, Vec<Instant>>> {
    static STORE: OnceLock<Mutex<HashMap<String, Vec<Instant>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Simple per-IP sliding-window rate limiter for API routes
async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();
    let now = Instant::now();

    let allowed = {
        let mut store = match rate_limit_store().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let timestamps = store.entry(ip).or_default();
        timestamps.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
        if timestamps.len() >= RATE_LIMIT_MAX_REQUESTS {
            false
        } else {
            timestamps.push(now);
            true
        }
    };

    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "Rate limit exceeded. Please wait before retrying."
            })),
        )
            .into_response();
    }

    next.run(request).await
}

// Import from workspace crates
use security_common::{
    database::{init_db, test_connection, DbPool},
    cvss,
    geolocation,
    AnalysisResult, ThreatStats, IpAnalysis, IpInfo, RiskAssessment, 
    ParsingInfo, ParseError, FormatQuality,
};
use security_analyzer_basic::BasicAnalyzer;

mod llm_handler;
mod simple_handler;

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenv::dotenv().ok();
    
    // Initialize database connection
    println!("Starting Security API Server...");
    let db_pool = match init_db().await {
        Ok(pool) => {
            if let Err(e) = test_connection(&pool).await {
                eprintln!("[ERROR] Database connection test failed: {}", e);
                eprintln!("  Server will run but database features will be unavailable");
            }
            Some(pool)
        }
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            eprintln!("Server will run but database features will be unavailable");
            eprintln!("Check your DATABASE_URL in .env file");
            None
        }
    };
    
    let static_files = ServeDir::new("crates/api/static");
    
    let api_routes = Router::new()
        .route("/api/analyze", post(analyze_logs))
        .route("/api/analyze-with-llm", post(llm_handler::analyze_logs_with_llm))
        .route("/api/llm-health", axum::routing::get(llm_handler::llm_health_check))
        .route("/api/explain-logs", post(simple_handler::explain_logs))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES));

    let mut app = api_routes.nest_service("/", static_files);
    
    // Add database pool to app state if available
    if let Some(pool) = db_pool {
        app = app.layer(Extension(pool));
    }
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("[INFO] Security API Server running on http://localhost:3000");
    println!("[INFO] Upload logs at: http://localhost:3000");
    println!("[INFO] LLM Analysis: POST /api/analyze-with-llm");
    println!("[INFO] LLM Health:   GET  /api/llm-health");
    
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

// Basic analysis endpoint
async fn analyze_logs(
    Extension(_db_pool): Extension<DbPool>,
    mut multipart: Multipart,
) -> Response {
    let mut content = String::new();
    let mut filename = String::from("unknown");
    
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_string();
                
                if name == "file" {
                    filename = field.file_name().unwrap_or("unknown").to_string();
                    match field.bytes().await {
                        Ok(data) => {
                            content = String::from_utf8_lossy(&data).to_string();
                        }
                        Err(e) => {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": format!("Failed to read uploaded file: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("Malformed multipart request: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    }
    
    if content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No file content provided" })),
        )
            .into_response();
    }
    
    println!("[INFO] Processing log file: {}", filename);
    
    // Parse logs and analyze
    let mut result = process_logs(&content);
    
    // Enrich IPs with geolocation data
    let all_ip_strings: Vec<String> = result.ip_analysis.all_ips.iter().map(|ip| ip.ip.clone()).collect();
    if !all_ip_strings.is_empty() {
        println!("[INFO] Looking up geolocation for {} IPs...", all_ip_strings.len());
        let geo_data = geolocation::lookup_batch(&all_ip_strings).await;
        
        for ip_info in &mut result.ip_analysis.all_ips {
            if let Some(geo) = geo_data.get(&ip_info.ip) {
                ip_info.country = geo.country.clone();
                ip_info.city = geo.city.clone();
                ip_info.is_vpn = geo.is_proxy || geo.is_hosting;
            }
        }
        
        for ip_info in &mut result.ip_analysis.high_risk_ips {
            if let Some(geo) = geo_data.get(&ip_info.ip) {
                ip_info.country = geo.country.clone();
                ip_info.city = geo.city.clone();
                ip_info.is_vpn = geo.is_proxy || geo.is_hosting;
            }
        }
    }
    
    println!("[INFO] Analysis complete");
    
    Json(result).into_response()
}

// Process logs with basic analyzer
pub fn process_logs(content: &str) -> AnalysisResult {
    use security_common::parsers::{parse_log_line_unified, parse_apache_combined};
    
    let mut entries = Vec::new();
    let mut total_lines = 0;
    let mut parsed_lines = 0;
    let mut parse_errors: Vec<ParseError> = Vec::new();
    let mut perfect_format = 0;
    let mut alternative_format = 0;
    let mut fallback_format = 0;
    
    // Parse all lines with unified parser (supports multiple formats)
    for line in content.lines() {
        total_lines += 1;
        
        if line.trim().is_empty() {
            continue;
        }
        
        // Try unified parser - supports Apache, generic, and fallback formats
        if let Some(entry) = parse_log_line_unified(line) {
            parsed_lines += 1;
            
            // Track format quality
            if parse_apache_combined(line).is_ok() {
                perfect_format += 1; // Apache format
            } else if entry.timestamp.contains('-') && !entry.level.is_empty() {
                alternative_format += 1; // Generic structured format
            } else {
                fallback_format += 1; // Minimal parsing
            }
            
            entries.push(entry);
        } else if parse_errors.len() < 10 {
            parse_errors.push(ParseError {
                line_number: total_lines,
                line_content: if line.len() > 100 {
                    format!("{}...", &line[..100])
                } else {
                    line.to_string()
                },
                error_type: "Parse failed".to_string(),
                suggestion: "Line was empty or invalid".to_string(),
            });
        }
    }
    
    // Run basic analysis
    let analyzer = BasicAnalyzer::new();
    let analysis = analyzer.analyze(&entries);
    let cvss_scores = analyzer.generate_cvss_scores(&analysis);
    
    // Build IP analysis
    let mut ip_vec: Vec<_> = analysis.ip_frequency.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));
    
    let high_risk_ips: Vec<IpInfo> = ip_vec.iter()
        .filter(|(_, count)| **count >= 3)
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: "high".to_string(),
            country: None,
            city: None,
            is_vpn: false,
        })
        .collect();
    
    let all_ips: Vec<IpInfo> = ip_vec.iter()
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: if **count >= 3 { "high" } else { "low" }.to_string(),
            country: None,
            city: None,
            is_vpn: false,
        })
        .collect();
    
    // Calculate aggregate CVSS
    let total_threats = analysis.failed_logins + analysis.root_attempts + 
                        analysis.suspicious_file_access + analysis.critical_alerts + 
                        analysis.sql_injection_attempts + analysis.port_scanning_attempts + 
                        analysis.malware_detections;
    
    let mut threat_types_for_aggregate = Vec::new();
    if analysis.sql_injection_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::SQLInjection, analysis.sql_injection_attempts));
    }
    if analysis.failed_logins > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::FailedLogin, analysis.failed_logins));
    }
    if analysis.root_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::RootAccess, analysis.root_attempts));
    }
    if analysis.suspicious_file_access > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::SuspiciousFileAccess, analysis.suspicious_file_access));
    }
    if analysis.port_scanning_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::PortScanning, analysis.port_scanning_attempts));
    }
    if analysis.malware_detections > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::Malware, analysis.malware_detections));
    }
    if analysis.critical_alerts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::CriticalAlert, analysis.critical_alerts));
    }
    
    let aggregate_cvss = cvss::calculate_aggregate_score(&threat_types_for_aggregate);
    
    let (level, description) = if total_threats > 20 {
        ("CRITICAL", "Immediate action required")
    } else if total_threats > 10 {
        ("HIGH", "Urgent attention needed")
    } else if total_threats > 5 {
        ("MEDIUM", "Review recommended")
    } else {
        ("LOW", "Normal activity")
    };
    
    AnalysisResult {
        threat_statistics: ThreatStats {
            failed_logins: analysis.failed_logins,
            root_attempts: analysis.root_attempts,
            suspicious_file_access: analysis.suspicious_file_access,
            critical_alerts: analysis.critical_alerts,
            sql_injection_attempts: analysis.sql_injection_attempts,
            port_scanning_attempts: analysis.port_scanning_attempts,
            malware_detections: analysis.malware_detections,
            cvss_scores,
        },
        ip_analysis: IpAnalysis {
            high_risk_ips,
            all_ips,
        },
        risk_assessment: RiskAssessment {
            level: level.to_string(),
            total_threats,
            description: description.to_string(),
            cvss_aggregate_score: aggregate_cvss.base_score,
            cvss_severity: aggregate_cvss.severity.as_str().to_string(),
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
        alerts: Vec::new(),
    }
}

