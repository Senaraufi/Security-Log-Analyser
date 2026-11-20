use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Request},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::post,
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

    // Periodically evict stale entries to prevent unbounded memory growth.
    // We piggyback on every 100th request to avoid adding a background task.
    static EVICT_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if EVICT_COUNTER
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .is_multiple_of(100)
        && let Ok(mut store) = rate_limit_store().lock()
    {
        let now = Instant::now();
        store.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
            !timestamps.is_empty()
        });
    }

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
use security_analyzer_basic::analyze::analyze as analyze_logs_basic;
use security_common::{
    database::{init_db, test_connection},
    geolocation,
};

mod llm_handler;
mod simple_handler;

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenv::dotenv().ok();

    // Database is optional and currently unused by any route handler
    // (kept for future persistence features); this is a startup diagnostic only.
    println!("Starting Security API Server...");
    match init_db().await {
        Ok(pool) => {
            if let Err(e) = test_connection(&pool).await {
                eprintln!("[ERROR] Database connection test failed: {}", e);
            } else {
                println!("[INFO] Database connected");
            }
        }
        Err(e) => {
            println!("[INFO] Running without a database: {}", e);
        }
    }

    let static_files = ServeDir::new("crates/api/static");

    let api_routes = Router::new()
        .route("/api/analyze", post(analyze_logs))
        .route(
            "/api/analyze-with-llm",
            post(llm_handler::analyze_logs_with_llm),
        )
        .route(
            "/api/llm-health",
            axum::routing::get(llm_handler::llm_health_check),
        )
        .route("/api/explain-logs", post(simple_handler::explain_logs))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES));

    let app = api_routes.nest_service("/", static_files);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

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
async fn analyze_logs(mut multipart: Multipart) -> Response {
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

    // Convert Kibana/CSV exports (e.g. honeypot data) into analyzable events
    let content = security_common::parsers::normalize_upload(content);

    println!("[INFO] Processing log file: {}", filename);

    // Parse logs and analyze
    let mut result = analyze_logs_basic(&content);

    // Enrich IPs with geolocation data
    let all_ip_strings: Vec<String> = result
        .ip_analysis
        .all_ips
        .iter()
        .map(|ip| ip.ip.clone())
        .collect();
    if !all_ip_strings.is_empty() {
        println!(
            "[INFO] Looking up geolocation for {} IPs...",
            all_ip_strings.len()
        );
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
