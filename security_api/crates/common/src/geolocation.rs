// IP Geolocation Module
// Provides real-time IP geolocation lookups using ip-api.com (free, no API key required)
// Supports batch lookups (up to 100 IPs per request) for efficiency

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Result of a geolocation lookup for a single IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoResult {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub is_proxy: bool,
    pub is_hosting: bool,
    pub timezone: Option<String>,
}

impl Default for GeoResult {
    fn default() -> Self {
        Self {
            country: None,
            country_code: None,
            region: None,
            city: None,
            lat: None,
            lon: None,
            isp: None,
            org: None,
            is_proxy: false,
            is_hosting: false,
            timezone: None,
        }
    }
}

/// Response from ip-api.com batch endpoint
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    query: Option<String>,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    isp: Option<String>,
    org: Option<String>,
    proxy: Option<bool>,
    hosting: Option<bool>,
    timezone: Option<String>,
}

/// Check if an IP is a private/reserved address (skip lookups for these)
fn is_private_ip(ip_str: &str) -> bool {
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_unspecified()
        }
        Ok(IpAddr::V6(ipv6)) => ipv6.is_loopback() || ipv6.is_unspecified(),
        Err(_) => true,
    }
}

/// Look up geolocation for a batch of IP addresses
/// Uses ip-api.com batch endpoint (max 100 IPs per request, 45 req/min for free tier)
/// Returns a HashMap mapping IP strings to their GeoResult
pub async fn lookup_batch(ips: &[String]) -> HashMap<String, GeoResult> {
    let mut results: HashMap<String, GeoResult> = HashMap::new();

    // Filter out private IPs
    let public_ips: Vec<&String> = ips
        .iter()
        .filter(|ip| !is_private_ip(ip))
        .collect();

    if public_ips.is_empty() {
        // Return default results for private IPs
        for ip in ips {
            results.insert(ip.clone(), GeoResult {
                country: Some("Private Network".to_string()),
                ..Default::default()
            });
        }
        return results;
    }

    // Build batch request body (ip-api.com accepts up to 100 per batch)
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[WARN] Failed to create HTTP client for geolocation: {}", e);
            return results;
        }
    };

    // Process in chunks of 100 (ip-api.com batch limit)
    for chunk in public_ips.chunks(100) {
        let batch_body: Vec<serde_json::Value> = chunk
            .iter()
            .map(|ip| {
                serde_json::json!({
                    "query": ip,
                    "fields": "status,query,country,countryCode,regionName,city,lat,lon,isp,org,proxy,hosting,timezone"
                })
            })
            .collect();

        match client
            .post("http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,lat,lon,isp,org,proxy,hosting,timezone")
            .json(&batch_body)
            .send()
            .await
        {
            Ok(response) => {
                if let Ok(api_results) = response.json::<Vec<IpApiResponse>>().await {
                    for api_result in api_results {
                        if api_result.status == "success" {
                            if let Some(query_ip) = &api_result.query {
                                results.insert(
                                    query_ip.clone(),
                                    GeoResult {
                                        country: api_result.country,
                                        country_code: api_result.country_code,
                                        region: api_result.region_name,
                                        city: api_result.city,
                                        lat: api_result.lat,
                                        lon: api_result.lon,
                                        isp: api_result.isp,
                                        org: api_result.org,
                                        is_proxy: api_result.proxy.unwrap_or(false),
                                        is_hosting: api_result.hosting.unwrap_or(false),
                                        timezone: api_result.timezone,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[WARN] Geolocation batch lookup failed: {}", e);
            }
        }
    }

    // Fill in private IP entries
    for ip in ips {
        if is_private_ip(ip) {
            results.insert(ip.clone(), GeoResult {
                country: Some("Private Network".to_string()),
                ..Default::default()
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(is_private_ip("not_an_ip"));
    }

    #[test]
    fn test_geo_result_default() {
        let result = GeoResult::default();
        assert!(result.country.is_none());
        assert!(!result.is_proxy);
        assert!(!result.is_hosting);
    }
}
