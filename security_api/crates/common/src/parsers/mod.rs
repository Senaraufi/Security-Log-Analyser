// Log Parser Module
// Structured parsers for different log formats

pub mod apache;
pub mod generic;
pub mod jsonl;
pub mod syslog;

pub use apache::{ApacheLog, parse_apache_combined};
pub use generic::parse_generic_log;
pub use jsonl::parse_json_line;
pub use syslog::parse_syslog;

use crate::LogEntry;

/// Unified log parser that tries multiple formats with fallback
/// 
/// Parsing strategy:
/// 1. Try Apache/nginx Combined Log Format (most specific; nginx's default
///    "combined" access-log format is identical to Apache's)
/// 2. Try JSON-lines (one JSON object per line, structured loggers)
/// 3. Try RFC 3164 syslog / auth.log format
/// 4. Try generic structured formats (timestamp + level + message)
/// 5. Fall back to minimal parsing (extract IPs and keywords)
/// 
/// This ensures NO log lines are lost - every line gets analyzed
pub fn parse_log_line_unified(line: &str) -> Option<LogEntry> {
    if line.trim().is_empty() {
        return None;
    }

    // Strategy 1: Try Apache/nginx Combined format first
    if let Ok(apache_log) = parse_apache_combined(line) {
        return Some(LogEntry {
            timestamp: apache_log.timestamp.to_rfc3339(),
            level: if apache_log.status >= 500 {
                "CRITICAL".to_string()
            } else if apache_log.status >= 400 {
                "ERROR".to_string()
            } else {
                "INFO".to_string()
            },
            ip_address: Some(apache_log.ip.clone()),
            username: None,
            message: format!(
                "{} {} - Status: {} - {}",
                apache_log.method,
                apache_log.path,
                apache_log.status,
                apache_log.threat_type.as_deref().unwrap_or("Normal")
            ),
        });
    }

    // Strategy 2: JSON-lines (structured loggers)
    if let Some(entry) = parse_json_line(line) {
        return Some(entry);
    }

    // Strategy 3: RFC 3164 syslog / auth.log
    if let Some(entry) = parse_syslog(line) {
        return Some(entry);
    }

    // Strategy 4 & 5: Use generic parser with fallback
    parse_generic_log(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_dispatches_nginx_combined_to_apache_parser() {
        // nginx's default "combined" format is identical to Apache's.
        let line = r#"203.0.113.10 - - [15/Dec/2025:17:19:00 +0000] "GET /api/health HTTP/1.1" 200 15 "-" "kube-probe/1.28""#;
        let entry = parse_log_line_unified(line).expect("should parse");
        assert_eq!(entry.ip_address, Some("203.0.113.10".to_string()));
        assert_eq!(entry.level, "INFO");
    }

    #[test]
    fn unified_dispatches_json_lines() {
        let line = r#"{"timestamp":"2025-02-20T10:30:45Z","level":"error","message":"Authentication failed","ip":"10.0.0.1"}"#;
        let entry = parse_log_line_unified(line).expect("should parse");
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn unified_dispatches_syslog() {
        let line = "Feb 20 10:30:45 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2";
        let entry = parse_log_line_unified(line).expect("should parse");
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.username, Some("root".to_string()));
        assert_eq!(entry.ip_address, Some("203.0.113.5".to_string()));
    }

    #[test]
    fn unified_falls_back_to_generic() {
        let line = "2025-02-20 10:30:45 [ERROR] Failed login from 192.168.1.100";
        let entry = parse_log_line_unified(line).expect("should parse");
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.ip_address, Some("192.168.1.100".to_string()));
    }
}
