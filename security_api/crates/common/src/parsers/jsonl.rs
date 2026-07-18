// JSON-lines (NDJSON) log parser
// Handles one JSON object per line, as emitted by most structured loggers
// (e.g. bunyan, pino, zap, logrus, CloudWatch/Datadog exports).

use serde_json::Value;

use crate::LogEntry;
use super::generic::{extract_ip_address, extract_username, infer_log_level};

const TIMESTAMP_KEYS: [&str; 6] = ["timestamp", "@timestamp", "time", "ts", "datetime", "date"];
const LEVEL_KEYS: [&str; 5] = ["level", "severity", "loglevel", "log_level", "lvl"];
const MESSAGE_KEYS: [&str; 4] = ["message", "msg", "event", "description"];
const IP_KEYS: [&str; 6] = ["ip", "ip_address", "client_ip", "remote_addr", "src_ip", "source_ip"];
const USER_KEYS: [&str; 3] = ["user", "username", "account"];

/// Parse a single JSON-object log line into a `LogEntry`.
///
/// Field names are matched against common conventions (`timestamp`/`@timestamp`,
/// `level`/`severity`, `message`/`msg`, `ip`/`remote_addr`, ...). Unknown or
/// missing fields fall back to inference from the message text. Returns `None`
/// for lines that are not a JSON object.
pub fn parse_json_line(line: &str) -> Option<LogEntry> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return None;
    }

    let value: Value = serde_json::from_str(trimmed).ok()?;
    let obj = value.as_object()?;

    let timestamp = TIMESTAMP_KEYS
        .iter()
        .find_map(|k| obj.get(*k))
        .map(json_value_to_string)
        .unwrap_or_default();

    let message = MESSAGE_KEYS
        .iter()
        .find_map(|k| obj.get(*k))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| trimmed.to_string());

    let level = LEVEL_KEYS
        .iter()
        .find_map(|k| obj.get(*k))
        .and_then(|v| v.as_str())
        .map(normalize_level)
        .unwrap_or_else(|| infer_log_level(&message));

    let ip_address = IP_KEYS
        .iter()
        .find_map(|k| obj.get(*k))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| extract_ip_address(&message));

    let username = USER_KEYS
        .iter()
        .find_map(|k| obj.get(*k))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| extract_username(&message));

    Some(LogEntry {
        timestamp,
        level,
        ip_address,
        username,
        message,
    })
}

/// Render a JSON timestamp value (string or epoch number) as a string.
fn json_value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Normalize logger-specific level names onto the common set.
fn normalize_level(raw: &str) -> String {
    let upper = raw.to_uppercase();
    match upper.as_str() {
        "WARNING" => "WARN".to_string(),
        "ERR" => "ERROR".to_string(),
        "CRIT" | "FATAL" | "EMERGENCY" | "PANIC" => "CRITICAL".to_string(),
        _ => upper,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_fields() {
        let line = r#"{"timestamp":"2025-02-20T10:30:45Z","level":"error","message":"Authentication failed","ip":"10.0.0.1","user":"bob"}"#;
        let entry = parse_json_line(line).expect("should parse");
        assert_eq!(entry.timestamp, "2025-02-20T10:30:45Z");
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.message, "Authentication failed");
        assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
        assert_eq!(entry.username, Some("bob".to_string()));
    }

    #[test]
    fn parses_alternate_key_names() {
        let line = r#"{"@timestamp":"2025-02-20T10:30:45Z","severity":"warning","msg":"disk nearly full","remote_addr":"192.0.2.4"}"#;
        let entry = parse_json_line(line).expect("should parse");
        assert_eq!(entry.timestamp, "2025-02-20T10:30:45Z");
        assert_eq!(entry.level, "WARN");
        assert_eq!(entry.message, "disk nearly full");
        assert_eq!(entry.ip_address, Some("192.0.2.4".to_string()));
    }

    #[test]
    fn infers_level_and_ip_from_message() {
        let line = r#"{"time":1719878400,"msg":"Failed password for admin from 203.0.113.9"}"#;
        let entry = parse_json_line(line).expect("should parse");
        assert_eq!(entry.timestamp, "1719878400");
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.ip_address, Some("203.0.113.9".to_string()));
    }

    #[test]
    fn rejects_non_json_lines() {
        assert!(parse_json_line("plain text").is_none());
        assert!(parse_json_line("[1, 2, 3]").is_none());
        assert!(parse_json_line("{not valid json}").is_none());
    }
}
