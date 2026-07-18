// RFC 3164-style syslog / auth.log parser
// Handles lines like:
//   Feb 20 10:30:45 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
//   Feb 20 10:30:45 myhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; COMMAND=/bin/ls

use regex::Regex;

use crate::LogEntry;
use super::generic::{extract_ip_address, infer_log_level};

/// Parse an RFC 3164-style syslog line (classic syslog / auth.log format).
///
/// The syslog timestamp carries no year or timezone, so it is preserved
/// verbatim rather than being converted to a (possibly wrong) absolute time.
pub fn parse_syslog(line: &str) -> Option<LogEntry> {
    let re = Regex::new(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Za-z0-9_./-]+)(?:\[(\d+)\])?:\s+(.+)$",
    )
    .ok()?;

    let caps = re.captures(line)?;
    let timestamp = caps.get(1)?.as_str().to_string();
    let hostname = caps.get(2)?.as_str();
    let process = caps.get(3)?.as_str();
    let body = caps.get(5)?.as_str();

    let message = format!("{} {}: {}", hostname, process, body);
    let level = infer_log_level(body);
    let ip_address = extract_ip_address(body);
    let username = extract_syslog_username(body);

    Some(LogEntry {
        timestamp,
        level,
        ip_address,
        username,
        message,
    })
}

/// Extract usernames from common sshd/auth.log message shapes:
/// - "Failed password for root from ..."
/// - "Failed password for invalid user admin from ..."
/// - "Invalid user admin from ..."
/// - "Accepted publickey for deploy from ..."
/// - "sudo: alice : TTY=..."
fn extract_syslog_username(body: &str) -> Option<String> {
    let patterns = [
        r"(?:Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?([A-Za-z0-9_.-]+)",
        r"[Ii]nvalid user\s+([A-Za-z0-9_.-]+)",
        r"^([A-Za-z0-9_.-]+)\s+:",
        r"user[=\s]+([A-Za-z0-9_.-]+)",
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(body) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sshd_failed_password() {
        let line = "Feb 20 10:30:45 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2";
        let entry = parse_syslog(line).expect("should parse");
        assert_eq!(entry.timestamp, "Feb 20 10:30:45");
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.ip_address, Some("203.0.113.5".to_string()));
        assert_eq!(entry.username, Some("root".to_string()));
        assert!(entry.message.contains("sshd"));
    }

    #[test]
    fn parses_invalid_user() {
        let line = "Feb  3 04:05:06 web01 sshd[999]: Invalid user admin from 198.51.100.7 port 51234";
        let entry = parse_syslog(line).expect("should parse");
        assert_eq!(entry.username, Some("admin".to_string()));
        assert_eq!(entry.ip_address, Some("198.51.100.7".to_string()));
    }

    #[test]
    fn parses_process_without_pid() {
        let line = "Feb 20 10:30:45 myhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; COMMAND=/bin/ls";
        let entry = parse_syslog(line).expect("should parse");
        assert_eq!(entry.username, Some("alice".to_string()));
        assert!(entry.message.contains("sudo"));
    }

    #[test]
    fn rejects_non_syslog_lines() {
        assert!(parse_syslog("2025-02-20 10:30:45 [ERROR] something").is_none());
        assert!(parse_syslog(r#"{"level":"error"}"#).is_none());
        assert!(parse_syslog("plain text with no structure").is_none());
    }
}
