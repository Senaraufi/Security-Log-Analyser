use chrono::{DateTime, Utc};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::{char, digit1, space1},
    combinator::map_res,
    sequence::delimited,
    IResult,
};
use serde::{Deserialize, Serialize};

/// Apache Combined Log Format Entry
/// Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApacheLog {
    pub ip: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub size: u64,
    pub referer: String,
    pub user_agent: String,
    
    // Security analysis fields
    pub is_suspicious: bool,
    pub threat_type: Option<String>,
    pub severity: Option<String>,
}

impl ApacheLog {
    /// Analyze log entry for security threats
    pub fn analyze(&mut self) {
        // SQL Injection patterns
        if self.is_sql_injection() {
            self.is_suspicious = true;
            self.threat_type = Some("SQL Injection".to_string());
            self.severity = Some("Critical".to_string());
            return;
        }
        
        // Path Traversal
        if self.is_path_traversal() {
            self.is_suspicious = true;
            self.threat_type = Some("Path Traversal".to_string());
            self.severity = Some("High".to_string());
            return;
        }
        
        // XSS attempts
        if self.is_xss() {
            self.is_suspicious = true;
            self.threat_type = Some("Cross-Site Scripting".to_string());
            self.severity = Some("High".to_string());
            return;
        }
        
        // Command Injection
        if self.is_command_injection() {
            self.is_suspicious = true;
            self.threat_type = Some("Command Injection".to_string());
            self.severity = Some("Critical".to_string());
            return;
        }
        
        // Suspicious status codes
        if self.status == 401 || self.status == 403 {
            self.is_suspicious = true;
            self.threat_type = Some("Unauthorized Access Attempt".to_string());
            self.severity = Some("Medium".to_string());
            return;
        }
        
        // Scanner detection
        if self.is_scanner() {
            self.is_suspicious = true;
            self.threat_type = Some("Security Scanner".to_string());
            self.severity = Some("Medium".to_string());
            return;
        }
    }
    
    fn is_sql_injection(&self) -> bool {
        let path_lower = self.path.to_lowercase();
        path_lower.contains("union") && path_lower.contains("select")
            || path_lower.contains("or 1=1")
            || path_lower.contains("or '1'='1")
            || path_lower.contains("'; drop table")
            || path_lower.contains("' or '1'='1")
    }
    
    fn is_path_traversal(&self) -> bool {
        self.path.contains("../")
            || self.path.contains("..\\")
            || self.path.contains("%2e%2e%2f")
            || self.path.contains("%2e%2e/")
    }
    
    fn is_xss(&self) -> bool {
        let path_lower = self.path.to_lowercase();
        path_lower.contains("<script")
            || path_lower.contains("javascript:")
            || path_lower.contains("onerror=")
            || path_lower.contains("onload=")
    }
    
    fn is_command_injection(&self) -> bool {
        let path_lower = self.path.to_lowercase();

        // A shell metacharacter alone is not enough: legitimate URLs often
        // contain ';' or '|' in query strings (e.g. matrix params, filters).
        // Require a chaining/substitution metacharacter *and* an actual shell
        // command token to flag a genuine injection payload.
        let has_metachar = path_lower.contains(';')
            || path_lower.contains('|')
            || path_lower.contains("&&")
            || path_lower.contains('`')
            || path_lower.contains("$(")
            || path_lower.contains("%3b") // ; encoded
            || path_lower.contains("%7c") // | encoded
            || path_lower.contains("%60"); // ` encoded

        if !has_metachar {
            return false;
        }

        const COMMAND_TOKENS: [&str; 16] = [
            "whoami", "netcat", "wget", "curl", "bash", "/bin/", "/etc/",
            "cat ", "cat%20", "ls ", "ls%20", "rm ", "rm%20", "chmod",
            "cmd.exe", "powershell",
        ];

        COMMAND_TOKENS
            .iter()
            .any(|token| path_lower.contains(token))
    }
    
    fn is_scanner(&self) -> bool {
        let ua_lower = self.user_agent.to_lowercase();
        ua_lower.contains("nmap")
            || ua_lower.contains("nikto")
            || ua_lower.contains("sqlmap")
            || ua_lower.contains("masscan")
            || ua_lower.contains("nessus")
            || ua_lower.contains("burp")
            || ua_lower.contains("acunetix")
    }
}

/// Parse IP address
fn parse_ip(input: &str) -> IResult<&str, String> {
    let (input, ip) = take_while1(|c: char| c.is_alphanumeric() || c == '.' || c == ':')(input)?;
    Ok((input, ip.to_string()))
}

/// Parse timestamp in Apache format: [15/Dec/2025:17:19:00 +0000]
///
/// The timezone offset is honored and the result is normalized to UTC, so a
/// `+0100` log line and a `+0000` log line an hour apart map to the same UTC
/// instant. This is essential for correct forensic timelines. If the timestamp
/// cannot be parsed we fall back to the Unix epoch rather than the current time,
/// so a parse failure can never silently falsify when an event occurred.
fn parse_timestamp(input: &str) -> IResult<&str, DateTime<Utc>> {
    let (input, ts_str) = delimited(
        char('['),
        take_until("]"),
        char(']'),
    )(input)?;

    let datetime = DateTime::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| DateTime::from_timestamp(0, 0).unwrap_or_default());

    Ok((input, datetime))
}

/// Parse HTTP request: "GET /path HTTP/1.1"
fn parse_request(input: &str) -> IResult<&str, (String, String, String)> {
    let (input, _) = char('"')(input)?;
    let (input, method) = take_while1(|c: char| c.is_alphabetic())(input)?;
    let (input, _) = space1(input)?;
    let (input, path) = take_until(" HTTP")(input)?;
    let (input, _) = space1(input)?;
    let (input, protocol) = take_until("\"")(input)?;
    let (input, _) = char('"')(input)?;
    
    Ok((input, (method.to_string(), path.to_string(), protocol.to_string())))
}

/// Parse status code
fn parse_status(input: &str) -> IResult<&str, u16> {
    map_res(digit1, |s: &str| s.parse::<u16>())(input)
}

/// Parse size (can be - or number)
fn parse_size(input: &str) -> IResult<&str, u64> {
    alt((
        map_res(digit1, |s: &str| s.parse::<u64>()),
        map_res(char('-'), |_| Ok::<u64, std::num::ParseIntError>(0)),
    ))(input)
}

/// Parse quoted string (referer or user-agent)
fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    delimited(
        char('"'),
        take_until("\""),
        char('"'),
    )(input)
    .map(|(i, s)| (i, s.to_string()))
}

/// Parse Apache Combined Log Format
/// Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
pub fn parse_apache_combined(input: &str) -> Result<ApacheLog, String> {
    let result: IResult<&str, ApacheLog> = (|| {
        let (input, ip) = parse_ip(input)?;
        let (input, _) = space1(input)?;
        let (input, _) = tag("-")(input)?;
        let (input, _) = space1(input)?;
        let (input, _) = tag("-")(input)?;
        let (input, _) = space1(input)?;
        let (input, timestamp) = parse_timestamp(input)?;
        let (input, _) = space1(input)?;
        let (input, (method, path, protocol)) = parse_request(input)?;
        let (input, _) = space1(input)?;
        let (input, status) = parse_status(input)?;
        let (input, _) = space1(input)?;
        let (input, size) = parse_size(input)?;
        let (input, _) = space1(input)?;
        let (input, referer) = parse_quoted_string(input)?;
        let (input, _) = space1(input)?;
        let (input, user_agent) = parse_quoted_string(input)?;
        
        let mut log = ApacheLog {
            ip,
            timestamp,
            method,
            path,
            protocol,
            status,
            size,
            referer,
            user_agent,
            is_suspicious: false,
            threat_type: None,
            severity: None,
        };
        
        // Analyze for threats
        log.analyze();
        
        Ok((input, log))
    })();
    
    result.map(|(_, log)| log).map_err(|e| format!("Parse error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_normal_request() {
        let line = r#"192.168.1.1 - - [15/Dec/2025:17:19:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0""#;
        let result = parse_apache_combined(line);
        assert!(result.is_ok());
        
        let log = result.unwrap();
        assert_eq!(log.ip, "192.168.1.1");
        assert_eq!(log.method, "GET");
        assert_eq!(log.path, "/index.html");
        assert_eq!(log.status, 200);
        assert_eq!(log.size, 1234);
        assert!(!log.is_suspicious);
    }
    
    #[test]
    fn test_parse_sql_injection() {
        let line = r#"10.0.0.1 - - [15/Dec/2025:17:19:00 +0000] "GET /api/users?id=1' UNION SELECT * FROM passwords-- HTTP/1.1" 200 0 "-" "curl/7.68.0""#;
        let result = parse_apache_combined(line);
        assert!(result.is_ok());
        
        let log = result.unwrap();
        assert!(log.is_suspicious);
        assert_eq!(log.threat_type, Some("SQL Injection".to_string()));
        assert_eq!(log.severity, Some("Critical".to_string()));
    }
    
    #[test]
    fn test_parse_path_traversal() {
        let line = r#"172.16.0.1 - - [15/Dec/2025:17:19:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 0 "-" "Mozilla/5.0""#;
        let result = parse_apache_combined(line);
        assert!(result.is_ok());
        
        let log = result.unwrap();
        assert!(log.is_suspicious);
        assert_eq!(log.threat_type, Some("Path Traversal".to_string()));
    }
    
    #[test]
    fn test_parse_scanner() {
        let line = r#"203.0.113.1 - - [15/Dec/2025:17:19:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Nmap Scripting Engine""#;
        let result = parse_apache_combined(line);
        assert!(result.is_ok());
        
        let log = result.unwrap();
        assert!(log.is_suspicious);
        assert_eq!(log.threat_type, Some("Security Scanner".to_string()));
    }

    #[test]
    fn test_parse_command_injection() {
        let line = r#"198.51.100.7 - - [15/Dec/2025:17:19:00 +0000] "GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 0 "-" "curl/7.68.0""#;
        let result = parse_apache_combined(line);
        assert!(result.is_ok());

        let log = result.unwrap();
        assert!(log.is_suspicious);
        assert_eq!(log.threat_type, Some("Command Injection".to_string()));
        assert_eq!(log.severity, Some("Critical".to_string()));
    }

    #[test]
    fn test_timestamp_timezone_normalized_to_utc() {
        // +0100 means the local wall-clock time is one hour ahead of UTC,
        // so 17:19:00 +0100 must normalize to 16:19:00 UTC.
        let line = r#"192.168.1.1 - - [15/Dec/2025:17:19:00 +0100] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        let log = parse_apache_combined(line).expect("should parse");
        assert_eq!(log.timestamp.to_rfc3339(), "2025-12-15T16:19:00+00:00");

        // A +0000 line at the same wall-clock time stays at 17:19:00 UTC.
        let line_utc = r#"192.168.1.1 - - [15/Dec/2025:17:19:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        let log_utc = parse_apache_combined(line_utc).expect("should parse");
        assert_eq!(log_utc.timestamp.to_rfc3339(), "2025-12-15T17:19:00+00:00");
    }

    #[test]
    fn test_metacharacter_in_url_is_not_command_injection() {
        // Legitimate URL with a ';' matrix parameter must not be flagged.
        let line = r#"192.168.1.50 - - [15/Dec/2025:17:19:00 +0000] "GET /shop/products;jsessionid=A1B2C3?sort=price|asc HTTP/1.1" 200 512 "https://example.com" "Mozilla/5.0""#;
        let result = parse_apache_combined(line);
        assert!(result.is_ok());

        let log = result.unwrap();
        assert!(!log.is_suspicious);
        assert_eq!(log.threat_type, None);
    }
}
