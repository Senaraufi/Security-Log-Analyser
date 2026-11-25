use chrono::{DateTime, Utc};
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::{char, digit1, space1},
    combinator::map_res,
    sequence::delimited,
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

        // Scanner detection
        if self.is_scanner() {
            self.is_suspicious = true;
            self.threat_type = Some("Security Scanner".to_string());
            self.severity = Some("Medium".to_string());
        }
    }

    /// Weak signal only (never a verdict): the request was refused with 401/403.
    /// Normal traffic produces these constantly, so they are not counted as attacks.
    pub fn is_auth_failure(&self) -> bool {
        self.status == 401 || self.status == 403
    }

    /// Lowercased path variants the rules match against: the raw path and the
    /// URL-decoded path (decoded twice to also catch double encoding).
    fn path_candidates(&self) -> Vec<String> {
        let raw = self.path.to_lowercase();
        let once = percent_decode(&raw);
        let twice = percent_decode(&once);
        let mut out = vec![raw];
        for p in [once, twice] {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    fn is_sql_injection(&self) -> bool {
        self.path_candidates().iter().any(|p| {
            p.contains("union") && p.contains("select")
                || p.contains("or 1=1")
                || p.contains("or '1'='1")
                || p.contains("'; drop table")
                || p.contains("' or '1'='1")
        })
    }

    fn is_path_traversal(&self) -> bool {
        self.path_candidates().iter().any(|p| {
            p.contains("../")
                || p.contains("..\\")
                || p.contains("%2e%2e%2f")
                || p.contains("%2e%2e/")
        })
    }

    fn is_xss(&self) -> bool {
        self.path_candidates().iter().any(|p| {
            p.contains("<script")
                || p.contains("javascript:")
                || p.contains("onerror=")
                || p.contains("onload=")
        })
    }

    fn is_command_injection(&self) -> bool {
        self.path_candidates()
            .iter()
            .any(|p| Self::has_command_injection(p))
    }

    fn has_command_injection(path_lower: &str) -> bool {
        // A shell metacharacter alone is not enough: legitimate URLs often
        // contain ';' or '|' in query strings (e.g. matrix params, filters).
        // Require a chaining/substitution metacharacter *and* an actual shell
        // command token to flag a genuine injection payload.
        let has_metachar = path_lower.contains(';')
            || path_lower.contains('|')
            || path_lower.contains("&&")
            || path_lower.contains('`')
            || path_lower.contains("$(");

        if !has_metachar {
            return false;
        }

        const COMMAND_TOKENS: [&str; 16] = [
            "whoami",
            "netcat",
            "wget",
            "curl",
            "bash",
            "/bin/",
            "/etc/",
            "cat ",
            "cat%20",
            "ls ",
            "ls%20",
            "rm ",
            "rm%20",
            "chmod",
            "cmd.exe",
            "powershell",
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

/// Decode `%XX` escapes and `+` (space). Invalid escapes are kept literally and
/// non-UTF-8 bytes are replaced, so decoding never fails.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit() =>
            {
                out.push(u8::from_str_radix(&input[i + 1..i + 3], 16).unwrap_or(b'%'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    let (input, ts_str) = delimited(char('['), take_until("]"), char(']'))(input)?;

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

    Ok((
        input,
        (method.to_string(), path.to_string(), protocol.to_string()),
    ))
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

/// Parse quoted string (referer or user-agent). Apache escapes embedded quotes
/// and backslashes as `\"` and `\\`, so those must not end the field.
fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    let (rest, _) = char('"')(input)?;
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((&rest[i + 1..], out)),
            '\\' => match chars.next() {
                Some((_, e @ ('"' | '\\'))) => out.push(e),
                Some((_, e)) => {
                    out.push('\\');
                    out.push(e);
                }
                None => break,
            },
            c => out.push(c),
        }
    }
    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Char,
    )))
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

    result
        .map(|(_, log)| log)
        .map_err(|e| format!("Parse error: {}", e))
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

    #[test]
    fn test_url_encoded_sqli_is_detected() {
        let line = r#"10.0.0.2 - - [15/Dec/2025:17:19:00 +0000] "GET /login?user=admin%27%20OR%201%3D1 HTTP/1.1" 200 0 "-" "Mozilla/5.0""#;
        let log = parse_apache_combined(line).unwrap();
        assert!(log.is_suspicious);
        assert_eq!(log.threat_type, Some("SQL Injection".to_string()));
    }

    #[test]
    fn test_plus_encoded_and_double_encoded() {
        let plus = r#"10.0.0.2 - - [15/Dec/2025:17:19:00 +0000] "GET /a?q=1'+UNION+SELECT+pw+FROM+users HTTP/1.1" 200 0 "-" "x""#;
        assert_eq!(
            parse_apache_combined(plus).unwrap().threat_type,
            Some("SQL Injection".to_string())
        );
        let double = r#"10.0.0.2 - - [15/Dec/2025:17:19:00 +0000] "GET /a?f=%252e%252e%252fetc HTTP/1.1" 200 0 "-" "x""#;
        assert_eq!(
            parse_apache_combined(double).unwrap().threat_type,
            Some("Path Traversal".to_string())
        );
    }

    #[test]
    fn test_url_encoded_xss_and_command_injection() {
        let xss = r#"10.0.0.2 - - [15/Dec/2025:17:19:00 +0000] "GET /s?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 0 "-" "x""#;
        assert_eq!(
            parse_apache_combined(xss).unwrap().threat_type,
            Some("Cross-Site Scripting".to_string())
        );
        let cmd = r#"10.0.0.2 - - [15/Dec/2025:17:19:00 +0000] "GET /p?h=1%3Bcat%20/etc/passwd HTTP/1.1" 200 0 "-" "x""#;
        assert_eq!(
            parse_apache_combined(cmd).unwrap().threat_type,
            Some("Command Injection".to_string())
        );
    }

    #[test]
    fn test_401_403_is_not_a_verdict() {
        let line = r#"10.0.0.3 - - [15/Dec/2025:17:19:00 +0000] "GET /private HTTP/1.1" 403 0 "-" "Mozilla/5.0""#;
        let log = parse_apache_combined(line).unwrap();
        assert!(!log.is_suspicious);
        assert!(log.is_auth_failure());
    }

    #[test]
    fn test_percent_decode_edge_cases() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
    }

    #[test]
    fn test_escaped_quotes_in_user_agent() {
        let line = r#"10.0.0.4 - - [15/Dec/2025:17:19:00 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "Mozilla \"ignore previous instructions\" end\\""#;
        let log = parse_apache_combined(line).expect("escaped quotes must parse");
        assert_eq!(
            log.user_agent,
            r#"Mozilla "ignore previous instructions" end\"#
        );
        assert_eq!(log.path, "/index.html");
    }

    #[test]
    fn test_unterminated_user_agent_fails() {
        let line = r#"10.0.0.4 - - [15/Dec/2025:17:19:00 +0000] "GET / HTTP/1.1" 200 5 "-" "oops"#;
        assert!(parse_apache_combined(line).is_err());
    }
}
