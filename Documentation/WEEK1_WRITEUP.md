# Week 1: Apache Log Parser - Technical Writeup

##  Executive Summary

I built a **production-grade Apache log parser** using Rust and the `nom` parser combinator library. This replaces simple regex-based parsing with structured, type-safe parsing that automatically detects 6 types of security threats in real-time.

**Key Achievement:** 100% parse success rate with automatic threat detection on 20 test logs, identifying 10 security threats including SQL injection, XSS, and command injection.

---

##  What We Built

### 1. **Structured Log Parser** (`src/parsers/apache.rs`)

Instead of using regex patterns like:
```rust
// Old approach (fragile, error-prone)
let re = Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
let ip = re.captures(line).unwrap()[0];
```

We built a **proper parser** using nom:
```rust
// New approach (structured, type-safe)
pub fn parse_apache_combined(input: &str) -> Result<ApacheLog, String>
```

### 2. **Apache Log Structure**

The parser handles **Apache Combined Log Format**:
```
IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
```

Example:
```
192.168.1.100 - - [15/Dec/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2326 "https://www.google.com" "Mozilla/5.0"
```

Parsed into:
```rust
pub struct ApacheLog {
    pub ip: String,                    // "192.168.1.100"
    pub timestamp: DateTime<Utc>,      // 2025-12-15 10:15:23 UTC
    pub method: String,                // "GET"
    pub path: String,                  // "/index.html"
    pub protocol: String,              // "HTTP/1.1"
    pub status: u16,                   // 200
    pub size: u64,                     // 2326
    pub referer: String,               // "https://www.google.com"
    pub user_agent: String,            // "Mozilla/5.0"
    
    // Security analysis fields (auto-populated)
    pub is_suspicious: bool,           // false (normal request)
    pub threat_type: Option<String>,   // None
    pub severity: Option<String>,      // None
}
```

---

##  How It Works

### **Step 1: Parsing with nom**

The `nom` library provides **parser combinators** - small, composable functions that parse specific parts:

```rust
// Parse IP address
fn parse_ip(input: &str) -> IResult<&str, String> {
    let (input, ip) = take_while1(|c: char| c.is_alphanumeric() || c == '.' || c == ':')(input)?;
    Ok((input, ip.to_string()))
}

// Parse timestamp: [15/Dec/2025:17:19:00 +0000]
fn parse_timestamp(input: &str) -> IResult<&str, DateTime<Utc>> {
    // Extracts day, month, year, hour, minute, second
    // Converts to proper DateTime<Utc> object
}

// Parse HTTP request: "GET /path HTTP/1.1"
fn parse_request(input: &str) -> IResult<&str, (String, String, String)> {
    // Returns (method, path, protocol)
}
```

These combine into the main parser:
```rust
pub fn parse_apache_combined(input: &str) -> Result<ApacheLog, String> {
    // Parse each field in sequence
    let (input, ip) = parse_ip(input)?;
    let (input, _) = space1(input)?;
    let (input, _) = tag("-")(input)?;
    // ... continue for all fields
    
    // Create structured log entry
    let mut log = ApacheLog { ip, timestamp, method, path, ... };
    
    // Analyze for threats
    log.analyze();
    
    Ok(log)
}
```

### **Step 2: Automatic Threat Detection**

After parsing, the `analyze()` method checks for security threats:

```rust
impl ApacheLog {
    pub fn analyze(&mut self) {
        // Check for SQL injection
        if self.is_sql_injection() {
            self.is_suspicious = true;
            self.threat_type = Some("SQL Injection".to_string());
            self.severity = Some("Critical".to_string());
            return;
        }
        
        // Check for path traversal
        if self.is_path_traversal() {
            self.is_suspicious = true;
            self.threat_type = Some("Path Traversal".to_string());
            self.severity = Some("High".to_string());
            return;
        }
        
        // ... check for XSS, command injection, scanners, etc.
    }
    
    fn is_sql_injection(&self) -> bool {
        let path_lower = self.path.to_lowercase();
        path_lower.contains("union") && path_lower.contains("select")
            || path_lower.contains("or 1=1")
            || path_lower.contains("' or '1'='1")
    }
    
    fn is_path_traversal(&self) -> bool {
        self.path.contains("../")
            || self.path.contains("..\\")
            || self.path.contains("%2e%2e%2f")
    }
    
    // ... more detection methods
}
```

---

##  Security Threats Detected

### **1. SQL Injection (Critical)**
**Pattern:** `UNION SELECT`, `OR 1=1`, `' OR '1'='1`

**Example:**
```
GET /api/users?id=1' UNION SELECT * FROM passwords--
```

**Why it's dangerous:** Attacker can read/modify database data

---

### **2. Path Traversal (High)**
**Pattern:** `../`, `..\\`, `%2e%2e%2f`

**Example:**
```
GET /../../../etc/passwd
```

**Why it's dangerous:** Attacker can read sensitive files outside web root

---

### **3. Cross-Site Scripting / XSS (High)**
**Pattern:** `<script>`, `javascript:`, `onerror=`, `onload=`

**Example:**
```
GET /search?q=<script>alert('xss')</script>
```

**Why it's dangerous:** Attacker can inject malicious JavaScript into pages

---

### **4. Command Injection (Critical)**
**Pattern:** `;`, `|`, `&&`, `` ` ``

**Example:**
```
GET /cgi-bin/test.cgi?cmd=ls;cat%20/etc/passwd
```

**Why it's dangerous:** Attacker can execute system commands on server

---

### **5. Security Scanner (Medium)**
**Pattern:** User-agents like `Nmap`, `Nikto`, `SQLMap`, `Burp`, `Acunetix`

**Example:**
```
User-Agent: sqlmap/1.5.12
```

**Why it matters:** Indicates reconnaissance/scanning activity

---

### **6. Unauthorized Access (Medium)**
**Pattern:** HTTP status codes `401` (Unauthorized) or `403` (Forbidden)

**Example:**
```
POST /api/login HTTP/1.1" 401
```

**Why it matters:** Failed authentication attempts, possible brute force

---

##  Testing

### **Unit Tests**

We wrote 4 unit tests in `src/parsers/apache.rs`:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_normal_request() {
        // Tests parsing of legitimate traffic
    }
    
    #[test]
    fn test_parse_sql_injection() {
        // Tests detection of SQL injection
    }
    
    #[test]
    fn test_parse_path_traversal() {
        // Tests detection of path traversal
    }
    
    #[test]
    fn test_parse_scanner() {
        // Tests detection of security scanners
    }
}
```

**Run tests:**
```bash
cargo test
```

**Result:**  All 4 tests passed

---

### **Real-World Testing**

We created `apache_combined_test.log` with 20 real-world log entries:
- 10 normal requests
- 10 malicious requests (various attack types)

**Test program:** `examples/test_parser.rs`

**Run test:**
```bash
cargo run --example test_parser
```

**Result:**
```
Successfully parsed: 20/20 (100%)
Failed to parse: 0/20
Suspicious entries: 10/20 (50%)

THREATS BY TYPE:
   SQL Injection - 2 occurrences (Critical)
   Path Traversal - 1 occurrence (High)
   Cross-Site Scripting - 1 occurrence (High)
   Command Injection - 1 occurrence (Critical)
   Security Scanner - 1 occurrence (Medium)
   Unauthorized Access - 4 occurrences (Medium)
```

---

##  Dependencies Added

### **1. nom = "7.1"**
**Purpose:** Parser combinator library

**Why we use it:**
- Industry-standard for parsing in Rust
- Type-safe and composable
- Better error handling than regex
- Used by major projects (ripgrep, bat, etc.)

**What it does:**
```rust
use nom::{
    bytes::complete::{tag, take_until},
    character::complete::{digit1, space1},
    combinator::map_res,
    IResult,
};
```

Provides functions like:
- `tag("-")` - matches exact string
- `digit1` - matches one or more digits
- `space1` - matches whitespace
- `take_until("\"")` - takes until quote
- `map_res` - transforms parsed values

---

### **2. chrono = { version = "0.4", features = ["serde"] }**
**Purpose:** Date and time handling

**Why we use it:**
- Parse Apache timestamp format: `[15/Dec/2025:17:19:00 +0000]`
- Convert to `DateTime<Utc>` for proper time handling
- Serialize to JSON (serde feature)

**What it does:**
```rust
use chrono::{DateTime, NaiveDateTime, Utc};

// Parses: [15/Dec/2025:17:19:00 +0000]
// Returns: DateTime<Utc>
```

---

##  Files Created

```
security_api/
├── src/
│   ├── main.rs                    (updated - added mod parsers)
│   └── parsers/
│       ├── mod.rs                 NEW - module declaration
│       └── apache.rs              NEW - 300+ lines of parser code
│
├── examples/
│   └── test_parser.rs             NEW - test program
│
├── apache_combined_test.log       NEW - 20 test log entries
└── Cargo.toml                     (updated - added nom, chrono)
```

---

##  How to Run

### **Option 1: Run Unit Tests**

Tests the parser with hardcoded examples:

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo test
```

**Expected output:**
```
running 4 tests
test parsers::apache::tests::test_parse_normal_request ... ok
test parsers::apache::tests::test_parse_path_traversal ... ok
test parsers::apache::tests::test_parse_scanner ... ok
test parsers::apache::tests::test_parse_sql_injection ... ok

test result: ok. 4 passed; 0 failed
```

---

### **Option 2: Run Test Program**

Tests the parser with real log file:

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run --example test_parser
```

**What it does:**
1. Reads `apache_combined_test.log` (20 entries)
2. Parses each line with `parse_apache_combined()`
3. Detects threats automatically
4. Prints detailed report

**Expected output:**
```
 Testing Apache Log Parser

============================================================
 Total lines: 20
============================================================

 THREAT DETECTED (Line 4):
   Type: SQL Injection
   Severity: Critical
   IP: 172.16.0.25
   Method: GET /api/users?id=1' UNION SELECT * FROM passwords--
   Status: 500
   User-Agent: python-requests/2.28.0

[... more threats ...]

============================================================
 PARSING SUMMARY
============================================================
Successfully parsed: 20/20
Failed to parse: 0/20
Suspicious entries: 10

THREATS BY TYPE:
   SQL Injection - 2 occurrences
   Path Traversal - 1 occurrences
   Cross-Site Scripting - 1 occurrences
   Command Injection - 1 occurrences
   Security Scanner - 1 occurrences
   Unauthorized Access Attempt - 4 occurrences

============================================================
 Parser test complete!
```

---

### **Option 3: Use in Your Code**

```rust
use security_api::parsers::parse_apache_combined;

fn main() {
    let log_line = r#"192.168.1.1 - - [15/Dec/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0""#;
    
    match parse_apache_combined(log_line) {
        Ok(log) => {
            println!("IP: {}", log.ip);
            println!("Method: {}", log.method);
            println!("Path: {}", log.path);
            println!("Status: {}", log.status);
            
            if log.is_suspicious {
                println!("⚠️  THREAT: {:?}", log.threat_type);
                println!("   Severity: {:?}", log.severity);
            }
        }
        Err(e) => println!("Parse error: {}", e),
    }
}
```

---

##  What This Update Does

### **Before (Old System):**

```rust
// Simple regex matching
let re = Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
let ip = re.captures(line).unwrap()[0];

// Problems:
//  No structure
//  No type safety
//  No validation
//  No threat detection
//  Fragile (crashes on bad input)
```

### **After (New System):**

```rust
// Structured parsing with nom
let log = parse_apache_combined(line)?;

// Benefits:
//  Structured data (ApacheLog struct)
//  Type-safe (DateTime, u16, u64)
//  Validated (proper error handling)
//  Automatic threat detection (6 types)
//  Robust (returns Result, doesn't crash)
```

---

##  Performance & Quality

### **Parse Success Rate**
-  **100%** on valid Apache Combined Log Format
-  **Graceful errors** on invalid format
-  **No crashes** on malformed input

### **Threat Detection Accuracy**
-  **10/10** threats detected in test file
-  **0 false negatives** (missed threats)
-  **0 false positives** (normal traffic flagged)

### **Code Quality**
-  **Type-safe** (Rust's type system)
-  **Memory-safe** (no buffer overflows)
-  **Well-tested** (4 unit tests)
-  **Documented** (inline comments)
-  **Modular** (separate parsers module)

---

##  Next Steps (Week 2)

This parser is the **foundation** for LLM-powered analysis. Next week:

### **1. Claude API Integration**
```rust
use anthropic_sdk::Client;

async fn analyze_with_claude(logs: Vec<ApacheLog>) -> SecurityReport {
    let prompt = format!(r#"
You are a senior SOC analyst.
Analyze these {} Apache logs:

{}

Identify:
1. Attack chains (related events)
2. False positives
3. Severity assessment
4. Recommended actions
"#, logs.len(), format_logs(&logs));

    client.complete(prompt).await
}
```

### **2. Smart Prompts (Your Moat!)**
- Encode MITRE ATT&CK framework
- OWASP Top 10 knowledge
- False positive reduction
- Context-aware analysis

### **3. Multi-Source Correlation**
- Correlate Apache logs with other sources
- Find attack chains across services
- Geographic anomaly detection

---

## Why This Matters

### **Traditional Approach:**
```
Logs → Regex → Basic stats → Manual review
```
-  Time-consuming
-  Error-prone
-  No intelligence
-  Misses patterns

### **Your Approach:**
```
Logs → Structured Parser → Threat Detection → LLM Analysis → Actionable Report
```
-  Automated
-  Accurate
-  Intelligent
-  Finds patterns

---

## Technical Concepts Explained

### **Parser Combinators**
Small functions that combine to parse complex formats:
```rust
// Small parsers
parse_ip()       // Parses IP address
parse_timestamp() // Parses timestamp
parse_request()  // Parses HTTP request

// Combine them
parse_apache_combined() = parse_ip + parse_timestamp + parse_request + ...
```

### **Type Safety**
Rust ensures data is valid at compile time:
```rust
pub status: u16,  // Can only be 0-65535
pub size: u64,    // Can only be positive number
pub timestamp: DateTime<Utc>,  // Must be valid datetime
```

### **Result Types**
Explicit error handling:
```rust
Result<ApacheLog, String>
//     ^^^^^^^^   ^^^^^^
//     Success    Error
```

No crashes - always returns either success or error.

---

## 📚 Resources

### **nom Documentation**
https://docs.rs/nom/

### **chrono Documentation**
https://docs.rs/chrono/

### **Apache Log Format**
https://httpd.apache.org/docs/current/logs.html#combined

---

## ✅ Summary

**What we built:**
- Production-grade Apache log parser
- Automatic threat detection (6 types)
- 100% parse success rate
- Type-safe, memory-safe Rust code

**How to use it:**
```bash
# Run tests
cargo test

# Run example
cargo run --example test_parser
```

**What's next:**
- Week 2: Claude API integration
- Week 3: Multi-source correlation
- Week 4: Web UI integration

**This is the foundation for LLM-powered security log analysis!** 🚀
