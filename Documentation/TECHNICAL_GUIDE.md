# Technical Guide - Architecture & Implementation

> **Deep dive into the security log analyzer's architecture, design patterns, and implementation details**

---

## 📐 System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      WEB INTERFACE                          │
│              (HTML/CSS/JavaScript)                          │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP POST
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   AXUM WEB SERVER                           │
│                  (Rust Backend)                             │
└────────────────────────┬────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌─────────┐    ┌──────────┐   ┌──────────┐
    │ PARSER  │    │   LLM    │   │ DATABASE │
    │ ENGINE  │    │ ANALYZER │   │  LAYER   │
    └─────────┘    └──────────┘   └──────────┘
          │              │              │
          ▼              ▼              ▼
    Parse Logs    Claude API      MySQL Storage
```

### Request Flow

```
1. User uploads log file
   ↓
2. Server receives multipart/form-data
   ↓
3. Parser extracts structured data
   ↓
4. Threat detection (pattern matching)
   ↓
5. [Optional] Claude AI analysis
   ↓
6. [Optional] Save to database
   ↓
7. Return JSON response
   ↓
8. Frontend displays results
```

---

## 🔍 Parser Architecture

### Universal Log Parser

The parser supports multiple log formats through a unified interface:

**Supported Formats:**
- Apache Combined Log Format
- Apache Common Log Format
- Custom structured formats

**Parser Flow:**
```
Raw Log Line
    ↓
Regex Pattern Matching
    ↓
Extract Components:
  - Timestamp
  - IP Address
  - HTTP Method
  - Request Path
  - Status Code
  - User Agent
    ↓
Threat Detection
    ↓
Structured LogEntry
```

### Threat Detection Rules

**7 Detection Categories:**

1. **SQL Injection**
   - Patterns: `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `--`, `/**/`
   - Severity: Critical

2. **XSS (Cross-Site Scripting)**
   - Patterns: `<script>`, `javascript:`, `onerror=`, `onload=`
   - Severity: High

3. **Path Traversal**
   - Patterns: `../`, `..\\`, `/etc/passwd`, `/etc/shadow`
   - Severity: High

4. **Scanner Activity**
   - Patterns: `nmap`, `nikto`, `sqlmap`, unusual user-agents
   - Severity: Medium

5. **Failed Logins**
   - Patterns: Status 401, 403, "Failed login"
   - Severity: Medium (High if repeated)

6. **Root Access Attempts**
   - Patterns: `user: root`, `admin`, privileged paths
   - Severity: High

7. **Suspicious File Access**
   - Patterns: System files, config files, credentials
   - Severity: High

### IP Analysis

**Tracking:**
- Frequency counting with HashMap
- High-risk threshold: 3+ occurrences
- Correlation with threat types

**Risk Scoring:**
```rust
let risk_score = 
    (sql_injection * 10) +
    (xss_attempts * 8) +
    (path_traversal * 8) +
    (scanner_activity * 5) +
    (failed_logins * 3) +
    (root_attempts * 9) +
    (suspicious_file_access * 7);
```

---

## 🤖 Claude AI Integration

### How It Works

**1. Prompt Engineering**

The system uses carefully crafted prompts to guide Claude:

```
┌─────────────────────────────────────────────────────────────┐
│ ROLE DEFINITION                                             │
│ "You are a senior SOC analyst with 10+ years experience"   │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ CONTEXT & FRAMEWORK                                         │
│ - MITRE ATT&CK Framework                                    │
│ - OWASP Top 10                                              │
│ - Industry best practices                                   │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ LOG DATA                                                    │
│ Parsed, structured log entries                             │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ ANALYSIS INSTRUCTIONS                                       │
│ - Identify attack patterns                                  │
│ - Correlate events                                          │
│ - Assess severity                                           │
│ - Provide recommendations                                   │
└─────────────────────────────────────────────────────────────┘
```

**2. Request Structure**

```rust
// Simplified example
let prompt = format!(
    "You are a senior SOC analyst. Analyze these logs:\n\n{}\n\n\
     Look for:\n\
     - SQL Injection (MITRE T1190)\n\
     - XSS (OWASP A03)\n\
     - Path Traversal\n\n\
     Provide:\n\
     1. Executive summary\n\
     2. Threat level\n\
     3. Key findings with confidence scores\n\
     4. Actionable recommendations",
    formatted_logs
);
```

**3. Response Parsing**

Claude returns structured JSON:
```json
{
  "summary": "Executive summary...",
  "threat_level": "Critical|High|Medium|Low",
  "findings": [
    {
      "attack_type": "SQL Injection",
      "severity": "Critical",
      "confidence": 0.95,
      "description": "...",
      "affected_resources": ["/api/users"],
      "indicators": ["UNION SELECT", "-- comment"]
    }
  ],
  "attack_chains": [...],
  "recommendations": [...]
}
```

### Why Prompts Are Critical

**Without Expert Prompts:**
- Generic analysis
- Missed context
- No actionable insights

**With Expert Prompts:**
- SOC-analyst-level insights
- Industry framework alignment
- Specific, actionable recommendations
- Confidence scoring
- Attack chain detection

---

## 🗄️ Database Architecture

### Schema Design

**Tables:**

1. **`log_uploads`** - Upload metadata
   - filename, size, upload_date
   - total_lines, parsed_lines, failed_lines
   - processing_time

2. **`analysis_results`** - Standard analysis
   - risk_level, threat_score
   - Threat counts by type
   - Format quality metrics

3. **`ai_analysis`** - Claude analysis
   - summary, threat_level
   - confidence_score
   - processing_time

4. **`ai_findings`** - Individual threats
   - attack_type, severity
   - confidence, description
   - affected_resources

5. **`ai_recommendations`** - Action items
   - priority, category
   - recommendation text

6. **`detected_threats`** - Specific threats
   - threat_type, severity
   - log_entry, timestamp

7. **`ip_analysis`** - IP behavior
   - ip_address, occurrence_count
   - risk_level, threat_types

8. **`threat_patterns`** - Learning table
   - pattern, threat_type
   - detection_count, false_positive_rate

### Query Patterns

**Save Analysis:**
```rust
sqlx::query!(
    "INSERT INTO log_uploads (...) VALUES (...)",
    filename, size, total_lines, ...
).execute(&pool).await?;
```

**Retrieve History:**
```rust
sqlx::query_as!(
    AnalysisRecord,
    "SELECT * FROM analysis_results 
     WHERE upload_date > ? 
     ORDER BY threat_score DESC",
    cutoff_date
).fetch_all(&pool).await?;
```

---

## 🔧 Key Rust Concepts

### 1. Option<T> for Missing Data

```rust
struct LogEntry {
    timestamp: String,
    ip_address: Option<String>,  // May not exist
    username: Option<String>,    // May not exist
    message: String,
}

// Safe handling
if let Some(ip) = &entry.ip_address {
    // Use IP
}
```

### 2. Result<T, E> for Error Handling

```rust
fn parse_log(line: &str) -> Result<LogEntry, ParseError> {
    let re = Regex::new(PATTERN)?;
    let caps = re.captures(line)
        .ok_or(ParseError::NoMatch)?;
    Ok(LogEntry { ... })
}
```

### 3. HashMap for Frequency Tracking

```rust
let mut ip_frequency: HashMap<String, usize> = HashMap::new();

// Efficient counting
ip_frequency.entry(ip.clone())
    .and_modify(|count| *count += 1)
    .or_insert(1);
```

### 4. Async/Await with Tokio

```rust
#[tokio::main]
async fn main() {
    let analyzer = ClaudeAnalyzer::new();
    let result = analyzer.analyze_logs(logs).await?;
}
```

### 5. Trait-Based Design

```rust
#[async_trait]
pub trait LLMAnalyzer {
    async fn analyze_logs(&self, logs: Vec<LogEntry>) 
        -> Result<AnalysisReport, LLMError>;
}

impl LLMAnalyzer for ClaudeAnalyzer { ... }
impl LLMAnalyzer for MockAnalyzer { ... }
```

---

## 🎨 Regex Patterns

### Apache Combined Log Format

```regex
(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) 
- - 
\[(?P<timestamp>[^\]]+)\] 
"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[^"]+" 
(?P<status>\d{3}) 
(?P<size>\d+|-) 
"[^"]*" 
"(?P<user_agent>[^"]*)"
```

**Breakdown:**
- `(?P<ip>...)` - Named capture group for IP
- `\d{1,3}` - 1-3 digits
- `[^\]]+` - Any character except ]
- `\w+` - Word characters (method)
- `[^\s]+` - Non-whitespace (path)

### IP Address Pattern

```regex
\b(?:\d{1,3}\.){3}\d{1,3}\b
```

**Matches:** `192.168.1.100`, `10.0.0.1`

### SQL Injection Pattern

```regex
(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table)
```

**Flags:** `(?i)` - Case insensitive

---

## 🔐 Security Considerations

### API Key Management
- ✅ Stored in `.env` file
- ✅ `.env` in `.gitignore`
- ✅ Never hardcoded
- ✅ Environment variable access only

### Database Security
- ✅ Prepared statements (SQLx)
- ✅ Connection pooling
- ✅ Password not in code
- ✅ Graceful degradation if unavailable

### Input Validation
- ✅ File size limits
- ✅ File type validation
- ✅ Sanitized error messages
- ✅ No raw log data in responses

---

## 📊 Performance Optimization

### Parser Performance
- **Compiled regex patterns** - Reused, not recreated
- **Streaming processing** - Line-by-line, not loading entire file
- **Early returns** - Skip invalid lines quickly

### Database Performance
- **Connection pooling** - Reuse connections
- **Batch inserts** - Multiple records at once
- **Indexed columns** - Fast queries on common fields

### API Efficiency
- **Async processing** - Non-blocking I/O
- **Tokio runtime** - Efficient task scheduling
- **Streaming responses** - Start sending before complete

---

## 🧪 Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_apache_combined() {
        let line = "192.168.1.1 - - [15/Dec/2025:10:15:23 +0000] ...";
        let result = parse_apache_combined(line);
        assert!(result.is_ok());
    }
}
```

### Integration Tests
- `examples/demo_analyzer.rs` - Interactive demo
- `examples/test_llm_analyzer.rs` - Mock AI test
- `examples/test_database.rs` - Database integration

### Manual Testing
- Sample log files with known threats
- Edge cases (malformed logs)
- Performance testing (large files)

---

## 🚀 Deployment Considerations

### Production Checklist
- [ ] Set `RUST_LOG=info` (not debug)
- [ ] Use `cargo build --release`
- [ ] Configure database connection pooling
- [ ] Set API rate limits
- [ ] Enable HTTPS
- [ ] Add request logging
- [ ] Set up monitoring
- [ ] Configure backups

### Scaling Strategies
- **Horizontal:** Multiple server instances
- **Vertical:** Increase server resources
- **Database:** Read replicas for queries
- **Caching:** Redis for frequent queries
- **Queue:** Background job processing

---

## 📝 Code Organization

### Module Structure

```
src/
├── main.rs              # Entry point, web server
├── database/
│   ├── mod.rs          # Database module
│   ├── models.rs       # Data structures
│   └── queries.rs      # SQL queries
├── llm/
│   ├── mod.rs          # LLM module
│   ├── analyzer.rs     # Claude integration
│   ├── mock.rs         # Mock analyzer
│   └── prompts.rs      # Prompt templates
└── parsers/
    ├── mod.rs          # Parser module
    ├── apache.rs       # Apache log parser
    └── universal.rs    # Universal parser
```

### Design Patterns

**1. Trait-based polymorphism**
- `LLMAnalyzer` trait for different AI providers
- Easy to add OpenAI, local models, etc.

**2. Builder pattern**
- Prompt construction
- Query building

**3. Repository pattern**
- Database abstraction
- Testable without real database

---

## 🎓 Learning Path

### Beginner Concepts (Covered)
- ✅ Structs and enums
- ✅ Pattern matching
- ✅ Error handling (Option, Result)
- ✅ String operations
- ✅ Vectors and iteration

### Intermediate Concepts (Covered)
- ✅ HashMap and collections
- ✅ Regex patterns
- ✅ Async/await
- ✅ Traits and generics
- ✅ Module organization

### Advanced Concepts (Covered)
- ✅ Async trait objects
- ✅ Database connection pooling
- ✅ HTTP server with Axum
- ✅ External API integration
- ✅ Error propagation with ?

---

## 🔮 Future Enhancements

### Planned Features
1. **Real-time monitoring** - WebSocket streaming
2. **Multiple AI providers** - OpenAI, local models
3. **Advanced correlation** - Time-series analysis
4. **Machine learning** - Pattern learning
5. **Alerting system** - Email/Slack notifications
6. **Dashboard analytics** - Historical trends
7. **Export functionality** - PDF/CSV reports
8. **User authentication** - Multi-tenant support

### Technical Debt
- Add comprehensive error types
- Improve test coverage (>80%)
- Add benchmarks
- Document all public APIs
- Add OpenAPI/Swagger spec

---

**Last Updated:** January 2026  
**Version:** 0.3.0  
**Status:** Production-ready core, active development
