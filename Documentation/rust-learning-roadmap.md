# Rust Learning Roadmap: Security AI Tool

## 🎯 Goal
Build a Rust-based AI security tool that ingests logs, detects threats, and provides AI-powered analysis.

---

## Phase 1: Rust Fundamentals (Weeks 1-3)

### Week 1: Core Concepts
**Resources:**
- 📖 [The Rust Book](https://doc.rust-lang.org/book/) - Chapters 1-6
- 🎥 [Rust Crash Course by Traversy Media](https://www.youtube.com/watch?v=zF34dRivLOw)

**Topics to Master:**
- Variables, mutability, data types
- Functions and control flow
- Ownership, borrowing, and lifetimes (most important!)
- Structs and enums
- Error handling with `Result` and `Option`

**Practice Project:**
```bash
# Build a simple CLI tool that reads a text file and counts words
cargo new word_counter
```

**Key Concepts for Your Project:**
- Understanding `String` vs `&str` (you'll use these constantly for logs)
- Error handling patterns (logs will have parsing errors)
- Structs (you'll define log event structures)

---

### Week 2: Collections & Patterns
**Resources:**
- 📖 The Rust Book - Chapters 7-10
- 🎯 [Rustlings Exercises](https://github.com/rust-lang/rustlings)

**Topics to Master:**
- Vectors, HashMaps, HashSets
- Pattern matching (critical for log parsing)
- Modules and project organization
- Generics and traits

**Practice Project:**
```bash
# Build a log parser that reads a file and extracts IP addresses
cargo new simple_log_parser
```

**Example Code to Practice:**
```rust
use std::collections::HashMap;

struct LogEvent {
    timestamp: String,
    level: String,
    message: String,
}

fn parse_log_line(line: &str) -> Option<LogEvent> {
    // Practice parsing strings
    // Practice error handling
    None
}
```

---

### Week 3: Advanced Concepts
**Resources:**
- 📖 The Rust Book - Chapters 11-15
- 📖 [Rust By Example](https://doc.rust-lang.org/rust-by-example/)

**Topics to Master:**
- Iterators and closures
- Smart pointers (Box, Rc, Arc)
- Testing in Rust
- Cargo and dependencies

**Practice Project:**
```bash
# Build a threat detector that scans logs for suspicious patterns
cargo new threat_detector
```

**Key Dependencies to Learn:**
```toml
[dependencies]
regex = "1.10"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

---

## Phase 2: Async Rust & Networking (Weeks 4-5)

### Week 4: Async Programming
**Resources:**
- 📖 [Async Book](https://rust-lang.github.io/async-book/)
- 🎥 [Tokio Tutorial](https://tokio.rs/tokio/tutorial)

**Topics to Master:**
- `async`/`await` syntax
- Tokio runtime
- Async file I/O
- Channels for message passing

**Practice Project:**
```bash
# Build an async log file watcher that processes logs in real-time
cargo new async_log_watcher
```

**Key Dependencies:**
```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
tokio-stream = "0.1"
```

**Example Pattern:**
```rust
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("logs.txt").await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    while let Some(line) = lines.next_line().await? {
        // Process each log line asynchronously
        println!("{}", line);
    }
    Ok(())
}
```

---

### Week 5: HTTP & APIs
**Resources:**
- 📖 [Reqwest Documentation](https://docs.rs/reqwest/)
- 📖 [Axum Documentation](https://docs.rs/axum/)

**Topics to Master:**
- Making HTTP requests with `reqwest`
- Building REST APIs with `axum`
- JSON serialization/deserialization
- Environment variables for API keys

**Practice Project:**
```bash
# Build a tool that sends log summaries to OpenAI API
cargo new ai_log_analyzer
```

**Key Dependencies:**
```toml
[dependencies]
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.35", features = ["full"] }
```

**Example: OpenAI Integration**
```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

async fn analyze_with_ai(log_summary: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let api_key = std::env::var("OPENAI_API_KEY")?;
    
    let request = OpenAIRequest {
        model: "gpt-4".to_string(),
        messages: vec![
            Message {
                role: "system".to_string(),
                content: "You are a security analyst.".to_string(),
            },
            Message {
                role: "user".to_string(),
                content: log_summary.to_string(),
            },
        ],
    };
    
    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&request)
        .send()
        .await?;
    
    // Parse response...
    Ok("AI analysis result".to_string())
}
```

---

## Phase 3: Security-Specific Skills (Weeks 6-8)

### Week 6: Log Parsing & Normalization
**Resources:**
- 📖 [Nom Parser Combinators](https://github.com/rust-bakery/nom)
- 📖 [Syslog RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)

**Topics to Master:**
- Parsing syslog format
- Parsing JSON logs
- Timestamp normalization
- IP address extraction

**Practice Project:**
```bash
# Build a multi-format log parser (syslog, JSON, CEF)
cargo new universal_log_parser
```

**Key Dependencies:**
```toml
[dependencies]
chrono = "0.4"
regex = "1.10"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
nom = "7.1"
```

**Example: Syslog Parser**
```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct NormalizedLog {
    timestamp: DateTime<Utc>,
    severity: String,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    event_type: String,
    raw_message: String,
}

fn parse_syslog(line: &str) -> Option<NormalizedLog> {
    // Implement syslog parsing
    None
}

fn parse_json_log(line: &str) -> Option<NormalizedLog> {
    // Implement JSON log parsing
    None
}
```

---

### Week 7: Rule Engine & Detection
**Resources:**
- 📖 [Sigma Rules](https://github.com/SigmaHQ/sigma)
- 📖 [Aho-Corasick Algorithm](https://docs.rs/aho-corasick/)

**Topics to Master:**
- Pattern matching for IOCs (IPs, domains, hashes)
- Rule-based detection logic
- Threshold-based alerting
- False positive reduction

**Practice Project:**
```bash
# Build a rule engine that detects common attack patterns
cargo new security_rule_engine
```

**Key Dependencies:**
```toml
[dependencies]
aho-corasick = "1.1"
regex = "1.10"
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
```

**Example: Simple Rule Engine**
```rust
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug)]
struct DetectionRule {
    name: String,
    description: String,
    patterns: Vec<String>,
    severity: String,
}

struct RuleEngine {
    rules: Vec<DetectionRule>,
    known_bad_ips: HashSet<String>,
}

impl RuleEngine {
    fn check_log(&self, log: &NormalizedLog) -> Vec<Alert> {
        let mut alerts = Vec::new();
        
        // Check for brute force attempts
        if log.raw_message.contains("Failed password") {
            alerts.push(Alert {
                rule_name: "Brute Force Attempt".to_string(),
                severity: "High".to_string(),
                description: "Multiple failed login attempts detected".to_string(),
            });
        }
        
        // Check for known bad IPs
        if let Some(ip) = &log.source_ip {
            if self.known_bad_ips.contains(ip) {
                alerts.push(Alert {
                    rule_name: "Known Malicious IP".to_string(),
                    severity: "Critical".to_string(),
                    description: format!("Traffic from known bad IP: {}", ip),
                });
            }
        }
        
        alerts
    }
}

#[derive(Debug)]
struct Alert {
    rule_name: String,
    severity: String,
    description: String,
}
```

---

### Week 8: AI Integration & Prompt Engineering
**Resources:**
- 📖 [OpenAI API Documentation](https://platform.openai.com/docs/)
- 📖 [Anthropic Claude API](https://docs.anthropic.com/)
- 📖 [Prompt Engineering Guide](https://www.promptingguide.ai/)

**Topics to Master:**
- Batching events for AI analysis
- Security-specific prompts
- Structured output from LLMs
- Cost optimization (token usage)

**Practice Project:**
```bash
# Build an AI-powered threat analyzer
cargo new ai_threat_analyzer
```

**Example: Security Analysis Prompt**
```rust
async fn analyze_security_events(events: &[Alert]) -> Result<String, Box<dyn std::error::Error>> {
    let summary = format!(
        "Analyze these security events and provide:\n\
         1. Root cause analysis\n\
         2. Severity assessment\n\
         3. Recommended remediation steps\n\
         4. False positive likelihood\n\n\
         Events:\n{}",
        events.iter()
            .map(|e| format!("- {}: {}", e.rule_name, e.description))
            .collect::<Vec<_>>()
            .join("\n")
    );
    
    // Send to AI API
    let analysis = call_openai_api(&summary).await?;
    Ok(analysis)
}
```

---

## Phase 4: MVP Development (Weeks 9-12)

### Week 9-10: Core Application
**Build the main application:**

```bash
cargo new security_ai_tool
cd security_ai_tool
```

**Project Structure:**
```
security_ai_tool/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point
│   ├── ingest/
│   │   ├── mod.rs
│   │   ├── syslog.rs        # Syslog parser
│   │   ├── json.rs          # JSON log parser
│   │   └── normalizer.rs    # Log normalization
│   ├── detection/
│   │   ├── mod.rs
│   │   ├── rules.rs         # Rule engine
│   │   └── patterns.rs      # Pattern matching
│   ├── ai/
│   │   ├── mod.rs
│   │   ├── client.rs        # AI API client
│   │   └── prompts.rs       # Prompt templates
│   └── output/
│       ├── mod.rs
│       └── formatter.rs     # Output formatting
├── rules/                   # Detection rules (YAML)
└── tests/                   # Integration tests
```

**Cargo.toml:**
```toml
[package]
name = "security_ai_tool"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
chrono = "0.4"
regex = "1.10"
reqwest = { version = "0.11", features = ["json"] }
clap = { version = "4.4", features = ["derive"] }
env_logger = "0.11"
log = "0.4"
anyhow = "1.0"
```

---

### Week 11: Testing & Refinement
**Focus Areas:**
- Unit tests for each module
- Integration tests with sample logs
- Error handling improvements
- Performance optimization

**Example Test:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syslog_parsing() {
        let log = "<134>1 2024-01-15T10:30:00Z host app - - - Failed login attempt";
        let parsed = parse_syslog(log);
        assert!(parsed.is_some());
    }

    #[tokio::test]
    async fn test_ai_integration() {
        let events = vec![
            Alert {
                rule_name: "Test Alert".to_string(),
                severity: "High".to_string(),
                description: "Test description".to_string(),
            }
        ];
        
        let result = analyze_security_events(&events).await;
        assert!(result.is_ok());
    }
}
```

---

### Week 12: CLI & Documentation
**Build a user-friendly CLI:**

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "security-ai")]
#[command(about = "AI-powered security log analyzer", long_about = None)]
struct Cli {
    /// Path to log file or directory
    #[arg(short, long)]
    input: String,
    
    /// Output format (json, text, html)
    #[arg(short, long, default_value = "text")]
    format: String,
    
    /// OpenAI API key (or set OPENAI_API_KEY env var)
    #[arg(long)]
    api_key: Option<String>,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize logger
    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }
    
    // Run the tool
    run_analysis(&cli).await?;
    Ok(())
}
```

---

## 📚 Essential Resources

### Documentation
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust By Example](https://doc.rust-lang.org/rust-by-example/)
- [Rust Standard Library](https://doc.rust-lang.org/std/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)

### Practice Platforms
- [Rustlings](https://github.com/rust-lang/rustlings) - Interactive exercises
- [Exercism Rust Track](https://exercism.org/tracks/rust) - Practice problems
- [Advent of Code](https://adventofcode.com/) - Solve in Rust

### Community
- [Rust Users Forum](https://users.rust-lang.org/)
- [r/rust](https://www.reddit.com/r/rust/)
- [Rust Discord](https://discord.gg/rust-lang)

### Security-Specific
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 🎯 Milestones & Checkpoints

### Milestone 1 (Week 3)
✅ Can write basic Rust programs  
✅ Understand ownership and borrowing  
✅ Can parse text files and extract data  

### Milestone 2 (Week 5)
✅ Can write async Rust code  
✅ Can make HTTP API calls  
✅ Can serialize/deserialize JSON  

### Milestone 3 (Week 8)
✅ Can parse multiple log formats  
✅ Can implement rule-based detection  
✅ Can integrate with AI APIs  

### Milestone 4 (Week 12)
✅ Working MVP that:
- Ingests logs from files
- Detects basic threats
- Sends summaries to AI
- Outputs human-readable reports

---

## 💡 Pro Tips

1. **Don't fight the borrow checker** - It's teaching you memory safety. When stuck, try cloning first, optimize later.

2. **Use `cargo clippy`** - It's like a Rust mentor that suggests better code patterns.

3. **Read error messages carefully** - Rust's compiler errors are extremely helpful and often suggest fixes.

4. **Start simple** - Don't try to build everything at once. Get one log format working first.

5. **Use `anyhow` for errors** - Makes error handling much easier in applications.

6. **Test with real logs** - Download sample logs from GitHub or generate your own.

7. **Join the community** - Rust developers are very helpful. Don't hesitate to ask questions.

8. **Iterate quickly** - Build, test, break, fix. Repeat.

---

## 🚀 Next Steps After MVP

Once you have a working MVP:
1. Add web dashboard (Axum + React/HTMX)
2. Support real-time log streaming
3. Add database for historical analysis (PostgreSQL + SQLx)
4. Implement user authentication
5. Add SIEM integrations (Splunk, Elastic, etc.)
6. Deploy to cloud (Docker + Kubernetes)
7. Add metrics and monitoring

---

## ⏱️ Time Commitment

- **Minimum:** 10-15 hours/week = 3 months to MVP
- **Recommended:** 20-25 hours/week = 6-8 weeks to MVP
- **Intensive:** 40+ hours/week = 4 weeks to MVP

Remember: Learning Rust has a steep initial curve, but it plateaus quickly. Weeks 1-3 are the hardest. After that, you'll be productive.

---

## 🎓 Learning Philosophy

1. **Read → Code → Break → Fix → Repeat**
2. **Build small projects** - Don't just read tutorials
3. **Embrace errors** - They're learning opportunities
4. **Ask for help** - The Rust community is welcoming
5. **Stay consistent** - Daily practice beats weekend marathons

Good luck! You're building something valuable. 🦀🔒
