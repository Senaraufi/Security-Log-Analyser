# Apache Log Parser - Quick Start

## 🚀 Quick Run

```bash
# Test the parser
cd /Users/senaraufi/Desktop/Startup/security_api

# Option 1: Run unit tests
cargo test

# Option 2: Run with test log file
cargo run --example test_parser
```

## 📊 What You'll See

```
🔍 Testing Apache Log Parser
============================================================
📄 Total lines: 20
============================================================

🚨 THREAT DETECTED (Line 4):
   Type: SQL Injection
   Severity: Critical
   IP: 172.16.0.25
   Method: GET /api/users?id=1' UNION SELECT * FROM passwords--

🚨 THREAT DETECTED (Line 5):
   Type: Path Traversal
   Severity: High
   IP: 192.168.1.102
   Method: GET /../../../etc/passwd

[... more threats ...]

============================================================
📊 PARSING SUMMARY
============================================================
✅ Successfully parsed: 20/20
🚨 Suspicious entries: 10

🎯 THREATS BY TYPE:
   SQL Injection - 2 occurrences
   Path Traversal - 1 occurrences
   Cross-Site Scripting - 1 occurrences
   Command Injection - 1 occurrences
   Security Scanner - 1 occurrences
   Unauthorized Access Attempt - 4 occurrences
```

## 🛡️ Threats Detected

| Threat Type | Severity | Example |
|------------|----------|---------|
| SQL Injection | Critical | `?id=1' UNION SELECT` |
| Command Injection | Critical | `cmd=ls;cat /etc/passwd` |
| Path Traversal | High | `/../../../etc/passwd` |
| Cross-Site Scripting | High | `<script>alert('xss')` |
| Security Scanner | Medium | User-Agent: `sqlmap` |
| Unauthorized Access | Medium | Status: `401`, `403` |

## 📁 Files

```
src/parsers/
├── mod.rs          # Module declaration
└── apache.rs       # Parser implementation (300+ lines)

examples/
└── test_parser.rs  # Test program

apache_combined_test.log  # 20 test entries
```

## 🔧 How It Works

1. **Parse** log line into structured data
2. **Analyze** for security threats
3. **Classify** by type and severity
4. **Report** findings

## 📖 Full Documentation

See `WEEK1_WRITEUP.md` for complete technical details.

## ⏭️ Next: Week 2

- Add Claude API integration
- Build security analysis prompts
- Implement LLM-powered correlation
