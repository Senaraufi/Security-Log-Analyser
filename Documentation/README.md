# Security Log Analyzer with AI-Powered Threat Intelligence

> **Production-grade security log analysis powered by Claude AI and Rust**

A comprehensive security log analyzer that combines pattern-based threat detection with AI-powered analysis to provide expert-level security insights.

---

## 🚀 Quick Start

### 1. Start the Server

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run --release
```

You should see:
```
🚀 Security API Server running on http://localhost:3000
📊 Upload logs at: http://localhost:3000
```

### 2. Open Web Interface

Navigate to: **http://localhost:3000**

### 3. Analyze Logs

1. Click **"📁 Choose Log File"**
2. Select your log file (`.txt` or `.log`)
3. Choose analysis mode:
   - **Standard Analysis** - Fast pattern-based detection
   - **AI Analysis** - Claude-powered expert analysis
4. View comprehensive security report

---

## ✨ Features

### Core Capabilities
- **🔍 Multi-Format Parser** - Apache Combined, Common, and custom formats
- **🤖 AI-Powered Analysis** - Claude 3.5 Sonnet integration
- **⚡ Real-time Detection** - Instant threat identification
- **🗄️ Database Integration** - MySQL storage for historical analysis
- **📊 Beautiful Web UI** - Modern, responsive dashboard
- **🔌 RESTful API** - Programmatic access

### Threat Detection (7 Types)
1. **SQL Injection** - UNION SELECT, OR 1=1, DROP TABLE
2. **XSS Attacks** - `<script>`, `javascript:`
3. **Path Traversal** - `../`, `/etc/passwd`
4. **Scanner Activity** - nmap, port scans
5. **Failed Logins** - Brute force indicators
6. **Root Access Attempts** - Privilege escalation
7. **Suspicious File Access** - Sensitive system files

### AI Analysis Features
- **Executive Summary** - High-level threat overview
- **Attack Chain Detection** - Correlates related events
- **MITRE ATT&CK Mapping** - Industry-standard framework
- **Confidence Scoring** - Reliability indicators
- **Actionable Recommendations** - Specific remediation steps

### CVSS 3.1 Scoring
- **Industry-Standard Severity** - CVSS 3.1 scores for all threats
- **Individual Threat Scores** - Each threat type has specific CVSS rating
- **Aggregate Risk Score** - Overall security posture assessment
- **Vector Strings** - Detailed CVSS metrics (AV:N/AC:L/PR:N/etc.)
- **Severity Levels** - None, Low, Medium, High, Critical

---

## 🛠️ Tech Stack

- **Backend:** Rust (Axum framework)
- **AI:** Claude 3.5 Sonnet (Anthropic API)
- **Database:** MySQL with SQLx
- **Parser:** Universal log parser with regex
- **Frontend:** HTML/CSS/JavaScript
- **Async Runtime:** Tokio

---

## 📊 API Endpoints

### `GET /`
Web interface (HTML dashboard)

### `POST /api/analyze`
Analyze uploaded log file

**Request:**
```bash
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@apache_logs.txt" \
  -F "mode=standard"  # or "ai"
```

**Response:**
```json
{
  "threat_statistics": {
    "sql_injection": 5,
    "failed_logins": 10,
    "root_attempts": 2,
    "suspicious_file_access": 1,
    "cvss_scores": [
      {
        "threat_type": "SQL Injection",
        "count": 5,
        "cvss_score": 9.8,
        "severity": "Critical",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "explanation": "Network-accessible SQL injection..."
      },
      {
        "threat_type": "Failed Login",
        "count": 10,
        "cvss_score": 5.3,
        "severity": "Medium",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "explanation": "Potential brute force attack..."
      }
    ]
  },
  "ip_analysis": {
    "high_risk_ips": [
      {"ip": "192.168.1.100", "count": 15, "risk_level": "high"}
    ]
  },
  "risk_assessment": {
    "level": "HIGH",
    "total_threats": 18,
    "cvss_aggregate_score": 10.0,
    "cvss_severity": "Critical"
  }
}
```

---

## 🎯 Risk Levels

| Threat Score | Risk Level | Action Required |
|-------------|------------|------------------|
| 80-100 | 🔴 **CRITICAL** | Immediate action required |
| 60-79 | 🟠 **HIGH** | Urgent attention needed |
| 40-59 | 🟡 **MEDIUM** | Monitor closely |
| 20-39 | 🟢 **LOW** | Routine monitoring |
| 0-19 | ⚪ **MINIMAL** | Normal activity |

---

## 📁 Project Structure

```
Startup/
├── security_api/          # Main application
│   ├── src/
│   │   ├── main.rs       # Web server & routes
│   │   ├── database/     # MySQL integration
│   │   ├── llm/          # Claude AI integration
│   │   └── parsers/      # Log parsing engines
│   ├── examples/         # Test programs
│   ├── static/           # Web UI
│   └── .env              # Configuration
├── log_parser/           # Original parser project
└── Documentation/        # This folder
```

---

## 🔧 Configuration

Create `.env` file in `security_api/`:

```bash
# Claude AI (Required for AI analysis)
ANTHROPIC_API_KEY=sk-ant-...

# Database (Optional - app works without it)
DATABASE_URL=mysql://root:password@localhost:3306/security_LogsDB

# Server
RUST_LOG=info
```

---

## 🧪 Testing

See **SETUP_AND_TESTING.md** for comprehensive testing guide.

**Quick Test:**
```bash
# Interactive demo
cargo run --example demo_analyzer

# Test with sample logs
cargo run --example test_llm_analyzer
```

---

## 📚 Documentation

- **README.md** (this file) - Project overview and quick start
- **TECHNICAL_GUIDE.md** - Architecture and implementation details
- **SETUP_AND_TESTING.md** - Setup, testing, and troubleshooting

---

## 🎓 Learning Resources

This project demonstrates:
- ✅ Production Rust web development
- ✅ AI/LLM integration patterns
- ✅ Database design and queries
- ✅ Security analysis techniques
- ✅ RESTful API design
- ✅ Async programming with Tokio

---

## 🚀 Development Status

- ✅ **Week 1** - Production-grade parser with threat detection
- ✅ **Week 2** - Claude API integration and AI analysis
- 🔄 **Week 3-4** - Full integration and enhanced UI

---

## 📝 License

Private project - All rights reserved

---

**Built with Rust 🦀 | Powered by Claude AI 🤖 | Secured by Design 🔒**
