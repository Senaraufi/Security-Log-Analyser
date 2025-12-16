# 🔒 Security Log Analyzer with AI-Powered Threat Intelligence

A production-grade Rust application that analyzes Apache web server logs using pattern-based threat detection and optional Claude AI-powered deep analysis.

## 🎯 Project Status

- ✅ **Week 1 Complete**: Production-grade Apache log parser with threat detection
- ✅ **Week 2 Complete**: Claude API integration with web interface
- 🔄 **Week 3-4 Planned**: Full UI integration and polish

---

## 🚀 Quick Start

### Prerequisites
- Rust (latest stable)
- Claude API key (optional - can use mock mode)

### Setup

1. **Clone and navigate to project**
```bash
cd /Users/senaraufi/Desktop/Startup/security_api
```

2. **Configure API key** (optional)
```bash
# Copy example env file
cp .env.example .env

# Edit .env and add your API key
# ANTHROPIC_API_KEY=your_key_here
# USE_MOCK_ANALYZER=false  # Set to true for testing without API
```

3. **Run the server**
```bash
cargo run
```

4. **Open the dashboard**
```
http://localhost:3000
```

---

## 📖 Features

### ✅ Implemented

#### **Apache Log Parser**
- Parser combinator-based parsing (nom library)
- Handles Apache Combined Log Format
- Type-safe data structures
- Comprehensive error handling

#### **Threat Detection**
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Path Traversal detection
- Command Injection detection
- Security Scanner detection
- Unauthorized Access detection

#### **Claude AI Analysis** (Optional)
- Executive summaries
- Threat level assessment
- Detailed findings with confidence scores
- Attack chain correlation
- Indicators of Compromise (IOCs)
- Expert recommendations
- MITRE ATT&CK mapping
- OWASP Top 10 coverage

#### **Web Dashboard**
- File upload interface
- Real-time analysis
- Threat statistics visualization
- IP analysis with VPN detection
- Security alerts
- CSV export
- AI analysis on-demand

---

## 🧪 Testing

### Run Unit Tests
```bash
cargo test
```

### Test Parser
```bash
cargo run --example test_parser
```

### Interactive Demo
```bash
cargo run --example demo_analyzer
```

### Test with Mock AI (No API key needed)
```bash
# Set USE_MOCK_ANALYZER=true in .env
cargo run --example test_llm_analyzer
```

---

## 📁 Project Structure

```
security_api/
├── src/
│   ├── main.rs              # Web server and API endpoints
│   ├── parsers/
│   │   ├── mod.rs
│   │   └── apache.rs        # Apache log parser
│   └── llm/
│       ├── mod.rs
│       ├── analyzer.rs      # Claude API integration
│       ├── prompts.rs       # Security analysis prompts
│       └── mock.rs          # Mock analyzer for testing
├── examples/
│   ├── test_parser.rs       # Parser testing
│   ├── test_llm_analyzer.rs # LLM testing (mock mode)
│   └── demo_analyzer.rs     # Interactive demo
├── apache_combined_test.log # Sample log file
├── .env.example             # Environment variables template
└── README.md                # This file
```

---

## 🔧 Configuration

### Environment Variables (.env)

```bash
# Claude API Configuration
ANTHROPIC_API_KEY=your_api_key_here
CLAUDE_MODEL=claude-3-5-sonnet-20241022

# Mock Mode (for testing without API)
USE_MOCK_ANALYZER=false  # Set to true to test without API costs
```

---

## 🌐 API Endpoints

### `GET /`
Serves the web dashboard

### `POST /api/analyze`
Basic log analysis with pattern matching
- **Input**: Multipart form data with log file
- **Output**: JSON with threat statistics, IP analysis, alerts

### `POST /api/analyze-with-ai`
AI-powered deep analysis using Claude
- **Input**: Multipart form data with log file
- **Output**: JSON with AI analysis report

---

## 📊 How It Works

### 1. Upload Logs
Upload Apache Combined Log Format files through the web interface

### 2. Basic Analysis (Automatic)
- Parses each log line
- Detects threats using pattern matching
- Generates statistics and alerts

### 3. AI Analysis (On-Demand)
- Click "Analyze with Claude AI" button
- Sends parsed logs to Claude API
- Receives expert-level security analysis
- Displays findings, recommendations, and IOCs

---

## 🎓 Key Concepts

### Prompts
The prompts in `src/llm/prompts.rs` are the competitive advantage. They:
- Define Claude's role as a senior security analyst
- Specify analysis frameworks (MITRE ATT&CK, OWASP Top 10)
- Teach attack pattern recognition
- Structure the output format
- Ensure consistent, expert-level analysis

### Mock Mode
Use `USE_MOCK_ANALYZER=true` to:
- Test without API costs
- Develop offline
- Demonstrate functionality
- Validate integration

---

## 💰 API Costs

Claude API usage (approximate):
- Small file (20 lines): $0.01-0.02
- Medium file (100 lines): $0.05-0.10
- Large file (1000+ lines): $0.50-1.00

Use mock mode for development to avoid costs.

---

## 🐛 Troubleshooting

### "API error 400 Bad Request: credit balance too low"
- Add credits to your Anthropic account
- Or enable mock mode: `USE_MOCK_ANALYZER=true`

### Server won't start
```bash
# Check if port 3000 is in use
lsof -ti:3000

# Kill existing process
lsof -ti:3000 | xargs kill -9

# Restart
cargo run
```

### AI button doesn't appear
- Check browser console for errors
- Ensure basic analysis completed successfully
- Refresh the page

---

## 📚 Additional Documentation

- **HOW_CLAUDE_WORKS.md** - Detailed explanation of AI analysis flow
- **HOW_TO_TEST.md** - Comprehensive testing guide
- **PROJECT_SPECIFICATION.txt** - Full technical specification (in parent directory)

---

## 🛣️ Roadmap

### Week 3-4 (Planned)
- Replace old parsing logic with new parser throughout
- Enhanced visualizations
- Real-time log monitoring
- PDF report generation
- Production deployment guide

---

## 🤝 Development

### Build
```bash
cargo build
```

### Run with auto-reload (requires cargo-watch)
```bash
cargo watch -x run
```

### Format code
```bash
cargo fmt
```

### Run linter
```bash
cargo clippy
```

---

## 📝 License

[Your License Here]

---

## 🎉 Quick Demo

1. Start server: `cargo run`
2. Open: http://localhost:3000
3. Upload: `apache_combined_test.log`
4. View basic analysis results
5. Click "🤖 Analyze with Claude AI"
6. See expert-level security insights!

---

**Built with Rust 🦀 | Powered by Claude AI 🤖 | Securing the web 🔒**
