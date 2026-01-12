# Security Log Analyser with AI-Powered Threat Intelligence

A production grade Rust application that analyses Apache web server logs using pattern-based threat detection and Claude AI-powered deep analysis.

## Project Goal

An AI-powered security tool that:
- Ingests and parses Apache web server logs
- Detects threats using pattern matching (SQL injection, XSS, path traversal, etc.)
- Provides AI-powered security analysis using Claude
- Generates executive summaries and recommendations
- Maps threats to MITRE ATT&CK and OWASP Top 10 frameworks
- Reduces false positives through intelligent context analysis
- Explains findings in plain English

## Tech Stack

**Primary Language:** Rust (for performance and memory safety)

**Implemented Components:**
- Apache Combined Log Format parser (nom combinators)
- Pattern-based threat detection engine
- Claude API integration for AI analysis
- Web dashboard with real-time analysis
- Alert system with severity classification
- IP analysis with VPN detection
- CSV export functionality

## Project Structure

```
Startup/
├── security_api/              # Main application (CURRENT)
│   ├── src/
│   │   ├── main.rs           # Web server & API endpoints
│   │   ├── parsers/          # Apache log parser module
│   │   │   └── apache.rs     # Parser implementation
│   │   └── llm/              # AI analysis module
│   │       ├── analyzer.rs   # Claude API integration
│   │       ├── prompts.rs    # Security analysis prompts
│   │       └── mock.rs       # Mock analyzer for testing
│   ├── examples/             # Test programs
│   │   ├── test_parser.rs
│   │   ├── test_llm_analyzer.rs
│   │   └── demo_analyzer.rs
│   ├── apache_combined_test.log  # Sample logs
│   ├── .env.example          # Environment template
│   ├── README.md             # Detailed documentation
│   ├── HOW_CLAUDE_WORKS.md   # AI system explanation
│   └── HOW_TO_TEST.md        # Testing guide
├── log_parser/               # Early learning project (archived)
├── Documentation/            # Project documentation & specs
│   └── PROJECT_SPECIFICATION.txt
└── README.md                 # This file
```

## Current Progress

### Week 1-2 Complete (Production-Ready)

**Apache Log Parser**
- Production-grade parser using nom combinators
- Comprehensive threat detection (SQL injection, XSS, path traversal, command injection)
- Type-safe data structures with full error handling
- Unit tests with 100% pass rate
- MITRE ATT&CK and OWASP Top 10 mapping

**Claude AI Integration**
- Claude API integration with async support
- Expert-level security analysis prompts
- Mock analyzer for testing without API costs
- Structured security reports with confidence scores
- Attack chain detection and IOC extraction

**Web Dashboard**
- Real-time log analysis interface
- Threat visualization and statistics
- IP analysis with VPN detection
- Security alerts with severity classification
- AI analysis on-demand with beautiful results display
- CSV export functionality

###  Week 3-4 Planned

- [ ] Full UI integration (replace old parsing logic)
- [ ] Enhanced visualizations and charts
- [ ] Real-time log monitoring
- [ ] PDF report generation
- [ ] Production deployment guide
- [ ] Performance optimization

## Getting Started

### Prerequisites
- Rust (latest stable): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Claude API key (optional - can use mock mode)

### Quick Start

1. **Navigate to the main application**
```bash
cd security_api
```

2. **Configure API key** (optional)
```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your Claude API key
# ANTHROPIC_API_KEY=your_key_here
# Or set USE_MOCK_ANALYZER=true for testing
```

3. **Run the server**
```bash
cargo run
```

4. **Open the dashboard**
```
http://localhost:3000
```

5. **Upload logs and analyze!**
   - Upload `apache_combined_test.log`
   - View basic analysis results
   - Click "🤖 Analyze with Claude AI" for deep analysis

### Testing

```bash
# Run unit tests
cargo test

# Test parser
cargo run --example test_parser

# Interactive demo
cargo run --example demo_analyzer

# Test AI (mock mode)
cargo run --example test_llm_analyzer
```

### Documentation

- **security_api/README.md** - Complete application documentation
- **security_api/HOW_CLAUDE_WORKS.md** - AI system explained
- **security_api/HOW_TO_TEST.md** - Testing guide
- **Documentation/PROJECT_SPECIFICATION.txt** - Full technical specs

## 🔐 Security & API Keys

### ✅ API Key Protection

Your API keys are **safe and protected**:

- `.env` files are in `.gitignore` (not tracked by git)
- No API keys in documentation (only placeholders)
- `.env.example` provided as template
- All sensitive data excluded from repository

### Setting Up Your API Key

```bash
# 1. Copy the example file
cp security_api/.env.example security_api/.env

# 2. Edit .env and add your key
ANTHROPIC_API_KEY=your_actual_key_here

# 3. Never commit .env file (already in .gitignore)
```

### Testing Without API Key

Set `USE_MOCK_ANALYZER=true` in `.env` to test without API costs.

---

## License

Private project - All rights reserved

---

## Project Status

**Status:** ✅ Week 1-2 Complete - Production-Ready MVP  
**Started:** November 2025  
**Language:** Rust 🦀  
**AI:** Claude (Anthropic)  
**Current Phase:** Week 3-4 - Full Integration & Polish

---

**Built with Rust 🦀 | Powered by Claude AI 🤖 | Securing the web 🔒**
