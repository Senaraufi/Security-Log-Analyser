# Logr — Security Log Analysis Platform

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

Advanced security log analysis platform powered by AI and traditional threat detection. Analyze Apache, Nginx, and other log formats with real-time threat intelligence, CVSS scoring, and comprehensive reporting.

![Logr Platform](https://img.shields.io/badge/Platform-Security%20Analysis-cyan)

![Logr trailer](./docs/Logr-trailer.gif)

> The trailer above shows the web UI and CLI in action.

## Features

### **Three Analysis Modes**

1. **Simple Mode**
   - Paste logs directly for instant analysis
   - Beginner-friendly interface
   - Risk scoring and threat identification
   - Actionable security fixes

2. **Standard Analysis**
   - Pattern-based threat detection
   - CVSS vulnerability scoring
   - IP reputation analysis
   - Parsing statistics
   - No API keys required

3. **AI-Powered Analysis**
   - LLM-driven threat intelligence
   - Contextual security insights
   - MITRE ATT&CK technique mapping
   - Natural language explanations
   - Supports multiple LLM providers

### **Key Capabilities**

- **Multi-Format Support**: Apache, Nginx, and common log formats
- **Real-time Analysis**: Instant threat detection and classification
- **Export Options**: JSON, CSV, and formatted text reports
- **LLM Integration**: Groq (free), Gemini, OpenAI, Anthropic
- **CVSS Scoring**: Industry-standard vulnerability assessment
- **IP Reputation**: Cross-reference with threat databases
- **MITRE ATT&CK**: Map threats to attack techniques
- **Modern UI**: Dark theme, responsive design

## Architecture

```
security_api/
├── crates/
│   ├── api/              # Axum web server & REST API
│   ├── analyzer-basic/   # Pattern-based threat detection
│   ├── analyzer-llm/     # LLM integration layer
│   ├── common/           # Shared types, log parsers & DB queries
│   └── cli/              # `logr` command-line tool
├── database/            # MySQL schema & migrations
└── .env.example        # Configuration template
```

**Tech Stack:**
- **Backend**: Rust, Axum, Tokio
- **Frontend**: Vanilla JS, Modern CSS, DOMPurify
- **CLI**: Rust, clap, comfy-table
- **Database**: MySQL
- **LLMs**: Groq, Gemini, OpenAI, Anthropic

## Security Hardening

- **Rate limiting**: 30 requests/minute per IP on all API routes
- **Upload limits**: 50 MB max body size to prevent resource exhaustion
- **XSS protection**: all dynamic output is sanitized with DOMPurify before rendering
- **Robust request handling**: no `unwrap()` panics in multipart parsing paths
- **Privacy**: IP geolocation is opt-out to avoid leaking log IPs over the plaintext lookup service
- **Tuned detection**: command-injection and SQL-injection heuristics require real payloads to cut false positives on legitimate traffic

## Installation

### Prerequisites

- **Docker** ([Install](https://docs.docker.com/get-docker/)) — easiest way to run Logr, no Rust/MySQL setup required
- or **Rust** 1.85+ ([Install](https://rustup.rs/)) for building from source
- **MySQL** 8.0+ ([Install](https://dev.mysql.com/downloads/)) — optional, only needed for persistent audit-trail storage
- **LLM API Keys** (optional, for AI analysis):
  - [Groq](https://console.groq.com) (Free)
  - [Google Gemini](https://ai.google.dev/)

### Quick Start (Docker — recommended)

One command, no Rust or MySQL install required. The database is optional; Simple Mode and Advanced Mode both work without it.

1. **Clone the repository**
   ```bash
   git clone https://github.com/senaraufi/Security-Log-Analyser.git
   cd Security-Log-Analyser/security_api
   ```

2. **Configure LLM keys (optional)**
   ```bash
   cp .env.example .env
   # Edit .env and set GROQ_API_KEY (or another provider) for AI analysis
   ```

3. **Start the stack**
   ```bash
   docker compose up
   ```

4. **Access the platform**
   ```
   Open http://localhost:3000 in your browser
   ```

**Want persistent audit-trail storage?** Start MySQL alongside the API and point `DATABASE_URL` at it:
```bash
docker compose --profile db up
# then in .env: DATABASE_URL=mysql://root:logr@db:3306/security_LogsDB
```

### Quick Start (from source)

1. **Clone the repository**
   ```bash
   git clone https://github.com/senaraufi/Security-Log-Analyser.git
   cd Security-Log-Analyser/security_api
   ```

2. **(Optional) Set up the database**
   ```bash
   # Only needed for persistent audit-trail storage; the app runs fine without it.
   mysql -u root -p < database/schema.sql
   ```

3. **Configure environment**
   ```bash
   # Copy example config
   cp .env.example .env
   
   # Edit .env with your settings
   nano .env
   ```

4. **Build and run**
   ```bash
   # Development mode
   cargo run -p security-api
   
   # Production mode (optimized)
   cargo run -p security-api --release
   ```

5. **Access the platform**
   ```
   Open http://localhost:3000 in your browser
   ```

## Configuration

Edit `.env` file:

```bash
# Database
DATABASE_URL=mysql://root:password@localhost:3306/security_LogsDB

# LLM Provider (groq, gemini, openai, anthropic)
LLM_PROVIDER=groq
LLM_MODEL=llama-3.3-70b-versatile

# API Keys (get from respective providers)
GROQ_API_KEY=your_groq_key_here
GEMINI_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
```

### LLM Provider Setup

- **Groq** (Recommended - Free): [Get API Key](https://console.groq.com)
- **Gemini**: [Get API Key](https://ai.google.dev/)
- **OpenAI**: [Get API Key](https://platform.openai.com/)
- **Anthropic**: [Get API Key](https://console.anthropic.com/)

## Usage

### Simple Mode
1. Navigate to "Simple Mode"
2. Paste your logs or generate sample logs
3. Click "Analyze Logs"
4. View threats, risk score, and recommended fixes
5. Export results in JSON, CSV, or TXT format

### Standard Analysis
1. Navigate to "Advanced Mode" → "Standard Analysis"
2. Upload log file (.log or .txt)
3. View comprehensive threat analysis
4. Export detailed reports

### AI-Powered Analysis
1. Navigate to "Advanced Mode" → "AI Analysis"
2. Select LLM provider (Groq or Gemini)
3. Upload log file
4. Get AI-generated threat intelligence
5. View MITRE ATT&CK mappings and recommendations

## API Endpoints

```
POST   /api/explain-logs        # Simple Mode analysis
POST   /api/analyze              # Standard analysis
POST   /api/analyze-with-llm     # AI-powered analysis
GET    /api/llm-health           # LLM provider health check
```

## Command-Line Tool (`logr`)

A standalone CLI for terminal workflows and CI/CD pipelines:

```bash
# Analyze a log file (human-readable table)
cargo run -p logr-cli -- analyze access.log

# Machine-readable JSON output
cargo run -p logr-cli -- analyze access.log --format json

# Read from stdin, fail the pipeline on high-severity threats
cat /var/log/auth.log | cargo run -p logr-cli -- analyze - --severity high --ci
```

## Deployment Notes

- **API Keys**: Never commit `.env` file (already in `.gitignore`)
- **Database**: Use strong passwords and secure connections
- **HTTPS**: Enable in production environments (terminate TLS at a reverse proxy)
- **Rate Limiting**: Built-in per-IP limiting is enabled; tune limits for your traffic profile

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **MITRE ATT&CK** for threat intelligence framework
- **CVSS** for vulnerability scoring standards
- **Groq** for free LLM API access
- **Rust Community** for excellent tooling

## Contact

**Developer**: YOUR_NAME

- LinkedIn: [YOUR_LINKEDIN_URL](YOUR_LINKEDIN_URL)
- GitHub: [YOUR_GITHUB_URL](YOUR_GITHUB_URL)
- Website: [YOUR_WEBSITE_URL](YOUR_WEBSITE_URL)

---

**Logr™** - Advanced Security Log Analysis Platform

© 2026 Logr Security Platform. All rights reserved.
