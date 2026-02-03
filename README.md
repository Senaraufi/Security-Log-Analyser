# Security Log Analyzer - AI-Powered Threat Intelligence

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)]()
[![CVSS](https://img.shields.io/badge/CVSS-3.1-green.svg)](https://www.first.org/cvss/)
[![AI](https://img.shields.io/badge/AI-Groq%20Llama%203.3%2070B-purple.svg)](https://groq.com/)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Workspace](https://img.shields.io/badge/cargo-workspace%20(4%20crates)-orange.svg)](https://doc.rust-lang.org/cargo/reference/workspaces.html)
[![Apache](https://img.shields.io/badge/logs-Apache%20Combined-blue.svg)]()
[![Database](https://img.shields.io/badge/database-MySQL-blue.svg)](https://www.mysql.com/)

A production-grade Rust workspace application that analyzes Apache web server logs using **CVSS 3.1 scoring**, pattern-based threat detection, and **Groq AI-powered** deep analysis with attack chain detection and MITRE ATT&CK mapping.

**Live Demo:** [senaraufi.github.io/website_rs](https://senaraufi.github.io/website_rs/)  
**Developer:** [Sena Raufi](https://github.com/Senaraufi) | [LinkedIn](https://www.linkedin.com/in/sena-raufi-610187293/)

## Features

### Core Capabilities
- **CVSS 3.1 Scoring** - Industry-standard vulnerability severity ratings
- **Dual-Mode Analysis** - Fast regex-based + AI-powered deep analysis
- **Attack Chain Detection** - Identifies multi-stage attacks using Groq AI
- **Real-time Dashboard** - Modern web UI with color-coded threat visualization
- **10+ Threat Types** - SQL injection, XSS, malware, port scanning, and more
- **IP Analysis** - Tracks malicious IPs with frequency analysis
- **MITRE ATT&CK Mapping** - Maps threats to industry frameworks
- **Database Integration** - MySQL storage for audit trails and compliance

### Technical Highlights
- **Cargo Workspace** - Modular architecture with 4 independent crates
- **70-80% Faster Builds** - Incremental compilation with parallel builds
- **Feature Flags** - Build with/without AI analyzer
- **Production-Ready** - Type-safe Rust with comprehensive error handling

## Tech Stack

### Backend
- **Rust** - Memory-safe systems programming
- **Axum** - Modern async web framework
- **Tokio** - Asynchronous runtime
- **SQLx** - Type-safe SQL with MySQL
- **Nom** - Parser combinators for log parsing
- **Regex** - Pattern matching for threat detection

### AI & Security
- **Groq (Llama 3.3 70B Versatile)** - Free, fast LLM for contextual analysis
- **CVSS 3.1** - Common Vulnerability Scoring System
- **MITRE ATT&CK** - Threat intelligence framework
- **Apache Combined Log Format** - Industry-standard log parsing

### Frontend
- **Vanilla JavaScript** - No framework dependencies
- **Modern CSS** - Dark theme with responsive design
- **HTML5** - Semantic markup

## Workspace Architecture

```
security_api/                    # Cargo Workspace Root
├── Cargo.toml                   # Workspace configuration
├── crates/
│   ├── common/                  # Shared types & utilities
│   │   ├── parsers/             # Apache log parser (Nom)
│   │   ├── cvss.rs              # CVSS 3.1 scoring
│   │   └── types.rs             # Common data structures
│   │
│   ├── analyzer-basic/          # Pattern-based analyzer
│   │   └── lib.rs               # Regex threat detection
│   │
│   ├── analyzer-llm/            # Multi-provider LLM analyzer
│   │   ├── lib.rs               # Multi-provider support via rig-core
│   │   ├── config.rs            # Provider configuration
│   │   ├── analyzer.rs          # Core analysis logic
│   │   └── LLM_CONFIG.md        # Configuration guide
│   │
│   └── api/                     # Web API server
│       ├── main.rs              # Axum server
│       ├── llm_handler.rs       # Multi-provider LLM endpoint
│       └── static/              # Frontend assets
│           └── index.html       # Dashboard UI
│
├── MIGRATION.md                 # Migration guide
├── .env                         # API keys (gitignored)
└── test_logs/                   # Sample log files
```

## Current Status

### ✅ Completed Features

**Workspace Architecture**
- Cargo workspace with 4 independent crates
- 70-80% faster incremental compilation
- Parallel builds (basic + llm compile together)
- Feature flags for flexible builds

**CVSS 3.1 Scoring**
- Individual threat scores for 10+ threat types
- Aggregate risk score with volume weighting
- Vector strings (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- Color-coded severity indicators (Critical/High/Medium/Low)

**Threat Detection**
- SQL Injection (CVSS 9.8)
- Malware Detection (CVSS 9.8)
- Root Access Attempts (CVSS 8.8)
- Suspicious File Access (CVSS 7.5)
- Port Scanning (CVSS 5.3)
- Failed Logins (CVSS 5.3)
- Critical Alerts (CVSS 8.0)

**Groq AI Analysis (FREE)**
- Attack chain detection with timelines
- MITRE ATT&CK technique mapping
- IOC extraction (IPs, patterns, user agents)
- Executive summaries and recommendations
- Contextual threat intelligence
- Llama 3.3 70B Versatile model

**Web Dashboard**
- Modern dark theme UI with professional footer
- CVSS score visualization
- Color-coded threat cards
- IP analysis with frequency tracking
- Real-time analysis results
- Dual-mode: Standard + AI analysis
- Comprehensive help documentation

## Getting Started

### Prerequisites
- **Rust 1.70+**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **MySQL** (optional): For database features
- **Groq API key** (FREE): For AI analysis mode - Get at https://console.groq.com

### Quick Start

```bash
# 1. Clone and navigate
cd security_api

# 2. Configure environment
cp .env.example .env
# Edit .env and add: GROQ_API_KEY=your_key_here
# Get free API key at: https://console.groq.com

# 3. Build and run (release mode)
cargo run -p security-api --release

# 4. Open browser
open http://localhost:3000
```

### Build Options

```bash
# Build everything (both analyzers)
cargo build --release

# Build only basic analyzer (smaller binary, no AI)
cargo build -p security-api --no-default-features --features basic-only

# Build specific crate
cargo build -p security-common
cargo build -p security-analyzer-basic
cargo build -p security-analyzer-groq
```

### Usage

1. **Standard Analysis** (Fast, regex-based)
   - Click "Standard Analysis"
   - Upload Apache Combined Log Format file
   - Get instant CVSS-scored results with threat distribution

2. **Groq AI Analysis** (Deep, contextual, FREE)
   - Click "AI-Powered Analysis"
   - Upload `test_ai_analysis.log` or any Apache log file
   - Get AI insights + attack chains + MITRE ATT&CK mapping + recommendations

### Testing

```bash
# Check all crates compile
cargo check --workspace

# Run all tests
cargo test --workspace

# Test specific crate
cargo test -p security-common
cargo test -p security-analyzer-basic

# Build in release mode
cargo build --release
```

### Documentation

- **[ProjectStructure.md](Documentation/ProjectStructure.md)** - Visual workspace architecture
- **[Complete_Guide](Documentation/COMPLETE_GUIDE.md)** - Visual workspace architecture



## License

Private project - All rights reserved

---

## Performance

### Compilation Speed (Workspace Benefits)

| Action | Before | After | Improvement |
|--------|--------|-------|-------------|
| Full build | 45-60s | 45-60s | Parallel |
| Change basic code | 45-60s | **5-10s** | **85% faster** |
| Change Groq code | 45-60s | **8-12s** | **80% faster** |
| Change API code | 45-60s | **10-15s** | **75% faster** |

### Binary Sizes

- **Full (both analyzers)**: ~15-20 MB
- **Basic only**: ~8-12 MB (40% smaller)

---

## AI Model Options & Fine-Tuning

### Current Setup: Groq AI (FREE)
- **Model:** Llama 3.3 70B Versatile
- **Cost:** Free tier with generous limits
- **Performance:** Fast inference, excellent quality
- **Use Case:** Production-ready for most log analysis needs

### Fine-Tuning Recommendations

#### Option 1: Local Fine-Tuning with Ollama (RECOMMENDED for learning)
**Cost:** FREE  
**Best for:** Experimentation, privacy, full control

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull Llama 3.1 8B
ollama pull llama3.1:8b

# Fine-tune on your security logs using LoRA/QLoRA
# Train on labeled attack patterns and threat data
# Export and integrate with your Rust application
```

**Pros:**
- Completely free, no API costs
- Full control over training data
- Privacy: logs never leave your infrastructure
- Can run on consumer hardware (16GB+ RAM)

**Cons:**
- Requires local compute resources
- Smaller models (8B) vs Groq's 70B
- Manual integration required

#### Option 2: OpenAI Fine-Tuning (RECOMMENDED for production)
**Cost:** ~$3/million tokens training, $0.30/million tokens inference  
**Best for:** Production deployment at scale

```bash
# Fine-tune GPT-4o-mini on security logs
# Much cheaper than Claude for fine-tuned models
# Better accuracy for domain-specific tasks
```

**Pros:**
- Cheaper than Claude for fine-tuned models
- Excellent quality after fine-tuning
- Managed infrastructure
- Easy API integration

**Cons:**
- Paid service (but cost-effective)
- Data leaves your infrastructure

#### Option 3: Hugging Face + AutoTrain (FREE tier available)
**Cost:** FREE for small datasets  
**Best for:** Quick experiments, proof of concept

**Pros:**
- Free tier available
- Easy to use interface
- Can export models for local use

**Cons:**
- Limited free compute
- May need paid tier for larger datasets

#### Option 4: Claude (NOT RECOMMENDED for fine-tuning)
**Cost:** $3/million input tokens  
**Best for:** One-off analysis, not fine-tuning

**Cons:**
- No fine-tuning available yet
- Most expensive option
- No cost reduction over time

### Recommendation Summary

**For Your Use Case:**
1. **Keep Groq** for current production use (free, works well)
2. **Add Ollama** for local fine-tuning experiments (learn the process)
3. **Consider OpenAI** if you need production fine-tuning later (cost-effective)

**Fine-Tuning Strategy:**
1. Collect labeled security log data (attacks + benign traffic)
2. Start with Ollama locally to validate the approach
3. If results are promising, move to OpenAI for production
4. Keep Groq as fallback for users without fine-tuned models

---

## Project Status

**Status:** ✅ Production-Ready with Workspace Architecture  
**Started:** November 2025  
**Language:** Rust 🦀  
**AI:** Multi-Provider LLM (OpenAI, Anthropic, Groq, Gemini) via `rig-core`  
**Architecture:** Cargo Workspace (4 crates)  
**CVSS:** 3.1 Compliant  
**Current Phase:** Optimized & Modular with Multi-Provider AI  
**Developer:** [Sena Raufi](https://github.com/Senaraufi)

---

**Built with Rust 🦀 | Powered by Multi-Provider AI 🤖 | Securing the web 🔒**

**Portfolio:** [senaraufi.github.io/website_rs](https://senaraufi.github.io/website_rs/)
