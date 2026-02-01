# Security Log Analyzer - AI-Powered Threat Intelligence

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Private-blue.svg)](LICENSE)
[![CVSS](https://img.shields.io/badge/CVSS-3.1-green.svg)](https://www.first.org/cvss/)
[![Claude](https://img.shields.io/badge/AI-Claude%203.5-purple.svg)](https://www.anthropic.com/)
[![Workspace](https://img.shields.io/badge/cargo-workspace-red.svg)](https://doc.rust-lang.org/cargo/reference/workspaces.html)

A production-grade Rust workspace application that analyzes security logs using **CVSS 3.1 scoring**, pattern-based threat detection, and **Claude AI-powered** deep analysis with attack chain detection.

## Features

### Core Capabilities
- **CVSS 3.1 Scoring** - Industry-standard vulnerability severity ratings
- **Dual-Mode Analysis** - Fast regex-based + AI-powered deep analysis
- **Attack Chain Detection** - Identifies multi-stage attacks using Claude AI
- **Real-time Dashboard** - Modern web UI with color-coded threat visualization
- **10+ Threat Types** - SQL injection, XSS, malware, port scanning, and more
- **IP Analysis** - Tracks malicious IPs with frequency analysis
- **MITRE ATT&CK Mapping** - Maps threats to industry frameworks
- **Database Integration** - MySQL storage for audit trails and compliance

### Technical Highlights
- **Cargo Workspace** - Modular architecture with 4 independent crates
- **70-80% Faster Builds** - Incremental compilation with parallel builds
- **Feature Flags** - Build with/without Claude AI analyzer
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
- **Claude 3.5 Sonnet** - Advanced LLM for contextual analysis
- **CVSS 3.1** - Common Vulnerability Scoring System
- **MITRE ATT&CK** - Threat intelligence framework

### Frontend
- **Vanilla JavaScript** - No framework dependencies
- **Modern CSS** - Dark theme with responsive design
- **HTML5** - Semantic markup

## Workspace Architecture

```
security_api/                    # Cargo Workspace Root
├── Cargo.toml                   # Workspace configuration
├── crates/
│   ├── common/                  # Shared library
│   │   ├── src/
│   │   │   ├── cvss.rs         # CVSS 3.1 scoring engine
│   │   │   ├── parsers/        # Log parsing (Apache, etc.)
│   │   │   └── database/       # MySQL integration
│   │   └── Cargo.toml
│   │
│   ├── analyzer-basic/          # Fast regex-based detection
│   │   ├── src/lib.rs          # Pattern matching engine
│   │   └── Cargo.toml
│   │
│   ├── analyzer-claude/         # AI-powered analysis
│   │   ├── src/llm/
│   │   │   ├── analyzer.rs     # Claude API integration
│   │   │   ├── prompts.rs      # Security prompts
│   │   │   └── mock.rs         # Testing without API
│   │   └── Cargo.toml
│   │
│   └── api/                     # Web server (binary)
│       ├── src/main.rs         # Axum REST API
│       ├── static/index.html   # Frontend UI
│       └── Cargo.toml
│
├── Documentation/               # Project docs
│   ├── README.md
│   ├── TECHNICAL_GUIDE.md
│   ├── CVSS_IMPLEMENTATION.md
│   └── ARCHITECTURE_DIAGRAM.md
│
├── test_logs_standard.log      # Basic analyzer test
└── test_logs_claude.log        # Claude analyzer test
```

## Current Status

### ✅ Completed Features

**Workspace Architecture**
- Cargo workspace with 4 independent crates
- 70-80% faster incremental compilation
- Parallel builds (basic + claude compile together)
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

**Claude AI Analysis**
- Attack chain detection with timelines
- MITRE ATT&CK technique mapping
- IOC extraction (IPs, patterns, user agents)
- Executive summaries and recommendations
- Contextual threat intelligence

**Web Dashboard**
- Modern dark theme UI
- CVSS score visualization
- Color-coded threat cards
- IP analysis with frequency tracking
- Real-time analysis results
- Dual-mode: Standard + AI analysis

## Getting Started

### Prerequisites
- **Rust 1.70+**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **MySQL** (optional): For database features
- **Claude API key** (optional): For AI analysis mode

### Quick Start

```bash
# 1. Clone and navigate
cd security_api

# 2. Configure environment (optional)
cp .env.example .env
# Edit .env and add: ANTHROPIC_API_KEY=your_key_here

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
cargo build -p security-analyzer-claude
```

### Usage

1. **Standard Analysis** (Fast, regex-based)
   - Click "Analyse Logs"
   - Upload `test_logs_standard.log`
   - Get instant CVSS-scored results

2. **Claude AI Analysis** (Deep, contextual)
   - Click "Analyse Logs with Claude"
   - Upload `test_logs_claude.log`
   - Get AI insights + attack chains + recommendations

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

- **[ARCHITECTURE_DIAGRAM.md](security_api/ARCHITECTURE_DIAGRAM.md)** - Visual workspace architecture
- **[WORKSPACE_MIGRATION_COMPLETE.md](security_api/WORKSPACE_MIGRATION_COMPLETE.md)** - Migration guide
- **[Documentation/TECHNICAL_GUIDE.md](Documentation/TECHNICAL_GUIDE.md)** - Technical details
- **[Documentation/CVSS_IMPLEMENTATION.md](Documentation/CVSS_IMPLEMENTATION.md)** - CVSS scoring system
- **[Documentation/SETUP_AND_TESTING.md](Documentation/SETUP_AND_TESTING.md)** - Setup guide


## License

Private project - All rights reserved

---

## Performance

### Compilation Speed (Workspace Benefits)

| Action | Before | After | Improvement |
|--------|--------|-------|-------------|
| Full build | 45-60s | 45-60s | Parallel |
| Change basic code | 45-60s | **5-10s** | **85% faster** |
| Change Claude code | 45-60s | **8-12s** | **80% faster** |
| Change API code | 45-60s | **10-15s** | **75% faster** |

### Binary Sizes

- **Full (both analyzers)**: ~15-20 MB
- **Basic only**: ~8-12 MB (40% smaller)

---

## Project Status

**Status:** ✅ Production-Ready with Workspace Architecture  
**Started:** November 2025  
**Language:** Rust 🦀  
**AI:** Claude 3.5 Sonnet (Anthropic)  
**Architecture:** Cargo Workspace (4 crates)  
**CVSS:** 3.1 Compliant  
**Current Phase:** Optimized & Modular

---

**Built with Rust 🦀 | Powered by Claude AI 🤖 | Securing the web 🔒**
