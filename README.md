# Security Log Analyzer

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CVSS](https://img.shields.io/badge/CVSS-3.1-green.svg)](https://www.first.org/cvss/)

Production-grade security log analysis platform with dual-mode operation: Simple Mode for beginners and Advanced Mode for security professionals. Built with Rust for performance and reliability. Runs with **zero setup friction** — one Docker command, no database required.

**Developer:** [Sena Raufi](https://github.com/Senaraufi)

## Demo

![Security Log Analyzer Demo](docs/Logr-trailer.gif)

## Quick Start

**Docker (recommended — no Rust/MySQL install needed):**

```bash
git clone https://github.com/senaraufi/Security-Log-Analyser.git
cd Security-Log-Analyser/security_api
cp .env.example .env   # optional: add an LLM key for AI analysis
docker compose up
# Open http://localhost:3000
```

The database is optional — Simple Mode and Advanced Mode both work without it. To persist audit trails, run `docker compose --profile db up` instead.

**CLI, prebuilt binary:**

```bash
curl -fsSL https://raw.githubusercontent.com/senaraufi/Security-Log-Analyser/master/install.sh | sh
logr analyze access.log
```

See [Install the CLI](#install-the-cli-logr) and [Run from source](#run-from-source) below for other options.

## Features

**Three ways to analyze logs:**
- **Simple Mode** — paste logs, get plain-English threat explanations, risk scores (0–10), and actionable fixes. No technical expertise required.
- **Advanced Mode** — batch file upload, CVSS 3.1 scoring, IP reputation, MITRE ATT&CK mapping, database-backed audit trails.
- **CLI (`logr`)** — analyze files or piped `stdin`, table/JSON/compact output, `--severity` filtering, `--ci` mode for pipelines.

**Detection & parsing:**
- Multi-format log parsing: Apache/Nginx combined, syslog/`auth.log` (sshd, sudo, PAM), JSON-lines (NDJSON), and a generic fallback
- Threat patterns: SQL injection, XSS, command injection, path traversal, scanners, malware, brute-force logins
- Tuned heuristics with regression tests to cut false positives on legitimate traffic
- Attack chain detection and timeline analysis
- Multi-provider LLM support: Groq (free), Gemini, OpenAI, Anthropic

**Security hardening:**
- Per-IP rate limiting and upload size limits on the API
- Client-side XSS protection via DOMPurify sanitization of all rendered output
- Panic-free multipart handling and truly optional database (fails fast, never blocks startup)
- Opt-out IP geolocation to avoid leaking log IPs over plaintext

**Technical stack:** Rust, Axum, Tokio, SQLx, rig-core (backend) · Vanilla JS/HTML/CSS + DOMPurify (frontend) · clap + comfy-table (CLI) · Cargo workspace, 5 crates

## Project Structure

```
security_api/
├── crates/
│   ├── common/          # Shared types, log parsers, CVSS scoring
│   ├── analyzer-basic/  # Pattern-based threat detection
│   ├── analyzer-llm/    # Multi-provider LLM analysis
│   ├── api/             # Web server and frontend
│   └── cli/             # `logr` command-line tool
├── Dockerfile, docker-compose.yml   # One-command local setup
├── .env.example         # Configuration template
└── test_logs/           # Sample log files
```

## Architecture Visualization

![Project Architecture Graph](graphify-out/graph.svg)

*Interactive knowledge graph showing 292 code entities and 574 relationships across 15 communities. Generated with [Graphify](https://github.com/safishamsi/graphify).*

[View Interactive Graph](graphify-out/graph.html) | [Full Analysis Report](graphify-out/GRAPH_REPORT.md)

## Install the CLI (`logr`)

| Method | Command |
| --- | --- |
| **Install script** (macOS/Linux) | `curl -fsSL https://raw.githubusercontent.com/senaraufi/Security-Log-Analyser/master/install.sh \| sh` |
| **Homebrew** | `brew install senaraufi/tap/logr` |
| **Manual download** | Grab an asset from [Releases](https://github.com/senaraufi/Security-Log-Analyser/releases) (each ships with a `.sha256`) |
| **From source** | `cargo install --path security_api/crates/cli` |

Usage:

```bash
logr analyze access.log                       # table output
logr analyze access.log --format json         # machine-readable
cat /var/log/auth.log | logr analyze - --severity high --ci
```

## Run from source

```bash
cd security_api
cp .env.example .env          # add GROQ_API_KEY (or another provider) for AI analysis
cargo run -p security-api --release
# Open http://localhost:3000
```

Requires Rust 1.85+. MySQL is optional — only needed for persistent audit-trail storage.

## Configuration

Edit `.env` (see `.env.example`):

```bash
LLM_PROVIDER=groq                              # groq | gemini | openai | anthropic
LLM_MODEL=llama-3.3-70b-versatile
GROQ_API_KEY=your_key_here

# Optional — leave unset to run without a database
#DATABASE_URL=mysql://root:password@localhost:3306/security_LogsDB
```

See `security_api/crates/analyzer-llm/LLM_CONFIG.md` for detailed LLM provider options.

## Development

```bash
cargo build --workspace       # build everything
cargo test --workspace        # run tests
cargo build -p security-analyzer-llm   # build one crate
```

## License

MIT License - See LICENSE file for details

## Project Information

- **Status:** Active Development
- **Language:** Rust
- **Architecture:** Cargo Workspace (5 crates)
- **Developer:** [Sena Raufi](https://github.com/Senaraufi)
