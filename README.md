# Security AI Startup

Building a Rust-based AI security tool that ingests logs, detects threats, and provides AI-powered analysis.

## Project Goal

An AI tool that:
- Ingests logs from SIEM/SOAR systems
- Summarizes threats
- Determines root cause
- Recommends remediation steps
- Reduces false positives
- Explains findings in plain English

## 🦀 Tech Stack

**Primary Language:** Rust (for performance and memory safety)

**Key Components:**
- Log ingestion (syslog, Windows, cloud events)
- Fast normalization with Rust
- Rule-based detection engine
- AI model integration (OpenAI/Claude/local models)
- Human-readable security insights

## Project Structure

```
Startup/
├── Ideas/                      # Project ideas and brainstorming
│   └── Ideas.txt
├── log_parser/                 # First practice project - log parsing
│   ├── src/
│   │   └── main.rs            # Log parser implementation
│   ├── sample_logs.txt        # Sample security logs
│   ├── HOW_IT_WORKS.md        # Detailed explanation
│   └── Cargo.toml
├── rust-learning-roadmap.md   # 12-week learning plan
└── README.md                  # This file
```

## Current Progress

### Completed
- [x] Initial project planning
- [x] Learning roadmap created
- [x] First Rust project: Log parser
  - Parses security logs
  - Extracts timestamps, IPs, usernames
  - Detects failed login attempts
  - Identifies suspicious IPs

### In Progress
- [ ] Learning Rust fundamentals (Week 1-3)
- [ ] Building log parsing skills

### Next Steps
- [ ] Add async log streaming
- [ ] Integrate with AI APIs
- [ ] Build rule engine
- [ ] Create web interface

## Getting Started

### Prerequisites
- Rust installed (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

### Run the Log Parser
```bash
cd log_parser
cargo run
```

### Run Tests
```bash
cd log_parser
cargo test
```

### Check Code Quality
```bash
cd log_parser
cargo clippy
```

## Learning Resources

See `rust-learning-roadmap.md` for a comprehensive 12-week learning plan.

## Security Note

This is a private repository for development and learning. Do not commit:
- API keys
- Sensitive credentials
- Real security logs with private data

## License

Private project - All rights reserved

---

**Status:** 🌱 Early Development  
**Started:** November 2025  
**Language:** Rust 🦀
