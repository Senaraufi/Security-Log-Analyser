# Security Log Analyzer - Workspace Architecture

## Visual Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CARGO WORKSPACE ROOT                             │
│                         (security_api/)                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
        ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
        │  COMMON LIBRARY  │ │    BASIC     │ │     CLAUDE       │
        │  (shared core)   │ │  ANALYZER    │ │   ANALYZER       │
        └──────────────────┘ └──────────────┘ └──────────────────┘
                │                    │                  │
                │                    │                  │
                └────────────────────┼──────────────────┘
                                     │
                                     ▼
                          ┌──────────────────┐
                          │   API SERVER     │
                          │  (web service)   │
                          └──────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
              ┌──────────┐    ┌──────────┐    ┌──────────┐
              │ Frontend │    │ Database │    │   REST   │
              │   (UI)   │    │  (MySQL) │    │   API    │
              └──────────┘    └──────────┘    └──────────┘
```

---

## Detailed Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    CRATE: security-common                           │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │   Models     │  │     CVSS     │  │   Parsers    │             │    │
│  │  │              │  │   Scoring    │  │   (Apache)   │             │    │
│  │  │ • LogEntry   │  │              │  │              │             │    │
│  │  │ • ThreatStats│  │ • ThreatType │  │ • parse_log  │             │    │
│  │  │ • IpInfo     │  │ • Severity   │  │ • formats    │             │    │
│  │  │ • Analysis   │  │ • calculate  │  │ • validation │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  │                                                                     │    │
│  │  ┌──────────────────────────────────────────────────────────┐     │    │
│  │  │              Database Layer                               │     │    │
│  │  │  • models.rs  • queries.rs  • mod.rs                     │     │    │
│  │  └──────────────────────────────────────────────────────────┘     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    ▲                                         │
│                                    │ (depends on)                            │
│  ┌─────────────────────────────────┼──────────────────────────────────┐    │
│  │                                 │                                   │    │
│  │  ┌──────────────────────────────┴────────────────────────────┐     │    │
│  │  │           CRATE: security-analyzer-basic                   │     │    │
│  │  │  ┌────────────────────────────────────────────────────┐   │     │    │
│  │  │  │  BasicAnalyzer                                      │   │     │    │
│  │  │  │  • analyze(entries) -> BasicAnalysisResult         │   │     │    │
│  │  │  │  • generate_cvss_scores()                          │   │     │    │
│  │  │  │                                                     │   │     │    │
│  │  │  │  Pattern Matching:                                 │   │     │    │
│  │  │  │  ✓ SQL Injection      ✓ Failed Logins             │   │     │    │
│  │  │  │  ✓ Root Access        ✓ File Access               │   │     │    │
│  │  │  │  ✓ Port Scanning      ✓ Malware                   │   │     │    │
│  │  │  │  ✓ Critical Alerts                                 │   │     │    │
│  │  │  └────────────────────────────────────────────────────┘   │     │    │
│  │  └───────────────────────────────────────────────────────────┘     │    │
│  │                                                                     │    │
│  │  ┌──────────────────────────────────────────────────────────┐     │    │
│  │  │           CRATE: security-analyzer-claude                 │     │    │
│  │  │  ┌────────────────────────────────────────────────────┐  │     │    │
│  │  │  │  ClaudeAnalyzer                                     │  │     │    │
│  │  │  │  • analyze_logs(logs) -> SecurityReport            │  │     │    │
│  │  │  │  • call_claude_api()                               │  │     │    │
│  │  │  │  • parse_claude_response()                         │  │     │    │
│  │  │  │                                                     │  │     │    │
│  │  │  │  LLM Features:                                      │  │     │    │
│  │  │  │  ✓ Attack Chain Detection                          │  │     │    │
│  │  │  │  ✓ Contextual Analysis                             │  │     │    │
│  │  │  │  ✓ MITRE ATT&CK Mapping                            │  │     │    │
│  │  │  │  ✓ IOC Extraction                                  │  │     │    │
│  │  │  │  ✓ Recommendations                                 │  │     │    │
│  │  │  └────────────────────────────────────────────────────┘  │     │    │
│  │  │  ┌────────────────────────────────────────────────────┐  │     │    │
│  │  │  │  MockAnalyzer (for testing)                        │  │     │    │
│  │  │  └────────────────────────────────────────────────────┘  │     │    │
│  │  └──────────────────────────────────────────────────────────┘     │    │
│  │                                                                     │    │
│  │  ┌──────────────────────────────────────────────────────────┐     │    │
│  │  │              CRATE: security-api (binary)                 │     │    │
│  │  │  ┌────────────────────────────────────────────────────┐  │     │    │
│  │  │  │  Axum Web Server                                    │  │     │    │
│  │  │  │                                                     │  │     │    │
│  │  │  │  Endpoints:                                         │  │     │    │
│  │  │  │  • POST /api/analyze          (basic)              │  │     │    │
│  │  │  │  • POST /api/analyze-with-ai  (claude)             │  │     │    │
│  │  │  │  • GET  /                     (static files)       │  │     │    │
│  │  │  │                                                     │  │     │    │
│  │  │  │  Features:                                          │  │     │    │
│  │  │  │  • Multipart file upload                           │  │     │    │
│  │  │  │  • JSON responses                                  │  │     │    │
│  │  │  │  • Database integration                            │  │     │    │
│  │  │  │  • Static file serving                             │  │     │    │
│  │  │  └────────────────────────────────────────────────────┘  │     │    │
│  │  │  ┌────────────────────────────────────────────────────┐  │     │    │
│  │  │  │  Frontend (static/index.html)                      │  │     │    │
│  │  │  │  • Dark theme UI                                   │  │     │    │
│  │  │  │  • CVSS score visualization                        │  │     │    │
│  │  │  │  • Threat cards with details                       │  │     │    │
│  │  │  │  • IP analysis dashboard                           │  │     │    │
│  │  │  └────────────────────────────────────────────────────┘  │     │    │
│  │  └──────────────────────────────────────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

```
┌──────────────┐
│   User       │
│  (Browser)   │
└──────┬───────┘
       │
       │ 1. Upload log file
       ▼
┌──────────────────────────────────────┐
│   API Server (Axum)                  │
│   POST /api/analyze                  │
└──────┬───────────────────────────────┘
       │
       │ 2. Parse log content
       ▼
┌──────────────────────────────────────┐
│   Common Library                     │
│   • parse_log_line()                 │
│   • Create LogEntry structs          │
└──────┬───────────────────────────────┘
       │
       │ 3. Analyze threats
       ▼
┌──────────────────────────────────────┐
│   Basic Analyzer                     │
│   • Pattern matching                 │
│   • Count threats                    │
│   • Track IPs                        │
└──────┬───────────────────────────────┘
       │
       │ 4. Calculate CVSS scores
       ▼
┌──────────────────────────────────────┐
│   Common Library (CVSS)              │
│   • ThreatType::cvss_score()         │
│   • calculate_aggregate_score()      │
└──────┬───────────────────────────────┘
       │
       │ 5. Build response
       ▼
┌──────────────────────────────────────┐
│   AnalysisResult                     │
│   • threat_statistics                │
│   • ip_analysis                      │
│   • risk_assessment                  │
│   • cvss_scores                      │
└──────┬───────────────────────────────┘
       │
       │ 6. Return JSON
       ▼
┌──────────────┐
│   Frontend   │
│   Display    │
│   Results    │
└──────────────┘
```

---

## Claude AI Flow (Optional)

```
┌──────────────┐
│   User       │
└──────┬───────┘
       │ Upload log file
       ▼
┌──────────────────────────────────────┐
│   API Server                         │
│   POST /api/analyze-with-ai          │
└──────┬───────────────────────────────┘
       │
       │ Parse Apache logs
       ▼
┌──────────────────────────────────────┐
│   Common Library                     │
│   parse_apache_combined()            │
└──────┬───────────────────────────────┘
       │
       │ Send to Claude
       ▼
┌──────────────────────────────────────┐
│   Claude Analyzer                    │
│   • Build prompt                     │
│   • Call Anthropic API               │
│   • Parse response                   │
└──────┬───────────────────────────────┘
       │
       │ AI Report
       ▼
┌──────────────────────────────────────┐
│   SecurityReport                     │
│   • summary                          │
│   • findings                         │
│   • attack_chains                    │
│   • recommendations                  │
└──────┬───────────────────────────────┘
       │
       │ Combine with basic analysis
       ▼
┌──────────────────────────────────────┐
│   Combined JSON Response             │
│   • basic_analysis                   │
│   • ai_report                        │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────┐
│   Frontend   │
└──────────────┘
```

---

## Compilation Dependencies

```
┌─────────────────────────────────────────────┐
│  Workspace Root                             │
│  (defines shared dependencies)              │
└─────────────────┬───────────────────────────┘
                  │
    ┌─────────────┼─────────────┬─────────────┐
    │             │             │             │
    ▼             ▼             ▼             ▼
┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ common │  │  basic   │  │  claude  │  │   api    │
└────────┘  └──────────┘  └──────────┘  └──────────┘
    │            │             │             │
    │            │             │             │
    │       depends on    depends on    depends on
    │            │             │             │
    │            ▼             ▼             ▼
    │       ┌────────┐    ┌────────┐    ┌────────┐
    │       │ common │    │ common │    │  all   │
    │       └────────┘    └────────┘    └────────┘
    │
    └──> No dependencies (base library)
```

**Compilation Order:**
1. `security-common` (no dependencies)
2. `security-analyzer-basic` (depends on common)
3. `security-analyzer-claude` (depends on common)
4. `security-api` (depends on all)

**Result:** Crates 2 & 3 can compile in parallel!

---

## Feature Flags

```
┌──────────────────────────────────────┐
│   security-api                       │
│                                      │
│   Features:                          │
│   ┌────────────────────────────┐    │
│   │ default = ["claude"]       │    │
│   │ basic-only = []            │    │
│   │ claude = ["analyzer-claude"]│   │
│   └────────────────────────────┘    │
└──────────────────────────────────────┘

Build Options:

cargo build                          → Both analyzers
cargo build --features claude        → Both analyzers
cargo build --features basic-only    → Basic only (smaller)
cargo build --no-default-features    → Basic only
```

---

## Directory Structure (Actual Files - After Cleanup)

```
security_api/
├── Cargo.toml                    # Workspace config
├── Cargo.lock                    # Dependency lock
├── .env                          # Environment vars (API keys)
├── .env.example                  # Template
│
├── crates/                       # ← All source code here
│   ├── common/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # Public exports
│   │       ├── cvss.rs           # CVSS engine
│   │       ├── parsers/
│   │       │   ├── mod.rs
│   │       │   └── apache.rs
│   │       └── database/
│   │           ├── mod.rs
│   │           ├── models.rs
│   │           └── queries.rs
│   │
│   ├── analyzer-basic/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs            # BasicAnalyzer
│   │
│   ├── analyzer-claude/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── llm/
│   │           ├── mod.rs
│   │           ├── analyzer.rs   # ClaudeAnalyzer
│   │           ├── prompts.rs
│   │           └── mock.rs
│   │
│   └── api/
│       ├── Cargo.toml
│       ├── src/
│       │   └── main.rs           # Axum server
│       └── static/
│           └── index.html        # Frontend
│
├── Documentation/                # Project documentation
│   ├── README.md
│   ├── TECHNICAL_GUIDE.md
│   ├── SETUP_AND_TESTING.md
│   ├── CVSS_IMPLEMENTATION.md
│   ├── UI_CVSS_UPDATE.md
│   └── TEST_LOGS_GUIDE.md
│
├── WORKSPACE_MIGRATION_COMPLETE.md  # Migration guide
├── ARCHITECTURE_DIAGRAM.md           # This file
├── CLEANUP_LIST.md                   # Cleanup instructions
│
├── Database Scripts/
│   ├── create_tables.sql         # Database schema
│   ├── check_database.sh         # Verification
│   ├── test_db_connection.sh     # Connection test
│   └── download_geoip.sh         # GeoIP data
│
├── Test Files/
│   ├── test_logs_standard.log    # Basic analyzer test
│   ├── test_logs_claude.log      # Claude analyzer test
│   ├── apache_combined_test.log  # Old test (optional)
│   ├── apache_sample.log         # Large sample (optional)
│   └── bad_format_test.txt       # Malformed test (optional)
│
└── corporate_frontend.html       # Old frontend (unused)
```

**Note:** Cleaned up! Removed:
- ❌ `src/` (moved to `crates/`)
- ❌ `examples/` (outdated)
- ❌ `target/` (build cache - 2.7 GB saved!)
- ❌ `Cargo.toml.old` (backup)

---

## Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Backend (Rust)                            │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │   Axum     │  │   Tokio    │  │   SQLx     │            │
│  │  (Web)     │  │  (Async)   │  │ (Database) │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │   Serde    │  │   Regex    │  │   Nom      │            │
│  │  (JSON)    │  │ (Parsing)  │  │ (Parsing)  │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    AI Integration                            │
│  ┌────────────┐  ┌────────────┐                             │
│  │  Reqwest   │  │   Claude   │                             │
│  │  (HTTP)    │  │ 3.5 Sonnet │                             │
│  └────────────┘  └────────────┘                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Frontend                                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ Vanilla JS │  │    CSS     │  │   HTML5    │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Database                                  │
│  ┌────────────┐                                              │
│  │   MySQL    │                                              │
│  └────────────┘                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Architectural Benefits

1. **Modularity**: Each analyzer is independent
2. **Parallel Compilation**: Basic and Claude compile simultaneously
3. **Feature Flags**: Build only what you need
4. **Shared Code**: Common library prevents duplication
5. **Scalability**: Easy to add new analyzers
6. **Testability**: Each crate can be tested independently
