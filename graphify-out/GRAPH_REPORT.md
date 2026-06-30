# Graph Report - /Users/senaraufi/Desktop/Startup  (2026-06-30)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 292 nodes · 574 edges · 15 communities (13 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 12 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d179c93e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]

## God Nodes (most connected - your core abstractions)
1. `LlmAnalyzer` - 21 edges
2. `AnalyzerError` - 21 edges
3. `ApacheLog` - 20 edges
4. `parse_apache_combined()` - 19 edges
5. `SecurityReport` - 14 edges
6. `LogEntry` - 12 edges
7. `parse_generic_log()` - 12 edges
8. `LlmConfig` - 11 edges
9. `LlmProvider` - 8 edges
10. `analyze_logs_with_llm()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `analyze_logs_with_llm()` --calls--> `parse_apache_combined()`  [INFERRED]
  security_api/crates/api/src/llm_handler.rs → security_api/crates/common/src/parsers/apache.rs
- `process_logs()` --calls--> `parse_apache_combined()`  [INFERRED]
  security_api/crates/api/src/main.rs → security_api/crates/common/src/parsers/apache.rs
- `process_logs()` --calls--> `parse_log_line_unified()`  [INFERRED]
  security_api/crates/api/src/main.rs → security_api/crates/common/src/parsers/mod.rs
- `explain_logs()` --calls--> `parse_apache_combined()`  [INFERRED]
  security_api/crates/api/src/simple_handler.rs → security_api/crates/common/src/parsers/apache.rs
- `parse_log_line_unified()` --calls--> `parse_apache_combined()`  [INFERRED]
  security_api/crates/common/src/parsers/mod.rs → security_api/crates/common/src/parsers/apache.rs

## Import Cycles
- None detected.

## Communities (15 total, 2 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.10
Nodes (22): LlmProvider, LlmAnalyzer, Default, Option, Result, Self, String, test_analyzer_default() (+14 more)

### Community 1 - "Community 1"
Cohesion: 0.12
Nodes (28): IResult, build_analysis_prompt(), build_ip_analysis_prompt(), build_recommendations_prompt(), build_triage_prompt(), create_test_log(), format_logs_for_analysis(), String (+20 more)

### Community 2 - "Community 2"
Cohesion: 0.18
Nodes (28): AIAnalysis, AnalysisResult, LogUpload, NewAIAnalysis, NewAnalysisResult, NewDetectedThreat, NewIPAnalysis, NewLogUpload (+20 more)

### Community 3 - "Community 3"
Cohesion: 0.14
Nodes (22): HashMap, BasicAnalysisResult, BasicAnalyzer, Default, Self, String, Vec, Alert (+14 more)

### Community 4 - "Community 4"
Cohesion: 0.13
Nodes (13): ConfigError, LlmConfig, LlmProvider, Display, Error, Formatter, Into, Option (+5 more)

### Community 5 - "Community 5"
Cohesion: 0.12
Nodes (12): ActionItem, IpAnalysisReport, RecommendationsReport, Option, Self, String, Vec, SecurityReport (+4 more)

### Community 6 - "Community 6"
Cohesion: 0.21
Nodes (17): LogEntry, extract_ip_address(), extract_username(), infer_log_level(), parse_generic_log(), Option, String, test_json_like_content() (+9 more)

### Community 7 - "Community 7"
Cohesion: 0.20
Nodes (9): calculate_aggregate_score(), CVSSScore, Option, Self, String, Severity, test_aggregate_score(), test_sql_injection_score() (+1 more)

### Community 8 - "Community 8"
Cohesion: 0.16
Nodes (15): analyze_logs(), main(), parse_log_line(), process_logs(), AnalysisResult, DbPool, Extension, IntoResponse (+7 more)

### Community 9 - "Community 9"
Cohesion: 0.30
Nodes (13): call_llm_simple(), explain_logs(), ExplainLogsRequest, ExplainLogsResponse, extract_json(), parse_simple_response(), IntoResponse, Option (+5 more)

### Community 10 - "Community 10"
Cohesion: 0.21
Nodes (5): Into, Self, String, test_api_error(), test_missing_api_key()

### Community 11 - "Community 11"
Cohesion: 0.25
Nodes (10): Json, analyze_logs_with_llm(), get_error_suggestion(), llm_health_check(), DbPool, Extension, IntoResponse, Multipart (+2 more)

### Community 12 - "Community 12"
Cohesion: 0.40
Nodes (4): GEMINI_API_KEY, LLM_MODEL, LLM_PROVIDER, test_gemini.sh script

## Knowledge Gaps
- **6 isolated node(s):** `check_database.sh script`, `test_db_connection.sh script`, `test_gemini.sh script`, `LLM_PROVIDER`, `LLM_MODEL` (+1 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ApacheLog` connect `Community 1` to `Community 0`?**
  _High betweenness centrality (0.249) - this node is a cross-community bridge._
- **Why does `parse_apache_combined()` connect `Community 1` to `Community 8`, `Community 9`, `Community 11`, `Community 6`?**
  _High betweenness centrality (0.227) - this node is a cross-community bridge._
- **Why does `LogEntry` connect `Community 6` to `Community 8`, `Community 3`?**
  _High betweenness centrality (0.176) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `parse_apache_combined()` (e.g. with `analyze_logs_with_llm()` and `process_logs()`) actually correct?**
  _`parse_apache_combined()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `check_database.sh script`, `test_db_connection.sh script`, `test_gemini.sh script` to the rest of the system?**
  _6 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.11711711711711711 - nodes in this community are weakly interconnected._