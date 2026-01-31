// Claude AI-powered threat analysis
// Advanced contextual analysis with attack chain detection

pub mod llm;

// Re-export main types
pub use llm::analyzer::{LLMAnalyzer, SecurityReport, ThreatLevel, Finding, AttackChain, IOC};
pub use llm::mock::MockAnalyzer;
