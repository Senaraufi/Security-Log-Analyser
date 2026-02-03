//! Multi-provider LLM analyzer for security log analysis.
//!
//! This crate provides intelligent security log analysis using various LLM providers
//! (OpenAI, Anthropic, Groq, etc.) through a unified interface powered by `rig-core`.
//!
//! # Features
//!
//! - **Multi-provider support**: Switch between OpenAI, Anthropic, Groq, and more
//! - **Environment-based configuration**: Easy provider/model switching via `.env`
//! - **Structured reports**: JSON-serializable security reports with MITRE ATT&CK mappings
//! - **Intelligent prompts**: Carefully crafted prompts for accurate threat detection
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use security_analyzer_llm::{LlmAnalyzer, SecurityReport};
//!
//! // Load configuration from environment variables
//! let analyzer = LlmAnalyzer::from_env()?;
//!
//! // Analyze logs
//! let report = analyzer.analyze_logs(&parsed_logs).await?;
//!
//! println!("Threat Level: {}", report.threat_level);
//! println!("Summary: {}", report.summary);
//! ```
//!
//! # Environment Variables
//!
//! Configure the analyzer using these environment variables:
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `LLM_PROVIDER` | Provider: openai, anthropic, groq, gemini | openai |
//! | `LLM_MODEL` | Model name (provider-specific) | Provider default |
//! | `LLM_TEMPERATURE` | Generation temperature (0.0-1.0) | 0.3 |
//! | `LLM_MAX_TOKENS` | Maximum response tokens | 4096 |
//! | `OPENAI_API_KEY` | OpenAI API key | - |
//! | `ANTHROPIC_API_KEY` | Anthropic API key | - |
//! | `GROQ_API_KEY` | Groq API key | - |
//! | `GEMINI_API_KEY` | Google Gemini API key | - |
//!
//! # Example Configuration
//!
//! Create a `.env` file in your project root:
//!
//! ```text
//! # Use Anthropic Claude
//! LLM_PROVIDER=anthropic
//! LLM_MODEL=claude-sonnet-4-20250514
//! ANTHROPIC_API_KEY=your-api-key-here
//!
//! # Or use OpenAI
//! # LLM_PROVIDER=openai
//! # LLM_MODEL=gpt-4o
//! # OPENAI_API_KEY=your-api-key-here
//!
//! # Or use Groq (fast inference)
//! # LLM_PROVIDER=groq
//! # LLM_MODEL=llama-3.1-70b-versatile
//! # GROQ_API_KEY=your-api-key-here
//! ```

// Module declarations
pub mod analyzer;
pub mod config;
pub mod error;
pub mod prompts;
pub mod report;

// Re-export main types for convenient access
pub use analyzer::LlmAnalyzer;
pub use config::{LlmConfig, LlmProvider, ConfigError};
pub use error::AnalyzerError;
pub use report::{
    SecurityReport,
    IpAnalysisReport,
    TriageReport,
    RecommendationsReport,
    ActionItem,
};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::analyzer::LlmAnalyzer;
    pub use crate::config::{LlmConfig, LlmProvider};
    pub use crate::error::AnalyzerError;
    pub use crate::report::SecurityReport;
}

/// Create an analyzer from environment variables (convenience function)
///
/// This is a shorthand for `LlmAnalyzer::from_env()`.
///
/// # Example
///
/// ```rust,ignore
/// let analyzer = security_analyzer_llm::from_env()?;
/// ```
pub fn from_env() -> Result<LlmAnalyzer, AnalyzerError> {
    LlmAnalyzer::from_env()
}

/// Create an analyzer with a specific configuration (convenience function)
///
/// # Example
///
/// ```rust,ignore
/// use security_analyzer_llm::{LlmConfig, LlmProvider};
///
/// let config = LlmConfig::new(LlmProvider::Anthropic, "claude-sonnet-4-20250514", "your-api-key");
/// let analyzer = security_analyzer_llm::with_config(config);
/// ```
pub fn with_config(config: LlmConfig) -> LlmAnalyzer {
    LlmAnalyzer::with_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_returns_error_without_config() {
        // Clear any existing env vars for this test
        std::env::remove_var("LLM_PROVIDER");
        std::env::remove_var("OPENAI_API_KEY");
        
        // Should return an error because no API key is set
        let result = from_env();
        assert!(result.is_err());
    }

    #[test]
    fn test_with_config() {
        let config = LlmConfig::new(
            LlmProvider::OpenAI,
            "gpt-4o",
            "test-key",
        );
        
        let analyzer = with_config(config);
        assert_eq!(*analyzer.provider(), LlmProvider::OpenAI);
        assert_eq!(analyzer.model(), "gpt-4o");
    }

    #[test]
    fn test_prelude_imports() {
        // Verify prelude exports work
        use crate::prelude::*;
        
        let config = LlmConfig::new(LlmProvider::Anthropic, "claude-3", "key");
        let _analyzer = LlmAnalyzer::with_config(config);
    }
}