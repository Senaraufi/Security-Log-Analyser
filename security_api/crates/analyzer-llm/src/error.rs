//! Error types for the LLM analyzer module.
//!
//! This module defines custom error types that provide clear,
//! actionable error messages for various failure scenarios.

use std::fmt;

/// Errors that can occur during LLM-based log analysis
#[derive(Debug, Clone)]
pub enum AnalyzerError {
    /// Configuration error (missing API key, invalid provider, etc.)
    Configuration(String),

    /// API call failed
    ApiError {
        /// The provider that failed
        provider: String,
        /// Error message from the provider
        message: String,
    },

    /// Failed to parse LLM response
    ParseError {
        /// The expected format
        expected: String,
        /// Description of what went wrong
        details: String,
    },

    /// Provider is not supported
    ProviderNotSupported {
        /// The unsupported provider name
        provider: String,
        /// Reason or alternative suggestion
        reason: String,
    },

    /// Rate limit exceeded
    RateLimitExceeded {
        /// The provider that rate limited
        provider: String,
        /// Retry after (if known)
        retry_after_seconds: Option<u64>,
    },

    /// Request timed out
    Timeout {
        /// The provider that timed out
        provider: String,
        /// Timeout duration in seconds
        timeout_seconds: u64,
    },

    /// Invalid input provided
    InvalidInput(String),

    /// Generic/unknown error
    Unknown(String),
}

impl fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalyzerError::Configuration(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            AnalyzerError::ApiError { provider, message } => {
                write!(f, "{} API error: {}", provider, message)
            }
            AnalyzerError::ParseError { expected, details } => {
                write!(
                    f,
                    "Failed to parse LLM response. Expected {}: {}",
                    expected, details
                )
            }
            AnalyzerError::ProviderNotSupported { provider, reason } => {
                write!(f, "Provider '{}' is not supported. {}", provider, reason)
            }
            AnalyzerError::RateLimitExceeded {
                provider,
                retry_after_seconds,
            } => {
                if let Some(seconds) = retry_after_seconds {
                    write!(
                        f,
                        "{} rate limit exceeded. Retry after {} seconds.",
                        provider, seconds
                    )
                } else {
                    write!(f, "{} rate limit exceeded. Please try again later.", provider)
                }
            }
            AnalyzerError::Timeout {
                provider,
                timeout_seconds,
            } => {
                write!(
                    f,
                    "{} request timed out after {} seconds.",
                    provider, timeout_seconds
                )
            }
            AnalyzerError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
            AnalyzerError::Unknown(msg) => {
                write!(f, "Unknown error: {}", msg)
            }
        }
    }
}

impl std::error::Error for AnalyzerError {}

impl AnalyzerError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AnalyzerError::RateLimitExceeded { .. }
                | AnalyzerError::Timeout { .. }
                | AnalyzerError::ApiError { .. }
        )
    }

    /// Get a user-friendly suggestion for fixing this error
    pub fn suggestion(&self) -> &'static str {
        match self {
            AnalyzerError::Configuration(_) => {
                "Check your .env file and ensure the required API key is set."
            }
            AnalyzerError::ApiError { .. } => {
                "Check your API key and network connection. The provider may be experiencing issues."
            }
            AnalyzerError::ParseError { .. } => {
                "Try running the analysis again. If the issue persists, the model may need adjustment."
            }
            AnalyzerError::ProviderNotSupported { .. } => {
                "Use a supported provider: openai, anthropic, or groq."
            }
            AnalyzerError::RateLimitExceeded { .. } => {
                "Wait a moment and try again, or upgrade your API plan."
            }
            AnalyzerError::Timeout { .. } => {
                "Try analyzing fewer logs at once, or increase the timeout."
            }
            AnalyzerError::InvalidInput(_) => {
                "Check that the log file is in a supported format (Apache combined log format)."
            }
            AnalyzerError::Unknown(_) => {
                "Check the logs for more details. If the issue persists, please report it."
            }
        }
    }

    /// Create a configuration error for missing API key
    pub fn missing_api_key(provider: &str, env_var: &str) -> Self {
        AnalyzerError::Configuration(format!(
            "API key for {} not found. Set the {} environment variable.",
            provider, env_var
        ))
    }

    /// Create an API error
    pub fn api_error(provider: impl Into<String>, message: impl Into<String>) -> Self {
        AnalyzerError::ApiError {
            provider: provider.into(),
            message: message.into(),
        }
    }

    /// Create a parse error
    pub fn parse_error(expected: impl Into<String>, details: impl Into<String>) -> Self {
        AnalyzerError::ParseError {
            expected: expected.into(),
            details: details.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration_error() {
        let error = AnalyzerError::Configuration("Test error".to_string());
        assert!(error.to_string().contains("Configuration error"));
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_api_error() {
        let error = AnalyzerError::api_error("OpenAI", "Connection refused");
        assert!(error.to_string().contains("OpenAI"));
        assert!(error.to_string().contains("Connection refused"));
        assert!(error.is_retryable());
    }

    #[test]
    fn test_rate_limit_error() {
        let error = AnalyzerError::RateLimitExceeded {
            provider: "Anthropic".to_string(),
            retry_after_seconds: Some(60),
        };
        assert!(error.to_string().contains("60 seconds"));
        assert!(error.is_retryable());
    }

    #[test]
    fn test_missing_api_key() {
        let error = AnalyzerError::missing_api_key("OpenAI", "OPENAI_API_KEY");
        assert!(error.to_string().contains("OPENAI_API_KEY"));
    }

    #[test]
    fn test_suggestions() {
        let config_error = AnalyzerError::Configuration("test".to_string());
        assert!(config_error.suggestion().contains("env"));

        let timeout_error = AnalyzerError::Timeout {
            provider: "Test".to_string(),
            timeout_seconds: 30,
        };
        assert!(timeout_error.suggestion().contains("timeout"));
    }
}