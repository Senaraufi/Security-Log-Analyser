//! Full record of a single LLM call, kept so experiment results can be audited
//! (prompt, raw response, model, temperature, mode and timing).

use serde::{Deserialize, Serialize};

/// Everything needed to reproduce and audit one analysis request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub provider: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub mode: String,
    pub batch_size: usize,
    /// Lines actually sent to the model
    pub lines_sent: usize,
    /// Lines available before the batch-size cut
    pub lines_total: usize,
    pub system_prompt: String,
    pub prompt: String,
    pub raw_response: String,
    /// RFC 3339 start time of the request
    pub started_at: String,
    pub duration_ms: u64,
    pub parse_failed: bool,
    /// True when the response came from a cache instead of a live call
    #[serde(default)]
    pub cached: bool,
}
