//! Labelled dataset rows (JSON Lines): `{id, line, label, attack_type, injected, variant}`.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub id: String,
    /// One Apache combined-format log line
    pub line: String,
    /// "attack" or "benign"
    pub label: String,
    #[serde(default)]
    pub attack_type: Option<String>,
    #[serde(default)]
    pub injected: bool,
    #[serde(default)]
    pub variant: Option<String>,
    /// For injected rows: id of the clean row they were made from
    #[serde(default)]
    pub source_id: Option<String>,
}

impl Row {
    pub fn is_attack(&self) -> bool {
        matches!(
            self.label.to_lowercase().as_str(),
            "attack" | "malicious" | "anomalous" | "1"
        )
    }
}

pub fn read_rows(path: &Path) -> Result<Vec<Row>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str(l).map_err(|e| format!("line {}: {e}", i + 1)))
        .collect()
}

pub fn write_jsonl<T: Serialize>(path: &Path, items: &[T]) -> Result<(), String> {
    let mut out = String::new();
    for item in items {
        out.push_str(&serde_json::to_string(item).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    std::fs::write(path, out).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reject duplicate row ids (e.g. the same lines supplied twice), which would
/// silently double-count them.
pub fn ensure_unique_ids(rows: &[Row]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    match rows.iter().find(|r| !seen.insert(r.id.as_str())) {
        Some(r) => Err(format!(
            "duplicate row id '{}': each row may appear only once",
            r.id
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_ids_are_rejected() {
        let row = |id: &str| Row {
            id: id.into(),
            line: String::new(),
            label: "attack".into(),
            attack_type: None,
            injected: false,
            variant: None,
            source_id: None,
        };
        assert!(ensure_unique_ids(&[row("a"), row("b")]).is_ok());
        assert!(ensure_unique_ids(&[row("a"), row("a")])
            .unwrap_err()
            .contains("'a'"));
    }
}
