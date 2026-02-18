use crate::diff::result::DiffEntry;

/// Format diff entries as JSON.
pub fn format_json(entries: &[DiffEntry]) -> String {
    serde_json::to_string_pretty(entries).unwrap_or_else(|_| "[]".to_string())
}
