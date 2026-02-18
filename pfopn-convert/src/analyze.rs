use serde::Serialize;
use xml_diff_core::DiffEntry;

/// Recommended action for a diff entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Safe insert from left into right tree.
    InsertLeftToRight,
    /// Safe insert from right into left tree.
    InsertRightToLeft,
    /// Requires manual reconciliation.
    ConflictManual,
    /// No action needed.
    Noop,
}

/// Action-oriented analysis record for one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisEntry {
    pub path: String,
    pub action: RecommendedAction,
    pub safe: bool,
    pub reason: String,
}

/// Build an actionable analysis from generic diff entries.
pub fn analyze(entries: &[DiffEntry]) -> Vec<AnalysisEntry> {
    entries
        .iter()
        .map(|entry| match entry {
            DiffEntry::Identical { path } => AnalysisEntry {
                path: path.clone(),
                action: RecommendedAction::Noop,
                safe: true,
                reason: "identical".to_string(),
            },
            DiffEntry::OnlyLeft { path, .. } => AnalysisEntry {
                path: path.clone(),
                action: RecommendedAction::InsertLeftToRight,
                safe: true,
                reason: "missing on right".to_string(),
            },
            DiffEntry::OnlyRight { path, .. } => AnalysisEntry {
                path: path.clone(),
                action: RecommendedAction::InsertRightToLeft,
                safe: true,
                reason: "missing on left".to_string(),
            },
            DiffEntry::Modified { path, .. } => AnalysisEntry {
                path: path.clone(),
                action: RecommendedAction::ConflictManual,
                safe: false,
                reason: "value differs on both sides".to_string(),
            },
            DiffEntry::Structural { path, description } => AnalysisEntry {
                path: path.clone(),
                action: RecommendedAction::ConflictManual,
                safe: false,
                reason: format!("structural mismatch: {description}"),
            },
        })
        .collect()
}

/// Count analysis outcomes by action type.
pub fn summarize_analysis(entries: &[AnalysisEntry]) -> String {
    let mut l2r = 0;
    let mut r2l = 0;
    let mut conflict = 0;
    let mut noop = 0;

    for entry in entries {
        match entry.action {
            RecommendedAction::InsertLeftToRight => l2r += 1,
            RecommendedAction::InsertRightToLeft => r2l += 1,
            RecommendedAction::ConflictManual => conflict += 1,
            RecommendedAction::Noop => noop += 1,
        }
    }

    format!(
        "insert_left_to_right={l2r} insert_right_to_left={r2l} conflict_manual={conflict} noop={noop}"
    )
}

#[cfg(test)]
mod tests {
    use super::{analyze, RecommendedAction};
    use xml_diff_core::{DiffEntry, XmlNode};

    #[test]
    fn classify_diff_entries() {
        let entries = vec![
            DiffEntry::OnlyLeft {
                path: "root.item[1]".to_string(),
                node: XmlNode::new("item"),
            },
            DiffEntry::OnlyRight {
                path: "root.item[2]".to_string(),
                node: XmlNode::new("item"),
            },
            DiffEntry::Modified {
                path: "root.value[1]".to_string(),
                left: "a".to_string(),
                right: "b".to_string(),
            },
        ];

        let actions = analyze(&entries);
        assert_eq!(actions[0].action, RecommendedAction::InsertLeftToRight);
        assert_eq!(actions[1].action, RecommendedAction::InsertRightToLeft);
        assert_eq!(actions[2].action, RecommendedAction::ConflictManual);
    }
}
