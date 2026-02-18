//! Per-section statistics aggregation for diff reports.
//!
//! This module aggregates diff entries and analysis actions by top-level section,
//! providing summary statistics for easier understanding of where changes are
//! concentrated.
//!
//! ## Statistics Tracked
//!
//! - **Modified** — Elements that exist in both but differ
//! - **OnlyLeft** — Elements only in left config
//! - **OnlyRight** — Elements only in right config
//! - **Structural** — Schema or structural differences
//! - **ConflictManual** — Actions requiring manual intervention
//! - **SafeActions** — Actions that can be safely automated
//!
//! ## Path Format
//!
//! Paths are expected in dot notation: `root.section.subsection[index]`
//! The section is extracted as the second segment (after root).

use std::collections::HashMap;

use crate::analyze::AnalysisEntry;
use xml_diff_core::DiffEntry;

use super::{diff_path, SectionStats};

/// Summarize diff and action counts by top-level section.
///
/// Aggregates diff entries and analysis actions, grouping by the top-level
/// section name extracted from each entry's path.
///
/// # Arguments
///
/// * `entries` - Diff entries to aggregate
/// * `analysis` - Analysis actions to aggregate
///
/// # Returns
///
/// Vector of per-section statistics, sorted by section name
pub fn summarize_by_section(
    entries: &[DiffEntry],
    analysis: &[AnalysisEntry],
) -> Vec<SectionStats> {
    let mut stats: HashMap<String, SectionStats> = HashMap::new();

    for entry in entries {
        let section = section_from_path(diff_path(entry));
        let row = stats
            .entry(section.clone())
            .or_insert_with(|| SectionStats {
                section,
                modified: 0,
                only_left: 0,
                only_right: 0,
                structural: 0,
                conflict_manual: 0,
                safe_actions: 0,
            });

        match entry {
            DiffEntry::Modified { .. } => row.modified += 1,
            DiffEntry::OnlyLeft { .. } => row.only_left += 1,
            DiffEntry::OnlyRight { .. } => row.only_right += 1,
            DiffEntry::Structural { .. } => row.structural += 1,
            DiffEntry::Identical { .. } => {}
        }
    }

    for action in analysis {
        let section = section_from_path(&action.path);
        if let Some(row) = stats.get_mut(&section) {
            if action.safe {
                row.safe_actions += 1;
            } else {
                row.conflict_manual += 1;
            }
        }
    }

    let mut rows = stats.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| a.section.cmp(&b.section));
    rows
}

/// Extract section name from a dot-notation path.
///
/// Takes the second segment (after root) as the section name, stripping
/// any array index notation.
///
/// # Example
///
/// ```ignore
/// assert_eq!(section_from_path("pfsense.interfaces.wan"), "interfaces");
/// assert_eq!(section_from_path("root.filter.rule[3]"), "filter");
/// assert_eq!(section_from_path("root"), "(root)");
/// ```
///
/// # Arguments
///
/// * `path` - Dot-notation XML path
///
/// # Returns
///
/// Section name or "(root)" if path is too short
fn section_from_path(path: &str) -> String {
    let mut segments = path.split('.');
    let _root = segments.next(); // Skip root element
    let Some(second) = segments.next() else {
        return "(root)".to_string();
    };
    // Strip array index notation like "filter[3]" -> "filter"
    second.split('[').next().unwrap_or("(unknown)").to_string()
}
