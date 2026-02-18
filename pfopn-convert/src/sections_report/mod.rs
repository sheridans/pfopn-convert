//! Section-level diff analysis and reporting.
//!
//! Analyzes configuration differences at the section level, providing inventory,
//! mapping suggestions, and statistics. This helps users understand structural
//! differences between configs at a high level before diving into detailed diffs.
//!
//! ## Analysis Features
//!
//! - **Section inventory** — What sections exist in each config
//! - **Mapping suggestions** — Suggests correspondences for renamed sections
//! - **Diff statistics** — Per-section counts of changes
//! - **Extras detection** — Finds sections that may have moved or been renamed
//!
//! ## Use Cases
//!
//! - Pre-migration: Understand what sections exist in source vs target
//! - Post-diff: Summarize changes by section for easier review
//! - Troubleshooting: Identify sections that may have moved between platforms

use std::collections::{BTreeSet, HashSet};

use serde::Serialize;
use xml_diff_core::XmlNode;

use crate::detect::{detect_version_info, VersionDetection};
use crate::known_mappings::KnownSectionMapping;
use xml_diff_core::DiffEntry;

mod extras;
mod paths;
mod stats;
mod wireguard;

pub use stats::summarize_by_section;

/// Suggested mapping between differing section names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuggestedMapping {
    pub left: String,
    pub right: String,
    pub confidence: String,
    pub reason: String,
}

/// Heuristic finding from the optional extras pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtraFinding {
    pub kind: String,
    pub section: String,
    pub side: String,
    pub paths: Vec<String>,
    pub reason: String,
}

/// Extras grouped by section identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtraGroup {
    pub section: String,
    pub findings: Vec<ExtraFinding>,
}

/// Top-level section inventory across two XML roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionInventory {
    pub left_root: String,
    pub right_root: String,
    pub left_version: VersionDetection,
    pub right_version: VersionDetection,
    pub left_dhcp_backend: crate::backend_detect::BackendDetection,
    pub right_dhcp_backend: crate::backend_detect::BackendDetection,
    pub mappings_source: String,
    pub left_sections: Vec<String>,
    pub right_sections: Vec<String>,
    pub common: Vec<String>,
    pub left_only: Vec<String>,
    pub right_only: Vec<String>,
    pub suggested_mappings: Vec<SuggestedMapping>,
    pub left_alias_paths: Vec<String>,
    pub right_alias_paths: Vec<String>,
    pub extras: Vec<ExtraFinding>,
    pub extras_grouped: Vec<ExtraGroup>,
    pub unmatched_left_only: Vec<String>,
    pub unmatched_right_only: Vec<String>,
}

/// Optional compact extras-only JSON report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtrasJsonReport {
    pub mappings_source: String,
    pub extras_grouped: Vec<ExtraGroup>,
    pub unmatched_left_only: Vec<String>,
    pub unmatched_right_only: Vec<String>,
}

/// Per-section diff/action counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionStats {
    pub section: String,
    pub modified: usize,
    pub only_left: usize,
    pub only_right: usize,
    pub structural: usize,
    pub conflict_manual: usize,
    pub safe_actions: usize,
}

/// Build section inventory comparing two configs.
///
/// Analyzes top-level sections in both configs and identifies:
/// - Sections present in both (common)
/// - Sections only in left
/// - Sections only in right
/// - Suggested mappings for renamed sections
/// - Optional extras (moved/renamed section hints)
///
/// # Arguments
///
/// * `left` - First config root
/// * `right` - Second config root
/// * `include_extras` - Enable heuristic extras detection
/// * `mappings` - Known section name mappings between platforms
///
/// # Returns
///
/// Complete section inventory with mapping suggestions
pub fn build_inventory(
    left: &XmlNode,
    right: &XmlNode,
    include_extras: bool,
    mappings: &[KnownSectionMapping],
    mappings_source: String,
) -> SectionInventory {
    let left_sections = paths::collect_top_sections(left);
    let right_sections = paths::collect_top_sections(right);

    let left_set: BTreeSet<String> = left_sections.iter().cloned().collect();
    let right_set: BTreeSet<String> = right_sections.iter().cloned().collect();

    let common = left_set
        .intersection(&right_set)
        .cloned()
        .collect::<Vec<_>>();
    let left_only = left_set.difference(&right_set).cloned().collect::<Vec<_>>();
    let right_only = right_set.difference(&left_set).cloned().collect::<Vec<_>>();

    let mut suggested_mappings = Vec::new();
    let mut matched_left_only = HashSet::new();
    let mut matched_right_only = HashSet::new();

    for mapping in mappings {
        if !left_only.iter().any(|x| x == &mapping.left) {
            continue;
        }
        for candidate in &mapping.right {
            let right_top_match = right_only
                .iter()
                .any(|x| paths::normalize(x) == paths::normalize(candidate));
            let right_nested = paths::find_paths_by_canonical_tag(right, candidate);
            if right_top_match || !right_nested.is_empty() {
                suggested_mappings.push(SuggestedMapping {
                    left: mapping.left.clone(),
                    right: candidate.clone(),
                    confidence: if right_top_match { "high" } else { "medium" }.to_string(),
                    reason: format!("{} [{}]", mapping.note, mapping.category),
                });
                matched_left_only.insert(mapping.left.clone());
                if let Some(actual) = right_only
                    .iter()
                    .find(|x| paths::normalize(x) == paths::normalize(candidate))
                    .cloned()
                {
                    matched_right_only.insert(actual);
                }
            }
        }
    }

    for left_name in &left_only {
        for right_name in &right_only {
            if paths::normalize(left_name) == paths::normalize(right_name) {
                suggested_mappings.push(SuggestedMapping {
                    left: left_name.clone(),
                    right: right_name.clone(),
                    confidence: "medium".to_string(),
                    reason: "normalized names match".to_string(),
                });
                matched_left_only.insert(left_name.clone());
                matched_right_only.insert(right_name.clone());
            }
        }
    }

    let left_alias_paths = paths::find_alias_paths(left);
    let right_alias_paths = paths::find_alias_paths(right);

    let extras = if include_extras {
        extras::build_all_extras(
            left,
            right,
            &left_only,
            &right_only,
            &left_sections,
            mappings,
        )
    } else {
        Vec::new()
    };
    let extras_grouped = extras::group_extras(&extras);

    for finding in &extras {
        if finding.kind == "nested_presence" {
            if finding.side == "left_only" {
                matched_left_only.insert(finding.section.clone());
            } else if finding.side == "right_only" {
                matched_right_only.insert(finding.section.clone());
            }
        }
    }

    let unmatched_left_only = left_only
        .iter()
        .filter(|s| !matched_left_only.contains(*s))
        .cloned()
        .collect::<Vec<_>>();
    let unmatched_right_only = right_only
        .iter()
        .filter(|s| !matched_right_only.contains(*s))
        .cloned()
        .collect::<Vec<_>>();

    SectionInventory {
        left_root: left.tag.clone(),
        right_root: right.tag.clone(),
        left_version: detect_version_info(left),
        right_version: detect_version_info(right),
        left_dhcp_backend: crate::backend_detect::detect_dhcp_backend(left),
        right_dhcp_backend: crate::backend_detect::detect_dhcp_backend(right),
        mappings_source,
        left_sections,
        right_sections,
        common,
        left_only,
        right_only,
        suggested_mappings,
        left_alias_paths,
        right_alias_paths,
        extras,
        extras_grouped,
        unmatched_left_only,
        unmatched_right_only,
    }
}

/// Build extras-only JSON payload from inventory.
pub fn extras_json_report(inv: &SectionInventory) -> ExtrasJsonReport {
    ExtrasJsonReport {
        mappings_source: inv.mappings_source.clone(),
        extras_grouped: inv.extras_grouped.clone(),
        unmatched_left_only: inv.unmatched_left_only.clone(),
        unmatched_right_only: inv.unmatched_right_only.clone(),
    }
}

pub(crate) fn diff_path(entry: &DiffEntry) -> &str {
    match entry {
        DiffEntry::Identical { path }
        | DiffEntry::Modified { path, .. }
        | DiffEntry::OnlyLeft { path, .. }
        | DiffEntry::OnlyRight { path, .. }
        | DiffEntry::Structural { path, .. } => path,
    }
}
