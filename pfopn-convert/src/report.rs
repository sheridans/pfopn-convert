use colored::Colorize;
use xml_diff_core::{format_summary, format_text, DiffEntry};

use crate::analyze::{AnalysisEntry, RecommendedAction};
use crate::sections_report::{SectionInventory, SectionStats};

/// Render diff entries for terminal output.
pub fn render_text(entries: &[DiffEntry]) -> String {
    let raw = format_text(entries);
    let mut out = Vec::new();

    for line in raw.lines() {
        let colored = if line.starts_with('+') {
            line.green().to_string()
        } else if line.starts_with('-') {
            line.red().to_string()
        } else if line.starts_with('~') {
            line.yellow().to_string()
        } else if line.starts_with('!') {
            line.magenta().to_string()
        } else {
            line.to_string()
        };
        out.push(colored);
    }

    out.join("\n")
}

/// Render summary counts for terminal output.
pub fn render_summary(entries: &[DiffEntry]) -> String {
    format_summary(entries).cyan().to_string()
}

/// Render action analysis lines.
pub fn render_analysis(entries: &[AnalysisEntry]) -> String {
    let mut out = Vec::new();
    for entry in entries {
        let prefix = match entry.action {
            RecommendedAction::InsertLeftToRight | RecommendedAction::InsertRightToLeft => "SAFE",
            RecommendedAction::ConflictManual => "MANUAL",
            RecommendedAction::Noop => "NOOP",
        };
        out.push(format!(
            "{prefix} action={:?} path={} reason={}",
            entry.action, entry.path, entry.reason
        ));
    }
    out.join("\n")
}

/// Render per-section diff/action stats.
pub fn render_section_stats(rows: &[SectionStats]) -> String {
    let mut rows_sorted = rows.to_vec();
    rows_sorted.sort_by(|a, b| {
        b.conflict_manual
            .cmp(&a.conflict_manual)
            .then_with(|| b.modified.cmp(&a.modified))
            .then_with(|| a.section.cmp(&b.section))
    });

    let mut out = Vec::new();
    out.push("section_summary".to_string());
    for row in rows_sorted {
        out.push(format!(
            "- {}: modified={} only_left={} only_right={} structural={} conflicts={} safe={}",
            row.section,
            row.modified,
            row.only_left,
            row.only_right,
            row.structural,
            row.conflict_manual,
            row.safe_actions
        ));
    }
    out.join("\n")
}

/// Render top-level section inventory and mapping hints.
pub fn render_section_inventory(inv: &SectionInventory) -> String {
    let mut out = Vec::new();
    out.push("roots".to_string());
    out.push(format!(
        "- left: {} version={} source={} confidence={}",
        inv.left_root, inv.left_version.value, inv.left_version.source, inv.left_version.confidence
    ));
    out.push(format!(
        "- right: {} version={} source={} confidence={}",
        inv.right_root,
        inv.right_version.value,
        inv.right_version.source,
        inv.right_version.confidence
    ));
    out.push(String::new());
    out.push("dhcp_backend".to_string());
    out.push(format!(
        "- left: {} ({})",
        inv.left_dhcp_backend.mode, inv.left_dhcp_backend.reason
    ));
    append_list_with_prefix(
        &mut out,
        "  evidence: ",
        &inv.left_dhcp_backend.evidence_paths,
    );
    out.push(format!(
        "- right: {} ({})",
        inv.right_dhcp_backend.mode, inv.right_dhcp_backend.reason
    ));
    append_list_with_prefix(
        &mut out,
        "  evidence: ",
        &inv.right_dhcp_backend.evidence_paths,
    );
    out.push(String::new());
    out.push("common".to_string());
    append_list(&mut out, &inv.common);
    out.push(String::new());
    out.push("left_only".to_string());
    append_list(&mut out, &inv.left_only);
    out.push(String::new());
    out.push("right_only".to_string());
    append_list(&mut out, &inv.right_only);
    out.push(String::new());
    out.push("suggested_mappings".to_string());
    if inv.suggested_mappings.is_empty() {
        out.push("- none".to_string());
    } else {
        for map in &inv.suggested_mappings {
            out.push(format!(
                "- {} -> {} [{}] {}",
                map.left, map.right, map.confidence, map.reason
            ));
        }
    }
    out.push(String::new());
    out.push("alias_locations".to_string());
    out.push("left".to_string());
    append_list(&mut out, &inv.left_alias_paths);
    out.push("right".to_string());
    append_list(&mut out, &inv.right_alias_paths);
    if !inv.extras.is_empty() {
        out.push(String::new());
        out.push("extras".to_string());
        for finding in &inv.extras {
            out.push(format!(
                "- {} {} [{}] {}",
                finding.side, finding.section, finding.kind, finding.reason
            ));
            if !finding.paths.is_empty() {
                for path in &finding.paths {
                    out.push(format!("  path: {path}"));
                }
            }
        }
    }
    if !inv.extras.is_empty() {
        out.push(String::new());
        out.push("unmatched_left_only".to_string());
        append_list(&mut out, &inv.unmatched_left_only);
        out.push("unmatched_right_only".to_string());
        append_list(&mut out, &inv.unmatched_right_only);
    }

    out.join("\n")
}

fn append_list(out: &mut Vec<String>, items: &[String]) {
    if items.is_empty() {
        out.push("- none".to_string());
        return;
    }
    for item in items {
        out.push(format!("- {item}"));
    }
}

fn append_list_with_prefix(out: &mut Vec<String>, prefix: &str, items: &[String]) {
    if items.is_empty() {
        out.push(format!("{prefix}none"));
        return;
    }
    for item in items {
        out.push(format!("{prefix}{item}"));
    }
}
