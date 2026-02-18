use crate::diff::result::DiffEntry;

/// Format diff entries as plain text.
pub fn format_text(entries: &[DiffEntry]) -> String {
    let mut lines = Vec::with_capacity(entries.len() + 1);
    for entry in entries {
        match entry {
            DiffEntry::Identical { path } => lines.push(format!("= {path}")),
            DiffEntry::Modified { path, left, right } => {
                lines.push(format!("~ {path}"));
                lines.push(format!("  left:  {left}"));
                lines.push(format!("  right: {right}"));
            }
            DiffEntry::OnlyLeft { path, .. } => lines.push(format!("- {path}")),
            DiffEntry::OnlyRight { path, .. } => lines.push(format!("+ {path}")),
            DiffEntry::Structural { path, description } => {
                lines.push(format!("! {path}: {description}"));
            }
        }
    }
    lines.join("\n")
}

/// Format a simple summary of diff counts.
pub fn format_summary(entries: &[DiffEntry]) -> String {
    let mut identical = 0;
    let mut modified = 0;
    let mut only_left = 0;
    let mut only_right = 0;
    let mut structural = 0;

    for entry in entries {
        match entry {
            DiffEntry::Identical { .. } => identical += 1,
            DiffEntry::Modified { .. } => modified += 1,
            DiffEntry::OnlyLeft { .. } => only_left += 1,
            DiffEntry::OnlyRight { .. } => only_right += 1,
            DiffEntry::Structural { .. } => structural += 1,
        }
    }

    format!(
        "identical={identical} modified={modified} only_left={only_left} only_right={only_right} structural={structural}"
    )
}
