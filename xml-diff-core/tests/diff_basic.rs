use std::path::PathBuf;

use xml_diff_core::{
    diff, diff_with_options, format_json, format_summary, format_text, parse_file, DiffEntry,
    DiffOptions,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

#[test]
fn diff_detects_modifications_and_insertions() {
    let left = parse_file(&fixture("fixtures/simple_a.xml")).expect("left parse");
    let right = parse_file(&fixture("fixtures/simple_b.xml")).expect("right parse");

    let entries = diff(&left, &right);

    let modified_count = entries
        .iter()
        .filter(|e| matches!(e, DiffEntry::Modified { .. }))
        .count();
    assert!(modified_count >= 2);

    let text = format_text(&entries);
    let json = format_json(&entries);
    let summary = format_summary(&entries);

    assert!(text.contains("~ config.settings[1].name[1]") || text.contains("~ config.settings[1]"));
    assert!(json.contains("\"type\""));
    assert!(summary.contains("modified="));
}

#[test]
fn ignore_paths_skips_version_differences() {
    let left = parse_file(&fixture("fixtures/simple_a.xml")).expect("left parse");
    let right = parse_file(&fixture("fixtures/simple_b.xml")).expect("right parse");

    let opts = DiffOptions {
        ignore_paths: vec!["version".to_string()],
        ..DiffOptions::default()
    };

    let entries = diff_with_options(&left, &right, &opts);

    assert!(!entries.iter().any(|entry| match entry {
        DiffEntry::Modified { path, .. } => path.contains("version"),
        _ => false,
    }));
}
