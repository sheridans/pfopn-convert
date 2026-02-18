use std::collections::HashMap;

use xml_diff_core::{diff, diff_with_options, parse, DiffEntry, DiffOptions};

#[test]
fn identical_inputs_have_no_entries_by_default() {
    let xml = br#"<root><items><item><id>a</id><value>1</value></item></items></root>"#;
    let left = parse(xml).expect("parse left");
    let right = parse(xml).expect("parse right");

    let entries = diff(&left, &right);
    assert!(entries.is_empty());
}

#[test]
fn key_field_matching_handles_reordered_repeated_elements() {
    let left_xml = br#"
<root>
  <rules>
    <rule><tracker>100</tracker><descr>A</descr></rule>
    <rule><tracker>200</tracker><descr>B</descr></rule>
  </rules>
</root>
"#;
    let right_xml = br#"
<root>
  <rules>
    <rule><tracker>200</tracker><descr>B changed</descr></rule>
    <rule><tracker>100</tracker><descr>A</descr></rule>
  </rules>
</root>
"#;

    let left = parse(left_xml).expect("parse left");
    let right = parse(right_xml).expect("parse right");

    let mut key_fields = HashMap::new();
    key_fields.insert("rule".to_string(), "tracker".to_string());

    let opts = DiffOptions {
        key_fields,
        ..DiffOptions::default()
    };

    let entries = diff_with_options(&left, &right, &opts);
    assert!(entries
        .iter()
        .any(|e| matches!(e, DiffEntry::Modified { path, .. } if path.contains("rule[200]"))));
    assert!(!entries
        .iter()
        .any(|e| matches!(e, DiffEntry::OnlyLeft { .. } | DiffEntry::OnlyRight { .. })));
}
