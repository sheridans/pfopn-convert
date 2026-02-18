use std::path::PathBuf;

use xml_diff_core::parse_file;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

#[test]
fn parses_attributes_empty_and_nested_elements() {
    let node = parse_file(&fixture("fixtures/simple_a.xml")).expect("parse should succeed");
    assert_eq!(node.tag, "config");

    let settings = node.get_child("settings").expect("settings should exist");
    assert!(settings.get_child("enabled").is_some());

    let items = node.get_child("items").expect("items should exist");
    let item_nodes = items.get_children("item");
    assert_eq!(item_nodes.len(), 3);
    assert_eq!(item_nodes[0].attributes.get("id"), Some(&"1".to_string()));
}

#[test]
fn parses_real_world_roots() {
    let pf = parse_file(&fixture("fixtures/pfsense-base.xml")).expect("pfSense fixture parse");
    let opn = parse_file(&fixture("fixtures/opnsense-base.xml")).expect("OPNsense fixture parse");

    assert_eq!(pf.tag, "pfsense");
    assert_eq!(opn.tag, "opnsense");
}
