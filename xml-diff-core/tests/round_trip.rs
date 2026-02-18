use std::path::PathBuf;

use xml_diff_core::{parse, parse_file, write, write_file};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

#[test]
fn parse_write_parse_round_trip_preserves_tree_shape() {
    let source_path = fixture("fixtures/simple_a.xml");
    let first = parse_file(&source_path).expect("initial parse should succeed");

    let written = write(&first).expect("write should succeed");
    let second = parse(&written).expect("re-parse should succeed");

    assert_eq!(first, second);
}

#[test]
fn parse_and_write_file_round_trip() {
    let source_path = fixture("fixtures/simple_b.xml");
    let out_dir = tempfile::tempdir().expect("tempdir should be created");
    let out_path = out_dir.path().join("roundtrip.xml");

    let node = parse_file(&source_path).expect("parse should succeed");
    write_file(&node, &out_path).expect("write_file should succeed");

    let reparsed = parse_file(&out_path).expect("parse_file should succeed");
    assert_eq!(node, reparsed);
}
