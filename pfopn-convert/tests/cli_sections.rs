use std::path::PathBuf;
use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

#[test]
fn sections_lists_inventory_and_mapping_hints() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg(fixture("fixtures/opnsense-base.xml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("roots"))
        .stdout(predicate::str::contains("- left: pfsense"))
        .stdout(predicate::str::contains("- right: opnsense"))
        .stdout(predicate::str::contains("dhcp_backend"))
        .stdout(predicate::str::contains("alias_locations"));
}

#[test]
fn sections_json_outputs_structured_payload() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"left_sections\""));
}

#[test]
fn sections_extras_emits_heuristic_hints() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--extras")
        .assert()
        .success()
        .stdout(predicate::str::contains("extras"))
        .stdout(predicate::str::contains("nested_presence"))
        .stdout(predicate::str::contains("vpn_dependency_gap"))
        .stdout(predicate::str::contains("backend_transition"));
}

#[test]
fn sections_extras_json_emits_grouped_payload() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--extras-json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"extras_grouped\""))
        .stdout(predicate::str::contains("vpn_dependency_gap"))
        .stdout(predicate::str::contains("backend_transition"))
        .stdout(predicate::str::contains("\"unmatched_left_only\""))
        .stdout(predicate::str::contains("\"unmatched_right_only\""));
}

#[test]
fn sections_uses_custom_mappings_file() {
    let dir = tempdir().expect("tempdir");
    let left_path = dir.path().join("left.xml");
    let right_path = dir.path().join("right.xml");
    let mappings_path = dir.path().join("mappings.toml");

    fs::write(&left_path, "<pfsense><foo/></pfsense>").expect("left write");
    fs::write(&right_path, "<opnsense><bar/></opnsense>").expect("right write");
    fs::write(
        &mappings_path,
        r#"
[[mapping]]
left = "foo"
right = ["bar"]
category = "test"
note = "custom test mapping"
"#,
    )
    .expect("mappings write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--format")
        .arg("json")
        .arg("--mappings-file")
        .arg(path_as_str(&mappings_path))
        .assert()
        .success()
        .stdout(predicate::str::contains("\"left\": \"foo\""))
        .stdout(predicate::str::contains("\"right\": \"bar\""))
        .stdout(predicate::str::contains("custom test mapping"));
}

#[test]
fn sections_reports_mappings_source_when_overridden() {
    let dir = tempdir().expect("tempdir");
    let mappings_path = dir.path().join("mappings.toml");

    fs::write(
        &mappings_path,
        r#"
[[mapping]]
left = "aliases"
right = ["Alias"]
category = "test"
note = "override"
"#,
    )
    .expect("mappings write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--mappings-file")
        .arg(path_as_str(&mappings_path))
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Using mappings: file:"));
}

#[test]
fn sections_reports_mappings_dir_when_overridden() {
    let dir = tempdir().expect("tempdir");
    let mappings_path = dir.path().join("sections.toml");

    fs::write(
        &mappings_path,
        r#"
[[mapping]]
left = "aliases"
right = ["Alias"]
category = "test"
note = "override"
"#,
    )
    .expect("mappings write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--mappings-dir")
        .arg(path_as_str(dir.path()))
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Using mappings: file:"));
}

#[test]
fn sections_extras_reports_wireguard_gap() {
    let dir = tempdir().expect("tempdir");
    let left_path = dir.path().join("left.xml");
    let right_path = dir.path().join("right.xml");

    fs::write(
        &left_path,
        r#"<pfsense><wireguard><tunnel><enabled>1</enabled></tunnel></wireguard></pfsense>"#,
    )
    .expect("left write");
    fs::write(&right_path, r#"<opnsense><system/></opnsense>"#).expect("right write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--extras")
        .assert()
        .success()
        .stdout(predicate::str::contains("wireguard_dependency_gap"));
}

#[test]
fn sections_extras_reports_ipsec_dependency_gap() {
    let dir = tempdir().expect("tempdir");
    let left_path = dir.path().join("left.xml");
    let right_path = dir.path().join("right.xml");

    fs::write(
        &left_path,
        r#"<pfsense>
            <interfaces><wan/></interfaces>
            <ipsec><phase1><interface>wan</interface><certref>cert1</certref></phase1></ipsec>
            <cert><refid>cert1</refid></cert>
        </pfsense>"#,
    )
    .expect("left write");
    fs::write(
        &right_path,
        r#"<opnsense><interfaces><lan/></interfaces><OPNsense><IPsec/></OPNsense></opnsense>"#,
    )
    .expect("right write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("sections")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--extras")
        .assert()
        .success()
        .stdout(predicate::str::contains("ipsec_dependency_gap"))
        .stdout(predicate::str::contains("missing_cert: cert1"))
        .stdout(predicate::str::contains("missing_interface: wan"));
}

fn path_as_str(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}
