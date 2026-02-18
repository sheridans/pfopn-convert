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
fn diff_summary_runs_end_to_end() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("diff")
        .arg(fixture("fixtures/simple_a.xml"))
        .arg(fixture("fixtures/simple_b.xml"))
        .arg("--summary")
        .arg("--section-summary")
        .assert()
        .success()
        .stdout(predicate::str::contains("backend_transition="))
        .stdout(predicate::str::contains("modified="))
        .stdout(predicate::str::contains("Section Summary"));
}

#[test]
fn diff_json_outputs_structured_entries() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("diff")
        .arg(fixture("fixtures/simple_a.xml"))
        .arg(fixture("fixtures/simple_b.xml"))
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\""))
        .stdout(predicate::str::contains("\"backend_transition\""));
}

#[test]
fn diff_writes_plan_file() {
    let dir = tempdir().expect("tempdir");
    let plan_path = dir.path().join("plan.json");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("diff")
        .arg(fixture("fixtures/simple_a.xml"))
        .arg(fixture("fixtures/simple_b.xml"))
        .arg("--plan")
        .arg(&plan_path)
        .assert()
        .success();

    let contents = fs::read_to_string(plan_path).expect("plan file should be readable");
    assert!(contents.contains("conflict_manual"));
}

#[test]
fn diff_writes_output_xml_with_safe_inserts() {
    let dir = tempdir().expect("tempdir");
    let left_path = dir.path().join("left.xml");
    let right_path = dir.path().join("right.xml");
    let output_path = dir.path().join("merged.xml");

    fs::write(
        &left_path,
        "<root><items><item><id>1</id></item><item><id>2</id></item></items></root>",
    )
    .expect("left write");
    fs::write(
        &right_path,
        "<root><items><item><id>1</id></item></items></root>",
    )
    .expect("right write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("diff")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--output")
        .arg(path_as_str(&output_path))
        .arg("--merge-to")
        .arg("right")
        .assert()
        .success();

    let merged = fs::read_to_string(output_path).expect("merged file");
    assert!(merged.contains("<id>2</id>"));
}

#[test]
fn diff_output_transfers_openvpn_certs_by_default_and_can_disable() {
    let dir = tempdir().expect("tempdir");
    let left_path = dir.path().join("left.xml");
    let right_path = dir.path().join("right.xml");
    let output_default = dir.path().join("merged_default.xml");
    let output_disabled = dir.path().join("merged_disabled.xml");

    fs::write(
        &left_path,
        r#"<pfsense>
            <system/>
            <openvpn><openvpn-server><certref>cert-pf</certref></openvpn-server></openvpn>
            <cert><refid>cert-pf</refid></cert>
        </pfsense>"#,
    )
    .expect("left write");
    fs::write(
        &right_path,
        r#"<opnsense>
            <system/>
            <openvpn><openvpn-server><certref>cert-opn</certref></openvpn-server></openvpn>
            <cert><refid>cert-opn</refid></cert>
        </opnsense>"#,
    )
    .expect("right write");

    let mut cmd_default = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd_default
        .arg("diff")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--output")
        .arg(path_as_str(&output_default))
        .arg("--merge-to")
        .arg("right")
        .assert()
        .success();

    let merged_default = fs::read_to_string(&output_default).expect("default merged file");
    assert!(merged_default.contains("<refid>cert-pf</refid>"));

    let mut cmd_disabled = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd_disabled
        .arg("diff")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--output")
        .arg(path_as_str(&output_disabled))
        .arg("--merge-to")
        .arg("right")
        .arg("--no-transfer-certs")
        .assert()
        .success();

    let merged_disabled = fs::read_to_string(&output_disabled).expect("disabled merged file");
    assert!(!merged_disabled.contains("<refid>cert-pf</refid>"));
}

#[test]
fn diff_output_transfers_wireguard_section_when_missing_on_target() {
    let dir = tempdir().expect("tempdir");
    let left_path = dir.path().join("left.xml");
    let right_path = dir.path().join("right.xml");
    let output_path = dir.path().join("merged.xml");

    fs::write(
        &left_path,
        r#"<pfsense>
            <wireguard><tunnel><enabled>1</enabled></tunnel></wireguard>
        </pfsense>"#,
    )
    .expect("left write");
    fs::write(&right_path, r#"<opnsense><system/></opnsense>"#).expect("right write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("diff")
        .arg(path_as_str(&left_path))
        .arg(path_as_str(&right_path))
        .arg("--output")
        .arg(path_as_str(&output_path))
        .arg("--merge-to")
        .arg("right")
        .assert()
        .success();

    let merged = fs::read_to_string(output_path).expect("merged file");
    assert!(merged.contains("<wireguard>"));
}

#[test]
fn diff_rejects_output_overwriting_input() {
    let input = fixture("fixtures/simple_a.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("diff")
        .arg(&input)
        .arg(fixture("fixtures/simple_b.xml"))
        .arg("--output")
        .arg(&input)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to overwrite source file",
        ));
}

fn path_as_str(path: &Path) -> &str {
    path.to_str().expect("path should be valid utf-8")
}
