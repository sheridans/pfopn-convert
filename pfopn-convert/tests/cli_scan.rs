use std::path::PathBuf;
use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

#[test]
fn scan_reports_tailscale_presence_on_opnsense_fixture() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("scan")
        .arg(fixture("fixtures/opnsense-base-with-tailscale.xml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("platform=opnsense"))
        .stdout(predicate::str::contains("known_plugins_present"))
        .stdout(predicate::str::contains("- tailscale"));
}

#[test]
fn scan_json_reports_unsupported_plugin_packages() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    fs::write(
        &input,
        r#"<pfsense>
            <system/>
            <installedpackages>
                <package><name>unknownpkg</name></package>
            </installedpackages>
        </pfsense>"#,
    )
    .expect("write src");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("scan")
        .arg(path_as_str(&input))
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"unsupported_plugins\""))
        .stdout(predicate::str::contains("unknownpkg"));
}

#[test]
fn scan_reports_target_incompatible_plugin_from_matrix() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    fs::write(
        &input,
        r#"<pfsense>
            <system/>
            <installedpackages>
                <package><name>pfBlockerNG</name></package>
            </installedpackages>
        </pfsense>"#,
    )
    .expect("write src");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"))
        .arg("scan")
        .arg(path_as_str(&input))
        .arg("--to")
        .arg("opnsense")
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan output");
    assert!(output.status.success(), "scan should succeed");

    let report: Value = serde_json::from_slice(&output.stdout).expect("json parse");
    let unsupported = report["unsupported_plugins"]
        .as_array()
        .expect("unsupported_plugins array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    let missing_target = report["missing_target_compat"]
        .as_array()
        .expect("missing_target_compat array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();

    assert!(unsupported.contains(&"pfblockerng"));
    assert!(missing_target.contains(&"pfblockerng"));
}

#[test]
fn scan_classifies_parseable_bridges_as_supported() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    let output = cmd
        .arg("scan")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan output");
    assert!(output.status.success(), "scan should succeed");

    let report: Value = serde_json::from_slice(&output.stdout).expect("json parse");
    let supported = report["supported_sections"]
        .as_array()
        .expect("supported_sections array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    let review = report["review_sections"]
        .as_array()
        .expect("review_sections array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();

    assert!(
        supported.contains(&"bridges"),
        "bridges should be supported"
    );
    assert!(!review.contains(&"bridges"), "bridges should not be review");
}

#[test]
fn scan_classifies_pfsense_dhcpbackend_as_supported() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    let output = cmd
        .arg("scan")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan output");
    assert!(output.status.success(), "scan should succeed");

    let report: Value = serde_json::from_slice(&output.stdout).expect("json parse");
    let supported = report["supported_sections"]
        .as_array()
        .expect("supported_sections array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    let review = report["review_sections"]
        .as_array()
        .expect("review_sections array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();

    assert!(
        supported.contains(&"dhcpbackend"),
        "dhcpbackend should be supported"
    );
    assert!(
        !review.contains(&"dhcpbackend"),
        "dhcpbackend should not be review"
    );
}

#[test]
fn scan_includes_target_version_metadata_in_text_output() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("scan")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--to")
        .arg("pfsense")
        .arg("--target-version")
        .arg("24.7")
        .assert()
        .success()
        .stdout(predicate::str::contains("target_platform=pfsense"))
        .stdout(predicate::str::contains("target_version=24.7"));
}

#[test]
fn scan_json_includes_target_version_metadata() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"))
        .arg("scan")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--to")
        .arg("pfsense")
        .arg("--target-version")
        .arg("24.7")
        .arg("--format")
        .arg("json")
        .output()
        .expect("scan output");
    assert!(output.status.success(), "scan should succeed");

    let report: Value = serde_json::from_slice(&output.stdout).expect("json parse");
    assert_eq!(report["target_platform"].as_str(), Some("pfsense"));
    assert_eq!(report["target_version"].as_str(), Some("24.7"));
}

#[test]
fn scan_reports_mappings_dir_source() {
    let dir = tempdir().expect("tempdir");
    let plugins_path = dir.path().join("plugins.toml");
    fs::write(
        &plugins_path,
        r#"
[[plugin]]
id = "wireguard"
pfsense_markers = ["wireguard"]
opnsense_markers = ["wireguard"]
compatible_targets = ["pfsense", "opnsense"]
status = "supported"
note = "test"
"#,
    )
    .expect("plugins write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("scan")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--mappings-dir")
        .arg(path_as_str(dir.path()))
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Using mappings: file:"));
}

fn path_as_str(path: &Path) -> &str {
    path.to_str().expect("path should be utf8")
}
