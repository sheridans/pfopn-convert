use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn path_as_str(path: &Path) -> &str {
    path.to_str().expect("path should be valid utf-8")
}

#[test]
fn migrate_check_passes_for_minimal_valid_target() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("cfg.xml");
    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><filter/></pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("migrate-check")
        .arg(path_as_str(&input))
        .arg("--to")
        .arg("pfsense")
        .assert()
        .success()
        .stdout(predicate::str::contains("migrate_check pass=true"));
}

#[test]
fn migrate_check_fails_on_missing_interface_reference() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("cfg.xml");
    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><filter><rule><interface>opt9</interface></rule></filter></pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("migrate-check")
        .arg(path_as_str(&input))
        .arg("--to")
        .arg("pfsense")
        .assert()
        .failure()
        .stdout(predicate::str::contains("[FAIL] interface_integrity"))
        .stderr(predicate::str::contains("migrate-check failed"));
}

#[test]
fn migrate_check_target_version_overrides_profile_selection() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("cfg.xml");
    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><filter/></pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("migrate-check")
        .arg(path_as_str(&input))
        .arg("--to")
        .arg("pfsense")
        .arg("--target-version")
        .arg("99")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "profile_baseline: advisory profile warnings=1",
        ));
}

#[test]
fn migrate_check_fails_on_dhcp_backend_inconsistency() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("cfg.xml");
    fs::write(
        &input,
        r#"<pfsense>
            <system/>
            <interfaces><lan/></interfaces>
            <filter/>
            <dhcpbackend>isc</dhcpbackend>
            <kea><dhcp4><general><enabled>1</enabled></general></dhcp4></kea>
        </pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("migrate-check")
        .arg(path_as_str(&input))
        .arg("--to")
        .arg("pfsense")
        .assert()
        .failure()
        .stdout(predicate::str::contains("[FAIL] dhcp_integrity"))
        .stderr(predicate::str::contains("migrate-check failed"));
}
