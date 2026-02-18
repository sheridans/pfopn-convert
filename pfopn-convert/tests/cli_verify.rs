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
fn verify_passes_for_real_fixture() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("result errors=0"));
}

#[test]
fn verify_fails_on_missing_required_section() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("broken.xml");
    fs::write(&input, r#"<pfsense><system/></pfsense>"#).expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(path_as_str(&input))
        .assert()
        .failure()
        .stderr(predicate::str::contains("verify failed"))
        .stdout(predicate::str::contains("missing_required_section"));
}

#[test]
fn verify_warns_on_missing_schedule_reference() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("sched-missing.xml");
    fs::write(
        &input,
        r#"<pfsense>
            <system/>
            <interfaces><lan/></interfaces>
            <filter><rule><interface>lan</interface><sched>workhours</sched></rule></filter>
        </pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(path_as_str(&input))
        .assert()
        .success()
        .stdout(predicate::str::contains("missing_schedule_reference"));
}

#[test]
fn verify_profiles_dir_override_reports_source() {
    let dir = tempdir().expect("tempdir");
    let profiles = dir.path().join("pfsense");
    std::fs::create_dir_all(&profiles).expect("mkdir");
    std::fs::write(
        profiles.join("default.toml"),
        r#"
required_sections = ["system"]
rule_required_fields = []
gateway_required_fields = []
route_required_fields = []
route_required_any_fields = []
bridge_require_members = false
deprecated_sections = []
"#,
    )
    .expect("write profile");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--to")
        .arg("pfsense")
        .arg("--profiles-dir")
        .arg(dir.path())
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Using profiles: file:"));
}

#[test]
fn verify_accepts_existing_schedule_reference() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("sched-ok.xml");
    fs::write(
        &input,
        r#"<pfsense>
            <system/>
            <interfaces><lan/></interfaces>
            <schedules><schedule><name>workhours</name></schedule></schedules>
            <filter><rule><interface>lan</interface><sched>workhours</sched></rule></filter>
        </pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(path_as_str(&input))
        .assert()
        .success()
        .stdout(predicate::str::contains("result errors=0 warnings=0"));
}

#[test]
fn verify_target_version_overrides_profile_selection() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("cfg.xml");
    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><filter/></pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(path_as_str(&input))
        .arg("--to")
        .arg("pfsense")
        .arg("--target-version")
        .arg("99")
        .assert()
        .success()
        .stdout(predicate::str::contains("version=99"))
        .stdout(predicate::str::contains("profile_missing_required_section"));
}

#[test]
fn verify_fails_on_pfsense_dhcp_backend_inconsistency() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("bad-dhcp.xml");
    fs::write(
        &input,
        r#"<pfsense>
            <system/>
            <interfaces><lan/></interfaces>
            <dhcpbackend>isc</dhcpbackend>
            <kea><dhcp4><general><enabled>1</enabled></general></dhcp4></kea>
        </pfsense>"#,
    )
    .expect("write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("verify")
        .arg(path_as_str(&input))
        .assert()
        .failure()
        .stderr(predicate::str::contains("verify failed"))
        .stdout(predicate::str::contains("dhcp_backend_inconsistent"));
}

fn path_as_str(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}
