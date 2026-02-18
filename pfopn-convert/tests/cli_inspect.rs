use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

#[test]
fn inspect_prints_tree() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("inspect")
        .arg(fixture("fixtures/simple_a.xml"))
        .arg("--depth")
        .arg("2")
        .assert()
        .success()
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("settings"));
}

#[test]
fn inspect_detect_identifies_platform() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("inspect")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--detect")
        .arg("--depth")
        .arg("0")
        .assert()
        .success()
        .stdout(predicate::str::contains("type=pfsense"))
        .stdout(predicate::str::contains("version="))
        .stdout(predicate::str::contains("version_source="))
        .stdout(predicate::str::contains("version_confidence="))
        .stdout(predicate::str::contains("dhcp_backend="));
}

#[test]
fn inspect_plugins_reports_common_plugin_states() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("inspect")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--plugins")
        .arg("--depth")
        .arg("0")
        .assert()
        .success()
        .stdout(predicate::str::contains("plugins platform=opnsense"))
        .stdout(predicate::str::contains("- isc-dhcp declared=true"))
        .stdout(predicate::str::contains("- openvpn"))
        .stdout(predicate::str::contains("- wireguard"));
}

#[test]
fn inspect_plugins_detects_tailscale_on_opnsense_fixture() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("inspect")
        .arg(fixture("fixtures/opnsense-base-with-tailscale.xml"))
        .arg("--plugins")
        .arg("--depth")
        .arg("0")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "- tailscale declared=false configured=true enabled=true",
        ));
}
