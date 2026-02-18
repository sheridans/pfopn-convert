use super::*;

#[test]
fn convert_allows_interface_subnet_difference() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><subnet>24</subnet></lan></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><subnet>25</subnet></lan></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();
}

#[test]
fn convert_uses_interface_map_for_renamed_interfaces() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");
    let map_file = dir.path().join("interfaces.toml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><opt2><subnet>24</subnet></opt2></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><igc3><subnet>24</subnet></igc3></interfaces></opnsense>"#,
    )
    .expect("dst write");
    fs::write(
        &map_file,
        r#"
[from]
opt2 = "igc3"
"#,
    )
    .expect("map write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .arg("--interface-map")
        .arg(path_as_str(&map_file))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected argument '--interface-map'",
        ));
}

#[test]
fn convert_fails_for_invalid_interface_map_target_name() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");
    let map_file = dir.path().join("interfaces.toml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><opt2><subnet>24</subnet></opt2></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><igc3><subnet>24</subnet></igc3></interfaces></opnsense>"#,
    )
    .expect("dst write");
    fs::write(
        &map_file,
        r#"
[from]
opt2 = "not_real"
"#,
    )
    .expect("map write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .arg("--interface-map")
        .arg(path_as_str(&map_file))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected argument '--interface-map'",
        ));
}

#[test]
fn convert_rewrites_vlan_parent_device_refs_to_target_nics() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan></interfaces><vlans><vlan><if>igb0</if><tag>100</tag></vlan></vlans></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan></interfaces><vlans><vlan><if>igb0</if><tag>100</tag></vlan></vlans></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<if>vtnet0</if>"));
    assert!(!out.contains("<if>igb0</if>"));
}

#[test]
fn convert_rewrites_dotted_interface_assignment_refs_to_target_nics() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan><opt3><if>igb0.50</if><subnet>24</subnet></opt3></interfaces><vlans><vlan><if>igb0</if><tag>50</tag></vlan></vlans></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan><opt3><if>vtnet0.50</if><subnet>24</subnet></opt3></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(!out.contains("<if>igb0.50</if>"));
    assert!(!out.contains("<if>vtnet0.50</if>"));
    assert!(out.contains("<vlanif>vlan01</vlanif>"));
    assert!(out.contains("<vlan uuid=\""));
    assert!(out.contains("<if>vlan01</if>"));
}

#[test]
fn convert_normalizes_tun_wg_to_existing_wg_device_name() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan><opt6><if>tun_wg0</if><subnet>24</subnet></opt6></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan><wireguard><if>wg0</if></wireguard></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<if>wg0</if>"));
    assert!(!out.contains("<if>tun_wg0</if>"));
}

#[test]
fn convert_normalizes_wireguard_if_from_instance_name_mapping() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan><opt6><if>corpwg</if><subnet>24</subnet></opt6></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan></interfaces><OPNsense><wireguard><server><servers><server><name>corpwg</name><instance>7</instance></server></servers></server></wireguard></OPNsense></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<if>wg7</if>"));
    assert!(!out.contains("<if>corpwg</if>"));
}

#[test]
fn convert_prunes_interfaces_missing_from_target_baseline() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><wan><subnet>24</subnet></wan><lan><subnet>24</subnet></lan><opt9><subnet>24</subnet></opt9></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><wan><subnet>24</subnet></wan><lan><subnet>24</subnet></lan></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing target interfaces: opt9"));
}

#[test]
fn convert_allows_missing_virtual_backed_interface_on_target() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan><opt9><if>vlan9</if><subnet>24</subnet></opt9></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<opt9>"));
    assert!(out.contains("<if>vlan9</if>"));
}

#[test]
fn convert_applies_source_interface_settings_by_default() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><wan><if>igb0</if><ipaddr>10.1.10.253</ipaddr><subnet>24</subnet></wan><lan><if>igb1</if><ipaddr>10.1.20.1</ipaddr><subnet>24</subnet></lan></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><wan><if>vtnet1</if><ipaddr>dhcp</ipaddr></wan><lan><if>vtnet0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<if>vtnet1</if>"));
    assert!(out.contains("<if>vtnet0</if>"));
    assert!(out.contains("<ipaddr>10.1.10.253</ipaddr>"));
}

#[test]
fn convert_does_not_retain_target_wan_mode_when_source_omits_wan_ipaddr() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><wan><if>igb0</if></wan><lan><if>igb1</if><ipaddr>10.1.20.1</ipaddr><subnet>24</subnet></lan></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><wan><if>vtnet1</if><ipaddr>dhcp</ipaddr></wan><lan><if>vtnet0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<wan>"));
    assert!(out.contains("<if>vtnet1</if>"));
    assert!(!out.contains("<ipaddr>dhcp</ipaddr>"));
}

#[test]
fn convert_keeps_empty_wan_ip_and_does_not_retain_target_dynamic_modes() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><wan><if>igb0</if><ipaddr></ipaddr></wan><opt1><if>igb1</if></opt1></interfaces><bridges><bridged><members>wan opt1</members></bridged></bridges></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><wan><if>vtnet1</if><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan><opt1><if>vtnet2</if></opt1></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<wan>"));
    assert!(out.contains("<if>vtnet1</if>"));
    assert!(!out.contains("<ipaddr>dhcp</ipaddr>"));
    assert!(!out.contains("<ipaddrv6>dhcp6</ipaddrv6>"));
}

#[test]
fn convert_auto_maps_optional_interface_and_rewrites_bridge_members() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><wan><if>igb0</if></wan><lan><if>igb1</if></lan><opt2><if>igb2</if><descr>DMZ</descr><ipaddr>172.16.50.1</ipaddr><subnet>24</subnet></opt2></interfaces><bridges><bridged><members>lan opt2</members></bridged></bridges></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><wan><if>vtnet1</if></wan><lan><if>vtnet0</if></lan><opt1><descr>DMZ</descr><if>vtnet2</if></opt1></interfaces></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing target interfaces: opt2"));
}
