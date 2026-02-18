use super::*;

#[test]
fn convert_disable_dhcp_is_opt_in() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan/></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></opnsense>"#,
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
    assert!(out.contains("<enable>1</enable>"));
    assert!(!out.contains("<disabled>1</disabled>"));
}

#[test]
fn convert_disable_dhcp_turns_off_dhcp_when_requested() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan/></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></opnsense>"#,
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
        .arg("--disable-dhcp")
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<enable>0</enable>"));
    assert!(out.contains("<disabled>1</disabled>"));
}

#[test]
fn convert_lan_ip_updates_lan_and_dhcp_lan_values() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpd><lan><range><from>10.1.10.100</from><to>10.1.10.200</to></range></lan></dhcpd></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpd><lan><range><from>10.1.10.100</from><to>10.1.10.200</to></range></lan></dhcpd></opnsense>"#,
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
        .arg("--lan-ip")
        .arg("192.168.1.1")
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<ipaddr>192.168.1.1</ipaddr>"));
    assert!(out.contains("<from>192.168.1.100</from>"));
    assert!(out.contains("<to>192.168.1.200</to>"));
}

#[test]
fn convert_lan_ip_allows_lan_subnet_mismatch_without_global_override() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet></lan></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>23</subnet></lan></interfaces></opnsense>"#,
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
        .arg("--lan-ip")
        .arg("192.168.1.1")
        .assert()
        .success();
}

#[test]
fn convert_lan_ip_fails_on_interface_conflict() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet></lan><opt1><ipaddr>192.168.1.1</ipaddr></opt1></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet></lan><opt1><ipaddr>192.168.1.1</ipaddr></opt1></interfaces></opnsense>"#,
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
        .arg("--lan-ip")
        .arg("192.168.1.1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--lan-ip conflicts"));
}

#[test]
fn convert_auto_backend_prefers_kea_for_opnsense_26_and_migrates_reservation() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpd><lan><range><from>192.168.1.100</from><to>192.168.1.200</to></range><staticmap><mac>aa:bb:cc:dd:ee:ff</mac><ipaddr>192.168.1.25</ipaddr><hostname>printer</hostname></staticmap></lan></dhcpd></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><version>26.1</version><system><firmware><plugins>os-kea</plugins></firmware></system><interfaces><lan><if>vtnet0</if></lan></interfaces><OPNsense><Kea><dhcp4><general><enabled>0</enabled><interfaces/></general><subnets/><reservations/></dhcp4></Kea></OPNsense></opnsense>"#,
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
    assert!(out.contains("<reservation>"));
    assert!(out.contains("<ip_address>192.168.1.25</ip_address>"));
    // v4 ISC section should be removed after Kea migration
    assert!(
        !out.contains("<dhcpd>"),
        "dhcpd ISC section should be removed after Kea migration"
    );
    // Kea dhcp4 should be enabled
    let parsed = parse(out.as_bytes()).expect("parse out");
    assert_eq!(
        parsed.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]),
        Some("1"),
        "Kea dhcp4 should be enabled after migration"
    );
}

#[test]
fn convert_auto_backend_falls_back_to_isc_when_kea_migration_fails() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><version>24.11</version><dhcpbackend>kea</dhcpbackend><interfaces><lan><if>igb1</if><ipaddr>192.168.10.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpd6><lan><enable>1</enable><range><from>2001:db8:10::100</from><to>2001:db8:10::1ff</to></range></lan></dhcpd6></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><version>24.7</version><system><firmware><plugins>os-isc-dhcp</plugins></firmware></system><interfaces><lan><if>vtnet0</if><ipaddr>192.168.10.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpd6><lan><enable>0</enable></lan></dhcpd6></opnsense>"#,
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
        .success()
        .stderr(predicate::str::contains(
            "warning: DHCPv6 range on lan but unable to determine IPv6 prefix",
        ));

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<dhcpd6>"));
    let parsed = parse(out.as_bytes()).expect("parse out");
    let general = parsed
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Kea"))
        .and_then(|kea| kea.get_child("dhcp6"))
        .and_then(|dhcp6| dhcp6.get_child("general"));
    assert!(general.is_some());
    assert_eq!(
        parsed.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]),
        None
    );
}

#[test]
fn convert_backend_isc_requires_os_isc_dhcp_plugin_on_opnsense() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan/></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><version>26.1</version><system><firmware><plugins>os-wireguard</plugins></firmware></system><interfaces><lan><if>vtnet0</if></lan></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--backend")
        .arg("isc")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .failure()
        .stderr(predicate::str::contains("os-isc-dhcp"));
}

#[test]
fn convert_to_pfsense_auto_prefers_source_kea_and_preserves_kea_data() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><interfaces><lan><if>vtnet0</if></lan></interfaces><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general><subnets><subnet4 uuid="sub-1"><subnet>192.168.1.0/24</subnet></subnet4></subnets><reservations><reservation><hw_address>aa:bb:cc:dd:ee:ff</hw_address><ip_address>192.168.1.50</ip_address><subnet>sub-1</subnet></reservation></reservations></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><interfaces><lan><if>igb0</if></lan></interfaces><dhcpd><lan><enable/></lan></dhcpd></pfsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("pfsense")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<dhcpbackend>kea</dhcpbackend>"));
    assert!(out.contains("<kea"));
    assert!(out.contains("<ip_address>192.168.1.50</ip_address>"));
    assert!(out.contains("<subnet4 uuid=\"sub-1\">"));
}

#[test]
fn convert_to_pfsense_isc_fails_for_kea_only_source() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><interfaces><lan><if>vtnet0</if></lan></interfaces><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general><subnets><subnet4 uuid="sub-1"><subnet>192.168.1.0/24</subnet></subnet4></subnets><reservations><reservation><hw_address>aa:bb:cc:dd:ee:ff</hw_address><ip_address>192.168.1.50</ip_address><subnet>sub-1</subnet></reservation></reservations></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><interfaces><lan><if>igb0</if></lan></interfaces><dhcpd><lan><enable/></lan></dhcpd></pfsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("pfsense")
        .arg("--backend")
        .arg("isc")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot convert Kea-only source to pfSense ISC",
        ));
}

#[test]
fn convert_to_opnsense_backend_isc_keeps_legacy_dhcp_and_disables_kea() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpd><lan><range><from>192.168.1.100</from><to>192.168.1.200</to></range></lan></dhcpd></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><version>26.1</version><system><firmware><plugins>os-isc-dhcp os-kea</plugins></firmware></system><interfaces><lan><if>vtnet0</if></lan></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general><subnets/><reservations/></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--backend")
        .arg("isc")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<dhcpd>"));
    assert!(out.contains("<from>192.168.1.100</from>"));
    let parsed = parse(out.as_bytes()).expect("parse out");
    assert_eq!(
        parsed.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]),
        Some("0")
    );
}

#[test]
fn convert_to_opnsense_isc_fails_for_kea_only_source() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><if>igb0</if></lan></interfaces><dhcpbackend>kea</dhcpbackend><kea><dhcp4><general><enabled>1</enabled></general><reservations><item><hw-address>aa:bb:cc:dd:ee:ff</hw-address><ip-address>192.168.1.50</ip-address></item></reservations></dhcp4></kea></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><version>26.1</version><system><firmware><plugins>os-isc-dhcp</plugins></firmware></system><interfaces><lan><if>vtnet0</if></lan></interfaces><dhcpd><lan><enable>1</enable></lan></dhcpd></opnsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--backend")
        .arg("isc")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot convert Kea-only source to OPNsense ISC",
        ));
}

#[test]
fn convert_to_pfsense_backend_isc_removes_kea_even_without_legacy_dhcp_sections() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><interfaces><lan><if>vtnet0</if></lan></interfaces></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><interfaces><lan><if>igb0</if></lan></interfaces><dhcpbackend>kea</dhcpbackend><kea><dhcp4><general><enabled>1</enabled></general></dhcp4></kea></pfsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("pfsense")
        .arg("--backend")
        .arg("isc")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<dhcpbackend>isc</dhcpbackend>"));
    assert!(!out.contains("<kea>"));
}

#[test]
fn convert_kea_partial_migration_v4_success_v6_fallback() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    // Source: pfSense with v4 ranges + v6 ranges (no static ipaddrv6 on lan)
    fs::write(
        &input,
        r#"<pfsense><interfaces><lan><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><ipaddrv6>track6</ipaddrv6><track6-interface>wan</track6-interface><track6-prefix-id>0</track6-prefix-id></lan></interfaces><dhcpd><lan><range><from>192.168.1.100</from><to>192.168.1.200</to></range></lan></dhcpd><dhcpdv6><lan><enable>1</enable><range><from>::1000</from><to>::2000</to></range></lan></dhcpdv6></pfsense>"#,
    )
    .expect("src write");
    // Target: OPNsense 26.1 with Kea structure
    fs::write(
        &target,
        r#"<opnsense><version>26.1</version><system><firmware><plugins>os-kea</plugins></firmware></system><interfaces><lan><if>vtnet0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces><OPNsense><Kea><dhcp4><general><enabled>0</enabled><interfaces/></general><subnets/><reservations/></dhcp4><dhcp6><general><enabled>0</enabled><interfaces/></general><subnets/><reservations/></dhcp6></Kea></OPNsense></opnsense>"#,
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
        .success()
        .stderr(predicate::str::contains(
            "DHCPv6 range on lan but unable to determine IPv6 prefix",
        ));

    let out = fs::read_to_string(&output).expect("read out");
    let parsed = parse(out.as_bytes()).expect("parse out");

    // v4 ISC removed
    assert!(
        parsed.get_child("dhcpd").is_none(),
        "dhcpd ISC section should be removed after v4 Kea migration"
    );
    // v6 ISC preserved (fallback)
    assert!(
        parsed.get_child("dhcpdv6").is_some(),
        "dhcpdv6 ISC section should be preserved when v6 falls back"
    );
    // Kea dhcp4 enabled
    assert_eq!(
        parsed.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]),
        Some("1"),
        "Kea dhcp4 should be enabled"
    );
    // Kea dhcp6 should NOT be enabled (no v6 migration)
    let dhcp6_enabled = parsed.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]);
    assert!(
        dhcp6_enabled.is_none() || dhcp6_enabled == Some("0"),
        "Kea dhcp6 should not be enabled when v6 falls back to ISC"
    );
}

#[test]
fn convert_kea_pfsense_removes_isc_sections() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    // OPNsense → pfSense with --backend kea; target has legacy ISC sections
    fs::write(
        &input,
        r#"<opnsense><interfaces><lan><if>vtnet0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general></dhcp4></Kea></OPNsense></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><interfaces><lan><if>igb0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces><dhcpbackend>isc</dhcpbackend><dhcpd><lan><enable>1</enable></lan></dhcpd><dhcpdv6><lan><enable>0</enable></lan></dhcpdv6></pfsense>"#,
    )
    .expect("dst write");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(path_as_str(&input))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("pfsense")
        .arg("--backend")
        .arg("kea")
        .arg("--target-file")
        .arg(path_as_str(&target))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(
        !out.contains("<dhcpd>"),
        "dhcpd ISC section should be removed with --backend kea on pfSense"
    );
    assert!(
        !out.contains("<dhcpdv6>"),
        "dhcpdv6 ISC section should be removed with --backend kea on pfSense"
    );
    assert!(
        out.contains("<dhcpbackend>kea</dhcpbackend>"),
        "dhcpbackend should be set to kea"
    );
}
