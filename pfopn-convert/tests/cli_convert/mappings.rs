use super::*;

#[test]
fn convert_to_opnsense_prunes_installedpackages_by_default() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><installedpackages><package><name>pfblockerng</name></package></installedpackages></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(!out.contains("<installedpackages>"));
}

#[test]
fn convert_to_pfsense_prunes_opnsense_container_by_default() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><system/><interfaces><lan/></interfaces><OPNsense><tailscale/></OPNsense></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><system/><interfaces><lan/></interfaces></pfsense>"#,
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
    assert!(!out.contains("<OPNsense>"));
}

#[test]
fn convert_maps_pfsense_aliases_into_opnsense_nested_aliases() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><aliases><alias><name>branch_hosts</name></alias></aliases></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(out.contains("<OPNsense>"));
    assert!(out.contains("<Firewall>"));
    assert!(out.contains("<Alias>"));
    assert!(out.contains("<aliases>"));
    assert!(out.contains("<name>branch_hosts</name>"));
}

#[test]
fn convert_to_opnsense_prunes_pfblocker_floating_rules() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan><if>igb0</if></lan></interfaces><filter><rule><floating>yes</floating><source><address>pfB_Top_v4</address></source><interface>wan</interface></rule><rule><floating>yes</floating><source><address>LAN_NET</address></source><interface>wan</interface></rule></filter></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan><if>vtnet0</if></lan></interfaces><filter/></opnsense>"#,
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
    assert!(!out.contains("pfB_Top_v4"));
    assert!(out.contains("LAN_NET"));
}

#[test]
fn convert_to_opnsense_copies_dhcp_relay_from_source() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan><if>igb0</if></lan><opt3><if>igb1</if></opt3><opt4><if>igb2</if></opt4></interfaces><dhcrelay><enable/><interface>opt3,opt4</interface><server>10.1.10.1</server></dhcrelay></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan><if>vtnet0</if></lan><opt3><if>vtnet1</if></opt3><opt4><if>vtnet2</if></opt4></interfaces><dhcrelay><enable>0</enable><interface>lan</interface><server>192.168.1.1</server></dhcrelay></opnsense>"#,
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
    assert!(out.contains("<dhcrelay>"));
    assert!(out.contains("<interface>opt3,opt4</interface>"));
    assert!(out.contains("<server>10.1.10.1</server>"));
}

#[test]
fn convert_maps_pfsense_tailscale_into_opnsense_container() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><lan/></interfaces><installedpackages><tailscale><config><enable>on</enable></config></tailscale><tailscaleauth><config><preauthkey>x</preauthkey></config></tailscaleauth></installedpackages></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(out.contains("<OPNsense>"));
    assert!(out.contains("<tailscale>"));
    assert!(out.contains("<tailscaleauth>"));
}

#[test]
fn convert_maps_opnsense_tailscale_into_pfsense_installedpackages() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><system/><interfaces><lan/></interfaces><OPNsense><tailscale><settings><enabled>1</enabled></settings></tailscale></OPNsense></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><system/><interfaces><lan/></interfaces></pfsense>"#,
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
    assert!(out.contains("<installedpackages>"));
    assert!(out.contains("<tailscale>"));
}

#[test]
fn convert_maps_pfsense_wireguard_tunnels_and_peers_to_opnsense_plugin_schema() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system/><interfaces><wireguard><if>tun_wg0</if></wireguard></interfaces><installedpackages><wireguard><tunnels><item><name>tun_wg0</name><enabled>yes</enabled><listenport>51820</listenport><privatekey>PRIV</privatekey><publickey>PUB</publickey></item></tunnels><peers><item><enabled>yes</enabled><tun>tun_wg0</tun><descr>peer1</descr><publickey>PEER_PUB</publickey></item></peers><config><enable>on</enable></config></wireguard></installedpackages></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system/><interfaces><wireguard><if>tun_wg0</if></wireguard></interfaces><OPNsense><wireguard><client><clients/></client><server><servers/></server><general><enabled>0</enabled></general></wireguard></OPNsense></opnsense>"#,
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
    assert!(out.contains("<OPNsense>"));
    assert!(out.contains("<wireguard>"));
    assert!(out.contains("<name>peer1</name>"));
    assert!(out.contains("<name>tun_wg0</name>"));
    assert!(out.contains("<if>wg0</if>"));
}

#[test]
fn convert_maps_pfsense_ipsec_into_opnsense_nested_ipsec() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><interfaces><lan/></interfaces><ipsec><phase1><descr>site-a</descr></phase1></ipsec></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><interfaces><lan/></interfaces><OPNsense><IPsec><phase1><descr>baseline</descr></phase1></IPsec></OPNsense></opnsense>"#,
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
    assert!(out.contains("<ipsec>"));
    assert!(out.contains("<OPNsense>"));
    assert!(out.contains("<IPsec>"));
    assert!(out.contains("<descr>site-a</descr>"));
}

#[test]
fn convert_maps_web_login_admin_to_root() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system><user><name>admin</name><bcrypt-hash>HASH_ADMIN</bcrypt-hash></user></system><interfaces><lan/></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system><user><name>root</name><password>OLD</password></user></system><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(out.contains("<name>root</name>"));
    assert!(out.contains("<password>HASH_ADMIN</password>"));
}

#[test]
fn convert_copies_hostname_and_domain_from_source_system() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system><hostname>gw-source</hostname><domain>example.org</domain></system><interfaces><lan/></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system><hostname>dst-host</hostname><domain>dst.local</domain></system><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(out.contains("<hostname>gw-source</hostname>"));
    assert!(out.contains("<domain>example.org</domain>"));
}

#[test]
fn convert_copies_ntp_timeservers_from_source_system() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system><timeservers>1.1.1.1 2.2.2.2</timeservers></system><interfaces><lan/></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system><timeservers>0.pool.ntp.org</timeservers></system><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(out.contains("<timeservers>1.1.1.1 2.2.2.2</timeservers>"));
}

#[test]
fn convert_maps_web_login_root_to_admin() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><system><user><name>root</name><password>HASH_ROOT</password></user></system><interfaces><lan/></interfaces></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><system><user><name>admin</name><bcrypt-hash>OLD</bcrypt-hash></user></system><interfaces><lan/></interfaces></pfsense>"#,
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
    assert!(out.contains("<name>admin</name>"));
    assert!(out.contains("<bcrypt-hash>HASH_ROOT</bcrypt-hash>"));
}

#[test]
fn convert_transfers_all_system_users_from_pfsense_to_opnsense() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<pfsense><system><user><name>admin</name><bcrypt-hash>H1</bcrypt-hash></user><user><name>alice</name><bcrypt-hash>H2</bcrypt-hash></user></system><interfaces><lan/></interfaces></pfsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<opnsense><system><user><name>root</name><password>OLD</password></user></system><interfaces><lan/></interfaces></opnsense>"#,
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
    assert!(out.contains("<name>root</name>"));
    assert!(out.contains("<name>alice</name>"));
}

#[test]
fn convert_transfers_all_system_users_from_opnsense_to_pfsense() {
    let dir = tempdir().expect("tempdir");
    let input = dir.path().join("src.xml");
    let target = dir.path().join("dst.xml");
    let output = dir.path().join("out.xml");

    fs::write(
        &input,
        r#"<opnsense><system><user><name>root</name><password>H1</password></user><user><name>bob</name><password>H2</password></user></system><interfaces><lan/></interfaces></opnsense>"#,
    )
    .expect("src write");
    fs::write(
        &target,
        r#"<pfsense><system><user><name>admin</name><bcrypt-hash>OLD</bcrypt-hash></user></system><interfaces><lan/></interfaces></pfsense>"#,
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
    assert!(out.contains("<name>admin</name>"));
    assert!(out.contains("<name>bob</name>"));
}

#[test]
fn convert_testdata_opnsense_to_pfsense_maps_openvpn_instances() {
    let dir = tempdir().expect("tempdir");
    let output = dir.path().join("out.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("pfsense")
        .arg("--target-file")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<openvpn-server>"));
    assert!(out.contains("<tunnel_network>10.0.8.0/24</tunnel_network>"));
}

#[test]
fn convert_testdata_pfsense_to_opnsense_maps_openvpn_instances() {
    let dir = tempdir().expect("tempdir");
    let output = dir.path().join("out.xml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("pfopn-convert"));
    cmd.arg("convert")
        .arg(fixture("fixtures/pfsense-base.xml"))
        .arg("--output")
        .arg(path_as_str(&output))
        .arg("--to")
        .arg("opnsense")
        .arg("--target-file")
        .arg(fixture("fixtures/opnsense-base.xml"))
        .assert()
        .success();

    let out = fs::read_to_string(&output).expect("read out");
    assert!(out.contains("<Instance"));
    assert!(out.contains("<server>10.8.0.0/24</server>"));
    assert!(out.contains("<if>ovpns1</if>"));
    assert!(out.contains("<opt"));
    assert!(!out.contains("<ovpns1>"));
    assert!(out.contains("<openvpn-server>"));
}
