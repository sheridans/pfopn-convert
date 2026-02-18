use xml_diff_core::parse;

use super::{to_opnsense, to_pfsense};

#[test]
fn replaces_target_relay_with_source_relay_opnsense() {
    let source = parse(
        br#"<pfsense><dhcrelay><enable/><interface>opt3,opt4</interface><server>10.1.10.1</server></dhcrelay></pfsense>"#,
    )
    .expect("parse");
    let target = parse(
        br#"<opnsense><OPNsense><DHCRelay/></OPNsense><dhcrelay><enable>0</enable><interface>lan</interface><server>192.168.1.1</server></dhcrelay></opnsense>"#,
    )
    .expect("parse");

    let mut out = target.clone();
    to_opnsense(&mut out, &source, &target);

    assert_eq!(out.get_text(&["dhcrelay", "interface"]), Some("opt3,opt4"));
    assert_eq!(out.get_text(&["dhcrelay", "server"]), Some("10.1.10.1"));
    assert_eq!(
        out.get_text(&["OPNsense", "DHCRelay", "destinations", "server"]),
        Some("10.1.10.1")
    );
    assert_eq!(
        out.get_text(&["OPNsense", "DHCRelay", "relays", "interface"]),
        Some("opt3")
    );
    assert_eq!(
        out.get_text(&["OPNsense", "DHCRelay", "relays", "enabled"]),
        Some("1")
    );
}

#[test]
fn removes_target_relay_when_source_has_none() {
    let source = parse(br#"<opnsense><system/></opnsense>"#).expect("parse");
    let target = parse(
        br#"<pfsense><dhcrelay><enable>1</enable></dhcrelay><dhcp6relay><enable>1</enable></dhcp6relay></pfsense>"#,
    )
    .expect("parse");

    let mut out = target.clone();
    to_pfsense(&mut out, &source, &target);

    assert!(out.get_child("dhcrelay").is_none());
    assert!(out.get_child("dhcp6relay").is_none());
}

#[test]
fn preserves_opnsense_dhcrelay_when_source_has_no_relay_sections() {
    let source = parse(br#"<pfsense><system/></pfsense>"#).expect("parse");
    let target = parse(br#"<opnsense><OPNsense><DHCRelay version="1.0.1"/></OPNsense></opnsense>"#)
        .expect("parse");

    let mut out = target.clone();
    to_opnsense(&mut out, &source, &target);

    assert!(out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("DHCRelay"))
        .is_some());
}

#[test]
fn maps_opnsense_dhcrelay_plugin_to_pfsense_dhcrelay() {
    let source = parse(
        br#"<opnsense><OPNsense><DHCRelay version="1.0.1"><relays uuid="r1"><enabled>1</enabled><interface>opt4</interface><destination>d1</destination></relays><destinations uuid="d1"><name>domain_server</name><server>10.1.10.254</server></destinations></DHCRelay></OPNsense></opnsense>"#,
    )
    .expect("parse");
    let target = parse(br#"<pfsense><system/></pfsense>"#).expect("parse");

    let mut out = target.clone();
    to_pfsense(&mut out, &source, &target);

    assert_eq!(out.get_text(&["dhcrelay", "interface"]), Some("opt4"));
    assert_eq!(out.get_text(&["dhcrelay", "server"]), Some("10.1.10.254"));
}

#[test]
fn maps_opnsense_dhcrelay_plugin_to_pfsense_dhcp6relay() {
    let source = parse(
        br#"<opnsense><OPNsense><DHCRelay version="1.0.1"><relays uuid="r1"><enabled>1</enabled><interface>opt6</interface><destination>d6</destination></relays><destinations uuid="d6"><name>v6_destination</name><server>2001:db8::10</server></destinations></DHCRelay></OPNsense></opnsense>"#,
    )
    .expect("parse");
    let target = parse(br#"<pfsense><system/></pfsense>"#).expect("parse");

    let mut out = target.clone();
    to_pfsense(&mut out, &source, &target);

    assert_eq!(out.get_text(&["dhcp6relay", "interface"]), Some("opt6"));
    assert_eq!(
        out.get_text(&["dhcp6relay", "server"]),
        Some("2001:db8::10")
    );
}
