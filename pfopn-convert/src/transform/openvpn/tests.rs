use xml_diff_core::parse;

use super::{to_opnsense, to_pfsense};

#[test]
fn preserves_additional_openvpn_options() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><interface>opt2</interface><protocol>UDP</protocol><dev_mode>tun</dev_mode><local_port>1194</local_port><tunnel_network>10.0.8.0/24</tunnel_network><local_network>10.1.10.0/24</local_network><dns_domain>sheridan.local</dns_domain><dns_server1>10.1.10.1</dns_server1><push_blockoutsidedns>yes</push_blockoutsidedns><push_register_dns>yes</push_register_dns><ntp_server1>10.1.10.1</ntp_server1><netbios_enable>yes</netbios_enable><netbios_ntype>0</netbios_ntype><netbios_scope>scope</netbios_scope><custom_options>push &quot;route 10.1.10.0 255.255.255.0&quot;</custom_options><username>vpnuser</username><username_as_common_name>enabled</username_as_common_name><strictusercn>1</strictusercn></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    let inst = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .expect("instance");

    assert_eq!(
        inst.get_text(&["various_push_flags"]),
        Some("block-outside-dns,register-dns")
    );
    assert_eq!(inst.get_text(&["register_dns"]), Some("1"));
    assert_eq!(inst.get_text(&["dns_servers"]), Some("10.1.10.1"));
    assert_eq!(inst.get_text(&["dns_domain"]), Some("sheridan.local"));
    assert_eq!(inst.get_text(&["ntp_servers"]), Some("10.1.10.1"));
    assert_eq!(
        inst.get_text(&["custom_options"]),
        Some(r#"push "route 10.1.10.0 255.255.255.0""#)
    );
    assert_eq!(inst.get_text(&["username"]), Some("vpnuser"));
    assert_eq!(inst.get_text(&["username_as_common_name"]), Some("1"));
    assert_eq!(inst.get_text(&["strictusercn"]), Some("1"));
    assert_eq!(inst.get_text(&["netbios_enable"]), Some("1"));
    assert_eq!(inst.get_text(&["netbios_ntype"]), Some("0"));
    assert_eq!(inst.get_text(&["netbios_scope"]), Some("scope"));
}

#[test]
fn ignores_zero_username() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><username>0</username></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    let inst = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .expect("instance");

    assert!(inst.get_text(&["username"]).is_none());
}

#[test]
fn maps_opnsense_instance_options_back_to_pfsense() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><dev_type>tun</dev_type><proto>udp</proto><port>1194</port><server>10.0.8.0/24</server><push_route>10.1.10.0/24</push_route><various_push_flags>block-outside-dns,register-dns,explicit-exit-notify</various_push_flags><register_dns>1</register_dns><dns_servers>10.1.10.1,1.1.1.1</dns_servers><ntp_servers>10.1.10.1</ntp_servers><custom_options>push &quot;route 192.168.20.0 255.255.255.0&quot;</custom_options><username>vpnuser</username><username_as_common_name>1</username_as_common_name><strictusercn>1</strictusercn><netbios_enable>1</netbios_enable><netbios_ntype>0</netbios_ntype><netbios_scope>scope</netbios_scope></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let target = parse(br#"<pfsense><openvpn/></pfsense>"#).expect("target parse");
    let mut out = target.clone();

    to_pfsense(&mut out, &source, &target);
    let server = out
        .get_child("openvpn")
        .and_then(|o| o.get_child("openvpn-server"))
        .expect("server");

    assert_eq!(server.get_text(&["dns_server1"]), Some("10.1.10.1"));
    assert_eq!(server.get_text(&["dns_server2"]), Some("1.1.1.1"));
    assert_eq!(server.get_text(&["push_blockoutsidedns"]), Some("yes"));
    assert_eq!(server.get_text(&["push_register_dns"]), Some("yes"));
    assert_eq!(server.get_text(&["exit_notify"]), Some("explicit"));
    assert_eq!(
        server.get_text(&["custom_options"]),
        Some(r#"push "route 192.168.20.0 255.255.255.0""#)
    );
    assert_eq!(server.get_text(&["username"]), Some("vpnuser"));
    assert_eq!(
        server.get_text(&["username_as_common_name"]),
        Some("enabled")
    );
    assert_eq!(server.get_text(&["strictusercn"]), Some("1"));
    assert_eq!(server.get_text(&["netbios_enable"]), Some("yes"));
    assert_eq!(server.get_text(&["netbios_ntype"]), Some("0"));
    assert_eq!(server.get_text(&["ntp_server1"]), Some("10.1.10.1"));
}

#[test]
fn maps_pfsense_openvpn_servers_to_opnsense_instances() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><protocol>UDP</protocol><dev_mode>tun</dev_mode><local_port>1194</local_port><tunnel_network>10.8.0.0/24</tunnel_network><local_network>192.168.1.0/24</local_network><certref>cert1</certref><caref>ca1</caref><description>srv</description></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "server"]),
        Some("10.8.0.0/24")
    );
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "proto"]),
        Some("udp")
    );
    let uuid = out
        .get_child("OPNsense")
        .and_then(|o| o.get_child("OpenVPN"))
        .and_then(|o| o.get_child("Instances"))
        .and_then(|i| i.get_child("Instance"))
        .and_then(|i| i.attributes.get("uuid"));
    assert!(uuid.is_some());
    assert_eq!(out.get_child("openvpn").map(|n| n.children.len()), Some(1));
}

#[test]
fn uses_source_openvpn_interface_unit_as_vpnid_fallback() {
    let source = parse(
        br#"<pfsense><interfaces><openvpn><if>ovpns2</if></openvpn></interfaces><openvpn><openvpn-server><protocol>UDP</protocol><dev_mode>tun</dev_mode></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><dev_type>tun</dev_type><proto>udp</proto><port/><role>server</role><server/><push_route/><cert/><ca/><cert_depth>1</cert_depth><topology>subnet</topology><description/></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "vpnid"]),
        Some("2")
    );
}

#[test]
fn prefers_assigned_ovpns_unit_over_stale_server_vpnid() {
    let source = parse(
        br#"<pfsense><interfaces><opt2><if>ovpns2</if></opt2></interfaces><openvpn><openvpn-server><vpnid>1</vpnid><protocol>UDP</protocol><dev_mode>tun</dev_mode></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><dev_type>tun</dev_type><proto>udp</proto><port/><role>server</role><server/><push_route/><cert/><ca/><cert_depth>1</cert_depth><topology>subnet</topology><description/></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["OPNsense", "OpenVPN", "Instances", "Instance", "vpnid"]),
        Some("2")
    );
}

#[test]
fn maps_opnsense_instances_to_pfsense_openvpn_servers() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><proto>udp</proto><dev_type>tun</dev_type><port>1194</port><server>10.0.8.0/24</server><push_route>10.1.10.0/24</push_route><cert>cert1</cert><ca>ca1</ca><description>openvpn server</description></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let target = parse(br#"<pfsense><openvpn/></pfsense>"#).expect("target parse");
    let mut out = target.clone();

    to_pfsense(&mut out, &source, &target);
    assert_eq!(
        out.get_text(&["openvpn", "openvpn-server", "tunnel_network"]),
        Some("10.0.8.0/24")
    );
    assert_eq!(
        out.get_text(&["openvpn", "openvpn-server", "protocol"]),
        Some("UDP")
    );
}

#[test]
fn to_opnsense_dedupes_top_level_openvpn_entries() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><vpnid>1</vpnid><protocol>UDP</protocol><dev_mode>tun</dev_mode></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target = parse(
        br#"<opnsense><openvpn/><openvpn><legacy/></openvpn><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    let count = out.children.iter().filter(|c| c.tag == "openvpn").count();
    assert_eq!(count, 1);
}

#[test]
fn to_pfsense_dedupes_top_level_openvpn_entries() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance><vpnid>1</vpnid><enabled>1</enabled><proto>udp</proto><dev_type>tun</dev_type><port>1194</port><server>10.0.8.0/24</server></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let target = parse(br#"<pfsense><openvpn/><openvpn><legacy/></openvpn></pfsense>"#)
        .expect("target parse");
    let mut out = target.clone();

    to_pfsense(&mut out, &source, &target);
    let count = out.children.iter().filter(|c| c.tag == "openvpn").count();
    assert_eq!(count, 1);
}

#[test]
fn preserves_instance_uuid_when_roundtripping_via_pfsense_openvpn() {
    let source = parse(
        br#"<opnsense><OPNsense><OpenVPN><Instances><Instance uuid="inst-uuid-1"><vpnid>1</vpnid><enabled>1</enabled><proto>udp</proto><dev_type>tun</dev_type><port>1194</port><server>10.0.8.0/24</server></Instance></Instances></OpenVPN></OPNsense></opnsense>"#,
    )
    .expect("source parse");
    let pf_target = parse(br#"<pfsense><openvpn/></pfsense>"#).expect("pf target parse");
    let mut pf = pf_target.clone();
    to_pfsense(&mut pf, &source, &pf_target);

    let opn_target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("opn target parse");
    let mut opn = opn_target.clone();
    to_opnsense(&mut opn, &pf, &opn_target);

    let uuid = opn
        .get_child("OPNsense")
        .and_then(|n| n.get_child("OpenVPN"))
        .and_then(|n| n.get_child("Instances"))
        .and_then(|n| n.get_child("Instance"))
        .and_then(|n| n.attributes.get("uuid"))
        .map(String::as_str);
    assert_eq!(uuid, Some("inst-uuid-1"));
}

#[test]
fn does_not_preserve_top_level_openvpn_servers_for_opnsense_origin() {
    let source = parse(
        br#"<pfsense><openvpn><openvpn-server><opnsense_instance_uuid>inst-uuid-1</opnsense_instance_uuid><vpnid>1</vpnid><protocol>UDP</protocol></openvpn-server></openvpn></pfsense>"#,
    )
    .expect("source parse");
    let target =
        parse(br#"<opnsense><OPNsense><OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>"#)
            .expect("target parse");
    let mut out = target.clone();

    to_opnsense(&mut out, &source, &target);
    assert_eq!(out.get_child("openvpn").map(|n| n.children.len()), Some(0));
}
