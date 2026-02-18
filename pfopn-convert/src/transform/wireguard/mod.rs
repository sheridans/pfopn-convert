//! WireGuard VPN configuration conversion between pfSense and OPNsense.
//!
//! This module handles bidirectional conversion of WireGuard configurations,
//! which have significantly different structures between the two platforms.
//!
//! ## Platform Differences
//!
//! **pfSense WireGuard structure:**
//! - Config lives in `<installedpackages><wireguard>` or `<wireguard>` (top-level)
//! - Uses `<tunnels><item>` for WireGuard instances/interfaces
//! - Uses `<peers><item>` for peer configurations
//! - Tunnels have `<name>` like "tun_wg0", "tun_wg1"
//! - Peers reference their parent tunnel via `<tun>` field
//! - Simple, flat structure inherited from the WireGuard package
//!
//! **OPNsense WireGuard structure:**
//! - Config lives in `<OPNsense><wireguard>`
//! - Uses `<server><servers><server>` for WireGuard instances
//! - Uses `<client><clients><client>` for peer configurations
//! - Servers have `<instance>` numbers (0, 1, 2...) that map to device names (wg0, wg1, wg2...)
//! - Clients reference their parent server via `<serveraddress>` and `<serverport>`
//! - More structured with separate server/client sections
//!
//! ## Interface Naming
//!
//! **pfSense:** Uses "tun_wg0", "tun_wg1", etc. as interface names
//! **OPNsense:** Uses "wg0", "wg1", etc. as interface names (mapped from instance numbers)
//!
//! This module handles the naming conversion automatically.
//!
//! ## Round-Trip Preservation
//!
//! To support lossless pfSense → OPNsense → pfSense round-trips, when converting
//! from OPNsense to pfSense, the original OPNsense config is stored as
//! `<opnsense_wireguard_snapshot>` within the pfSense structure. When converting
//! back to OPNsense, this snapshot is restored if present, preserving all
//! OPNsense-specific fields that don't exist in pfSense.

use xml_diff_core::XmlNode;

mod common;
mod opn_to_pf;
mod pf_to_opn;

/// Convert WireGuard configuration to OPNsense format.
///
/// Handles two cases:
/// 1. Source already has OPNsense nested WireGuard config → copy it directly
/// 2. Source has pfSense WireGuard config → map tunnels/peers to servers/clients
///
/// Also ensures the output has appropriate `<interfaces><wireguard>` assignments.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    // If the source already has OPNsense-style nested WireGuard config, use it directly
    if let Some(source_nested) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("wireguard"))
    {
        common::upsert_nested_wireguard(out, source_nested.clone());
    } else if let Some(source_top) = source_pfsense_wireguard(source) {
        // Source has pfSense-style WireGuard config — map it to OPNsense format
        let mapped = pf_to_opn::map_pfsense_wireguard(source_top);
        common::upsert_nested_wireguard(out, mapped);
    }

    // Ensure interface assignments exist for WireGuard devices
    common::ensure_wireguard_interface_assignment(out, source);
    let _ = target;
}

/// Convert WireGuard configuration to pfSense format.
///
/// Handles two cases:
/// 1. Source already has pfSense WireGuard config → copy it directly
/// 2. Source has OPNsense nested WireGuard config → map servers/clients to tunnels/peers
///
/// Also ensures the output has appropriate `<interfaces><wireguard>` assignments.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    // If the source already has pfSense-style WireGuard config, use it directly
    if let Some(source_top) = source_pfsense_wireguard(source) {
        upsert_pfsense_wireguard(out, source_top.clone());
    } else if let Some(source_nested) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("wireguard"))
    {
        // Source has OPNsense-style WireGuard config — map it to pfSense format
        let mapped = opn_to_pf::map_opnsense_wireguard(source_nested);
        upsert_pfsense_wireguard(out, mapped);
    }

    // Ensure interface assignments exist for WireGuard devices
    common::ensure_wireguard_interface_assignment(out, source);
    let _ = target;
}

/// Find pfSense WireGuard config in the source tree.
///
/// Checks two possible locations:
/// - `<wireguard>` (top-level, used when config was already converted)
/// - `<installedpackages><wireguard>` (standard pfSense package location)
fn source_pfsense_wireguard(source: &XmlNode) -> Option<&XmlNode> {
    source.get_child("wireguard").or_else(|| {
        source
            .get_child("installedpackages")
            .and_then(|n| n.get_child("wireguard"))
    })
}

/// Insert or replace pfSense WireGuard config in the standard package location.
///
/// pfSense stores WireGuard config under `<installedpackages><wireguard>`.
fn upsert_pfsense_wireguard(out: &mut XmlNode, wireguard: XmlNode) {
    let installed = common::ensure_child_mut(out, "installedpackages");
    common::upsert_child(installed, wireguard);
}

/// Normalize WireGuard interface names in OPNsense output.
///
/// Converts various WireGuard interface name formats to OPNsense's standard "wgN" format:
/// - "tun_wg0" → "wg0"  (pfSense-style names)
/// - Server instance names → "wgN" based on instance number
///
/// This ensures interface assignments use consistent device names.
pub fn normalize_opnsense_interface_names(out: &mut XmlNode) {
    common::normalize_opnsense_wireguard_if_names(out);
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn maps_pfsense_wireguard_to_opnsense_instances_and_peers() {
        let source = parse(
            br#"<pfsense>
                <installedpackages><wireguard>
                    <tunnels>
                        <item>
                            <name>tun_wg0</name>
                            <enabled>yes</enabled>
                            <listenport>51820</listenport>
                            <privatekey>PRIV</privatekey>
                            <publickey>PUB</publickey>
                        </item>
                    </tunnels>
                    <peers>
                        <item>
                            <enabled>yes</enabled>
                            <tun>tun_wg0</tun>
                            <descr>peer1</descr>
                            <publickey>PEER_PUB</publickey>
                        </item>
                    </peers>
                    <config><enable>on</enable></config>
                </wireguard></installedpackages>
                <interfaces><wireguard><if>tun_wg0</if></wireguard></interfaces>
            </pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><interfaces><wan/><lan/></interfaces></opnsense>"#)
            .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&[
                "OPNsense",
                "wireguard",
                "server",
                "servers",
                "server",
                "name"
            ]),
            Some("tun_wg0")
        );
        assert_eq!(
            out.get_text(&[
                "OPNsense",
                "wireguard",
                "client",
                "clients",
                "client",
                "name"
            ]),
            Some("peer1")
        );
    }

    #[test]
    fn maps_opnsense_wireguard_to_pfsense_tunnels_and_peers() {
        let source = parse(
            br#"<opnsense><OPNsense><wireguard>
                <client><clients><client uuid="abc"><enabled>1</enabled><name>peer1</name><pubkey>PUB</pubkey><psk>PSK</psk><tunneladdress>172.31.31.2/32</tunneladdress></client></clients></client>
                <general><enabled>1</enabled></general>
                <server><servers><server><enabled>1</enabled><name>tun_wg0</name><instance>0</instance><pubkey>SERVER_PUB</pubkey><privkey>SERVER_PRIV</privkey><port>51820</port><peers>abc</peers></server></servers></server>
            </wireguard></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><interfaces><wan/><lan/></interfaces></pfsense>"#)
            .expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["installedpackages", "wireguard", "tunnels", "item", "name"]),
            Some("tun_wg0")
        );
        assert_eq!(
            out.get_text(&["installedpackages", "wireguard", "peers", "item", "descr"]),
            Some("peer1")
        );
    }

    #[test]
    fn ensures_wireguard_interface_even_when_config_disabled() {
        let source = parse(
            br#"<pfsense>
                <installedpackages><wireguard><config><enable>off</enable></config></wireguard></installedpackages>
                <interfaces><opt6><if>tun_wg0</if></opt6></interfaces>
            </pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><interfaces><lan/></interfaces></opnsense>"#)
            .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        assert_eq!(out.get_text(&["interfaces", "opt6", "if"]), Some("tun_wg0"));
    }

    #[test]
    fn restores_opnsense_wireguard_snapshot_after_pfsense_hop() {
        let opn_source = parse(
            br#"<opnsense><OPNsense><wireguard><server version="1.0.1"><servers><server uuid="srv-1"><name>wg_instance</name><instance>0</instance><dns>10.1.10.1</dns><peers>peer-1</peers></server></servers></server><client version="1.0.0"><clients><client uuid="peer-1"><name>peer-a</name><serveraddress>10.1.10.1</serveraddress><serverport>51820</serverport></client></clients></client></wireguard></OPNsense><interfaces><opt2><if>wg0</if></opt2></interfaces></opnsense>"#,
        )
        .expect("source parse");
        let pf_target = parse(br#"<pfsense><interfaces><lan/></interfaces></pfsense>"#)
            .expect("pf target parse");
        let mut pf = pf_target.clone();
        to_pfsense(&mut pf, &opn_source, &pf_target);

        let opn_target = parse(br#"<opnsense><interfaces><lan/></interfaces></opnsense>"#)
            .expect("opn target parse");
        let mut opn = opn_target.clone();
        to_opnsense(&mut opn, &pf, &opn_target);

        assert_eq!(
            opn.get_text(&[
                "OPNsense",
                "wireguard",
                "server",
                "servers",
                "server",
                "name"
            ]),
            Some("wg_instance")
        );
        assert_eq!(
            opn.get_text(&[
                "OPNsense",
                "wireguard",
                "server",
                "servers",
                "server",
                "dns"
            ]),
            Some("10.1.10.1")
        );
        let peer_uuid = opn
            .get_child("OPNsense")
            .and_then(|n| n.get_child("wireguard"))
            .and_then(|n| n.get_child("client"))
            .and_then(|n| n.get_child("clients"))
            .and_then(|n| n.get_child("client"))
            .and_then(|n| n.attributes.get("uuid"))
            .map(String::as_str);
        assert_eq!(peer_uuid, Some("peer-1"));
    }
}
