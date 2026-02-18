use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

use super::common::{is_truthy, push_text_child, text_of};

/// Map OPNsense WireGuard configuration to pfSense format.
///
/// Converts OPNsense's server/client structure to pfSense's tunnel/peer structure:
///
/// **OPNsense structure:**
/// ```xml
/// <wireguard>
///   <server><servers><server><name>wg_instance</name><instance>0</instance>...</server></servers></server>
///   <client><clients><client><name>peer1</name>...</client></clients></client>
/// </wireguard>
/// ```
///
/// **pfSense structure:**
/// ```xml
/// <wireguard>
///   <tunnels><item><name>tun_wg0</name>...</item></tunnels>
///   <peers><item><tun>tun_wg0</tun><descr>peer1</descr>...</item></peers>
/// </wireguard>
/// ```
///
/// ## Round-Trip Preservation
///
/// The full OPNsense config is preserved as `<opnsense_wireguard_snapshot>` so that
/// a pfSense → OPNsense → pfSense conversion can restore all OPNsense-specific fields
/// that don't exist in pfSense's simpler model (like DNS settings, advanced options, etc.).
///
/// ## Mapping Details
///
/// - Servers → Tunnels: Each `<server>` becomes a `<tunnels><item>`
/// - Clients → Peers: Each `<client>` becomes a `<peers><item>`
/// - Client-to-server association: OPNsense links via UUID list in `<peers>` field;
///   pfSense uses tunnel name in `<tun>` field
/// - Interface names: Ensures "tun_" prefix (e.g., "wg0" → "tun_wg0")
/// - Allowed IPs: OPNsense's comma-separated CIDRs become pfSense's `<allowedips><row>` structure
pub fn map_opnsense_wireguard(source: &XmlNode) -> XmlNode {
    let mut out = XmlNode::new("wireguard");
    // Build a map of peer UUID → tunnel name for linking clients to their parent servers
    let server_peer_map = collect_server_peers(source);

    // First pass: Convert all OPNsense servers to pfSense tunnels
    let mut tunnels = XmlNode::new("tunnels");
    if let Some(servers) = source
        .get_child("server")
        .and_then(|s| s.get_child("servers"))
    {
        for (idx, server) in servers.get_children("server").into_iter().enumerate() {
            let mut item = XmlNode::new("item");
            // Get server name, defaulting to "tun_wgN" if not set
            let name = text_of(server, &["name"])
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("tun_wg{idx}"));
            push_text_child(
                &mut item,
                "addresses",
                text_of(server, &["tunneladdress"]).unwrap_or(""),
            );
            // Ensure tunnel name has "tun_" prefix (pfSense convention)
            push_text_child(
                &mut item,
                "name",
                if name.starts_with("tun_") {
                    name
                } else {
                    format!("tun_{name}")
                },
            );
            push_text_child(
                &mut item,
                "enabled",
                if is_truthy(text_of(server, &["enabled"]).unwrap_or("0")) {
                    "yes"
                } else {
                    "no"
                },
            );
            push_text_child(&mut item, "descr", text_of(server, &["name"]).unwrap_or(""));
            push_text_child(
                &mut item,
                "listenport",
                text_of(server, &["port"]).unwrap_or(""),
            );
            push_text_child(
                &mut item,
                "privatekey",
                text_of(server, &["privkey"]).unwrap_or(""),
            );
            push_text_child(
                &mut item,
                "publickey",
                text_of(server, &["pubkey"]).unwrap_or(""),
            );
            push_text_child(&mut item, "mtu", text_of(server, &["mtu"]).unwrap_or(""));
            tunnels.children.push(item);
        }
    }
    out.children.push(tunnels);

    // Second pass: Convert all OPNsense clients to pfSense peers
    let mut peers = XmlNode::new("peers");
    if let Some(clients) = source
        .get_child("client")
        .and_then(|c| c.get_child("clients"))
    {
        for (idx, client) in clients.get_children("client").into_iter().enumerate() {
            // Extract the client's UUID for linking to parent server
            let uuid = client
                .attributes
                .get("uuid")
                .map(|s| s.as_str())
                .unwrap_or("");
            let mut item = XmlNode::new("item");
            // Convert OPNsense's comma-separated CIDRs to pfSense's <allowedips><row> structure
            let mut allowed = XmlNode::new("allowedips");
            for cidr in text_of(client, &["tunneladdress"])
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let (addr, mask) = split_cidr(cidr);
                let mut row = XmlNode::new("row");
                push_text_child(&mut row, "address", addr);
                push_text_child(&mut row, "mask", mask);
                push_text_child(&mut row, "descr", "");
                allowed.children.push(row);
            }
            item.children.push(allowed);
            push_text_child(
                &mut item,
                "enabled",
                if is_truthy(text_of(client, &["enabled"]).unwrap_or("0")) {
                    "yes"
                } else {
                    "no"
                },
            );
            // Link this peer to its parent tunnel via the server_peer_map
            // Falls back to "tun_wgN" if no mapping found
            let tun = server_peer_map
                .get(uuid)
                .cloned()
                .unwrap_or_else(|| format!("tun_wg{idx}"));
            push_text_child(&mut item, "tun", tun);
            push_text_child(
                &mut item,
                "descr",
                text_of(client, &["name"]).unwrap_or("imported_peer"),
            );
            push_text_child(
                &mut item,
                "persistentkeepalive",
                text_of(client, &["keepalive"]).unwrap_or(""),
            );
            push_text_child(
                &mut item,
                "publickey",
                text_of(client, &["pubkey"]).unwrap_or(""),
            );
            push_text_child(
                &mut item,
                "presharedkey",
                text_of(client, &["psk"]).unwrap_or(""),
            );
            peers.children.push(item);
        }
    }
    out.children.push(peers);

    let mut config = XmlNode::new("config");
    push_text_child(
        &mut config,
        "enable",
        if is_truthy(
            text_of(source, &["general", "enabled"])
                .or_else(|| text_of(source, &["general", "enable"]))
                .unwrap_or("0"),
        ) {
            "on"
        } else {
            "off"
        },
    );
    push_text_child(&mut config, "keep_conf", "yes");
    push_text_child(&mut config, "resolve_interval", "300");
    push_text_child(&mut config, "resolve_interval_track", "no");
    push_text_child(&mut config, "interface_group", "all");
    push_text_child(&mut config, "hide_secrets", "yes");
    push_text_child(&mut config, "hide_peers", "yes");
    out.children.push(config);

    // Preserve full OPNsense schema for round-trip restoration.
    let mut snapshot = source.clone();
    snapshot.tag = "opnsense_wireguard_snapshot".to_string();
    out.children.push(snapshot);

    out
}

/// Build a mapping from peer UUID to tunnel name.
///
/// OPNsense servers reference their clients via a comma-separated list of UUIDs
/// in the `<peers>` field. This function inverts that relationship to create a map
/// from each peer UUID to its parent tunnel name.
///
/// This allows efficient lookup when converting clients to peers — we can quickly
/// determine which tunnel each peer belongs to via the `<tun>` field in pfSense.
///
/// # Returns
///
/// A map where:
/// - Key: Peer/client UUID from OPNsense
/// - Value: Parent tunnel name (with "tun_" prefix)
///
/// # Example
///
/// If an OPNsense server has `<name>wg_main</name><peers>abc,def,ghi</peers>`,
/// this function returns:
/// ```text
/// {
///   "abc" => "tun_wg_main",
///   "def" => "tun_wg_main",
///   "ghi" => "tun_wg_main"
/// }
/// ```
fn collect_server_peers(source: &XmlNode) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Some(servers) = source
        .get_child("server")
        .and_then(|s| s.get_child("servers"))
    else {
        return map;
    };
    for (idx, server) in servers.get_children("server").into_iter().enumerate() {
        // Get tunnel name and ensure it has the "tun_" prefix
        let tun = text_of(server, &["name"])
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("tun_wg{idx}"));
        let tun = if tun.starts_with("tun_") {
            tun
        } else {
            format!("tun_{tun}")
        };
        // Parse the comma-separated list of peer UUIDs and map each to this tunnel
        for id in text_of(server, &["peers"])
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            map.insert(id.to_string(), tun.clone());
        }
    }
    map
}

/// Split a CIDR notation string into address and mask components.
///
/// OPNsense stores tunnel addresses as comma-separated CIDRs (e.g., "10.0.0.1/24,fd00::1/64").
/// pfSense stores each allowed IP in a separate `<row>` with `<address>` and `<mask>` fields.
///
/// # Arguments
///
/// * `value` - A CIDR string like "192.168.1.1/24" or "10.0.0.1" (no mask)
///
/// # Returns
///
/// A tuple of (address, mask):
/// - If CIDR contains "/", returns the parts: "192.168.1.1/24" → ("192.168.1.1", "24")
/// - If no "/", defaults to /32 for single host: "10.0.0.1" → ("10.0.0.1", "32")
///
/// # Examples
///
/// ```ignore
/// assert_eq!(split_cidr("192.168.1.0/24"), ("192.168.1.0", "24"));
/// assert_eq!(split_cidr("10.0.0.1"), ("10.0.0.1", "32"));
/// assert_eq!(split_cidr("fd00::1/64"), ("fd00::1", "64"));
/// ```
fn split_cidr(value: &str) -> (&str, &str) {
    if let Some((addr, mask)) = value.split_once('/') {
        (addr.trim(), mask.trim())
    } else {
        (value.trim(), "32")
    }
}
