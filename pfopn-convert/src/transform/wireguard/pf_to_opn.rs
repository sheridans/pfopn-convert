use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

use super::common::{as_bool_text, push_text_child, text_of};

/// Map pfSense WireGuard configuration to OPNsense format.
///
/// Converts pfSense's tunnel/peer structure to OPNsense's server/client structure:
///
/// **pfSense structure:**
/// ```xml
/// <wireguard>
///   <tunnels><item><name>tun_wg0</name>...</item></tunnels>
///   <peers><item><tun>tun_wg0</tun><descr>peer1</descr>...</item></peers>
/// </wireguard>
/// ```
///
/// **OPNsense structure:**
/// ```xml
/// <wireguard>
///   <server><servers><server><name>tun_wg0</name><instance>0</instance>...</server></servers></server>
///   <client><clients><client><name>peer1</name>...</client></clients></client>
/// </wireguard>
/// ```
///
/// ## Round-Trip Support
///
/// If an `<opnsense_wireguard_snapshot>` exists in the source (from a previous
/// OPNsense → pfSense conversion), it is restored directly to preserve all
/// OPNsense-specific fields that don't exist in pfSense's simpler model.
///
/// ## Mapping Details
///
/// - Tunnels → Servers: Each `<tunnels><item>` becomes a `<server>`
/// - Peers → Clients: Each `<peers><item>` becomes a `<client>`
/// - Peer-to-tunnel association: pfSense uses `<tun>` field; OPNsense links via `<peers>` UUID list
/// - Instance numbers: Extracted from tunnel names (e.g., "tun_wg0" → instance "0")
/// - Tunnel addresses: pfSense's `<allowedips><row>` becomes OPNsense's comma-separated CIDRs
pub fn map_pfsense_wireguard(source: &XmlNode) -> XmlNode {
    // If we have a snapshot from a previous OPNsense → pfSense → OPNsense round-trip,
    // restore it to preserve all OPNsense-specific fields
    if let Some(snapshot) = source.get_child("opnsense_wireguard_snapshot") {
        let mut restored = snapshot.clone();
        restored.tag = "wireguard".to_string();
        return restored;
    }

    let mut out = XmlNode::new("wireguard");
    let mut uuid_by_peer_idx: BTreeMap<usize, String> = BTreeMap::new();
    // Build a map of tunnel name → list of peer UUIDs for that tunnel
    // OPNsense servers reference their clients via a comma-separated UUID list
    let mut peers_by_tun: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // First pass: Convert all pfSense peers to OPNsense clients
    let mut client_wrap = XmlNode::new("client");
    let mut clients = XmlNode::new("clients");
    if let Some(peers) = source.get_child("peers") {
        for (idx, peer) in peers.get_children("item").into_iter().enumerate() {
            let uuid = stable_uuid("pf-peer", idx);
            let mut client = XmlNode::new("client");
            client.attributes.insert("uuid".to_string(), uuid.clone());
            push_text_child(
                &mut client,
                "enabled",
                as_bool_text(text_of(peer, &["enabled"]).unwrap_or("0")),
            );
            // pfSense uses <descr> for peer names; generate a default if missing
            let name = text_of(peer, &["descr"])
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("wg_peer_{}", idx + 1));
            push_text_child(&mut client, "name", name);
            push_text_child(
                &mut client,
                "pubkey",
                text_of(peer, &["publickey"]).unwrap_or_default(),
            );
            push_text_child(
                &mut client,
                "psk",
                text_of(peer, &["presharedkey"]).unwrap_or_default(),
            );
            // Convert pfSense's <allowedips><row> structure to comma-separated CIDRs
            let tunnel_address = peer_tunnel_address(peer);
            push_text_child(&mut client, "tunneladdress", tunnel_address);
            push_text_child(
                &mut client,
                "serveraddress",
                text_of(peer, &["endpoint", "address"]).unwrap_or_default(),
            );
            push_text_child(
                &mut client,
                "serverport",
                text_of(peer, &["endpoint", "port"]).unwrap_or_default(),
            );
            push_text_child(
                &mut client,
                "keepalive",
                text_of(peer, &["persistentkeepalive"]).unwrap_or_default(),
            );
            // Associate this peer with its parent tunnel (via <tun> field in pfSense)
            if let Some(tun) = text_of(peer, &["tun"]) {
                peers_by_tun
                    .entry(tun.to_string())
                    .or_default()
                    .push(uuid.clone());
            }
            uuid_by_peer_idx.insert(idx, uuid);
            clients.children.push(client);
        }
    }
    client_wrap.children.push(clients);
    out.children.push(client_wrap);

    // Copy the global enabled setting
    let mut general = XmlNode::new("general");
    push_text_child(
        &mut general,
        "enabled",
        as_bool_text(
            text_of(source, &["config", "enable"])
                .or_else(|| text_of(source, &["config", "enabled"]))
                .unwrap_or("0"),
        ),
    );
    out.children.push(general);

    // Second pass: Convert all pfSense tunnels to OPNsense servers
    let mut server_wrap = XmlNode::new("server");
    let mut servers = XmlNode::new("servers");
    if let Some(tunnels) = source.get_child("tunnels") {
        for (idx, tunnel) in tunnels.get_children("item").into_iter().enumerate() {
            let tun_name = text_of(tunnel, &["name"])
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("tun_wg{idx}"));
            let mut server = XmlNode::new("server");
            server
                .attributes
                .insert("uuid".to_string(), stable_uuid("pf-tunnel", idx));
            push_text_child(
                &mut server,
                "enabled",
                as_bool_text(text_of(tunnel, &["enabled"]).unwrap_or("0")),
            );
            push_text_child(&mut server, "name", tun_name.clone());
            // Extract instance number from tunnel name (e.g., "tun_wg0" → "0")
            push_text_child(&mut server, "instance", extract_instance_id(&tun_name));
            push_text_child(
                &mut server,
                "pubkey",
                text_of(tunnel, &["publickey"]).unwrap_or_default(),
            );
            push_text_child(
                &mut server,
                "privkey",
                text_of(tunnel, &["privatekey"]).unwrap_or_default(),
            );
            push_text_child(
                &mut server,
                "port",
                text_of(tunnel, &["listenport"]).unwrap_or_default(),
            );
            push_text_child(
                &mut server,
                "mtu",
                text_of(tunnel, &["mtu"]).unwrap_or_default(),
            );
            push_text_child(
                &mut server,
                "tunneladdress",
                text_of(tunnel, &["addresses"]).unwrap_or_default(),
            );
            push_text_child(&mut server, "disableroutes", "1"); // OPNsense default
            push_text_child(&mut server, "gateway", ""); // Not set by default
            push_text_child(&mut server, "carp_depend_on", ""); // CARP dependency (unused)
                                                                // Link this server to its clients via comma-separated UUID list
            let peer_list = peers_by_tun.get(&tun_name).cloned().unwrap_or_default();
            push_text_child(&mut server, "peers", peer_list.join(","));
            push_text_child(&mut server, "debug", "0"); // Debug mode off
            push_text_child(&mut server, "endpoint", ""); // Not used for servers
            push_text_child(&mut server, "peer_dns", ""); // DNS servers pushed to clients
            servers.children.push(server);
        }
    }
    server_wrap.children.push(servers);
    out.children.push(server_wrap);

    let _ = uuid_by_peer_idx;
    out
}

/// Extract tunnel addresses from pfSense peer's allowedips structure.
///
/// pfSense stores allowed IPs as `<allowedips><row><address>` and `<mask>`.
/// OPNsense expects a comma-separated list of CIDRs (e.g., "10.0.0.2/32,fd00::2/128").
///
/// Returns comma-separated CIDR list, or empty string if no allowed IPs.
fn peer_tunnel_address(peer: &XmlNode) -> String {
    let Some(allowed) = peer.get_child("allowedips") else {
        return String::new();
    };
    let mut cidrs = Vec::new();
    for row in allowed.get_children("row") {
        let Some(addr) = text_of(row, &["address"]) else {
            continue;
        };
        let mask = text_of(row, &["mask"]).unwrap_or("32"); // Default to /32 for single IPs
        cidrs.push(format!("{addr}/{mask}"));
    }
    cidrs.join(",")
}

/// Extract WireGuard instance number from pfSense tunnel name.
///
/// pfSense uses names like "tun_wg0", "tun_wg1", etc.
/// OPNsense uses instance numbers (0, 1, 2...) that map to device names (wg0, wg1, wg2...).
///
/// Extracts all digits from the tunnel name. If no digits found, defaults to "0".
///
/// # Examples
/// - "tun_wg0" → "0"
/// - "tun_wg12" → "12"
/// - "custom_tunnel" → "0" (no digits, default)
fn extract_instance_id(tun_name: &str) -> String {
    let digits: String = tun_name.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        "0".to_string()
    } else {
        digits
    }
}

/// Generate a deterministic UUID for WireGuard config elements.
///
/// Creates stable UUIDs so the same pfSense configuration always produces
/// the same OPNsense UUIDs. This ensures:
/// - Idempotent conversions (converting twice produces identical output)
/// - Server-client linking via UUID references works correctly
/// - Diff stability (unchanged configs keep the same UUIDs)
///
/// Uses CRC32 of the prefix XORed with the index to ensure uniqueness.
fn stable_uuid(prefix: &str, idx: usize) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        crc32(prefix.as_bytes()) ^ (idx as u32),
        0,
        0,
        0,
        (idx as u64) + 1
    )
}

/// Compute CRC32 checksum (ISO 3309 / ITU-T V.42) using standard polynomial 0xEDB88320.
fn crc32(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for b in input {
        crc ^= *b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg(); // All-ones if LSB set, else all-zeros
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc // Final inversion
}
