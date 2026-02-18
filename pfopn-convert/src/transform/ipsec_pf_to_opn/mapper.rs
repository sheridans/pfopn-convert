use xml_diff_core::XmlNode;

use super::base::{base_opnsense_ipsec, base_swanctl, push_to_ipsec_psk, push_to_swanctl};
use super::util::{
    enabled_from_disabled, on_off_to_bool, p1_auth_to_swanctl, p1_local_id, p1_remote_id,
    p2_local_ts, p2_remote_ts, p2_start_action, push_text_child, stable_uuid, text_or,
};

/// Map pfSense IPsec phase1/phase2 configuration to OPNsense IPsec/Swanctl format.
///
/// This is the core mapping function that converts pfSense's phase1/phase2 IPsec
/// structure into OPNsense's Swanctl (strongSwan) configuration model.
///
/// # Mapping Strategy
///
/// For each pfSense `<phase1>` (IKE SA):
/// 1. Create an OPNsense `<Connection>` with IKE parameters
/// 2. Create a `<local>` entry for local endpoint authentication
/// 3. Create a `<remote>` entry for remote endpoint authentication
/// 4. Extract pre-shared key into `<IPsec><preSharedKeys>`
/// 5. All elements are linked by deterministic UUIDs
///
/// For each pfSense `<phase2>` (ESP child SA):
/// 1. Match to parent phase1 via `ikeid`
/// 2. Create an OPNsense `<child>` entry linked to the parent Connection
/// 3. Convert traffic selectors (local/remote networks)
///
/// # Returns
///
/// A tuple of `(IPsec, Swanctl)` nodes to be inserted under `<OPNsense>`.
pub(super) fn map_pf_ipsec_to_opnsense(source_ipsec: &XmlNode) -> (XmlNode, XmlNode) {
    let mut ipsec = base_opnsense_ipsec();
    let mut swanctl = base_swanctl();

    // Collect all phase1 (IKE SA) and phase2 (ESP child SA) entries from pfSense config
    let phase1s: Vec<&XmlNode> = source_ipsec
        .children
        .iter()
        .filter(|n| n.tag == "phase1")
        .collect();
    let phase2s: Vec<&XmlNode> = source_ipsec
        .children
        .iter()
        .filter(|n| n.tag == "phase2")
        .collect();

    // Process each phase1 entry (IKE tunnel)
    for (idx, p1) in phase1s.iter().enumerate() {
        // Extract ikeid (tunnel identifier) — used to link phase2 entries to phase1
        // Fall back to 1-based index if ikeid is missing (shouldn't happen in valid configs)
        let ikeid = p1
            .get_text(&["ikeid"])
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| (idx + 1).to_string());

        // Generate deterministic UUIDs for Connection, local, and remote entries
        // These UUIDs link the elements together in OPNsense's data model
        let conn_uuid = stable_uuid("conn", idx, &ikeid);
        let local_uuid = stable_uuid("local", idx, &ikeid);
        let remote_uuid = stable_uuid("remote", idx, &ikeid);

        // Create the Connection entry (IKE SA configuration)
        let mut conn = XmlNode::new("Connection");
        conn.attributes
            .insert("uuid".to_string(), conn_uuid.clone());
        push_text_child(&mut conn, "enabled", enabled_from_disabled(p1));
        push_text_child(&mut conn, "proposals", "default"); // Use OPNsense's default IKE proposals
        push_text_child(&mut conn, "unique", "no"); // Allow multiple SAs with same peer
        push_text_child(&mut conn, "aggressive", "0"); // Main mode (not aggressive)
        push_text_child(&mut conn, "version", "0"); // Auto-detect IKEv1/IKEv2
        push_text_child(
            &mut conn,
            "mobike",
            on_off_to_bool(text_or(p1, "mobike", "off")), // MOBIKE (IKEv2 mobility)
        );
        push_text_child(&mut conn, "local_addrs", ""); // Empty = use default local address
        push_text_child(&mut conn, "local_port", "");
        push_text_child(&mut conn, "remote_addrs", text_or(p1, "remote-gateway", ""));
        push_text_child(&mut conn, "remote_port", "");
        push_text_child(
            &mut conn,
            "encap",
            on_off_to_bool(text_or(p1, "nat_traversal", "off")), // NAT-T (UDP encapsulation)
        );
        push_text_child(&mut conn, "reauth_time", ""); // Use default reauth time
        push_text_child(&mut conn, "rekey_time", ""); // Use default rekey time
        push_text_child(&mut conn, "over_time", ""); // Use default overtime
        push_text_child(&mut conn, "dpd_delay", text_or(p1, "dpd_delay", "")); // Dead Peer Detection delay
        push_text_child(&mut conn, "dpd_timeout", text_or(p1, "dpd_maxfail", "")); // DPD timeout (pfSense calls it maxfail)
        push_text_child(&mut conn, "pools", "radius"); // Virtual IP pool (unused for site-to-site)
        push_text_child(&mut conn, "send_certreq", "1"); // Request peer's certificate
        push_text_child(&mut conn, "send_cert", "");
        push_text_child(&mut conn, "keyingtries", ""); // Unlimited retries
        push_text_child(&mut conn, "description", text_or(p1, "descr", ""));
        push_to_swanctl(&mut swanctl, "Connections", conn);

        // Create the local endpoint authentication entry
        let mut local = XmlNode::new("local");
        local.attributes.insert("uuid".to_string(), local_uuid);
        push_text_child(&mut local, "enabled", enabled_from_disabled(p1));
        push_text_child(&mut local, "connection", &conn_uuid); // Link to parent Connection
        push_text_child(&mut local, "round", "0"); // Authentication round (multi-auth support)
        push_text_child(
            &mut local,
            "auth",
            p1_auth_to_swanctl(text_or(p1, "authentication_method", "pre_shared_key")),
        );
        push_text_child(&mut local, "id", &p1_local_id(p1)); // Local IKE identifier
        push_text_child(&mut local, "eap_id", ""); // EAP identity (unused for site-to-site)
        push_text_child(&mut local, "certs", text_or(p1, "certref", "")); // Certificate reference for pubkey auth
        push_text_child(&mut local, "pubkeys", ""); // Public key (alternative to certs)
        push_text_child(&mut local, "description", text_or(p1, "descr", ""));
        push_to_swanctl(&mut swanctl, "locals", local);

        // Create the remote endpoint authentication entry
        let mut remote = XmlNode::new("remote");
        remote.attributes.insert("uuid".to_string(), remote_uuid);
        push_text_child(&mut remote, "enabled", enabled_from_disabled(p1));
        push_text_child(&mut remote, "connection", &conn_uuid); // Link to parent Connection
        push_text_child(&mut remote, "round", "0"); // Authentication round
        push_text_child(&mut remote, "auth", "psk"); // Remote always uses PSK in pfSense configs
        push_text_child(&mut remote, "id", &p1_remote_id(p1)); // Remote IKE identifier
        push_text_child(&mut remote, "eap_id", "");
        push_text_child(&mut remote, "groups", ""); // Authorization groups (unused for site-to-site)
        push_text_child(&mut remote, "certs", ""); // Remote certificate (unused with PSK)
        push_text_child(&mut remote, "cacerts", text_or(p1, "caref", "")); // CA certificate reference
        push_text_child(&mut remote, "pubkeys", ""); // Remote public key
        push_text_child(&mut remote, "description", text_or(p1, "descr", ""));
        push_to_swanctl(&mut swanctl, "remotes", remote);

        // Extract pre-shared key and store in IPsec preSharedKeys section
        // In pfSense, PSK is embedded in phase1. In OPNsense, it's stored separately.
        let mut psk = XmlNode::new("preSharedKey");
        psk.attributes
            .insert("uuid".to_string(), stable_uuid("psk", idx, &ikeid));
        push_text_child(&mut psk, "ident", &p1_local_id(p1)); // Local identity for PSK lookup
        push_text_child(&mut psk, "remote_ident", &p1_remote_id(p1)); // Remote identity for PSK lookup
        push_text_child(&mut psk, "keyType", "PSK");
        push_text_child(&mut psk, "Key", text_or(p1, "pre-shared-key", ""));
        push_text_child(&mut psk, "description", text_or(p1, "descr", ""));
        push_to_ipsec_psk(&mut ipsec, psk);

        // Process all phase2 entries (ESP child SAs) that belong to this phase1
        // Each phase2 defines a set of traffic selectors (local/remote networks)
        for (cidx, p2) in phase2s
            .iter()
            .filter(|p2| text_or(p2, "ikeid", "") == ikeid.as_str()) // Match by ikeid
            .enumerate()
        {
            let mut child = XmlNode::new("child");
            child
                .attributes
                .insert("uuid".to_string(), stable_uuid("child", cidx, &ikeid));
            push_text_child(&mut child, "enabled", "1"); // Always enabled (pfSense doesn't disable individual phase2s)
            push_text_child(&mut child, "connection", &conn_uuid); // Link to parent Connection
            push_text_child(&mut child, "reqid", text_or(p2, "reqid", "")); // IPsec policy ID
            push_text_child(&mut child, "esp_proposals", "default"); // Use OPNsense's default ESP proposals
            push_text_child(&mut child, "sha256_96", "0"); // Use full SHA256 (not truncated)
            push_text_child(&mut child, "start_action", p2_start_action(p1)); // Initiation policy
            push_text_child(&mut child, "close_action", "none"); // Don't close on inactivity
            push_text_child(&mut child, "dpd_action", "clear"); // Clear SA on DPD failure
            push_text_child(&mut child, "mode", text_or(p2, "mode", "tunnel")); // tunnel or transport mode
            push_text_child(&mut child, "policies", "1"); // Install IPsec policies
            push_text_child(&mut child, "local_ts", &p2_local_ts(p2)); // Local traffic selector
            push_text_child(&mut child, "remote_ts", &p2_remote_ts(p2)); // Remote traffic selector
            push_text_child(&mut child, "rekey_time", text_or(p2, "lifetime", "")); // SA lifetime
            push_text_child(&mut child, "description", text_or(p2, "descr", ""));
            push_to_swanctl(&mut swanctl, "children", child);
        }
    }

    (ipsec, swanctl)
}
