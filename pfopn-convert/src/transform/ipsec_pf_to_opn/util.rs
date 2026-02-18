use xml_diff_core::XmlNode;

/// Convert pfSense's `<disabled>` field to OPNsense's `<enabled>` field.
///
/// pfSense uses presence of `<disabled>` to indicate disabled state.
/// OPNsense uses `<enabled>` with "1" for enabled, "0" for disabled.
///
/// Returns "1" if the node has no `<disabled>` child (enabled in pfSense).
/// Returns "0" if the node has a `<disabled>` child (disabled in pfSense).
pub(super) fn enabled_from_disabled(node: &XmlNode) -> &'static str {
    if text_or(node, "disabled", "").is_empty() {
        "1"
    } else {
        "0"
    }
}

/// Convert pfSense phase1 authentication method to Swanctl auth type.
///
/// pfSense uses longer authentication_method names like "pre_shared_key".
/// Swanctl uses shorter auth types: "psk" for pre-shared keys, "pubkey" for certificates.
pub(super) fn p1_auth_to_swanctl(auth: &str) -> &'static str {
    if auth.eq_ignore_ascii_case("pre_shared_key") {
        "psk"
    } else {
        "pubkey"
    }
}

/// Extract local endpoint identifier from a pfSense phase1 entry.
///
/// Returns the value of `<myid_data>` if present, otherwise empty string.
/// The local ID is used by IKE to identify this endpoint to the remote peer.
pub(super) fn p1_local_id(p1: &XmlNode) -> String {
    let data = text_or(p1, "myid_data", "");
    if !data.is_empty() {
        return data.to_string();
    }
    String::new()
}

/// Extract remote endpoint identifier from a pfSense phase1 entry.
///
/// Returns the value of `<peerid_data>` if present, otherwise empty string.
/// The remote ID is what we expect the remote peer to identify itself as during IKE negotiation.
pub(super) fn p1_remote_id(p1: &XmlNode) -> String {
    let data = text_or(p1, "peerid_data", "");
    if !data.is_empty() {
        return data.to_string();
    }
    String::new()
}

/// Extract local traffic selector from a pfSense phase2 entry.
///
/// Traffic selectors define which IP addresses/subnets are allowed through the tunnel.
/// Converts pfSense's `<localid>` structure to Swanctl traffic selector format.
///
/// Returns formatted traffic selector (e.g., "192.168.1.0/24" or "10.0.0.1-10.0.0.10").
pub(super) fn p2_local_ts(p2: &XmlNode) -> String {
    let Some(localid) = p2.get_child("localid") else {
        return String::new();
    };
    ts_from_selector(localid)
}

/// Extract remote traffic selector from a pfSense phase2 entry.
///
/// Traffic selectors define which remote IP addresses/subnets are allowed through the tunnel.
/// Converts pfSense's `<remoteid>` structure to Swanctl traffic selector format.
///
/// Returns formatted traffic selector (e.g., "10.9.9.0/24" or "192.168.1.100").
pub(super) fn p2_remote_ts(p2: &XmlNode) -> String {
    let Some(remoteid) = p2.get_child("remoteid") else {
        return String::new();
    };
    ts_from_selector(remoteid)
}

/// Determine Swanctl start_action from pfSense phase1 startaction.
///
/// Controls whether the tunnel should be initiated automatically:
/// - "start" — initiate tunnel immediately on boot
/// - "none" — wait for traffic to trigger tunnel (on-demand)
pub(super) fn p2_start_action(p1: &XmlNode) -> &'static str {
    let action = text_or(p1, "startaction", "none");
    if action.eq_ignore_ascii_case("start") {
        "start"
    } else {
        "none"
    }
}

/// Convert pfSense "on"/"off" strings to OPNsense "1"/"0" strings.
///
/// pfSense uses "on" and "off" for boolean toggles in IPsec config.
/// OPNsense uses "1" and "0" in Swanctl configuration.
pub(super) fn on_off_to_bool(v: &str) -> &'static str {
    if v.eq_ignore_ascii_case("on") {
        "1"
    } else {
        "0"
    }
}

/// Extract trimmed text from a child element, or return a default value.
///
/// Helper to safely access XML text content with a fallback.
pub(super) fn text_or<'a>(node: &'a XmlNode, child: &str, default: &'a str) -> &'a str {
    node.get_text(&[child]).map(str::trim).unwrap_or(default)
}

/// Create and append a text-only child element to a parent node.
///
/// Helper to reduce boilerplate when building XML structures.
pub(super) fn push_text_child(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

/// Generate a deterministic UUID v4 from a prefix, index, and seed string.
///
/// Creates stable UUIDs for IPsec config elements so that the same pfSense
/// configuration always produces the same OPNsense UUIDs. This is important
/// for:
/// - Idempotent conversions (converting twice produces identical output)
/// - Linking related elements (Connection → local/remote/child via UUID references)
/// - Diff stability (unchanged tunnels keep the same UUIDs)
///
/// The algorithm:
/// 1. Mix prefix and seed bytes into a 16-byte accumulator with position-dependent rotation
/// 2. Fold in the index to ensure different elements with the same seed get unique UUIDs
/// 3. Set UUID version 4 bits and RFC 4122 variant bits for format compliance
///
/// # Example
/// ```ignore
/// stable_uuid("conn", 0, "1") // -> "abc12345-6789-4...-8...-..."
/// stable_uuid("conn", 0, "1") // -> same UUID (deterministic)
/// stable_uuid("conn", 1, "1") // -> different UUID (different index)
/// stable_uuid("local", 0, "1") // -> different UUID (different prefix)
/// ```
pub(super) fn stable_uuid(prefix: &str, idx: usize, seed: &str) -> String {
    let mut bytes = [0u8; 16];
    // Mix prefix and seed bytes into the accumulator with position-dependent rotation
    for (i, b) in prefix.bytes().chain(seed.bytes()).enumerate() {
        bytes[i % 16] = bytes[i % 16].wrapping_add(b).rotate_left((i % 7) as u32);
    }
    // Fold in the index so that elements with identical seeds but different positions
    // still produce distinct UUIDs
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = b.wrapping_add(((idx + i) as u8).rotate_left((idx % 5) as u32));
    }
    // Set UUID version 4 nibble (0x40) and RFC 4122 variant bits (0x80-0xBF)
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Convert a pfSense traffic selector to Swanctl traffic selector format.
///
/// pfSense phase2 `<localid>` and `<remoteid>` elements describe which IP
/// addresses/subnets are allowed through the tunnel using different selector types:
///
/// - **"network"** — A subnet in CIDR notation (e.g., "192.168.1.0/24")
///   - Extracts `<address>` and `<netbits>`, formats as "address/netbits"
/// - **"address"** — A single IP address (e.g., "10.0.0.1")
///   - Extracts `<address>` directly
/// - **"range"** — An IP address range (e.g., "10.0.0.10-10.0.0.20")
///   - Extracts `<from>` and `<to>`, formats as "from-to"
///
/// Returns empty string if the selector type is unrecognized or required fields are missing.
fn ts_from_selector(node: &XmlNode) -> String {
    let typ = text_or(node, "type", "");
    if typ.eq_ignore_ascii_case("network") {
        return network_cidr(node);
    }
    if typ.eq_ignore_ascii_case("address") {
        return text_or(node, "address", "").to_string();
    }
    if typ.eq_ignore_ascii_case("range") {
        let from = text_or(node, "from", "");
        let to = text_or(node, "to", "");
        if !from.is_empty() && !to.is_empty() {
            return format!("{from}-{to}");
        }
    }
    String::new()
}

/// Format a network selector as CIDR notation.
///
/// Extracts `<address>` and `<netbits>` from a pfSense network selector
/// and formats them as "address/netbits" (e.g., "192.168.1.0/24").
///
/// Returns empty string if either field is missing.
fn network_cidr(node: &XmlNode) -> String {
    let addr = text_or(node, "address", "");
    let bits = text_or(node, "netbits", "");
    if addr.is_empty() || bits.is_empty() {
        return String::new();
    }
    format!("{addr}/{bits}")
}
