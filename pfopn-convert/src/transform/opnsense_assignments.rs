use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

/// Normalize OPNsense interface assignments to use standard opt1, opt2, opt3... naming.
///
/// OPNsense allows interfaces to be assigned with arbitrary logical names like
/// "ovpns1" (OpenVPN server), "wg1" (WireGuard), "tailscale0", etc. These aren't
/// part of the standard "opt1, opt2, opt3..." sequence that OPNsense expects for
/// additional interfaces beyond wan/lan.
///
/// This function finds those non-standard assignments and remaps them to the next
/// available "optN" slot. It returns a map of old names -> new names so that
/// references elsewhere in the config can be updated (via logical_refs.rs).
///
/// Example: If you have wan, lan, opt1, and ovpns1, this will rename ovpns1 to opt2.
pub fn normalize(out: &mut XmlNode) -> BTreeMap<String, String> {
    let mut rewrites = BTreeMap::new();
    let Some(interfaces) = child_mut(out, "interfaces") else {
        return rewrites;
    };

    // Build a sorted list of which opt indices (1, 2, 3...) are already in use
    let mut used_opt = collect_used_opt_indices(interfaces);

    for iface in &mut interfaces.children {
        let old_tag = iface.tag.clone();

        // If this is already a valid OPNsense logical name (wan, lan, opt1...),
        // leave it alone.
        if is_allowed_opnsense_logical(&old_tag) {
            continue;
        }

        // If this isn't a virtual interface assignment (OpenVPN, WireGuard, etc.),
        // skip it (we only care about renaming virtual assignments).
        if !is_virtual_assignment_candidate(&old_tag) {
            continue;
        }

        // Find the next available opt number and rename this interface
        let new_tag = next_opt_tag(&mut used_opt);
        iface.tag = new_tag.clone();
        rewrites.insert(old_tag, new_tag);
    }

    rewrites
}

/// Helper to get a mutable reference to a direct child node by tag name.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

/// Check if this interface name is already valid in OPNsense without remapping.
///
/// Valid names include:
/// - Built-in interfaces: wan, lan, lo0
/// - Virtual interface group names: openvpn, wireguard, tailscale
/// - Standard optional interfaces: opt1, opt2, opt3, etc.
fn is_allowed_opnsense_logical(tag: &str) -> bool {
    if matches!(
        tag,
        "wan" | "lan" | "lo0" | "openvpn" | "wireguard" | "tailscale"
    ) {
        return true;
    }
    // If it's already in optN format with a valid number, it's fine
    parse_opt_index(tag).is_some()
}

/// Check if this looks like a virtual interface assignment that should be remapped.
///
/// These are interface names that OPNsense auto-generates for VPN tunnels and
/// virtual interfaces:
/// - ovpns1, ovpns2... (OpenVPN server instances)
/// - ovpnc1, ovpnc2... (OpenVPN client instances)
/// - wg1, wg2... (WireGuard interfaces)
/// - tun_wg1... (alternative WireGuard naming)
/// - tailscale0... (Tailscale interfaces)
fn is_virtual_assignment_candidate(tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    lower.starts_with("ovpns")
        || lower.starts_with("ovpnc")
        || lower.starts_with("wg")
        || lower.starts_with("tun_wg")
        || lower.starts_with("tailscale")
}

/// Parse an interface tag like "opt3" into its numeric index (3).
/// Returns None if the tag isn't in optN format or N isn't a valid number.
fn parse_opt_index(tag: &str) -> Option<u32> {
    let rest = tag.strip_prefix("opt")?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// Collect all currently-used opt indices (1, 2, 3...) from interface assignments.
/// Returns a sorted, deduplicated list.
fn collect_used_opt_indices(interfaces: &XmlNode) -> Vec<u32> {
    let mut out: Vec<u32> = interfaces
        .children
        .iter()
        .filter_map(|n| parse_opt_index(&n.tag))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Find the next available opt index (starting from 1) that isn't already used.
/// Adds it to the `used` list and returns the tag name (e.g. "opt2").
///
/// Uses binary search for efficiency since `used` is kept sorted.
fn next_opt_tag(used: &mut Vec<u32>) -> String {
    let mut idx = 1u32;
    // Keep incrementing until we find a number that's NOT in the used list
    while used.binary_search(&idx).is_ok() {
        idx += 1;
    }
    used.push(idx);
    used.sort_unstable();
    format!("opt{idx}")
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::normalize;

    #[test]
    fn remaps_ovpns_assignment_to_next_opt() {
        let mut root = parse(
            br#"<opnsense><interfaces><wan><if>vtnet1</if></wan><lan><if>vtnet0</if></lan><opt1><if>vlan01</if></opt1><ovpns1><if>ovpns1</if></ovpns1></interfaces></opnsense>"#,
        )
        .expect("parse");

        let map = normalize(&mut root);
        assert_eq!(map.get("ovpns1"), Some(&"opt2".to_string()));
        assert!(root
            .get_child("interfaces")
            .and_then(|i| i.get_child("opt2"))
            .is_some());
    }
}
