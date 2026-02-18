use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

/// Remove interface entries from `out` that have no matching physical port in
/// the destination baseline config.
///
/// When converting between pfSense and OPNsense, the source config may define
/// optional interfaces (e.g. `opt1`, `opt2`) that are bound to hardware NICs
/// which don't exist on the target box. Importing those entries would create
/// broken interface assignments. This function compares the output's
/// `<interfaces>` children against the target baseline and drops any that
/// aren't present -- unless they are backed by virtual devices (VLANs, tunnels,
/// bridges, etc.) which don't depend on physical port availability.
///
/// Returns a sorted, deduplicated list of the interface tags that were removed.
pub fn prune_missing(out: &mut XmlNode, target_baseline: &XmlNode) -> Vec<String> {
    let Some(out_ifaces) = child_mut(out, "interfaces") else {
        return Vec::new();
    };
    let Some(target_ifaces) = target_baseline.get_child("interfaces") else {
        return Vec::new();
    };

    // Build the set of interface tags that exist on the target box.
    let allowed: BTreeSet<&str> = target_ifaces
        .children
        .iter()
        .map(|c| c.tag.as_str())
        .collect();
    let mut removed = Vec::new();
    out_ifaces.children.retain(|iface| {
        // Keep if the target has a matching tag, or if it's a virtual interface
        // that doesn't need a physical port.
        let keep = allowed.contains(iface.tag.as_str()) || is_virtual_backed_interface(iface);
        if !keep {
            removed.push(iface.tag.clone());
        }
        keep
    });
    removed.sort();
    removed.dedup();
    removed
}

/// Check whether an interface entry is backed by a virtual device.
///
/// Virtual interfaces (WireGuard, VLANs, OpenVPN tunnels, bridges, etc.)
/// are safe to keep even when the target baseline doesn't list them, because
/// they don't depend on a specific physical NIC being present. This is
/// checked two ways:
/// - The tag itself is `wireguard` (case-insensitive).
/// - The `<if>` child contains a known virtual device name pattern.
fn is_virtual_backed_interface(iface: &XmlNode) -> bool {
    if iface.tag.eq_ignore_ascii_case("wireguard") {
        return true;
    }
    iface
        .get_text(&["if"])
        .map(is_virtual_if_name)
        .unwrap_or(false)
}

/// Return `true` if a device name looks like a virtual/software interface.
///
/// Matches dotted names (VLAN sub-interfaces like `em0.100`), names containing
/// "wg" (WireGuard), and names starting with common virtual device prefixes
/// (vlan, bridge, ovpns/ovpnc, tun, gif, gre, lagg, tap, enc, ipsec, lo).
fn is_virtual_if_name(if_name: &str) -> bool {
    let lower = if_name.trim().to_ascii_lowercase();
    // Dotted names are VLAN sub-interfaces; "wg" anywhere indicates WireGuard.
    if lower.contains('.') || lower.contains("wg") {
        return true;
    }
    [
        "vlan", "bridge", "ovpns", "ovpnc", "openvpn", "wg", "tun_wg", "gif", "gre", "lagg", "tap",
        "tun", "enc", "ipsec", "lo",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

/// Return a mutable reference to the first child with the given tag.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

#[cfg(test)]
mod tests {
    use super::prune_missing;
    use xml_diff_core::parse;

    #[test]
    fn prunes_interfaces_not_in_target_baseline() {
        let mut out =
            parse(br#"<opnsense><interfaces><wan/><lan/><opt1/><opt2/></interfaces></opnsense>"#)
                .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><wan/><lan/></interfaces></opnsense>"#).expect("parse");
        let removed = prune_missing(&mut out, &target);
        assert_eq!(removed, vec!["opt1".to_string(), "opt2".to_string()]);
        let interfaces = out.get_child("interfaces").expect("interfaces");
        assert!(interfaces.get_child("wan").is_some());
        assert!(interfaces.get_child("lan").is_some());
        assert!(interfaces.get_child("opt1").is_none());
        assert!(interfaces.get_child("opt2").is_none());
    }

    #[test]
    fn keeps_wireguard_interface_even_if_not_in_target_baseline() {
        let mut out = parse(
            br#"<opnsense><interfaces><wan/><lan/><wireguard><if>tun_wg0</if></wireguard></interfaces></opnsense>"#,
        )
        .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><wan/><lan/></interfaces></opnsense>"#).expect("parse");
        let removed = prune_missing(&mut out, &target);
        assert!(!removed.contains(&"wireguard".to_string()));
        let interfaces = out.get_child("interfaces").expect("interfaces");
        assert!(interfaces.get_child("wireguard").is_some());
    }

    #[test]
    fn keeps_virtual_backed_interface_even_if_not_in_target_baseline() {
        let mut out = parse(
            br#"<opnsense><interfaces><wan/><lan/><opt9><if>vlan9</if></opt9></interfaces></opnsense>"#,
        )
        .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><wan/><lan/></interfaces></opnsense>"#).expect("parse");
        let removed = prune_missing(&mut out, &target);
        assert!(!removed.contains(&"opt9".to_string()));
        let interfaces = out.get_child("interfaces").expect("interfaces");
        assert!(interfaces.get_child("opt9").is_some());
    }
}
