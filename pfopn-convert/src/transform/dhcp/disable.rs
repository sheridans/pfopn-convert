use xml_diff_core::XmlNode;

/// Disable DHCP backends in-place on a generated config tree.
///
/// This is intentionally opt-in and should only be called when the user
/// explicitly requests DHCP shutdown for safe restore/testing workflows.
pub fn apply(root: &mut XmlNode) {
    disable_legacy_section(root, "dhcpd");
    disable_legacy_section(root, "dhcpdv6");
    disable_legacy_section(root, "dhcpd6");
    disable_opnsense_kea(root);
    disable_kea_container(root, "kea");
    disable_kea_container(root, "Kea");
}

/// Disable all interfaces in a legacy ISC DHCP section.
///
/// For each interface child in the section (e.g., `<lan>`, `<wan>`, `<opt1>`),
/// sets multiple disable flags to ensure the DHCP server won't start:
/// - `<enable>0</enable>`
/// - `<enabled>0</enabled>`
/// - `<disabled>1</disabled>`
///
/// Skips children whose tags start with '#' (comments).
fn disable_legacy_section(root: &mut XmlNode, section: &str) {
    let Some(node) = child_mut(root, section) else {
        return;
    };
    for iface in &mut node.children {
        if iface.tag.starts_with('#') {
            continue;
        }
        set_or_insert_text_child(iface, "enable", "0");
        set_or_insert_text_child(iface, "enabled", "0");
        set_or_insert_text_child(iface, "disabled", "1");
    }
}

/// Disable OPNsense Kea DHCP services.
///
/// Disables Kea by setting `<enabled>0</enabled>` in the general settings for:
/// - `dhcp4` (IPv4 DHCP server)
/// - `dhcp6` (IPv6 DHCP server)
/// - `ctrl_agent` (Kea control agent)
///
/// Also recursively disables all enabled flags throughout the Kea subtree.
fn disable_opnsense_kea(root: &mut XmlNode) {
    let Some(opn) = child_mut(root, "OPNsense") else {
        return;
    };
    let Some(kea) = child_mut(opn, "Kea") else {
        return;
    };

    for service in ["dhcp4", "dhcp6", "ctrl_agent"] {
        if let Some(service_node) = child_mut(kea, service) {
            let general = ensure_child_mut(service_node, "general");
            set_or_insert_text_child(general, "enabled", "0");
        }
    }
    disable_enabled_flags_recursive(kea);
}

/// Disable a Kea container by recursively disabling all enabled flags.
///
/// Used for both `<kea>` (pfSense-style) and `<Kea>` (OPNsense-style) containers.
fn disable_kea_container(root: &mut XmlNode, tag: &str) {
    if let Some(kea) = child_mut(root, tag) {
        disable_enabled_flags_recursive(kea);
    }
}

/// Recursively walk the tree and disable all enabled/enable flags.
///
/// For each node in the tree:
/// - If tag is "enabled" or "enable", set text to "0"
/// - If tag is "disabled", set text to "1"
/// - Recurse into all children
///
/// This ensures complete shutdown of any DHCP service by flipping all
/// boolean flags to the "off" state.
fn disable_enabled_flags_recursive(node: &mut XmlNode) {
    if node.tag == "enabled" || node.tag == "enable" {
        node.text = Some("0".to_string());
    } else if node.tag == "disabled" {
        node.text = Some("1".to_string());
    }
    for child in &mut node.children {
        disable_enabled_flags_recursive(child);
    }
}

/// Get a mutable reference to a child by tag name, if it exists.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

/// Get or create a mutable reference to a child node by tag name.
fn ensure_child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(idx) = node.children.iter().position(|c| c.tag == tag) {
        return &mut node.children[idx];
    }
    node.children.push(XmlNode::new(tag));
    let idx = node.children.len() - 1;
    &mut node.children[idx]
}

/// Set or insert a text child element.
///
/// If a child with the tag exists, updates its text. Otherwise, creates it.
fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    node.children.push(child);
}

#[cfg(test)]
mod tests {
    use super::apply;
    use xml_diff_core::parse;

    #[test]
    fn disables_legacy_dhcp_sections() {
        let mut root = parse(
            br#"<pfsense><dhcpd><lan><enable>1</enable></lan></dhcpd><dhcpdv6><lan/></dhcpdv6></pfsense>"#,
        )
        .expect("parse");
        apply(&mut root);

        let lan4 = root
            .get_child("dhcpd")
            .and_then(|n| n.get_child("lan"))
            .expect("dhcpd lan");
        assert_eq!(lan4.get_text(&["enable"]), Some("0"));
        assert_eq!(lan4.get_text(&["disabled"]), Some("1"));

        let lan6 = root
            .get_child("dhcpdv6")
            .and_then(|n| n.get_child("lan"))
            .expect("dhcpdv6 lan");
        assert_eq!(lan6.get_text(&["disabled"]), Some("1"));
    }

    #[test]
    fn disables_opnsense_kea_general_flags() {
        let mut root = parse(
            br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general></dhcp4><dhcp6><general><enabled>1</enabled></general></dhcp6></Kea></OPNsense></opnsense>"#,
        )
        .expect("parse");
        apply(&mut root);

        let dhcp4_enabled = root.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]);
        let dhcp6_enabled = root.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]);
        assert_eq!(dhcp4_enabled, Some("0"));
        assert_eq!(dhcp6_enabled, Some("0"));
    }

    #[test]
    fn disables_pfsense_kea_style_flags() {
        let mut root = parse(
            br#"<pfsense><dhcpbackend>kea</dhcpbackend><kea><dhcp4><general><enabled>1</enabled></general></dhcp4><ctrl_agent><general><enable>1</enable></general></ctrl_agent></kea></pfsense>"#,
        )
        .expect("parse");
        apply(&mut root);

        let dhcp4_enabled = root.get_text(&["kea", "dhcp4", "general", "enabled"]);
        let ctrl_enable = root.get_text(&["kea", "ctrl_agent", "general", "enable"]);
        assert_eq!(dhcp4_enabled, Some("0"));
        assert_eq!(ctrl_enable, Some("0"));
    }
}
