use std::collections::HashMap;
use std::net::Ipv6Addr;

use xml_diff_core::XmlNode;

/// Normalize domain search list to space-separated format.
///
/// ISC DHCP allows multiple separators (semicolons, commas, whitespace).
/// Kea expects space-separated domain names.
pub(crate) fn normalize_domain_search(raw: &str) -> String {
    raw.split(|c: char| c == ';' || c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Expand a potentially abbreviated IPv6 address within a subnet prefix.
///
/// ISC DHCP allows IPv6 address ranges to use short notation that assumes
/// the subnet prefix. For example, in subnet fd00::/64, the range "::10 - ::20"
/// should expand to "fd00::10 - fd00::20".
///
/// This function takes a short IPv6 address and combines it with the subnet
/// network and prefix to produce the full address.
///
/// # Arguments
///
/// * `value` - IPv6 address (possibly abbreviated)
/// * `network` - Subnet network address
/// * `prefix` - Subnet prefix length (e.g., 64 for /64)
///
/// # Returns
///
/// Fully expanded IPv6 address string, or `None` if parsing fails
pub(crate) fn expand_ipv6_in_prefix(value: &str, network: Ipv6Addr, prefix: u8) -> Option<String> {
    let addr = value.trim().parse::<Ipv6Addr>().ok()?;
    let mask = ipv6_mask(prefix);
    let network_u = u128::from(network) & mask;
    let host_mask = !mask;
    let host = u128::from(addr) & host_mask;
    Some(Ipv6Addr::from(network_u | host).to_string())
}

/// Generate an IPv6 network mask from a prefix length.
///
/// Converts a CIDR prefix length (e.g., 64) into a 128-bit network mask.
/// Used for subnet calculations.
pub(crate) fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Get or create the `<OPNsense><Kea>` structure in the config tree.
///
/// Ensures both the `<OPNsense>` and `<Kea>` elements exist and returns
/// a mutable reference to the `<Kea>` node.
pub(crate) fn ensure_opnsense_kea(root: &mut XmlNode) -> &mut XmlNode {
    let opn = ensure_child_mut(root, "OPNsense");
    ensure_child_mut(opn, "Kea")
}

/// Get or create a mutable reference to a child node by tag name.
pub(crate) fn ensure_child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(pos) = node.children.iter().position(|c| c.tag == tag) {
        return &mut node.children[pos];
    }
    node.children.push(XmlNode::new(tag));
    let len = node.children.len();
    &mut node.children[len - 1]
}

/// Create and append a text-only child element.
pub(crate) fn push_text_child(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

/// Set or insert a text child element.
///
/// Updates existing child's text if it exists, otherwise creates new child.
pub(crate) fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    push_text_child(node, tag, value);
}

/// Collect interface names from a map and return as sorted comma-separated string.
///
/// Used for creating the `<interfaces>` field in Kea general settings.
pub(crate) fn collect_iface_list(m: &HashMap<String, String>) -> String {
    let mut ifaces: Vec<_> = m.keys().cloned().collect();
    ifaces.sort();
    ifaces.join(",")
}

/// Enable Kea DHCP on a set of interfaces.
///
/// Sets `<enabled>1</enabled>` and populates `<interfaces>` with a sorted,
/// comma-separated list of interface names from the provided map.
pub(crate) fn enable_family_interfaces(general: &mut XmlNode, iface_map: &HashMap<String, String>) {
    set_or_insert_text_child(general, "enabled", "1");
    let iface_list = collect_iface_list(iface_map);
    if !iface_list.is_empty() {
        set_or_insert_text_child(general, "interfaces", &iface_list);
    }
}

/// Get the next synthetic ID for UUID generation, starting from at least 1.
pub(crate) fn next_synthetic_id(start: usize) -> usize {
    start.max(1)
}
