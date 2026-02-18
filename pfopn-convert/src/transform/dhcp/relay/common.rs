use xml_diff_core::XmlNode;

/// DHCP relay section tag names used by both platforms.
///
/// - `dhcrelay` — IPv4 DHCP relay configuration
/// - `dhcrelay6` — IPv6 DHCP relay configuration (modern naming)
/// - `dhcp6relay` — IPv6 DHCP relay configuration (legacy naming)
pub(super) const RELAY_TAGS: [&str; 3] = ["dhcrelay", "dhcrelay6", "dhcp6relay"];

/// Sync DHCP relay sections from source to output.
///
/// Removes any existing relay sections from the output, then copies all relay
/// sections from the source. This ensures the output has exactly the relay
/// configuration from the source, with no duplicates or leftovers from the target template.
pub(super) fn sync_relay_sections(out: &mut XmlNode, source: &XmlNode) {
    out.children
        .retain(|child| !RELAY_TAGS.iter().any(|tag| child.tag == *tag));

    for child in &source.children {
        if RELAY_TAGS.iter().any(|tag| child.tag == *tag) {
            out.children.push(child.clone());
        }
    }
}

/// Get or create a mutable reference to a child node by tag name.
pub(super) fn ensure_child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(pos) = node.children.iter().position(|c| c.tag == tag) {
        return &mut node.children[pos];
    }
    node.children.push(XmlNode::new(tag));
    let len = node.children.len();
    &mut node.children[len - 1]
}

/// Create and append a text-only child element.
pub(super) fn push_text_child(parent: &mut XmlNode, tag: &str, value: &str) {
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    parent.children.push(child);
}

/// Convert a boolean to "1" or "0" string representation.
pub(super) fn bool_to_01(enabled: bool) -> &'static str {
    if enabled {
        "1"
    } else {
        "0"
    }
}

/// Parse relay enabled text to boolean.
///
/// Returns `true` if the value is "1", "on", or "true" (case-insensitive).
pub(super) fn relay_enabled_text(v: Option<&str>) -> bool {
    let Some(v) = v else {
        return false;
    };
    let v = v.trim();
    v == "1" || v.eq_ignore_ascii_case("on") || v.eq_ignore_ascii_case("true")
}

/// Generate a deterministic UUID from a seed value.
///
/// Creates stable UUIDs for relay configuration elements. Used for OPNsense
/// plugin config which requires UUIDs for each relay instance.
pub(super) fn synthetic_uuid(seed: usize) -> String {
    format!("00000000-0000-4000-8000-{seed:012x}")
}

/// Add a value to a vector if it's not already present.
///
/// Used for collecting unique interface names or server addresses.
pub(super) fn push_unique(items: &mut Vec<String>, value: String) {
    if !items.iter().any(|v| v == &value) {
        items.push(value);
    }
}
