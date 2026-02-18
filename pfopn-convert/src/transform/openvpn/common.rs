use xml_diff_core::XmlNode;

/// Extract OPNsense OpenVPN instances from the source configuration.
///
/// Looks for instances at `<OPNsense><OpenVPN><Instances>` which is where
/// OPNsense stores its native OpenVPN configuration.
///
/// Returns `None` if the path doesn't exist or if the source is pfSense format.
pub(super) fn source_opnsense_instances(source: &XmlNode) -> Option<XmlNode> {
    source
        .get_child("OPNsense")
        .and_then(|n| n.get_child("OpenVPN"))
        .and_then(|n| n.get_child("Instances"))
        .cloned()
}

/// Extract pfSense OpenVPN configuration from the source.
///
/// Looks for the root-level `<openvpn>` element that contains
/// `<openvpn-server>` or `<openvpn-client>` children.
///
/// Returns `None` if:
/// - No `<openvpn>` element exists
/// - The `<openvpn>` element exists but has no server/client children
///   (which indicates an empty or OPNsense-normalized structure)
pub(super) fn source_pfsense_servers(source: &XmlNode) -> Option<XmlNode> {
    let openvpn = source.get_child("openvpn")?;
    if openvpn
        .children
        .iter()
        .any(|c| c.tag == "openvpn-server" || c.tag == "openvpn-client")
    {
        return Some(openvpn.clone());
    }
    None
}

/// Check if a pfSense OpenVPN config originated from OPNsense.
///
/// Detects round-trip conversions by checking for `<opnsense_instance_uuid>`
/// markers in the server configurations. These markers are added when converting
/// from OPNsense to pfSense to enable lossless round-trip conversion.
///
/// Returns `true` if ALL servers have UUID markers, indicating this config
/// came from OPNsense and should be handled specially to avoid duplication.
pub(super) fn is_opnsense_origin_openvpn(openvpn: &XmlNode) -> bool {
    let servers = openvpn.get_children("openvpn-server");
    if servers.is_empty() {
        return false;
    }
    servers
        .into_iter()
        .all(|s| s.get_text(&["opnsense_instance_uuid"]).is_some())
}

/// Get or create a mutable reference to a child node by tag name.
///
/// If the child exists, returns a reference to it. Otherwise, creates a new
/// empty child with the given tag and returns a reference to it.
///
/// This is useful for ensuring nested structures exist before inserting data.
pub(super) fn ensure_child_mut<'a>(parent: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == tag) {
        return &mut parent.children[idx];
    }
    parent.children.push(XmlNode::new(tag));
    let idx = parent.children.len() - 1;
    &mut parent.children[idx]
}

/// Insert or replace a child node in the parent by tag name.
///
/// If a child with the same tag exists, it is replaced. Otherwise, the new
/// child is appended to the parent's children.
pub(super) fn upsert_child(parent: &mut XmlNode, child: XmlNode) {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == child.tag) {
        parent.children[idx] = child;
        return;
    }
    parent.children.push(child);
}

/// Create or replace the top-level `<openvpn>` element with an empty one.
///
/// When converting to OPNsense format, we use the nested `<OPNsense><OpenVPN>`
/// structure as the primary storage. However, we maintain an empty `<openvpn>`
/// element at the root level for compatibility with tools that expect it.
///
/// This function ensures exactly one empty `<openvpn>` element exists.
pub(super) fn normalize_top_level_openvpn_for_opnsense(out: &mut XmlNode) {
    let Some(idx) = out.children.iter().position(|c| c.tag == "openvpn") else {
        out.children.push(XmlNode::new("openvpn"));
        return;
    };
    out.children[idx] = XmlNode::new("openvpn");
}

/// Remove duplicate `<openvpn>` elements, keeping only the first occurrence.
///
/// During conversion, we may end up with multiple `<openvpn>` elements from
/// different sources (preserved original + newly created). This function
/// ensures only one `<openvpn>` element exists in the output.
pub(super) fn dedupe_top_level_openvpn(out: &mut XmlNode) {
    let mut first_seen = false;
    out.children.retain(|n| {
        if n.tag != "openvpn" {
            return true;
        }
        if !first_seen {
            first_seen = true;
            return true;
        }
        false
    });
}

/// Extract an OPNsense instance template from the target configuration.
///
/// When converting pfSense to OPNsense, we use the target's existing instance
/// structure as a template to ensure we create instances with the correct
/// default fields and structure.
///
/// Returns the first `<Instance>` found in the target's OpenVPN configuration,
/// or `None` if no template exists.
pub(super) fn opnsense_instance_template(target: &XmlNode) -> Option<XmlNode> {
    target
        .get_child("OPNsense")
        .and_then(|n| n.get_child("OpenVPN"))
        .and_then(|n| n.get_child("Instances"))
        .and_then(|n| n.get_child("Instance"))
        .cloned()
}

/// Extract all assigned OpenVPN server unit numbers from interface assignments.
///
/// Scans the `<interfaces>` section for interface assignments that reference
/// OpenVPN servers (named "ovpnsN" where N is a digit string).
///
/// Returns a sorted, deduplicated list of unit numbers as strings (e.g., ["1", "2", "10"]).
///
/// # Example
///
/// If interfaces contain `<opt1><if>ovpns1</if></opt1>` and `<opt2><if>ovpns2</if></opt2>`,
/// this returns `vec!["1", "2"]`.
pub(super) fn source_assigned_ovpns_units(source: &XmlNode) -> Vec<String> {
    let Some(interfaces) = source.get_child("interfaces") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for iface in &interfaces.children {
        let Some(raw) = iface.get_text(&["if"]).map(str::trim) else {
            continue;
        };
        let lower = raw.to_ascii_lowercase();
        let Some(unit) = lower.strip_prefix("ovpns") else {
            continue;
        };
        if unit.is_empty() || !unit.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        out.push(unit.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// Generate a deterministic UUID for an OpenVPN instance.
///
/// Creates stable UUIDs based on the pfSense `<vpnid>` field so that the same
/// pfSense configuration always produces the same OPNsense UUIDs. This ensures:
/// - Idempotent conversions (converting twice produces identical output)
/// - Diff stability (unchanged instances keep the same UUIDs)
///
/// The UUID format is v4-like (with version bits set appropriately) and incorporates
/// the numeric portion of the vpnid. Falls back to using the index if vpnid has no digits.
///
/// # Arguments
///
/// * `vpnid` - The pfSense vpnid (e.g., "1", "2", "10")
/// * `index` - Fallback index if vpnid parsing fails
///
/// # Returns
///
/// A UUID string like "00000000-0000-4000-8000-000000000001"
pub(super) fn synthetic_uuid_for_id(vpnid: &str, index: usize) -> String {
    let digits: String = vpnid.chars().filter(|c| c.is_ascii_digit()).collect();
    let id_num = digits.parse::<u64>().unwrap_or((index + 1) as u64);
    format!(
        "00000000-0000-4000-8000-{id_num:012x}",
        id_num = id_num % 0x1_0000_0000_0000
    )
}

/// Create and append a text-only child element to a parent node.
///
/// Helper to reduce boilerplate when building XML structures.
pub(super) fn push_text_child(parent: &mut XmlNode, tag: &str, value: impl Into<String>) {
    let mut n = XmlNode::new(tag);
    n.text = Some(value.into());
    parent.children.push(n);
}

/// Set or insert a text child element in a node.
///
/// If a child with the given tag already exists, updates its text value.
/// Otherwise, creates a new child with the given tag and text value.
pub(super) fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: impl Into<String>) {
    let value = value.into();
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value);
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value);
    node.children.push(child);
}

/// Extract trimmed, non-empty text from a nested path or return a fallback.
///
/// Navigates the XML tree following the given path, extracts the text content,
/// trims whitespace, and returns it. If the path doesn't exist or the text is
/// empty/whitespace-only, returns the fallback value.
///
/// # Arguments
///
/// * `node` - The node to start from
/// * `path` - Path to the target text node (e.g., `&["server", "port"]`)
/// * `fallback` - Value to return if path doesn't exist or is empty
pub(super) fn text_or<'a>(node: &'a XmlNode, path: &[&str], fallback: &'a str) -> String {
    node.get_text(path)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

/// Check if a string value represents a boolean true.
///
/// Recognizes multiple boolean-like strings: "1", "yes", "true", "enabled", "on".
/// Case-insensitive.
pub(super) fn is_truthy(value: String) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "enabled" | "on"
    )
}

/// Convert a boolean value to "1" or "0" string representation.
///
/// Used when setting boolean fields in XML config elements.
pub(super) fn bool_to_01(v: bool) -> &'static str {
    if v {
        "1"
    } else {
        "0"
    }
}
