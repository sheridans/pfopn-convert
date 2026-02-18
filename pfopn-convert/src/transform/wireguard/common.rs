use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

/// Get or create a mutable reference to a child node by tag name.
///
/// If the child exists, returns a reference to it. Otherwise, creates a new
/// empty child with the given tag and returns a reference to it.
pub fn ensure_child_mut<'a>(parent: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
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
/// child is appended.
pub fn upsert_child(parent: &mut XmlNode, child: XmlNode) {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == child.tag) {
        parent.children[idx] = child;
        return;
    }
    parent.children.push(child);
}

/// Insert or replace WireGuard config in the OPNsense nested structure.
///
/// Ensures `<OPNsense>` exists and inserts/replaces the `<wireguard>` node within it.
/// OPNsense stores WireGuard config at `<OPNsense><wireguard>`.
pub fn upsert_nested_wireguard(out: &mut XmlNode, wireguard: XmlNode) {
    let opn = ensure_child_mut(out, "OPNsense");
    upsert_child(opn, wireguard);
}

/// Ensure the output has WireGuard interface assignments from the source.
///
/// WireGuard needs interface assignments in `<interfaces>` for the firewall to
/// recognize the WireGuard devices. This function:
/// 1. Copies any existing WireGuard interface assignments from source
/// 2. If none exist but WireGuard config is present, derives interface names
///    from the config (tunnel names, instance numbers, etc.)
/// 3. Creates basic `<interfaces><wireguard><if>wgN</if></wireguard>` entries
///
/// This prevents the situation where WireGuard is configured but has no
/// interface assignment, making it invisible to firewall rules.
pub fn ensure_wireguard_interface_assignment(out: &mut XmlNode, source: &XmlNode) {
    // Nothing to do if there's no WireGuard config and no interface assignments
    if !wireguard_config_present(source) && source_wireguard_interfaces(source).is_empty() {
        return;
    }
    // Output already has WireGuard interface assignments
    if has_wireguard_interface_assignment(out) {
        return;
    }
    // Try to copy interface assignments from source
    let mut source_ifaces = source_wireguard_interfaces(source);
    // If source has no explicit assignments, derive one from the config
    if source_ifaces.is_empty() {
        if let Some(fallback_if) = derive_wireguard_if_from_config(source) {
            source_ifaces.push(build_wireguard_interface_node(&fallback_if));
        }
    }
    if source_ifaces.is_empty() {
        return;
    }
    // Add the interface assignments to output, avoiding duplicates
    let interfaces = ensure_child_mut(out, "interfaces");
    for iface in source_ifaces {
        if interfaces
            .children
            .iter()
            .any(|n| n.tag == iface.tag || interface_if_name(n) == interface_if_name(&iface))
        {
            continue;
        }
        interfaces.children.push(iface);
    }
}

/// Normalize WireGuard interface names to OPNsense's "wgN" format.
///
/// OPNsense uses "wg0", "wg1", etc. as WireGuard device names (based on instance numbers).
/// pfSense uses "tun_wg0", "tun_wg1", etc. or custom names.
///
/// This function:
/// 1. Builds a map of WireGuard server names/instances to correct device names
/// 2. Rewrites interface assignments to use the correct "wgN" format
/// 3. Converts pfSense "tun_wgN" names to OPNsense "wgN" names
///
/// This ensures all WireGuard interface references use consistent OPNsense naming.
pub fn normalize_opnsense_wireguard_if_names(out: &mut XmlNode) {
    // Build a map of server instance numbers to device names (wg0, wg1, etc.)
    let instance_map = opnsense_wireguard_instance_map(out);
    let Some(interfaces_mut) = ensure_interfaces_mut(out) else {
        return;
    };
    for iface in &mut interfaces_mut.children {
        let Some(cur) = iface
            .get_text(&["if"])
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let lowered = cur.to_ascii_lowercase();
        // Try to map server name → device name
        if let Some(mapped) = instance_map.get(lowered.as_str()) {
            set_or_insert_text_child(iface, "if", mapped);
            continue;
        }
        // Try to convert pfSense-style "tun_wgN" → "wgN"
        if let Some(mapped) = tun_wg_to_wg(cur) {
            set_or_insert_text_child(iface, "if", &mapped);
        }
    }
}

fn derive_wireguard_if_from_config(source: &XmlNode) -> Option<String> {
    wireguard_if_names_from_top(source.get_child("wireguard"))
        .into_iter()
        .next()
}

fn wireguard_if_names_from_top(top: Option<&XmlNode>) -> Vec<String> {
    let Some(top) = top else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_candidate_names(top, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_candidate_names(node: &XmlNode, out: &mut Vec<String>) {
    if node.tag == "name" || node.tag == "tun" || node.tag == "interface" || node.tag == "if" {
        if let Some(text) = node.text.as_deref().map(str::trim) {
            let lowered = text.to_ascii_lowercase();
            if lowered.contains("wg") {
                out.push(text.to_string());
            }
        }
    }
    if node.tag == "instance" {
        if let Some(text) = node.text.as_deref().map(str::trim) {
            if text.chars().all(|c| c.is_ascii_digit()) {
                out.push(format!("wg{text}"));
            }
        }
    }
    for child in &node.children {
        collect_candidate_names(child, out);
    }
}

fn build_wireguard_interface_node(if_name: &str) -> XmlNode {
    let mut iface = XmlNode::new("wireguard");
    let mut if_node = XmlNode::new("if");
    if_node.text = Some(if_name.to_string());
    iface.children.push(if_node);
    iface
}

fn source_wireguard_interfaces(source: &XmlNode) -> Vec<XmlNode> {
    let Some(interfaces) = source.get_child("interfaces") else {
        return Vec::new();
    };
    interfaces
        .children
        .iter()
        .filter(|iface| {
            iface.tag.eq_ignore_ascii_case("wireguard")
                || interface_if_name(iface)
                    .map(|v| v.contains("wg"))
                    .unwrap_or(false)
        })
        .cloned()
        .collect()
}

fn has_wireguard_interface_assignment(root: &XmlNode) -> bool {
    let Some(interfaces) = root.get_child("interfaces") else {
        return false;
    };
    interfaces.children.iter().any(|iface| {
        iface.tag.eq_ignore_ascii_case("wireguard")
            || interface_if_name(iface)
                .map(|v| v.contains("wg"))
                .unwrap_or(false)
    })
}

fn wireguard_config_present(root: &XmlNode) -> bool {
    root.get_child("wireguard").is_some()
        || root
            .get_child("installedpackages")
            .and_then(|n| n.get_child("wireguard"))
            .is_some()
        || root
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("wireguard"))
            .is_some()
}

fn interface_if_name(iface: &XmlNode) -> Option<String> {
    iface
        .get_text(&["if"])
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
}

fn ensure_interfaces_mut(root: &mut XmlNode) -> Option<&mut XmlNode> {
    let idx = root.children.iter().position(|c| c.tag == "interfaces")?;
    Some(&mut root.children[idx])
}

fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    node.children.push(child);
}

/// Convert pfSense-style "tun_wgN" names to OPNsense-style "wgN" names.
///
/// # Examples
/// - "tun_wg0" → Some("wg0")
/// - "tun_wg12" → Some("wg12")
/// - "wg0" → None (already correct format)
/// - "tun_wg" → None (no digits)
fn tun_wg_to_wg(input: &str) -> Option<String> {
    let lowered = input.to_ascii_lowercase();
    let suffix = lowered.strip_prefix("tun_wg")?;
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("wg{suffix}"))
}

fn opnsense_wireguard_instance_map(root: &XmlNode) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(servers) = root
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("wireguard"))
        .and_then(|wg| wg.get_child("server"))
        .and_then(|s| s.get_child("servers"))
    else {
        return out;
    };

    for server in servers.get_children("server") {
        let Some(instance) = server.get_text(&["instance"]).map(str::trim) else {
            continue;
        };
        if instance.is_empty() || !instance.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let device = format!("wg{instance}");
        if let Some(name) = server
            .get_text(&["name"])
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            out.insert(name.to_ascii_lowercase(), device.clone());
        }
        out.insert(device.clone(), device);
    }
    out
}

/// Check if a string value represents a boolean true.
///
/// Recognizes multiple boolean-like strings: "1", "yes", "true", "enabled", "on".
/// Case-insensitive.
pub fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "enabled" | "on"
    )
}

/// Convert any boolean-like string to normalized "1" or "0".
///
/// Uses `is_truthy` to recognize various true values, returns "1" for true, "0" for false.
pub fn as_bool_text(value: &str) -> &'static str {
    if is_truthy(value) {
        "1"
    } else {
        "0"
    }
}

/// Extract trimmed, non-empty text from a nested path in an XML node.
///
/// Returns `None` if the path doesn't exist or the text is empty/whitespace-only.
pub fn text_of<'a>(node: &'a XmlNode, path: &[&str]) -> Option<&'a str> {
    node.get_text(path).map(str::trim).filter(|v| !v.is_empty())
}

/// Create and append a text-only child element to a parent node.
///
/// Helper to reduce boilerplate when building XML structures.
pub fn push_text_child(parent: &mut XmlNode, tag: &str, value: impl Into<String>) {
    let mut n = XmlNode::new(tag);
    n.text = Some(value.into());
    parent.children.push(n);
}
