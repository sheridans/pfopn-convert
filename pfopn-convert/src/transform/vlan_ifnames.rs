use std::collections::{BTreeMap, BTreeSet};

use xml_diff_core::XmlNode;

/// Normalize VLAN interface device names for OPNsense.
///
/// **Problem:** pfSense and OPNsense handle VLAN naming differently:
/// - pfSense allows interface assignments to reference VLANs using dotted notation
///   like `vtnet0.50` (parent interface + VLAN tag)
/// - OPNsense requires VLANs to have explicit `vlanXX` device names like `vlan01`, `vlan02`
///
/// **What this does:**
/// 1. Scans all VLAN definitions in `<vlans><vlan>`
/// 2. For each VLAN, ensures it has a `<vlanif>vlanXX</vlanif>` name
/// 3. If a VLAN is missing a vlanif, generates the next available one (vlan01, vlan02, etc.)
/// 4. Builds a map of dotted names (e.g., `vtnet0.50`) → vlanif names (e.g., `vlan01`)
/// 5. Rewrites interface assignments in `<interfaces>` to use vlanif names instead of dotted names
/// 6. Adds OPNsense-specific metadata (uuid, pcp, proto, descr) to each VLAN
///
/// **Example:**
/// Before:
/// ```xml
/// <interfaces><opt3><if>vtnet0.50</if></opt3></interfaces>
/// <vlans><vlan><if>vtnet0</if><tag>50</tag></vlan></vlans>
/// ```
///
/// After:
/// ```xml
/// <interfaces><opt3><if>vlan01</if></opt3></interfaces>
/// <vlans><vlan uuid="..."><if>vtnet0</if><tag>50</tag><vlanif>vlan01</vlanif><pcp>0</pcp><proto/><descr/></vlan></vlans>
/// ```
pub fn normalize_opnsense_vlan_ifnames(root: &mut XmlNode) {
    let Some(vlans) = child_mut(root, "vlans") else {
        return;
    };

    // Collect already-used vlanif names to avoid collisions
    let mut used = collect_used_vlanif(vlans);
    let mut dotted_to_vlanif: BTreeMap<String, String> = BTreeMap::new();

    for vlan in vlans.children.iter_mut().filter(|n| n.tag == "vlan") {
        let parent = text_of(vlan, "if").unwrap_or_default();
        let tag = text_of(vlan, "tag").unwrap_or_default();
        if parent.is_empty() || tag.is_empty() {
            continue; // Invalid VLAN definition, skip it
        }

        // Build the dotted name (e.g., "vtnet0.50")
        let dotted = format!("{parent}.{tag}");

        // Check if this VLAN already has a valid vlanif name
        let current_vlanif = text_of(vlan, "vlanif").unwrap_or_default();
        let vlanif = if current_vlanif.starts_with("vlan") && current_vlanif.len() >= 5 {
            current_vlanif // Keep existing vlanif name
        } else {
            next_vlanif_name(&used) // Generate a new one
        };

        // Set or update the vlanif field
        set_or_insert_text_child(vlan, "vlanif", &vlanif);

        // Add OPNsense-specific metadata (uuid, pcp, proto, descr)
        ensure_vlan_opnsense_shape(vlan, idx_seed(&vlanif, &parent, &tag));

        used.insert(vlanif.clone());
        dotted_to_vlanif.insert(dotted, vlanif);
    }

    if dotted_to_vlanif.is_empty() {
        return; // No VLANs to rewrite
    }

    // Rewrite interface assignments to use vlanif names instead of dotted names
    rewrite_interface_if_assignments(root, &dotted_to_vlanif);
}

/// Rewrite interface assignments to use vlanif names instead of dotted names.
///
/// Scans all interfaces in `<interfaces>` and replaces their `<if>` fields
/// if they match a dotted name in the map.
fn rewrite_interface_if_assignments(root: &mut XmlNode, map: &BTreeMap<String, String>) {
    let Some(interfaces) = child_mut(root, "interfaces") else {
        return;
    };
    for iface in &mut interfaces.children {
        let Some(current) = text_of(iface, "if") else {
            continue;
        };
        // If this assignment uses a dotted name, replace it with the vlanif name
        if let Some(mapped) = map.get(current.as_str()) {
            set_or_insert_text_child(iface, "if", mapped);
        }
    }
}

/// Collect all vlanif names currently in use.
fn collect_used_vlanif(vlans: &XmlNode) -> BTreeSet<String> {
    vlans
        .children
        .iter()
        .filter(|n| n.tag == "vlan")
        .filter_map(|v| text_of(v, "vlanif"))
        .filter(|name| name.starts_with("vlan"))
        .collect()
}

/// Generate the next available vlanif name (vlan01, vlan02, ..., vlan999).
fn next_vlanif_name(used: &BTreeSet<String>) -> String {
    for i in 1..1000u16 {
        let name = format!("vlan{i:02}");
        if !used.contains(&name) {
            return name;
        }
    }
    "vlan999".to_string() // Fallback if we somehow have 999 VLANs
}

/// Extract trimmed, non-empty text from a child element.
fn text_of(node: &XmlNode, child: &str) -> Option<String> {
    node.get_text(&[child])
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

/// Get a mutable reference to a child node by tag.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

/// Set or insert a text child element.
fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    node.children.push(child);
}

/// Add OPNsense-specific fields and attributes to a VLAN definition.
///
/// OPNsense expects:
/// - uuid attribute (for tracking in the UI)
/// - <pcp> (Priority Code Point, usually 0)
/// - <proto> (protocol/ethertype, usually empty)
/// - <descr> (description, usually empty)
fn ensure_vlan_opnsense_shape(vlan: &mut XmlNode, seed: usize) {
    if !vlan.attributes.contains_key("uuid") {
        vlan.attributes
            .insert("uuid".to_string(), stable_uuid(seed));
    }
    ensure_child(vlan, "pcp", "0");
    ensure_child(vlan, "proto", "");
    ensure_child(vlan, "descr", "");
}

/// Ensure a child element exists with a default value.
fn ensure_child(node: &mut XmlNode, tag: &str, default_value: &str) {
    if node.children.iter().any(|c| c.tag == tag) {
        return; // Already exists
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(default_value.to_string());
    node.children.push(child);
}

/// Generate a hash seed from VLAN properties for deterministic UUID generation.
fn idx_seed(vlanif: &str, parent: &str, tag: &str) -> usize {
    let mut s: usize = 0;
    for b in vlanif.bytes().chain(parent.bytes()).chain(tag.bytes()) {
        s = s.wrapping_mul(131).wrapping_add(b as usize);
    }
    s
}

/// Generate a stable UUID v4 from a seed value.
///
/// Uses a simple LCG (Linear Congruential Generator) to produce deterministic
/// but pseudo-random-looking UUIDs. The same seed always produces the same UUID.
fn stable_uuid(seed: usize) -> String {
    let mut acc = [0u8; 16];
    let mut x = seed as u64;

    // Fill 16 bytes using LCG
    for (i, a) in acc.iter_mut().enumerate() {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1 + i as u64);
        *a = (x >> ((i % 8) * 8)) as u8;
    }

    // Set UUID version 4 bits (0x40 in byte 6, 0x80-0xBF in byte 8)
    acc[6] = (acc[6] & 0x0f) | 0x40;
    acc[8] = (acc[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        acc[0],
        acc[1],
        acc[2],
        acc[3],
        acc[4],
        acc[5],
        acc[6],
        acc[7],
        acc[8],
        acc[9],
        acc[10],
        acc[11],
        acc[12],
        acc[13],
        acc[14],
        acc[15]
    )
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::normalize_opnsense_vlan_ifnames;

    #[test]
    fn rewrites_interface_if_to_vlanif_name() {
        let mut root = parse(
            br#"<opnsense>
                <interfaces>
                    <lan><if>vtnet0</if></lan>
                    <opt3><if>vtnet0.50</if></opt3>
                </interfaces>
                <vlans>
                    <vlan><if>vtnet0</if><tag>50</tag></vlan>
                </vlans>
            </opnsense>"#,
        )
        .expect("parse");

        normalize_opnsense_vlan_ifnames(&mut root);
        assert_eq!(root.get_text(&["vlans", "vlan", "vlanif"]), Some("vlan01"));
        assert_eq!(root.get_text(&["interfaces", "opt3", "if"]), Some("vlan01"));
    }

    #[test]
    fn keeps_existing_vlanif_names() {
        let mut root = parse(
            br#"<opnsense>
                <interfaces><opt3><if>vtnet0.50</if></opt3></interfaces>
                <vlans><vlan><if>vtnet0</if><tag>50</tag><vlanif>vlan07</vlanif></vlan></vlans>
            </opnsense>"#,
        )
        .expect("parse");

        normalize_opnsense_vlan_ifnames(&mut root);
        assert_eq!(root.get_text(&["vlans", "vlan", "vlanif"]), Some("vlan07"));
        assert_eq!(root.get_text(&["interfaces", "opt3", "if"]), Some("vlan07"));
    }

    #[test]
    fn adds_opnsense_vlan_uuid_and_defaults() {
        let mut root = parse(
            br#"<opnsense>
                <interfaces><opt3><if>vtnet0.50</if></opt3></interfaces>
                <vlans><vlan><if>vtnet0</if><tag>50</tag></vlan></vlans>
            </opnsense>"#,
        )
        .expect("parse");

        normalize_opnsense_vlan_ifnames(&mut root);
        let vlan = root
            .get_child("vlans")
            .and_then(|v| v.children.iter().find(|c| c.tag == "vlan"))
            .expect("vlan");
        assert!(vlan.attributes.contains_key("uuid"));
        assert_eq!(vlan.get_text(&["pcp"]), Some("0"));
        assert_eq!(vlan.get_text(&["proto"]), Some(""));
        assert_eq!(vlan.get_text(&["descr"]), Some(""));
    }
}
