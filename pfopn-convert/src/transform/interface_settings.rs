use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

/// Merge logical interface settings from the source config into the output,
/// while preserving the physical device bindings (`<if>`) from the destination
/// baseline.
///
/// When migrating between pfSense and OPNsense, each box typically has
/// different physical NICs (e.g. `igb0` vs `vtnet1`). The user wants their IP
/// addresses, subnet masks, and other logical settings carried over, but the
/// `<if>` device name must stay as-is on the target hardware.
///
/// For each source interface:
/// 1. Resolve the destination tag via `interface_map_from` (e.g. `opt2` ->
///    `igc3`), falling back to the same tag name if no mapping is provided.
/// 2. Skip if the target baseline doesn't have a matching interface (the
///    source may reference ports that don't exist on the target box).
/// 3. Clone the full source interface node (all settings), rename its tag to
///    the mapped name, then overwrite `<if>` with the target baseline's
///    device name.
/// 4. Upsert the merged node into the output tree.
pub fn apply(
    out: &mut XmlNode,
    source: &XmlNode,
    target: &XmlNode,
    interface_map_from: Option<&BTreeMap<String, String>>,
) {
    let src_interfaces = match source.get_child("interfaces") {
        Some(n) => n,
        None => return,
    };
    let target_interfaces = match target.get_child("interfaces") {
        Some(n) => n,
        None => return,
    };
    let out_interfaces = match child_mut(out, "interfaces") {
        Some(n) => n,
        None => return,
    };

    for src_iface in &src_interfaces.children {
        // Map source tag to destination tag (e.g. opt2 -> igc3).
        let mapped = interface_map_from
            .and_then(|m| m.get(&src_iface.tag))
            .cloned()
            .unwrap_or_else(|| src_iface.tag.clone());
        // Only process interfaces that exist on the target box.
        let Some(target_iface) = target_interfaces.get_child(&mapped) else {
            continue;
        };

        // Start with all source settings, renamed to the destination tag.
        let mut merged_iface = src_iface.clone();
        merged_iface.tag = mapped.clone();

        // Overwrite the device binding with the target's physical NIC name.
        if let Some(dst_if) = target_iface.get_text(&["if"]).map(str::trim) {
            set_or_insert_text_child(&mut merged_iface, "if", dst_if);
        }
        upsert_child(out_interfaces, merged_iface);
    }
}

/// Return a mutable reference to the first child with the given tag.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

/// Replace an existing child that shares the same tag, or append if none exists.
fn upsert_child(parent: &mut XmlNode, child: XmlNode) {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == child.tag) {
        parent.children[idx] = child;
        return;
    }
    parent.children.push(child);
}

/// Set the text of an existing `<tag>` child, or create one if it doesn't exist.
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
    use std::collections::BTreeMap;
    use xml_diff_core::parse;

    #[test]
    fn copies_wan_settings_but_keeps_target_if_name() {
        let source = parse(
            br#"<pfsense><interfaces><wan><if>igb0</if><ipaddr>10.1.10.253</ipaddr><subnet>24</subnet></wan></interfaces></pfsense>"#,
        )
        .expect("parse");
        let target = parse(
            br#"<opnsense><interfaces><wan><if>vtnet1</if><ipaddr>dhcp</ipaddr></wan></interfaces></opnsense>"#,
        )
        .expect("parse");
        let mut out = target.clone();

        apply(&mut out, &source, &target, None);
        assert_eq!(
            out.get_text(&["interfaces", "wan", "ipaddr"]),
            Some("10.1.10.253")
        );
        assert_eq!(out.get_text(&["interfaces", "wan", "if"]), Some("vtnet1"));
    }

    #[test]
    fn applies_logical_interface_mapping_for_opt() {
        let source = parse(
            br#"<pfsense><interfaces><opt2><if>igb3</if><ipaddr>172.16.20.1</ipaddr><subnet>24</subnet></opt2></interfaces></pfsense>"#,
        )
        .expect("parse");
        let target = parse(
            br#"<opnsense><interfaces><igc3><if>vtnet2</if><ipaddr>dhcp</ipaddr></igc3></interfaces></opnsense>"#,
        )
        .expect("parse");
        let mut out = target.clone();
        let mut map = BTreeMap::new();
        map.insert("opt2".to_string(), "igc3".to_string());

        apply(&mut out, &source, &target, Some(&map));
        assert_eq!(
            out.get_text(&["interfaces", "igc3", "ipaddr"]),
            Some("172.16.20.1")
        );
        assert_eq!(out.get_text(&["interfaces", "igc3", "if"]), Some("vtnet2"));
    }

    #[test]
    fn does_not_keep_target_ipaddr_when_source_omits_it() {
        let source =
            parse(br#"<pfsense><interfaces><wan><if>igb0</if></wan></interfaces></pfsense>"#)
                .expect("parse");
        let target = parse(
            br#"<opnsense><interfaces><wan><if>vtnet1</if><ipaddr>dhcp</ipaddr></wan></interfaces></opnsense>"#,
        )
        .expect("parse");
        let mut out = target.clone();

        apply(&mut out, &source, &target, None);
        assert_eq!(out.get_text(&["interfaces", "wan", "if"]), Some("vtnet1"));
        assert_eq!(out.get_text(&["interfaces", "wan", "ipaddr"]), None);
    }

    #[test]
    fn empty_wan_ip_fields_clear_target_dynamic_modes() {
        let source = parse(
            br#"<pfsense><interfaces><wan><if>igb0</if><ipaddr></ipaddr></wan><opt1><if>igb1</if></opt1></interfaces><bridges><bridged><members>wan opt1</members></bridged></bridges></pfsense>"#,
        )
        .expect("parse");
        let target = parse(
            br#"<opnsense><interfaces><wan><if>vtnet1</if><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan></interfaces></opnsense>"#,
        )
        .expect("parse");
        let mut out = target.clone();

        apply(&mut out, &source, &target, None);
        assert_eq!(out.get_text(&["interfaces", "wan", "ipaddr"]), None);
        assert_eq!(out.get_text(&["interfaces", "wan", "ipaddrv6"]), None);
    }

    #[test]
    fn empty_lan_ipv6_in_source_clears_target_ipv6_mode() {
        let source = parse(
            br#"<pfsense><interfaces><lan><if>igb1</if><ipaddr>10.1.10.1</ipaddr><subnet>24</subnet><ipaddrv6></ipaddrv6><subnetv6></subnetv6></lan></interfaces></pfsense>"#,
        )
        .expect("parse");
        let target = parse(
            br#"<opnsense><interfaces><lan><if>vtnet0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><ipaddrv6>dhcp6</ipaddrv6><subnetv6>64</subnetv6></lan></interfaces></opnsense>"#,
        )
        .expect("parse");
        let mut out = target.clone();

        apply(&mut out, &source, &target, None);
        assert_eq!(
            out.get_text(&["interfaces", "lan", "ipaddr"]),
            Some("10.1.10.1")
        );
        assert_eq!(out.get_text(&["interfaces", "lan", "ipaddrv6"]), None);
        assert_eq!(out.get_text(&["interfaces", "lan", "subnetv6"]), None);
    }
}
