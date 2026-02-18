use xml_diff_core::XmlNode;

/// Normalize static routes for OPNsense format.
///
/// OPNsense static routes require two additional fields that pfSense doesn't have:
/// 1. A `uuid` attribute on each `<route>` element
/// 2. A `<disabled>` child element (set to "0" for enabled routes)
///
/// This function adds those fields if they're missing, using deterministic UUID
/// generation based on the route's properties (network, gateway, description).
pub fn to_opnsense(out: &mut XmlNode, _source: &XmlNode, _destination_baseline: &XmlNode) {
    let Some(routes) = out.get_child("staticroutes").cloned() else {
        return;
    };
    let mut normalized = routes;

    for (idx, route) in normalized
        .children
        .iter_mut()
        .filter(|n| n.tag == "route")
        .enumerate()
    {
        // Add a uuid attribute if missing
        if !route.attributes.contains_key("uuid") {
            // Generate a deterministic UUID from route properties
            let seed = format!(
                "{}|{}|{}|{}",
                route.get_text(&["network"]).unwrap_or_default(),
                route.get_text(&["gateway"]).unwrap_or_default(),
                route.get_text(&["descr"]).unwrap_or_default(),
                idx
            );
            route
                .attributes
                .insert("uuid".to_string(), stable_uuid(seed.as_bytes(), idx));
        }

        // Add <disabled>0</disabled> if missing (OPNsense expects this field)
        if route.get_child("disabled").is_none() {
            let mut disabled = XmlNode::new("disabled");
            disabled.text = Some("0".to_string());
            route.children.push(disabled);
        }
    }
    upsert_child(out, normalized);
}

/// Normalize static routes for pfSense format.
///
/// pfSense static routes do NOT have:
/// 1. A `uuid` attribute (OPNsense-only requirement)
/// 2. A `<disabled>` child element (OPNsense uses this; pfSense just omits the route)
///
/// This function removes those OPNsense-specific fields to produce clean pfSense XML.
pub fn to_pfsense(out: &mut XmlNode, _source: &XmlNode, _destination_baseline: &XmlNode) {
    let Some(routes) = out.get_child("staticroutes").cloned() else {
        return;
    };
    let mut normalized = routes;

    for route in normalized.children.iter_mut().filter(|n| n.tag == "route") {
        // Remove OPNsense-specific uuid attribute
        route.attributes.remove("uuid");

        // Remove OPNsense-specific <disabled> element
        if let Some(idx) = route.children.iter().position(|c| c.tag == "disabled") {
            route.children.remove(idx);
        }
    }
    upsert_child(out, normalized);
}

/// Replace or insert a child node into the parent by tag name.
fn upsert_child(parent: &mut XmlNode, child: XmlNode) {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == child.tag) {
        parent.children[idx] = child;
        return;
    }
    parent.children.push(child);
}

/// Generate a stable UUID from a seed string and index.
///
/// Uses CRC32 of the seed XORed with the index to create a deterministic but
/// unique-looking UUID. This isn't a real UUID v4, but it's good enough for
/// config file identification and ensures the same route always gets the same UUID.
fn stable_uuid(seed: &[u8], idx: usize) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        crc32(seed) ^ (idx as u32),
        0,
        0,
        0,
        (idx as u64) + 1
    )
}

/// CRC32 hash using the standard polynomial (IEEE 802.3).
fn crc32(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for b in input {
        crc ^= *b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn adds_uuid_and_disabled_for_opnsense_routes() {
        let source = parse(br#"<pfsense><staticroutes/></pfsense>"#).expect("parse");
        let baseline = parse(br#"<opnsense><staticroutes/></opnsense>"#).expect("parse");
        let mut out = parse(
            br#"<opnsense><staticroutes><route><network>10.9.9.0/24</network><gateway>GW1</gateway><descr>imported</descr></route></staticroutes></opnsense>"#,
        )
        .expect("parse");

        to_opnsense(&mut out, &source, &baseline);
        let route = out
            .get_child("staticroutes")
            .and_then(|s| s.get_child("route"))
            .expect("route");
        assert!(route.attributes.contains_key("uuid"));
        assert_eq!(route.get_text(&["disabled"]), Some("0"));
    }

    #[test]
    fn strips_opnsense_route_uuid_for_pfsense() {
        let source = parse(br#"<opnsense><staticroutes/></opnsense>"#).expect("parse");
        let baseline = parse(br#"<pfsense><staticroutes/></pfsense>"#).expect("parse");
        let mut out = parse(
            br#"<pfsense><staticroutes><route uuid="abc"><network>10.9.9.0/24</network><gateway>GW1</gateway><descr>imported</descr><disabled>0</disabled></route></staticroutes></pfsense>"#,
        )
        .expect("parse");

        to_pfsense(&mut out, &source, &baseline);
        let route = out
            .get_child("staticroutes")
            .and_then(|s| s.get_child("route"))
            .expect("route");
        assert!(!route.attributes.contains_key("uuid"));
        assert!(route.get_child("disabled").is_none());
    }
}
