use xml_diff_core::XmlNode;

/// Normalizes bridge configuration for OPNsense format.
///
/// OPNsense requires each `<bridged>` element to carry a `uuid` attribute.
/// pfSense configs don't include these, so when converting pf -> opn we
/// generate a deterministic UUID from the bridge's member list (or interface
/// name as fallback). Already-present UUIDs are left untouched.
pub fn normalize_for_opnsense(root: &mut XmlNode) {
    let Some(bridges) = child_mut(root, "bridges") else {
        return;
    };
    for (idx, bridged) in bridges
        .children
        .iter_mut()
        .filter(|c| c.tag == "bridged")
        .enumerate()
    {
        if !bridged.attributes.contains_key("uuid") {
            // Use the member list as the seed so the same bridge always gets the
            // same UUID. Fall back to the bridge interface name, then a generic
            // constant if neither is present.
            let seed = bridged
                .get_text(&["members"])
                .or_else(|| bridged.get_text(&["bridgeif"]))
                .unwrap_or("bridge");
            bridged
                .attributes
                .insert("uuid".to_string(), stable_uuid(seed.as_bytes(), idx));
        }
    }
}

/// Normalizes bridge configuration for pfSense format.
///
/// pfSense does not use `uuid` attributes on `<bridged>` elements, so when
/// converting opn -> pf we strip them.
pub fn normalize_for_pfsense(root: &mut XmlNode) {
    let Some(bridges) = child_mut(root, "bridges") else {
        return;
    };
    for bridged in bridges.children.iter_mut().filter(|c| c.tag == "bridged") {
        bridged.attributes.remove("uuid");
    }
}

/// Returns a mutable reference to the first child with the given tag name.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

/// Generates a deterministic, RFC 4122 v4-shaped UUID from a byte seed and an
/// index. This is NOT a true random UUID — it's a content-addressed hash so
/// that the same bridge definition always produces the same identifier across
/// runs, which keeps diffs stable.
///
/// The algorithm mixes `seed` bytes into a 16-byte accumulator using wrapping
/// addition and bit rotation, then folds in `idx` to disambiguate bridges that
/// would otherwise share the same seed. Finally it stamps the version (4) and
/// variant (RFC 4122) nibbles so the result looks like a valid v4 UUID.
fn stable_uuid(seed: &[u8], idx: usize) -> String {
    let mut acc = [0u8; 16];
    // Mix seed bytes into the accumulator with position-dependent rotation.
    for (i, b) in seed.iter().enumerate() {
        acc[i % 16] = acc[i % 16].wrapping_add(*b).rotate_left((i % 7) as u32);
    }
    // Fold in the bridge index so identical member lists at different positions
    // still produce distinct UUIDs.
    for (i, a) in acc.iter_mut().enumerate() {
        *a = a.wrapping_add(((idx + i) as u8).rotate_left((idx % 5) as u32));
    }
    // Set UUID version 4 nibble and RFC 4122 variant bits.
    acc[6] = (acc[6] & 0x0f) | 0x40; // version 4
    acc[8] = (acc[8] & 0x3f) | 0x80; // variant 10xx
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

    use super::{normalize_for_opnsense, normalize_for_pfsense};

    #[test]
    fn adds_uuid_to_opnsense_bridges() {
        let mut root = parse(
            br#"<opnsense><bridges><bridged><members>lan,opt1</members></bridged></bridges></opnsense>"#,
        )
        .expect("parse");
        normalize_for_opnsense(&mut root);
        let bridged = root
            .get_child("bridges")
            .and_then(|b| b.children.iter().find(|c| c.tag == "bridged"))
            .expect("bridged");
        assert!(bridged.attributes.contains_key("uuid"));
    }

    #[test]
    fn strips_uuid_for_pfsense_bridges() {
        let mut root = parse(
            br#"<pfsense><bridges><bridged uuid="abc"><members>lan,opt1</members></bridged></bridges></pfsense>"#,
        )
        .expect("parse");
        normalize_for_pfsense(&mut root);
        let bridged = root
            .get_child("bridges")
            .and_then(|b| b.children.iter().find(|c| c.tag == "bridged"))
            .expect("bridged");
        assert!(!bridged.attributes.contains_key("uuid"));
    }
}
