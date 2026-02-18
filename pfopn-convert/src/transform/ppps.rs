use xml_diff_core::XmlNode;

/// Transfer PPP (Point-to-Point Protocol) settings to OPNsense output.
///
/// Replaces the entire `<ppps>` section in the output with the one from the
/// source config. This preserves PPPoE, PPTP, and other PPP configurations.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    sync_ppps(out, source);
}

/// Transfer PPP (Point-to-Point Protocol) settings to pfSense output.
///
/// Replaces the entire `<ppps>` section in the output with the one from the
/// source config. This preserves PPPoE, PPTP, and other PPP configurations.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    sync_ppps(out, source);
}

/// Replace the `<ppps>` section in `out` with the one from `source`.
///
/// PPP config structure is identical between pfSense and OPNsense, so this
/// is a straight copy. If the source has no `<ppps>` section, the output's
/// `<ppps>` section (if any) is removed.
fn sync_ppps(out: &mut XmlNode, source: &XmlNode) {
    // Remove any existing <ppps> section
    out.children.retain(|c| c.tag != "ppps");

    // Copy the source's <ppps> section if it exists
    if let Some(ppps) = source.get_child("ppps") {
        out.children.push(ppps.clone());
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::to_opnsense;

    #[test]
    fn replaces_target_ppps_with_source_ppps() {
        let source = parse(
            br#"<pfsense><ppps><ppp><if>pppoe0</if><ports>igb0</ports></ppp></ppps></pfsense>"#,
        )
        .expect("parse");
        let target = parse(
            br#"<opnsense><ppps><ppp><if>vtnet1</if><ports>igb0</ports></ppp></ppps></opnsense>"#,
        )
        .expect("parse");
        let mut out = target.clone();
        to_opnsense(&mut out, &source, &target);
        assert_eq!(out.get_text(&["ppps", "ppp", "if"]), Some("pppoe0"));
        assert_eq!(out.get_text(&["ppps", "ppp", "ports"]), Some("igb0"));
    }
}
