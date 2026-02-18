use crate::transform::ipsec_pf_to_opn;
use xml_diff_core::XmlNode;

/// Transform IPsec configuration for OPNsense output.
///
/// IPsec config lives in up to three places across the two platforms:
/// - `<ipsec>` -- top-level legacy section (both platforms, pfSense-style
///   `<phase1>`/`<phase2>` structure or OPNsense-style `<general>`/`<charon>`).
/// - `<OPNsense><IPsec>` -- nested OPNsense-native settings (pre-shared keys,
///   general tunables, etc.).
/// - `<OPNsense><Swanctl>` -- strongSwan/swanctl connection definitions
///   (OPNsense's modern IPsec backend).
///
/// When a top-level `<ipsec>` exists in the source:
/// - It is copied as-is to the output's top-level `<ipsec>`.
/// - If it contains `<phase1>`/`<phase2>` (pfSense-style), the data is also
///   mapped into OPNsense's `<IPsec>` and `<Swanctl>` structures via
///   `ipsec_pf_to_opn`.
/// - Otherwise (already OPNsense-style), it is placed directly into
///   `<OPNsense><IPsec>`.
///
/// When no top-level `<ipsec>` exists, the nested `<OPNsense><IPsec>` and
/// `<OPNsense><Swanctl>` sections are copied through from the source.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    if let Some(top) = source.get_child("ipsec") {
        // Always preserve the top-level section for round-trip fidelity.
        upsert_top_level_node("ipsec", out, top);
        if looks_like_pfsense_ipsec(top) {
            // pfSense phase1/phase2 layout -- translate into OPNsense's
            // Swanctl connection model and IPsec pre-shared-key store.
            let (mapped_ipsec, mapped_swanctl) = ipsec_pf_to_opn::map_pf_ipsec_to_opnsense(top);
            upsert_nested_opnsense_node("IPsec", out, &mapped_ipsec);
            upsert_nested_opnsense_node("Swanctl", out, &mapped_swanctl);
        } else {
            // Already OPNsense-style (general/charon) -- nest it directly.
            upsert_nested_opnsense_node("IPsec", out, top);
        }
        let _ = target;
        return;
    }

    // No top-level <ipsec> -- pass through nested OPNsense sections as-is.
    if let Some(nested) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("IPsec"))
    {
        upsert_nested_opnsense_node("IPsec", out, nested);
    }

    if let Some(swanctl) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Swanctl"))
    {
        upsert_nested_opnsense_node("Swanctl", out, swanctl);
    }

    let _ = target;
}

/// Transform IPsec configuration for pfSense output.
///
/// pfSense expects a top-level `<ipsec>` section. The source data may come
/// from either location:
/// - A top-level `<ipsec>` (preferred -- used directly and also mirrored
///   into `<OPNsense><IPsec>` for round-trip fidelity).
/// - A nested `<OPNsense><IPsec>` (fallback when no top-level exists --
///   promoted to top-level `<ipsec>` and also kept nested).
///
/// `<OPNsense><Swanctl>` is always carried through so that strongSwan
/// connection data isn't lost if the config is later converted back to
/// OPNsense.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    let mut had_top_level_ipsec = false;
    if let Some(top) = source.get_child("ipsec") {
        // Top-level exists -- use it as the authoritative source.
        had_top_level_ipsec = true;
        upsert_top_level_node("ipsec", out, top);
        upsert_nested_opnsense_node("IPsec", out, top);
    }

    if !had_top_level_ipsec {
        // Fall back to nested OPNsense IPsec and promote it to top-level.
        if let Some(nested) = source
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"))
        {
            upsert_top_level_node("ipsec", out, nested);
            upsert_nested_opnsense_node("IPsec", out, nested);
        }
    }

    // Always carry Swanctl through for lossless round-tripping.
    if let Some(swanctl) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Swanctl"))
    {
        upsert_nested_opnsense_node("Swanctl", out, swanctl);
    }

    let _ = target;
}

/// Replace or append a top-level child section in the output root.
fn upsert_top_level_node(section: &str, out: &mut XmlNode, node: &XmlNode) {
    if let Some(idx) = out.children.iter().position(|c| c.tag == section) {
        out.children[idx] = clone_with_tag(node, section);
    } else {
        out.children.push(clone_with_tag(node, section));
    }
}

/// Replace or append a section inside the `<OPNsense>` wrapper element.
///
/// If `<OPNsense>` doesn't exist yet, it is created. This ensures nested
/// OPNsense-specific config (IPsec tunables, Swanctl connections) is always
/// stored in the correct location regardless of whether the output tree
/// already had the wrapper.
fn upsert_nested_opnsense_node(section: &str, out: &mut XmlNode, node: &XmlNode) {
    if let Some(opn) = out.children.iter_mut().find(|c| c.tag == "OPNsense") {
        if let Some(idx) = opn.children.iter().position(|c| c.tag == section) {
            opn.children[idx] = clone_with_tag(node, section);
        } else {
            opn.children.push(clone_with_tag(node, section));
        }
        return;
    }

    // No <OPNsense> wrapper yet -- create one.
    let mut opn = XmlNode::new("OPNsense");
    opn.children.push(clone_with_tag(node, section));
    out.children.push(opn);
}

/// Clone a node and override its tag name.
fn clone_with_tag(node: &XmlNode, tag: &str) -> XmlNode {
    let mut out = node.clone();
    out.tag = tag.to_string();
    out
}

/// Detect whether an `<ipsec>` node uses pfSense's phase1/phase2 structure.
///
/// pfSense stores tunnel definitions as `<phase1>` and `<phase2>` children.
/// OPNsense's top-level `<ipsec>` instead contains `<general>` and `<charon>`
/// with the actual tunnels living under `<OPNsense><Swanctl>`. The presence
/// of either phase element is a reliable indicator of pfSense-style config.
fn looks_like_pfsense_ipsec(node: &XmlNode) -> bool {
    node.get_child("phase1").is_some() || node.get_child("phase2").is_some()
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn transfers_nested_opnsense_ipsec_when_missing() {
        let source = parse(
            br#"<opnsense><OPNsense><IPsec><general/></IPsec><Swanctl><Connections/></Swanctl></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);

        let nested_ipsec = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"));
        let nested_swanctl = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Swanctl"));
        assert!(nested_ipsec.is_some());
        assert!(nested_swanctl.is_some());
    }

    #[test]
    fn replaces_placeholder_top_level_ipsec_with_source() {
        let source =
            parse(br#"<pfsense><ipsec><phase1><descr>src-p1</descr></phase1></ipsec></pfsense>"#)
                .expect("source parse");
        let target =
            parse(br#"<opnsense><ipsec><phase1><descr>dst-p1</descr></phase1></ipsec></opnsense>"#)
                .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        assert_eq!(out.get_text(&["ipsec", "phase1", "descr"]), Some("src-p1"));
        assert_eq!(
            out.get_text(&[
                "OPNsense",
                "Swanctl",
                "Connections",
                "Connection",
                "description"
            ]),
            Some("src-p1")
        );
    }

    #[test]
    fn replaces_placeholder_nested_opnsense_ipsec_with_source() {
        let source = parse(
            br#"<opnsense><OPNsense><IPsec><phase1><descr>src-ipsec</descr></phase1></IPsec><Swanctl><Connections><c><name>src-conn</name></c></Connections></Swanctl></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<pfsense><OPNsense><IPsec><phase1><descr>dst-ipsec</descr></phase1></IPsec><Swanctl><Connections><c><name>dst-conn</name></c></Connections></Swanctl></OPNsense></pfsense>"#,
        )
        .expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["OPNsense", "IPsec", "phase1", "descr"]),
            Some("src-ipsec")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "Connections", "c", "name"]),
            Some("src-conn")
        );
    }

    #[test]
    fn maps_nested_opnsense_ipsec_to_top_level_for_pfsense_output() {
        let source = parse(
            br#"<opnsense><OPNsense><IPsec><phase1><descr>src-nested</descr></phase1></IPsec></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["ipsec", "phase1", "descr"]),
            Some("src-nested")
        );
    }

    #[test]
    fn maps_pfsense_phase1_phase2_into_opnsense_swanctl() {
        let source = parse(
            br#"<pfsense><ipsec>
                <phase1>
                  <ikeid>1</ikeid>
                  <remote-gateway>198.51.100.10</remote-gateway>
                  <authentication_method>pre_shared_key</authentication_method>
                  <pre-shared-key>secret</pre-shared-key>
                  <myid_type>myaddress</myid_type>
                  <peerid_type>peeraddress</peerid_type>
                  <descr>Watford</descr>
                  <nat_traversal>on</nat_traversal>
                  <mobike>off</mobike>
                  <dpd_delay>10</dpd_delay>
                  <dpd_maxfail>5</dpd_maxfail>
                  <startaction>none</startaction>
                </phase1>
                <phase2>
                  <ikeid>1</ikeid>
                  <mode>tunnel</mode>
                  <reqid>1</reqid>
                  <localid><type>lan</type></localid>
                  <remoteid><type>network</type><address>192.168.10.0</address><netbits>24</netbits></remoteid>
                  <lifetime>3600</lifetime>
                </phase2>
              </ipsec></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&[
                "OPNsense",
                "Swanctl",
                "Connections",
                "Connection",
                "remote_addrs"
            ]),
            Some("198.51.100.10")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "children", "child", "remote_ts"]),
            Some("192.168.10.0/24")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "children", "child", "local_ts"]),
            Some("")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "IPsec", "preSharedKeys", "preSharedKey", "Key"]),
            Some("secret")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "locals", "local", "id"]),
            Some("")
        );
        assert_eq!(
            out.get_text(&["OPNsense", "Swanctl", "remotes", "remote", "id"]),
            Some("")
        );
    }

    #[test]
    fn to_pfsense_prefers_existing_top_level_ipsec_over_nested_copy() {
        let source = parse(
            br#"<opnsense><ipsec><phase1><descr>top-source</descr></phase1></ipsec><OPNsense><IPsec><phase1><descr>nested-source</descr></phase1></IPsec></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["ipsec", "phase1", "descr"]),
            Some("top-source")
        );
    }

    #[test]
    fn to_opnsense_preserves_opnsense_style_top_level_ipsec() {
        let source = parse(
            br#"<pfsense><ipsec version="1.0.5"><general><enabled>1</enabled></general><charon><threads>8</threads><max_ikev1_exchanges>5</max_ikev1_exchanges></charon></ipsec></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);
        assert_eq!(
            out.get_text(&["OPNsense", "IPsec", "charon", "max_ikev1_exchanges"]),
            Some("5")
        );
        let attrs = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"))
            .map(|n| &n.attributes);
        assert_eq!(
            attrs.and_then(|a| a.get("version")).map(String::as_str),
            Some("1.0.5")
        );
    }
}
