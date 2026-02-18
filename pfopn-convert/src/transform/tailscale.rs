use xml_diff_core::XmlNode;

/// Transfer Tailscale configuration from pfSense to OPNsense format.
///
/// Tailscale config lives in different locations:
/// - pfSense: `<installedpackages><tailscale>` and `<installedpackages><tailscaleauth>`
/// - OPNsense: `<OPNsense><tailscale>` and `<OPNsense><tailscaleauth>`
///
/// This function moves the config sections to the OPNsense location.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    // Ensure the <OPNsense> container exists
    let dst_opn = ensure_child_mut(out, "OPNsense");

    // Remove any existing Tailscale config in the output
    dst_opn
        .children
        .retain(|c| c.tag != "tailscale" && c.tag != "tailscaleauth");

    // Copy Tailscale main config from pfSense source
    let Some(src_tailscale) = source_pfsense_tailscale(source) else {
        return;
    };
    dst_opn.children.push(src_tailscale.clone());

    // Copy Tailscale auth config if it exists
    if let Some(src_auth) = source_pfsense_tailscaleauth(source) {
        dst_opn.children.push(src_auth.clone());
    }

    let _ = target;
}

/// Transfer Tailscale configuration from OPNsense to pfSense format.
///
/// Tailscale config lives in different locations:
/// - OPNsense: `<OPNsense><tailscale>` and `<OPNsense><tailscaleauth>`
/// - pfSense: `<installedpackages><tailscale>` and `<installedpackages><tailscaleauth>`
///
/// This function moves the config sections to the pfSense location.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    // Ensure the <installedpackages> container exists
    let installed = ensure_child_mut(out, "installedpackages");

    // Remove any existing Tailscale config in the output
    installed
        .children
        .retain(|c| c.tag != "tailscale" && c.tag != "tailscaleauth");

    // Copy Tailscale main config from OPNsense source
    let Some(src_tailscale) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("tailscale"))
    else {
        return;
    };
    installed.children.push(src_tailscale.clone());

    // Copy Tailscale auth config if it exists
    if let Some(src_auth) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("tailscaleauth"))
    {
        installed.children.push(src_auth.clone());
    }

    let _ = target;
}

/// Find Tailscale main config in pfSense source.
///
/// Checks both:
/// - Top-level `<tailscale>` (legacy location)
/// - `<installedpackages><tailscale>` (standard location)
fn source_pfsense_tailscale(root: &XmlNode) -> Option<&XmlNode> {
    root.get_child("tailscale").or_else(|| {
        root.get_child("installedpackages")
            .and_then(|ip| ip.get_child("tailscale"))
    })
}

/// Find Tailscale auth config in pfSense source.
///
/// Checks both:
/// - Top-level `<tailscaleauth>` (legacy location)
/// - `<installedpackages><tailscaleauth>` (standard location)
fn source_pfsense_tailscaleauth(root: &XmlNode) -> Option<&XmlNode> {
    root.get_child("tailscaleauth").or_else(|| {
        root.get_child("installedpackages")
            .and_then(|ip| ip.get_child("tailscaleauth"))
    })
}

/// Get a mutable reference to a child, creating it if it doesn't exist.
fn ensure_child_mut<'a>(parent: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(idx) = parent.children.iter().position(|c| c.tag == tag) {
        return &mut parent.children[idx];
    }
    parent.children.push(XmlNode::new(tag));
    let last = parent.children.len() - 1;
    &mut parent.children[last]
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn transfers_pfsense_tailscale_to_opnsense_container() {
        let source = parse(
            br#"<pfsense><installedpackages><tailscale><config><enable>on</enable></config></tailscale></installedpackages></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);

        let ts = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("tailscale"));
        assert!(ts.is_some());
    }

    #[test]
    fn transfers_opnsense_tailscale_to_pfsense_installedpackages() {
        let source = parse(
            br#"<opnsense><OPNsense><tailscale><settings/></tailscale></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);

        let ts = out
            .get_child("installedpackages")
            .and_then(|ip| ip.get_child("tailscale"));
        assert!(ts.is_some());
    }
}
