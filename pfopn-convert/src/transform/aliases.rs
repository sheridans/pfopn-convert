use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

/// Converts pfSense aliases to OPNsense format.
///
/// pfSense uses a flat `<aliases><alias>...</alias></aliases>` structure,
/// whereas OPNsense nests them under `<OPNsense><Firewall><Alias><aliases>`.
/// Alias names are compared case-insensitively to prevent duplicates.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    let Some(src_aliases) = source.get_child("aliases") else {
        return;
    };
    let src_items = src_aliases
        .children
        .iter()
        .filter(|c| c.tag == "alias")
        .cloned()
        .collect::<Vec<_>>();
    let dst_aliases = ensure_opnsense_aliases_node(out);
    dst_aliases.children.retain(|c| c.tag != "alias");
    let mut existing = collect_alias_names(dst_aliases);
    for alias in src_items {
        if should_insert_alias(&alias, &mut existing) {
            dst_aliases.children.push(alias);
        }
    }

    let _ = target;
}

/// Converts OPNsense aliases to pfSense format.
///
/// The reverse of `to_opnsense`: OPNsense's nested `<OPNsense><Firewall><Alias><aliases>`
/// becomes pfSense's flat `<aliases>` structure.
/// Case-insensitive deduplication is applied.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    let Some(src_aliases) = source
        .get_child("OPNsense")
        .and_then(|opn| opn.get_child("Firewall"))
        .and_then(|fw| fw.get_child("Alias"))
        .and_then(|alias| alias.get_child("aliases"))
    else {
        return;
    };
    let src_items = src_aliases
        .children
        .iter()
        .filter(|c| c.tag == "alias")
        .cloned()
        .collect::<Vec<_>>();
    let dst_aliases = ensure_child_mut(out, "aliases");
    dst_aliases.children.retain(|c| c.tag != "alias");
    let mut existing = collect_alias_names(dst_aliases);
    for alias in src_items {
        if should_insert_alias(&alias, &mut existing) {
            dst_aliases.children.push(alias);
        }
    }

    let _ = target;
}

/// Determines whether an alias should be inserted, based on name uniqueness.
///
/// Alias names are compared case-insensitively; "Mullvad_Hosts" and "mullvad_hosts"
/// are considered duplicates.
fn should_insert_alias(alias: &XmlNode, existing: &mut BTreeSet<String>) -> bool {
    let Some(name) = alias_name(alias) else {
        return true;
    };
    existing.insert(name)
}

/// Extracts the name field from an alias node, normalising to lowercase.
/// Returns `None` if the name is empty or missing.
fn alias_name(alias: &XmlNode) -> Option<String> {
    let value = alias.get_text(&["name"])?.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

/// Collects all alias names from an aliases container node.
fn collect_alias_names(aliases_node: &XmlNode) -> BTreeSet<String> {
    aliases_node
        .children
        .iter()
        .filter(|c| c.tag == "alias")
        .filter_map(alias_name)
        .collect()
}

/// Ensures the OPNsense nested structure exists: `OPNsense > Firewall > Alias > aliases`.
fn ensure_opnsense_aliases_node(out: &mut XmlNode) -> &mut XmlNode {
    let opn = ensure_child_mut(out, "OPNsense");
    let fw = ensure_child_mut(opn, "Firewall");
    let alias = ensure_child_mut(fw, "Alias");
    ensure_child_mut(alias, "aliases")
}

/// Gets or creates a child element with the given tag name.
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
    fn transfers_pfsense_aliases_into_opnsense_nested_aliases() {
        let source = parse(
            br#"<pfsense><aliases><alias><name>mullvad_hosts</name></alias></aliases></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<opnsense><system/></opnsense>"#).expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);

        let aliases = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Firewall"))
            .and_then(|fw| fw.get_child("Alias"))
            .and_then(|alias| alias.get_child("aliases"))
            .expect("nested aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }

    #[test]
    fn does_not_duplicate_existing_alias_name() {
        let source = parse(
            br#"<pfsense><aliases><alias><name>mullvad_hosts</name></alias></aliases></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<opnsense><OPNsense><Firewall><Alias><aliases><alias><name>mullvad_hosts</name></alias></aliases></Alias></Firewall></OPNsense></opnsense>"#,
        )
        .expect("target parse");
        let mut out = target.clone();

        to_opnsense(&mut out, &source, &target);

        let aliases = out
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Firewall"))
            .and_then(|fw| fw.get_child("Alias"))
            .and_then(|alias| alias.get_child("aliases"))
            .expect("nested aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }

    #[test]
    fn transfers_opnsense_nested_aliases_to_pfsense_top_level() {
        let source = parse(
            br#"<opnsense><OPNsense><Firewall><Alias><aliases><alias><name>remote_sites</name></alias></aliases></Alias></Firewall></OPNsense></opnsense>"#,
        )
        .expect("source parse");
        let target = parse(br#"<pfsense><system/></pfsense>"#).expect("target parse");
        let mut out = target.clone();

        to_pfsense(&mut out, &source, &target);

        let aliases = out.get_child("aliases").expect("top-level aliases");
        assert_eq!(aliases.get_children("alias").len(), 1);
    }
}
