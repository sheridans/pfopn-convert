use xml_diff_core::XmlNode;

/// Normalize interface groups for OPNsense output.
///
/// Two adjustments are made:
/// 1. Auto-generated plugin interface groups (WireGuard, Tailscale) are pruned
///    because OPNsense recreates them on its own -- importing them causes
///    duplicates.
/// 2. The WireGuard group token is rewritten from pfSense's `WireGuard` casing
///    to OPNsense's `wireGuard` casing throughout the tree (firewall rules,
///    interface assignments, group memberships, etc.).
pub fn normalize_for_opnsense(root: &mut XmlNode) {
    prune_autogen_ifgroups(root);
    rewrite_group_tokens(root, "WireGuard", "wireGuard");
}

/// Normalize interface groups for pfSense output.
///
/// Rewrites OPNsense's `wireGuard` casing back to pfSense's `WireGuard`
/// throughout the tree. No pruning is needed since pfSense doesn't
/// auto-generate these groups.
pub fn normalize_for_pfsense(root: &mut XmlNode) {
    rewrite_group_tokens(root, "wireGuard", "WireGuard");
}

/// Remove auto-generated plugin interface groups from `<ifgroups>`.
///
/// OPNsense plugins (WireGuard, Tailscale) auto-create interface group entries
/// marked with "DO NOT EDIT/DELETE!" in their description. These should not be
/// carried over during conversion because the target OPNsense instance will
/// recreate them when the plugin is active. User-created groups are preserved.
fn prune_autogen_ifgroups(root: &mut XmlNode) {
    let Some(ifgroups) = child_mut(root, "ifgroups") else {
        return;
    };
    ifgroups.children.retain(|entry| {
        if entry.tag != "ifgroupentry" {
            return true;
        }
        let ifname = entry
            .get_text(&["ifname"])
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let descr = entry
            .get_text(&["descr"])
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();

        let looks_autogen = descr.contains("do not edit/delete");
        let is_plugin_group = ifname == "wireguard" || ifname == "tailscale";
        // Keep the entry unless it matches both criteria.
        !(looks_autogen && is_plugin_group)
    });
}

/// Rewrite all occurrences of a group name token throughout the tree.
///
/// Delegates to `rewrite_node` which walks the full tree recursively.
fn rewrite_group_tokens(root: &mut XmlNode, from: &str, to: &str) {
    rewrite_node(root, from, to);
}

/// Recursively walk the tree and rewrite group name tokens in relevant elements.
///
/// Only elements whose tag is `interface`, `members`, or `interfaces` have
/// their text content inspected -- these are the fields where interface group
/// names appear as comma/space-separated token lists in both pfSense and
/// OPNsense configs.
fn rewrite_node(node: &mut XmlNode, from: &str, to: &str) {
    if node.tag == "interface" || node.tag == "members" || node.tag == "interfaces" {
        if let Some(text) = node.text.clone() {
            let rewritten = rewrite_token_list(&text, from, to);
            if rewritten != text {
                node.text = Some(rewritten);
            }
        }
    }
    for child in &mut node.children {
        rewrite_node(child, from, to);
    }
}

/// Replace exact token matches within a delimiter-separated list.
///
/// Splits `input` on commas and whitespace, replaces tokens that exactly match
/// `from` with `to`, and preserves the original delimiters in place. This
/// avoids false positives from substring matches (e.g. "WireGuard_backup"
/// won't be rewritten when replacing "WireGuard").
fn rewrite_token_list(input: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut token = String::new();
    for ch in input.chars() {
        if matches!(ch, ',' | ' ' | '\t' | '\n' | '\r') {
            flush_token(&mut out, &mut token, from, to);
            out.push(ch);
        } else {
            token.push(ch);
        }
    }
    flush_token(&mut out, &mut token, from, to);
    out
}

/// Write the accumulated token to `out`, replacing it if it matches `from`.
fn flush_token(out: &mut String, token: &mut String, from: &str, to: &str) {
    if token.is_empty() {
        return;
    }
    if token == from {
        out.push_str(to);
    } else {
        out.push_str(token);
    }
    token.clear();
}

/// Return a mutable reference to the first child with the given tag.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{normalize_for_opnsense, normalize_for_pfsense};

    #[test]
    fn opnsense_prunes_autogen_wireguard_ifgroup_and_rewrites_interface_token() {
        let mut root = parse(
            br#"<opnsense>
                <ifgroups>
                  <ifgroupentry><ifname>WireGuard</ifname><descr>WireGuard Interface Group (DO NOT EDIT/DELETE!)</descr><members/></ifgroupentry>
                  <ifgroupentry><ifname>lan</ifname><descr>LAN Group</descr><members>lan</members></ifgroupentry>
                </ifgroups>
                <filter><rule><interface>WireGuard</interface></rule></filter>
            </opnsense>"#,
        )
        .expect("parse");
        normalize_for_opnsense(&mut root);
        let ifgroups = root.get_child("ifgroups").expect("ifgroups");
        assert_eq!(
            ifgroups
                .children
                .iter()
                .filter(|c| c.tag == "ifgroupentry")
                .count(),
            1
        );
        assert_eq!(
            root.get_text(&["filter", "rule", "interface"]),
            Some("wireGuard")
        );
    }

    #[test]
    fn pfsense_rewrites_wireguard_group_token_back() {
        let mut root = parse(
            br#"<pfsense><filter><rule><interface>wireGuard</interface></rule></filter></pfsense>"#,
        )
        .expect("parse");
        normalize_for_pfsense(&mut root);
        assert_eq!(
            root.get_text(&["filter", "rule", "interface"]),
            Some("WireGuard")
        );
    }
}
