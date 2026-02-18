use xml_diff_core::XmlNode;

/// Remove pfBlockerNG floating firewall rules when converting to OPNsense.
///
/// pfBlockerNG is a popular pfSense package for blocking ads, malware, and geographic
/// regions. It creates "floating" firewall rules that apply to all interfaces and
/// contain special alias references like "pfB_Top_v4", "pfB_Top_v6", or custom
/// "pfB_*" aliases.
///
/// Since OPNsense doesn't have pfBlockerNG (it has its own alternatives like
/// os-firewall and os-ips), these floating rules would be invalid and potentially
/// break the firewall config. This function identifies and removes them.
///
/// Regular (non-floating) rules that happen to reference pfBlocker aliases are
/// also problematic, but this function specifically targets floating rules since
/// those are the most common and most problematic.
pub fn prune_pfblocker_floating_rules_for_opnsense(root: &mut XmlNode) {
    let Some(filter) = child_mut(root, "filter") else {
        return;
    };

    // Remove any <rule> children that are pfBlocker floating rules.
    // Keep everything else (separator rules, non-pfBlocker rules, etc.)
    filter.children.retain(|child| {
        if child.tag != "rule" {
            return true; // Keep non-rule elements
        }
        !is_pfblocker_floating_rule(child) // Remove if it's a pfBlocker floating rule
    });
}

/// Check if a firewall rule is both floating AND contains pfBlocker markers.
///
/// A rule is considered a pfBlocker floating rule if:
/// 1. It has <floating>yes</floating>
/// 2. Anywhere in the rule's XML tree there's text matching pfBlocker patterns
///    (pfB_Top_v4, pfB_Top_v6, or anything starting with pfb_)
fn is_pfblocker_floating_rule(rule: &XmlNode) -> bool {
    // First check: is this a floating rule?
    let is_floating = rule
        .get_text(&["floating"])
        .map(|v| v.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    if !is_floating {
        return false; // Not floating, so definitely not a pfBlocker floating rule
    }

    // Second check: does this rule contain any pfBlocker markers?
    // Collect all text content from anywhere in the rule's XML subtree
    let mut texts = Vec::new();
    collect_text(rule, &mut texts);

    // Check if any of those text snippets look like pfBlocker identifiers
    texts.into_iter().any(is_pfblocker_marker)
}

/// Recursively walk an XML node and collect all non-empty text content.
///
/// This is used to scan a firewall rule for any mention of pfBlocker aliases,
/// which could appear in <source>, <destination>, <descr>, or other fields.
fn collect_text(node: &XmlNode, out: &mut Vec<String>) {
    if let Some(text) = node.text.as_deref() {
        let v = text.trim();
        if !v.is_empty() {
            out.push(v.to_string());
        }
    }
    // Recurse into all children to catch text at any depth
    for child in &node.children {
        collect_text(child, out);
    }
}

/// Check if a string looks like a pfBlockerNG alias or identifier.
///
/// pfBlocker uses these naming conventions:
/// - "pfB_Top_v4" and "pfB_Top_v6" — special top-priority rule aliases
/// - "pfB_*" — custom aliases created by the user (e.g. "pfB_Ads", "pfB_Russia")
fn is_pfblocker_marker(s: String) -> bool {
    let t = s.trim();
    t.eq_ignore_ascii_case("pfB_Top_v4")
        || t.eq_ignore_ascii_case("pfB_Top_v6")
        || t.to_ascii_lowercase().starts_with("pfb_")
}

/// Helper to get a mutable reference to a direct child node by tag name.
fn child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> Option<&'a mut XmlNode> {
    let idx = node.children.iter().position(|c| c.tag == tag)?;
    Some(&mut node.children[idx])
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::prune_pfblocker_floating_rules_for_opnsense;

    #[test]
    fn prunes_pfblocker_floating_rules() {
        let mut root = parse(
            br#"<opnsense><filter>
                <rule><floating>yes</floating><source><address>pfB_Top_v4</address></source></rule>
                <rule><floating>yes</floating><source><address>LAN_NET</address></source></rule>
                <rule><interface>lan</interface><source><address>pfB_Top_v6</address></source></rule>
            </filter></opnsense>"#,
        )
        .expect("parse");
        prune_pfblocker_floating_rules_for_opnsense(&mut root);
        let filter = root.get_child("filter").expect("filter");
        assert_eq!(
            filter.children.iter().filter(|c| c.tag == "rule").count(),
            2
        );
    }
}
