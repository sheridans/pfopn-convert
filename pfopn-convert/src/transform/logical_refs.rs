use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

/// Rewrite logical interface references throughout the entire XML config tree.
///
/// When interfaces are renumbered during conversion (e.g. the source config's
/// "opt2" maps to "opt1" on the target), every place in the config that refers
/// to an interface by its logical name must be updated. This includes firewall
/// rules (`<interface>opt2</interface>`), bridge members (`<members>lan opt2</members>`),
/// gateway groups, and similar fields.
///
/// `logical_map` maps old logical names to new ones, e.g. {"opt2" => "opt1"}.
pub fn apply(root: &mut XmlNode, logical_map: Option<&BTreeMap<String, String>>) {
    // If no map was provided or it's empty, there's nothing to rewrite.
    let Some(logical_map) = logical_map else {
        return;
    };
    if logical_map.is_empty() {
        return;
    }
    rewrite_node(root, logical_map);
}

/// Walk every node in the tree recursively, rewriting interface references
/// in tags we know carry them.
fn rewrite_node(node: &mut XmlNode, logical_map: &BTreeMap<String, String>) {
    match node.tag.as_str() {
        // <members> and <interfaces> can hold space-separated lists of
        // logical interface names, e.g. "lan opt1 opt2".
        "members" | "interfaces" => rewrite_token_list(node, logical_map),
        // <interface> holds a single logical name, e.g. "opt2".
        "interface" => rewrite_single(node, logical_map),
        _ => {}
    }
    // Recurse into children so we catch these tags at any depth in the tree.
    for child in &mut node.children {
        rewrite_node(child, logical_map);
    }
}

/// Replace a node's text when it contains exactly one logical interface name.
/// Example: `<interface>opt2</interface>` -> `<interface>opt1</interface>`
fn rewrite_single(node: &mut XmlNode, logical_map: &BTreeMap<String, String>) {
    let Some(current) = node.text.as_deref().map(str::trim) else {
        return;
    };
    // Look up the trimmed text in the map; if not found, leave it alone.
    let Some(mapped) = logical_map.get(current) else {
        return;
    };
    node.text = Some(mapped.clone());
}

/// Replace interface names inside a space/comma-delimited token list.
/// Example: `<members>lan opt2</members>` -> `<members>lan opt1</members>`
fn rewrite_token_list(node: &mut XmlNode, logical_map: &BTreeMap<String, String>) {
    let Some(current) = node.text.clone() else {
        return;
    };
    let rewritten = rewrite_tokens(&current, logical_map);
    // Only mutate the node if something actually changed.
    if rewritten != current {
        node.text = Some(rewritten);
    }
}

/// Tokenize a string by delimiters (space, comma, whitespace), replace each
/// token that appears in `logical_map`, and reassemble preserving the original
/// delimiters.
///
/// For example, given input "lan opt2" and map {"opt2" => "opt1"},
/// produces "lan opt1" — the space between tokens is preserved as-is.
fn rewrite_tokens(input: &str, logical_map: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut token = String::new(); // accumulates non-delimiter characters

    for ch in input.chars() {
        if is_delim(ch) {
            // We hit a delimiter — flush the token we've been building,
            // then append the delimiter character verbatim.
            flush_token(&mut out, &mut token, logical_map);
            out.push(ch);
        } else {
            // Non-delimiter character — keep building the current token.
            token.push(ch);
        }
    }
    // Flush any trailing token (input doesn't necessarily end with a delimiter).
    flush_token(&mut out, &mut token, logical_map);
    out
}

/// Write the accumulated `token` into `out`, replacing it with its mapped value
/// if one exists in `logical_map`. Clears `token` afterwards.
fn flush_token(out: &mut String, token: &mut String, logical_map: &BTreeMap<String, String>) {
    if token.is_empty() {
        return;
    }
    if let Some(mapped) = logical_map.get(token.as_str()) {
        out.push_str(mapped);
    } else {
        out.push_str(token);
    }
    token.clear();
}

/// Characters that separate interface names in token lists.
fn is_delim(ch: char) -> bool {
    matches!(ch, ',' | ' ' | '\t' | '\n' | '\r')
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xml_diff_core::parse;

    use super::apply;

    #[test]
    fn rewrites_bridge_members_and_rule_interface() {
        let mut root = parse(
            br#"<opnsense><bridges><bridged><members>lan opt2</members></bridged></bridges><filter><rule><interface>opt2</interface></rule></filter></opnsense>"#,
        )
        .expect("parse");
        let mut map = BTreeMap::new();
        map.insert("opt2".to_string(), "opt1".to_string());

        apply(&mut root, Some(&map));
        assert_eq!(
            root.get_text(&["bridges", "bridged", "members"]),
            Some("lan opt1")
        );
        assert_eq!(
            root.get_text(&["filter", "rule", "interface"]),
            Some("opt1")
        );
    }
}
