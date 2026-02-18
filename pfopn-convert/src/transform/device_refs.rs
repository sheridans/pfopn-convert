use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

/// Rewrite raw interface device references (e.g. igb0 -> vtnet0) using
/// source/target logical interface mapping.
pub fn apply(
    out: &mut XmlNode,
    source: &XmlNode,
    target: &XmlNode,
    interface_map_from: Option<&BTreeMap<String, String>>,
) {
    let replacements = build_device_map(source, target, interface_map_from);
    if replacements.is_empty() {
        return;
    }
    rewrite_tree(out, &replacements, &mut Vec::new());
}

fn build_device_map(
    source: &XmlNode,
    target: &XmlNode,
    interface_map_from: Option<&BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let src = interface_device_by_logical(source);
    let dst = interface_device_by_logical(target);

    for (logical, src_if) in &src {
        let mapped_logical = interface_map_from
            .and_then(|m| m.get(logical))
            .unwrap_or(logical);
        // Maps source logical interface names (e.g., opt2) to target logical names
        // before looking up the corresponding physical device.
        let Some(dst_if) = dst.get(mapped_logical) else {
            continue;
        };
        if is_pppoe_ifname(src_if) {
            continue;
        }
        // PPPoE interfaces use logical names (pppoe0) rather than physical device names.
        // These are assigned by the PPP subsystem and should not be rewritten.
        if src_if != dst_if {
            out.insert(src_if.clone(), dst_if.clone());
        }
    }
    augment_pppoe_port_map(source, target, interface_map_from, &mut out);
    out
}

fn augment_pppoe_port_map(
    source: &XmlNode,
    target: &XmlNode,
    interface_map_from: Option<&BTreeMap<String, String>>,
    out: &mut BTreeMap<String, String>,
) {
    // PPPoE configurations store the physical port separately from the interface name.
    // The <if> element contains the logical PPPoE name (pppoe0), while <ports> contains
    // the underlying physical interface. This function maps the physical ports.
    let Some(ppps) = source.get_child("ppps") else {
        return;
    };

    let src = interface_device_by_logical(source);
    let dst = interface_device_by_logical(target);
    let src_logical_by_if: BTreeMap<String, String> =
        src.iter().map(|(k, v)| (v.clone(), k.clone())).collect();

    for ppp in ppps.get_children("ppp") {
        if !ppp
            .get_text(&["type"])
            .map(str::trim)
            .unwrap_or("")
            .eq_ignore_ascii_case("pppoe")
        {
            continue;
        }
        let Some(ppp_if) = ppp
            .get_text(&["if"])
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let Some(port_if) = ppp
            .get_text(&["ports"])
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let Some(src_logical) = src_logical_by_if.get(ppp_if) else {
            continue;
        };
        let mapped_logical = interface_map_from
            .and_then(|m| m.get(src_logical))
            .unwrap_or(src_logical);
        let Some(dst_if) = dst.get(mapped_logical) else {
            continue;
        };
        if port_if != dst_if {
            out.insert(port_if.to_string(), dst_if.to_string());
        }
    }
}

fn interface_device_by_logical(root: &XmlNode) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(interfaces) = root.get_child("interfaces") else {
        return out;
    };
    for iface in &interfaces.children {
        let Some(name) = iface.get_text(&["if"]).map(str::trim) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.insert(iface.tag.clone(), name.to_string());
    }
    out
}

fn rewrite_tree(
    node: &mut XmlNode,
    replacements: &BTreeMap<String, String>,
    path: &mut Vec<String>,
) {
    path.push(node.tag.clone());
    if let Some(text) = node.text.clone() {
        let rewritten = if should_skip_rewrite(path) {
            text.clone()
        } else {
            rewrite_tokens(&text, replacements)
        };
        if rewritten != text {
            node.text = Some(rewritten);
        }
    }
    for child in &mut node.children {
        rewrite_tree(child, replacements, path);
    }
    path.pop();
}

fn should_skip_rewrite(path: &[String]) -> bool {
    // Preserve the PPP interface reference itself (e.g., pppoe0) when it appears
    // inside <ppps><ppp><if>. Only the physical <ports> element should be rewritten.
    path.ends_with(&["ppps".to_string(), "ppp".to_string(), "if".to_string()])
}

fn is_pppoe_ifname(v: &str) -> bool {
    v.trim().to_ascii_lowercase().starts_with("pppoe")
}

fn rewrite_tokens(input: &str, replacements: &BTreeMap<String, String>) -> String {
    // Tokenizes on delimiters (whitespace, commas) to handle comma-separated
    // interface lists while preserving surrounding punctuation and spacing.
    let mut out = String::with_capacity(input.len());
    let mut token = String::new();
    for ch in input.chars() {
        if is_delim(ch) {
            flush_token(&mut out, &mut token, replacements);
            out.push(ch);
        } else {
            token.push(ch);
        }
    }
    flush_token(&mut out, &mut token, replacements);
    out
}

fn flush_token(out: &mut String, token: &mut String, replacements: &BTreeMap<String, String>) {
    // Attempts exact match first, then falls back to dotted-parent matching
    // (e.g., "igb0.50" -> rewrite "igb0" to target, preserve ".50" suffix).
    if token.is_empty() {
        return;
    }
    if let Some(newv) = replacements.get(token.as_str()) {
        out.push_str(newv);
    } else if let Some((base, suffix)) = split_dotted_parent(token) {
        if let Some(new_base) = replacements.get(base) {
            out.push_str(new_base);
            out.push('.');
            out.push_str(suffix);
        } else {
            out.push_str(token);
        }
    } else {
        out.push_str(token);
    }
    token.clear();
}

fn split_dotted_parent(token: &str) -> Option<(&str, &str)> {
    // Handles VLAN subinterfaces (e.g., igb0.50 -> igb0 with VLAN tag 50).
    // The base device name is looked up for rewriting while preserving the VLAN tag.
    let dot = token.find('.')?;
    if dot == 0 || dot + 1 >= token.len() {
        return None;
    }
    Some((&token[..dot], &token[dot + 1..]))
}

fn is_delim(ch: char) -> bool {
    matches!(ch, ',' | ' ' | '\t' | '\n' | '\r')
}

#[cfg(test)]
mod tests {
    use super::apply;
    use std::collections::BTreeMap;
    use xml_diff_core::parse;

    #[test]
    fn rewrites_vlan_parent_device_from_source_to_target() {
        let source = parse(
            br#"<pfsense><interfaces><lan><if>igb0</if></lan></interfaces><vlans><vlan><if>igb0</if></vlan></vlans></pfsense>"#,
        )
        .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><lan><if>vtnet0</if></lan></interfaces></opnsense>"#)
                .expect("parse");
        let mut out = parse(
            br#"<opnsense><interfaces><lan><if>vtnet0</if></lan></interfaces><vlans><vlan><if>igb0</if></vlan></vlans></opnsense>"#,
        )
        .expect("parse");

        apply(&mut out, &source, &target, None);
        assert_eq!(out.get_text(&["vlans", "vlan", "if"]), Some("vtnet0"));
    }

    #[test]
    fn rewrites_with_logical_interface_map() {
        let source = parse(
            br#"<pfsense><interfaces><opt2><if>igb3</if></opt2></interfaces><vlans><vlan><if>igb3</if></vlan></vlans></pfsense>"#,
        )
        .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><igc3><if>vtnet2</if></igc3></interfaces></opnsense>"#)
                .expect("parse");
        let mut out = parse(
            br#"<opnsense><interfaces><igc3><if>vtnet2</if></igc3></interfaces><vlans><vlan><if>igb3</if></vlan></vlans></opnsense>"#,
        )
        .expect("parse");

        let mut from = BTreeMap::new();
        from.insert("opt2".to_string(), "igc3".to_string());
        apply(&mut out, &source, &target, Some(&from));
        assert_eq!(out.get_text(&["vlans", "vlan", "if"]), Some("vtnet2"));
    }

    #[test]
    fn rewrites_dotted_vlan_style_interface_refs() {
        let source = parse(
            br#"<pfsense><interfaces><lan><if>igb0</if></lan><opt3><if>igb0.50</if></opt3></interfaces></pfsense>"#,
        )
        .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><lan><if>vtnet0</if></lan></interfaces></opnsense>"#)
                .expect("parse");
        let mut out = parse(
            br#"<opnsense><interfaces><lan><if>vtnet0</if></lan><opt3><if>igb0.50</if></opt3></interfaces></opnsense>"#,
        )
        .expect("parse");

        apply(&mut out, &source, &target, None);
        assert_eq!(
            out.get_text(&["interfaces", "opt3", "if"]),
            Some("vtnet0.50")
        );
    }

    #[test]
    fn keeps_pppoe_ifname_and_rewrites_ports_to_target_physical() {
        let source = parse(
            br#"<pfsense>
                <interfaces><wan><if>pppoe0</if></wan></interfaces>
                <ppps><ppp><type>pppoe</type><if>pppoe0</if><ports>igb0</ports></ppp></ppps>
            </pfsense>"#,
        )
        .expect("parse");
        let target =
            parse(br#"<opnsense><interfaces><wan><if>vtnet2</if></wan></interfaces></opnsense>"#)
                .expect("parse");
        let mut out = parse(
            br#"<opnsense>
                <interfaces><wan><if>vtnet2</if></wan></interfaces>
                <ppps><ppp><type>pppoe</type><if>pppoe0</if><ports>igb0</ports></ppp></ppps>
            </opnsense>"#,
        )
        .expect("parse");

        apply(&mut out, &source, &target, None);
        assert_eq!(out.get_text(&["ppps", "ppp", "if"]), Some("pppoe0"));
        assert_eq!(out.get_text(&["ppps", "ppp", "ports"]), Some("vtnet2"));
    }
}
