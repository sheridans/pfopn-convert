use std::collections::BTreeSet;

use serde::Serialize;
use xml_diff_core::XmlNode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpsecInventory {
    pub configured: bool,
    pub referenced_ca_ids: BTreeSet<String>,
    pub referenced_cert_ids: BTreeSet<String>,
    pub referenced_interfaces: BTreeSet<String>,
    pub available_ca_ids: BTreeSet<String>,
    pub available_cert_ids: BTreeSet<String>,
    pub available_interfaces: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpsecDependencyGap {
    pub direction: String,
    pub missing_ca_ids: Vec<String>,
    pub missing_cert_ids: Vec<String>,
    pub missing_interfaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpsecDependencyReport {
    pub left: IpsecInventory,
    pub right: IpsecInventory,
    pub left_to_right: IpsecDependencyGap,
    pub right_to_left: IpsecDependencyGap,
}

pub fn compare_ipsec_dependencies(left: &XmlNode, right: &XmlNode) -> IpsecDependencyReport {
    let left_inventory = collect_ipsec_inventory(left);
    let right_inventory = collect_ipsec_inventory(right);
    IpsecDependencyReport {
        left_to_right: build_gap("left_to_right", &left_inventory, &right_inventory),
        right_to_left: build_gap("right_to_left", &right_inventory, &left_inventory),
        left: left_inventory,
        right: right_inventory,
    }
}

fn build_gap(
    direction: &str,
    source: &IpsecInventory,
    target: &IpsecInventory,
) -> IpsecDependencyGap {
    IpsecDependencyGap {
        direction: direction.to_string(),
        missing_ca_ids: sorted_diff(&source.referenced_ca_ids, &target.available_ca_ids),
        missing_cert_ids: sorted_diff(&source.referenced_cert_ids, &target.available_cert_ids),
        missing_interfaces: sorted_diff(
            &source.referenced_interfaces,
            &target.available_interfaces,
        ),
    }
}

fn sorted_diff(source: &BTreeSet<String>, target: &BTreeSet<String>) -> Vec<String> {
    source
        .iter()
        .filter(|entry| !target.contains(*entry))
        .cloned()
        .collect()
}

fn collect_ipsec_inventory(root: &XmlNode) -> IpsecInventory {
    let ipsec_roots = find_ipsec_roots(root);
    let mut referenced_ca_ids = BTreeSet::new();
    let mut referenced_cert_ids = BTreeSet::new();
    let mut referenced_interfaces = BTreeSet::new();

    for node in &ipsec_roots {
        walk_ipsec_refs(
            node,
            &mut referenced_ca_ids,
            &mut referenced_cert_ids,
            &mut referenced_interfaces,
        );
    }

    IpsecInventory {
        configured: !ipsec_roots.is_empty(),
        referenced_ca_ids,
        referenced_cert_ids,
        referenced_interfaces,
        available_ca_ids: collect_top_level_refids(root, "ca"),
        available_cert_ids: collect_top_level_refids(root, "cert"),
        available_interfaces: collect_interface_names(root),
    }
}

fn find_ipsec_roots(root: &XmlNode) -> Vec<&XmlNode> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.tag.eq_ignore_ascii_case("ipsec") || node.tag.eq_ignore_ascii_case("swanctl") {
            out.push(node);
        }
        for child in &node.children {
            stack.push(child);
        }
    }
    out
}

fn walk_ipsec_refs(
    node: &XmlNode,
    ca_ids: &mut BTreeSet<String>,
    cert_ids: &mut BTreeSet<String>,
    ifaces: &mut BTreeSet<String>,
) {
    let tag = node.tag.to_ascii_lowercase();
    if let Some(value) = normalized_text(&node.text) {
        match tag.as_str() {
            "caref" | "ca_ref" => {
                ca_ids.insert(value);
            }
            "certref" | "cert_ref" | "localcertref" | "peercertref" => {
                cert_ids.insert(value);
            }
            "interface" | "if" => {
                ifaces.insert(value);
            }
            _ => {}
        }
    }
    for child in &node.children {
        walk_ipsec_refs(child, ca_ids, cert_ids, ifaces);
    }
}

fn normalized_text(input: &Option<String>) -> Option<String> {
    let text = input.as_deref()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn collect_top_level_refids(root: &XmlNode, section_tag: &str) -> BTreeSet<String> {
    root.children
        .iter()
        .filter(|child| child.tag == section_tag)
        .filter_map(|child| child.get_text(&["refid"]))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn collect_interface_names(root: &XmlNode) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(interfaces) = root.get_child("interfaces") else {
        return out;
    };
    for iface in &interfaces.children {
        out.insert(iface.tag.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::compare_ipsec_dependencies;

    #[test]
    fn reports_missing_cert_and_interface() {
        let left = parse(
            br#"<pfsense>
                <interfaces><wan/></interfaces>
                <ipsec><phase1><interface>wan</interface><certref>cert1</certref></phase1></ipsec>
                <cert><refid>cert1</refid></cert>
            </pfsense>"#,
        )
        .expect("left parse");
        let right = parse(
            br#"<opnsense>
                <interfaces><lan/></interfaces>
                <OPNsense><IPsec><phase1/></IPsec></OPNsense>
            </opnsense>"#,
        )
        .expect("right parse");

        let report = compare_ipsec_dependencies(&left, &right);
        assert_eq!(report.left_to_right.missing_cert_ids, vec!["cert1"]);
        assert_eq!(report.left_to_right.missing_interfaces, vec!["wan"]);
    }
}
