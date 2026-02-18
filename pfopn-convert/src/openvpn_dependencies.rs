use std::collections::BTreeSet;

use serde::Serialize;
use xml_diff_core::XmlNode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenVpnInventory {
    pub instance_count: usize,
    pub enabled_instances: usize,
    pub disabled_instances: usize,
    pub referenced_ca_ids: BTreeSet<String>,
    pub referenced_cert_ids: BTreeSet<String>,
    pub referenced_usernames: BTreeSet<String>,
    pub available_ca_ids: BTreeSet<String>,
    pub available_cert_ids: BTreeSet<String>,
    pub available_usernames: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenVpnDependencyGap {
    pub direction: String,
    pub missing_ca_ids: Vec<String>,
    pub missing_cert_ids: Vec<String>,
    pub missing_usernames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenVpnDependencyReport {
    pub left: OpenVpnInventory,
    pub right: OpenVpnInventory,
    pub left_to_right: OpenVpnDependencyGap,
    pub right_to_left: OpenVpnDependencyGap,
}

pub fn compare_openvpn_dependencies(left: &XmlNode, right: &XmlNode) -> OpenVpnDependencyReport {
    let left_inventory = collect_openvpn_inventory(left);
    let right_inventory = collect_openvpn_inventory(right);

    OpenVpnDependencyReport {
        left_to_right: build_gap("left_to_right", &left_inventory, &right_inventory),
        right_to_left: build_gap("right_to_left", &right_inventory, &left_inventory),
        left: left_inventory,
        right: right_inventory,
    }
}

fn build_gap(
    direction: &str,
    source: &OpenVpnInventory,
    target: &OpenVpnInventory,
) -> OpenVpnDependencyGap {
    OpenVpnDependencyGap {
        direction: direction.to_string(),
        missing_ca_ids: sorted_diff(&source.referenced_ca_ids, &target.available_ca_ids),
        missing_cert_ids: sorted_diff(&source.referenced_cert_ids, &target.available_cert_ids),
        missing_usernames: sorted_diff(&source.referenced_usernames, &target.available_usernames),
    }
}

fn sorted_diff(source: &BTreeSet<String>, target: &BTreeSet<String>) -> Vec<String> {
    source
        .iter()
        .filter(|entry| !target.contains(*entry))
        .cloned()
        .collect()
}

fn collect_openvpn_inventory(root: &XmlNode) -> OpenVpnInventory {
    let openvpn_roots = find_openvpn_roots(root);
    let available_ca_ids = collect_top_level_refids(root, "ca");
    let available_cert_ids = collect_top_level_refids(root, "cert");
    let available_usernames = collect_system_usernames(root);

    let mut referenced_ca_ids = BTreeSet::new();
    let mut referenced_cert_ids = BTreeSet::new();
    let mut referenced_usernames = BTreeSet::new();

    let mut instance_count = 0usize;
    let mut enabled_instances = 0usize;
    let mut disabled_instances = 0usize;

    for openvpn_root in openvpn_roots {
        walk_openvpn_refs(
            openvpn_root,
            &mut referenced_ca_ids,
            &mut referenced_cert_ids,
            &mut referenced_usernames,
        );
        count_instances(
            openvpn_root,
            &mut instance_count,
            &mut enabled_instances,
            &mut disabled_instances,
        );
    }

    OpenVpnInventory {
        instance_count,
        enabled_instances,
        disabled_instances,
        referenced_ca_ids,
        referenced_cert_ids,
        referenced_usernames,
        available_ca_ids,
        available_cert_ids,
        available_usernames,
    }
}

fn find_openvpn_roots(root: &XmlNode) -> Vec<&XmlNode> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.tag == "openvpn" || node.tag == "OpenVPN" {
            out.push(node);
        }
        for child in &node.children {
            stack.push(child);
        }
    }
    out
}

fn walk_openvpn_refs(
    node: &XmlNode,
    ca_ids: &mut BTreeSet<String>,
    cert_ids: &mut BTreeSet<String>,
    users: &mut BTreeSet<String>,
) {
    let tag = node.tag.to_ascii_lowercase();
    if let Some(value) = normalized_text(&node.text) {
        match tag.as_str() {
            "caref" | "authcertca" | "ca" => {
                ca_ids.insert(value);
            }
            "certref" | "authcertname" | "cert" => {
                cert_ids.insert(value);
            }
            "username" | "user" | "local_user" => {
                users.insert(value);
            }
            _ => {}
        }
    }

    for child in &node.children {
        walk_openvpn_refs(child, ca_ids, cert_ids, users);
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

fn count_instances(node: &XmlNode, total: &mut usize, enabled: &mut usize, disabled: &mut usize) {
    if node.tag == "openvpn-server" || node.tag == "Instance" {
        *total += 1;
        if is_disabled_instance(node) {
            *disabled += 1;
        } else {
            *enabled += 1;
        }
    }

    for child in &node.children {
        count_instances(child, total, enabled, disabled);
    }
}

fn is_disabled_instance(node: &XmlNode) -> bool {
    if let Some(disable) = node.get_child("disable") {
        if disable.text.is_none() {
            return true;
        }
        if let Some(value) = normalized_text(&disable.text) {
            return value == "1"
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("true");
        }
        return true;
    }

    if let Some(enabled) = node.get_child("enabled") {
        if let Some(value) = normalized_text(&enabled.text) {
            return !(value == "1"
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("true"));
        }
    }

    false
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

fn collect_system_usernames(root: &XmlNode) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(system) = root.get_child("system") else {
        return names;
    };

    for user in system.children.iter().filter(|child| child.tag == "user") {
        if let Some(name) = user.get_text(&["name"]) {
            let name = name.trim();
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::compare_openvpn_dependencies;

    fn parse_xml(input: &str) -> xml_diff_core::XmlNode {
        parse(input.as_bytes()).expect("parse xml")
    }

    #[test]
    fn detects_disabled_pfsense_openvpn_server() {
        let left = parse_xml(
            r#"<pfsense>
                <system><user><name>admin</name></user></system>
                <openvpn>
                    <openvpn-server>
                        <disable></disable>
                        <caref>ca1</caref>
                        <certref>cert1</certref>
                    </openvpn-server>
                </openvpn>
                <ca><refid>ca1</refid></ca>
                <cert><refid>cert1</refid></cert>
            </pfsense>"#,
        );
        let right = parse_xml("<opnsense><system/></opnsense>");

        let report = compare_openvpn_dependencies(&left, &right);
        assert_eq!(report.left.instance_count, 1);
        assert_eq!(report.left.disabled_instances, 1);
        assert_eq!(report.left_to_right.missing_ca_ids, vec!["ca1"]);
        assert_eq!(report.left_to_right.missing_cert_ids, vec!["cert1"]);
    }

    #[test]
    fn detects_missing_usernames_on_target() {
        let left = parse_xml(
            r#"<pfsense>
                <system>
                    <user><name>alice</name></user>
                    <user><name>bob</name></user>
                </system>
                <openvpn>
                    <openvpn-server>
                        <username>alice</username>
                    </openvpn-server>
                </openvpn>
            </pfsense>"#,
        );
        let right = parse_xml(
            r#"<opnsense>
                <system><user><name>root</name></user></system>
                <openvpn/>
            </opnsense>"#,
        );

        let report = compare_openvpn_dependencies(&left, &right);
        assert_eq!(report.left_to_right.missing_usernames, vec!["alice"]);
    }
}
