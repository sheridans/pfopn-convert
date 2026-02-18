use serde::Serialize;
use xml_diff_core::XmlNode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireGuardInventory {
    pub configured: bool,
    pub enabled_entries: usize,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireGuardDependencyReport {
    pub left: WireGuardInventory,
    pub right: WireGuardInventory,
}

pub fn compare_wireguard_dependencies(
    left: &XmlNode,
    right: &XmlNode,
) -> WireGuardDependencyReport {
    WireGuardDependencyReport {
        left: collect_wireguard_inventory(left),
        right: collect_wireguard_inventory(right),
    }
}

fn collect_wireguard_inventory(root: &XmlNode) -> WireGuardInventory {
    let mut paths = find_wireguard_paths(root);
    paths.sort();
    let enabled_entries = count_enabled_entries_in_paths(root, &paths);

    WireGuardInventory {
        configured: !paths.is_empty(),
        enabled_entries,
        paths,
    }
}

fn find_wireguard_paths(root: &XmlNode) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(root, root.tag.clone())];

    while let Some((node, path)) = stack.pop() {
        if node.tag.eq_ignore_ascii_case("wireguard") {
            out.push(path.clone());
        }
        for child in &node.children {
            stack.push((child, format!("{path}.{}", child.tag)));
        }
    }

    out
}

fn count_enabled_entries_in_paths(root: &XmlNode, paths: &[String]) -> usize {
    let mut count = 0usize;
    for path in paths {
        if let Some(node) = find_node_by_path(root, path) {
            count += count_enabled_flags(node);
        }
    }
    count
}

fn find_node_by_path<'a>(root: &'a XmlNode, path: &str) -> Option<&'a XmlNode> {
    let mut iter = path.split('.');
    let first = iter.next()?;
    if first != root.tag {
        return None;
    }

    let mut node = root;
    for tag in iter {
        node = node.children.iter().find(|c| c.tag == tag)?;
    }
    Some(node)
}

fn count_enabled_flags(node: &XmlNode) -> usize {
    let mut count = 0usize;
    if node.tag.eq_ignore_ascii_case("enabled")
        && is_truthy(node.text.as_deref().unwrap_or_default())
    {
        count += 1;
    }
    for child in &node.children {
        count += count_enabled_flags(child);
    }
    count
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "enabled" | "on"
    )
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::compare_wireguard_dependencies;

    #[test]
    fn detects_wireguard_presence_and_enabled_counts() {
        let left = parse(
            br#"<pfsense>
                <wireguard><tunnel><enabled>1</enabled></tunnel></wireguard>
            </pfsense>"#,
        )
        .expect("left parse");
        let right = parse(
            br#"<opnsense>
                <OPNsense><wireguard><general><enabled>0</enabled></general></wireguard></OPNsense>
            </opnsense>"#,
        )
        .expect("right parse");

        let report = compare_wireguard_dependencies(&left, &right);
        assert!(report.left.configured);
        assert_eq!(report.left.enabled_entries, 1);
        assert!(report.right.configured);
        assert_eq!(report.right.enabled_entries, 0);
    }
}
