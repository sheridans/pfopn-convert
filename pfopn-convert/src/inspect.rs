use xml_diff_core::XmlNode;

/// Render an XML tree with a configurable max depth.
pub fn render_tree(node: &XmlNode, max_depth: usize) -> String {
    let mut out = String::new();
    render_node(node, 0, max_depth, &mut out);
    out
}

fn render_node(node: &XmlNode, depth: usize, max_depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    out.push_str(&format!("{}{}\n", indent, node.tag));

    if depth >= max_depth {
        return;
    }

    for child in &node.children {
        render_node(child, depth + 1, max_depth, out);
    }
}
