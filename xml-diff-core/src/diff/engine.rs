use std::collections::{HashMap, HashSet};

use crate::diff::result::DiffEntry;
use crate::XmlNode;

/// Configures tree diff behavior.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// Include [`DiffEntry::Identical`] rows.
    pub include_identical: bool,
    /// Maximum recursion depth. `-1` means unlimited.
    pub max_depth: i32,
    /// Optional map from tag -> child tag used as key for repeated-element matching.
    pub key_fields: HashMap<String, String>,
    /// Paths or tag names to ignore.
    pub ignore_paths: Vec<String>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            include_identical: false,
            max_depth: -1,
            key_fields: HashMap::new(),
            ignore_paths: Vec::new(),
        }
    }
}

/// Diff two XML trees with default options.
pub fn diff(left: &XmlNode, right: &XmlNode) -> Vec<DiffEntry> {
    diff_with_options(left, right, &DiffOptions::default())
}

/// Diff two XML trees with custom options.
pub fn diff_with_options(left: &XmlNode, right: &XmlNode, opts: &DiffOptions) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    let root_path = left.tag.clone();
    diff_node(left, right, &root_path, 0, opts, &mut out);
    out
}

fn diff_node(
    left: &XmlNode,
    right: &XmlNode,
    path: &str,
    depth: i32,
    opts: &DiffOptions,
    out: &mut Vec<DiffEntry>,
) {
    if should_ignore(path, opts) {
        return;
    }

    if opts.max_depth >= 0 && depth > opts.max_depth {
        return;
    }

    let start_len = out.len();

    if left.tag != right.tag {
        out.push(DiffEntry::Structural {
            path: path.to_string(),
            description: format!("tag mismatch: left='{}' right='{}'", left.tag, right.tag),
        });
        diff_children(left, right, path, depth, opts, out);
        return;
    }

    if left.attributes != right.attributes
        || normalize_text(&left.text) != normalize_text(&right.text)
    {
        out.push(DiffEntry::Modified {
            path: path.to_string(),
            left: local_signature(left),
            right: local_signature(right),
        });
    }

    diff_children(left, right, path, depth, opts, out);

    if opts.include_identical && out.len() == start_len {
        out.push(DiffEntry::Identical {
            path: path.to_string(),
        });
    }
}

struct MatchContext<'a, 'b> {
    parent_path: &'a str,
    depth: i32,
    opts: &'a DiffOptions,
    out: &'b mut Vec<DiffEntry>,
}

fn match_by_index(
    tag: &str,
    left_nodes: Vec<&XmlNode>,
    right_nodes: Vec<&XmlNode>,
    ctx: &mut MatchContext<'_, '_>,
) {
    let max = left_nodes.len().max(right_nodes.len());
    for i in 0..max {
        let child_path = format!("{}.{tag}[{}]", ctx.parent_path, i + 1);
        match (left_nodes.get(i), right_nodes.get(i)) {
            (Some(l), Some(r)) => diff_node(l, r, &child_path, ctx.depth + 1, ctx.opts, ctx.out),
            (Some(l), None) => ctx.out.push(DiffEntry::OnlyLeft {
                path: child_path,
                node: (*l).clone(),
            }),
            (None, Some(r)) => ctx.out.push(DiffEntry::OnlyRight {
                path: child_path,
                node: (*r).clone(),
            }),
            (None, None) => {}
        }
    }
}

fn match_by_key(
    tag: &str,
    key_field: &str,
    left_nodes: Vec<&XmlNode>,
    right_nodes: Vec<&XmlNode>,
    ctx: &mut MatchContext<'_, '_>,
) {
    let right_keys: Vec<Option<String>> = right_nodes
        .iter()
        .map(|n| n.get_text(&[key_field]).map(ToString::to_string))
        .collect();

    let mut used_right = HashSet::new();

    for (left_idx, left_node) in left_nodes.iter().enumerate() {
        let left_key = left_node.get_text(&[key_field]).map(ToString::to_string);
        let child_path = if let Some(key) = &left_key {
            format!("{}.{tag}[{key}]", ctx.parent_path)
        } else {
            format!("{}.{tag}[{}]", ctx.parent_path, left_idx + 1)
        };

        let matched_right = if let Some(left_key_val) = &left_key {
            right_keys.iter().enumerate().find_map(|(idx, right_key)| {
                if used_right.contains(&idx) {
                    return None;
                }
                if right_key.as_ref() == Some(left_key_val) {
                    Some(idx)
                } else {
                    None
                }
            })
        } else {
            None
        };

        if let Some(right_idx) = matched_right {
            used_right.insert(right_idx);
            diff_node(
                left_node,
                right_nodes[right_idx],
                &child_path,
                ctx.depth + 1,
                ctx.opts,
                ctx.out,
            );
            continue;
        }

        let positional = if left_idx < right_nodes.len() && !used_right.contains(&left_idx) {
            Some(left_idx)
        } else {
            None
        };

        if let Some(right_idx) = positional {
            used_right.insert(right_idx);
            diff_node(
                left_node,
                right_nodes[right_idx],
                &child_path,
                ctx.depth + 1,
                ctx.opts,
                ctx.out,
            );
        } else {
            ctx.out.push(DiffEntry::OnlyLeft {
                path: child_path,
                node: (*left_node).clone(),
            });
        }
    }

    for (right_idx, right_node) in right_nodes.iter().enumerate() {
        if used_right.contains(&right_idx) {
            continue;
        }
        let right_key = right_node.get_text(&[key_field]).map(ToString::to_string);
        let child_path = if let Some(key) = right_key {
            format!("{}.{tag}[{key}]", ctx.parent_path)
        } else {
            format!("{}.{tag}[{}]", ctx.parent_path, right_idx + 1)
        };
        ctx.out.push(DiffEntry::OnlyRight {
            path: child_path,
            node: (*right_node).clone(),
        });
    }
}

fn diff_children(
    left: &XmlNode,
    right: &XmlNode,
    path: &str,
    depth: i32,
    opts: &DiffOptions,
    out: &mut Vec<DiffEntry>,
) {
    let mut tags = Vec::new();
    for child in &left.children {
        if !tags.iter().any(|t| t == &child.tag) {
            tags.push(child.tag.clone());
        }
    }
    for child in &right.children {
        if !tags.iter().any(|t| t == &child.tag) {
            tags.push(child.tag.clone());
        }
    }

    for tag in tags {
        let left_nodes: Vec<&XmlNode> = left.children.iter().filter(|n| n.tag == tag).collect();
        let right_nodes: Vec<&XmlNode> = right.children.iter().filter(|n| n.tag == tag).collect();
        let mut ctx = MatchContext {
            parent_path: path,
            depth,
            opts,
            out,
        };

        if let Some(key_field) = opts.key_fields.get(&tag) {
            match_by_key(&tag, key_field, left_nodes, right_nodes, &mut ctx);
        } else {
            match_by_index(&tag, left_nodes, right_nodes, &mut ctx);
        }
    }
}

fn should_ignore(path: &str, opts: &DiffOptions) -> bool {
    opts.ignore_paths.iter().any(|ignore| {
        path == ignore
            || path.ends_with(&format!(".{ignore}"))
            || path.contains(&format!(".{ignore}["))
            || path == format!("{ignore}[1]")
    })
}

fn normalize_text(input: &Option<String>) -> Option<&str> {
    input.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn local_signature(node: &XmlNode) -> String {
    format!(
        "attributes={:?}, text={:?}",
        node.attributes,
        normalize_text(&node.text)
    )
}
