//! XML path utilities for section inventory and fuzzy matching.
//!
//! This module provides utilities for:
//! - Collecting and normalizing section names
//! - Finding paths by tag name in XML trees
//! - Fuzzy matching for rename detection
//! - Alias path discovery
//!
//! ## Normalization
//!
//! Section names are normalized by removing non-alphanumeric characters and
//! converting to lowercase. Plural forms are singularized for fuzzy matching.
//!
//! ## Path Format
//!
//! Paths use dot notation: `root.parent.child`

use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

/// Collect all unique top-level section names from config root.
///
/// Excludes the `version` element. Useful for section inventory analysis.
///
/// # Arguments
///
/// * `root` - Configuration root
///
/// # Returns
///
/// Sorted vector of unique section names
pub(crate) fn collect_top_sections(root: &XmlNode) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for child in &root.children {
        if child.tag != "version" {
            seen.insert(child.tag.clone());
        }
    }
    seen.into_iter().collect()
}

/// Normalize a section name by removing non-alphanumeric chars and lowercasing.
///
/// Used for case-insensitive comparisons between platforms.
///
/// # Example
///
/// ```ignore
/// assert_eq!(normalize("OpenVPN-Config"), "openvpnconfig");
/// ```
pub(crate) fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Normalize a tag name and strip trailing 's' for singular form.
///
/// Helps match plural/singular variants (e.g., "aliases" vs "alias").
///
/// # Arguments
///
/// * `name` - Tag name to normalize
///
/// # Returns
///
/// Normalized singular form
fn normalize_tag(name: &str) -> String {
    let mut s = normalize(name);
    if s.ends_with('s') && s.len() > 1 {
        s.pop();
    }
    s
}

/// Find all paths containing alias definitions in the config tree.
///
/// Searches for `aliases` and `Alias` tags at any depth. Useful for
/// discovering where alias configuration lives (different between platforms).
///
/// # Arguments
///
/// * `root` - Configuration root to search
///
/// # Returns
///
/// Sorted list of paths to alias sections (e.g., "pfsense.aliases", "opnsense.OPNsense.Firewall.Alias")
pub(crate) fn find_alias_paths(root: &XmlNode) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(root, root.tag.clone())];
    while let Some((node, path)) = stack.pop() {
        if node.tag == "aliases" || node.tag == "Alias" {
            out.push(path.clone());
        }
        for child in &node.children {
            stack.push((child, format!("{path}.{}", child.tag)));
        }
    }
    out.sort();
    out
}

/// Find all paths where a normalized tag name appears.
///
/// Performs fuzzy matching using normalized singular forms. Useful for
/// detecting sections that may have moved or been renamed.
///
/// # Arguments
///
/// * `root` - Configuration root to search
/// * `target` - Target tag name to find (will be normalized)
///
/// # Returns
///
/// Sorted list of paths where tag appears
pub(crate) fn find_paths_by_canonical_tag(root: &XmlNode, target: &str) -> Vec<String> {
    let mut out = Vec::new();
    let target_norm = normalize_tag(target);
    let mut stack = vec![(root, root.tag.clone())];
    while let Some((node, path)) = stack.pop() {
        if normalize_tag(&node.tag) == target_norm {
            out.push(path.clone());
        }
        for child in &node.children {
            stack.push((child, format!("{path}.{}", child.tag)));
        }
    }
    out.sort();
    out
}

/// Check if two section names are fuzzy rename candidates.
///
/// Returns true if:
/// - Normalized forms match exactly
/// - One name contains the other
/// - They share a token of 4+ characters
///
/// Used to suggest that a section may have been renamed between platforms.
///
/// # Example
///
/// ```ignore
/// assert!(is_fuzzy_rename_candidate("openvpn", "OpenVPN"));
/// assert!(is_fuzzy_rename_candidate("dhcpd", "dhcp4"));
/// ```
///
/// # Arguments
///
/// * `left` - Left section name
/// * `right` - Right section name
///
/// # Returns
///
/// True if names appear related by fuzzy matching rules
pub(crate) fn is_fuzzy_rename_candidate(left: &str, right: &str) -> bool {
    let l = normalize_tag(left);
    let r = normalize_tag(right);
    // Exact or substring match
    if l == r || l.contains(&r) || r.contains(&l) {
        return true;
    }
    // Token overlap (4+ chars to avoid false positives)
    let l_tokens = split_tokens(&l);
    let r_tokens = split_tokens(&r);
    l_tokens
        .iter()
        .any(|t| t.len() >= 4 && r_tokens.contains(t))
}

/// Split a normalized string into alphabetic tokens.
///
/// Used for fuzzy matching by token overlap.
///
/// # Arguments
///
/// * `s` - String to tokenize
///
/// # Returns
///
/// Vector of alphabetic tokens
fn split_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphabetic() {
            current.push(ch);
        } else if !current.is_empty() {
            out.push(current.clone());
            current.clear();
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
