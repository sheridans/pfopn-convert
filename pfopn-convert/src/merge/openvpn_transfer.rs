//! OpenVPN dependency transfer during merge operations.
//!
//! OpenVPN configurations reference external resources that must exist in the
//! target config for OpenVPN to function properly:
//!
//! - **Certificate Authorities (CAs)** — For certificate validation
//! - **Certificates (certs)** — For server/client authentication
//! - **System users** — For authentication and access control
//!
//! When merging configs, these dependencies must be transferred from source to
//! target to prevent broken references. This module implements intelligent
//! dependency transfer that:
//!
//! 1. Analyzes OpenVPN config to find referenced CAs, certs, and users
//! 2. Determines which dependencies are missing in the target
//! 3. Transfers only the missing dependencies to avoid duplicates
//! 4. Respects user-specified transfer options (can disable via CLI)
//!
//! ## Deduplication
//!
//! All transfer functions check for existing entries before inserting. This
//! prevents duplicate CAs, certs, or users even if they're already present in
//! the target or were inserted by the base merge operation.

use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

use crate::merge::{MergeOptions, MergeTarget};
use crate::openvpn_dependencies::compare_openvpn_dependencies;

/// Apply OpenVPN dependency transfer from source to target.
///
/// Analyzes OpenVPN configuration to identify missing dependencies (CAs, certs,
/// users) and transfers them from source to target based on merge direction and
/// user preferences.
///
/// ## Transfer Strategy
///
/// - **MergeTarget::Right** — Transfers left → right (source is left)
/// - **MergeTarget::Left** — Transfers right → left (source is right)
///
/// Only transfers dependencies that are:
/// 1. Referenced by OpenVPN config
/// 2. Missing in the target
/// 3. Enabled via options (transfer_cas, transfer_certs, transfer_users)
///
/// ## Deduplication
///
/// All transfers check existing entries to avoid duplicates, even if the same
/// dependency was already inserted by the base merge.
///
/// # Arguments
///
/// * `out` - Output config being built (will be modified)
/// * `left` - Left config in the merge
/// * `right` - Right config in the merge
/// * `target` - Merge direction (which side is the target)
/// * `options` - User preferences for which dependencies to transfer
pub(super) fn apply_openvpn_dependency_transfer(
    out: &mut XmlNode,
    left: &XmlNode,
    right: &XmlNode,
    target: MergeTarget,
    options: MergeOptions,
) {
    // Determine source/target based on merge direction
    let (source, target_tree, to_target) = match target {
        MergeTarget::Right => {
            let report = compare_openvpn_dependencies(left, right);
            (left, right, report.left_to_right)
        }
        MergeTarget::Left => {
            let report = compare_openvpn_dependencies(left, right);
            (right, left, report.right_to_left)
        }
    };

    // Transfer missing dependencies based on user preferences
    if options.transfer_cas {
        transfer_section_by_refids(out, source, "ca", &to_target.missing_ca_ids);
    }
    if options.transfer_certs {
        transfer_section_by_refids(out, source, "cert", &to_target.missing_cert_ids);
    }
    if options.transfer_users {
        transfer_users(out, source, target_tree, &to_target.missing_usernames);
    }
}

/// Transfer CA or cert entries by reference IDs.
///
/// Copies `<ca>` or `<cert>` nodes from source to output, matching by `<refid>`.
/// Only transfers entries that:
/// 1. Are in the missing IDs list (referenced but not present in target)
/// 2. Don't already exist in the output (prevents duplicates)
///
/// ## Matching Strategy
///
/// Both CAs and certs use a `<refid>` child element as their unique identifier.
/// This function searches for nodes with matching refids and copies them.
///
/// # Arguments
///
/// * `out` - Output config being built
/// * `source` - Source config to extract dependencies from
/// * `section_tag` - Tag name ("ca" or "cert")
/// * `missing_ids` - List of refids that are missing in the target
fn transfer_section_by_refids(
    out: &mut XmlNode,
    source: &XmlNode,
    section_tag: &str,
    missing_ids: &[String],
) {
    if missing_ids.is_empty() {
        return;
    }

    // Collect existing refids in the output to avoid duplicates
    let mut existing: BTreeSet<String> = out
        .children
        .iter()
        .filter(|n| n.tag == section_tag)
        .filter_map(|n| n.get_text(&["refid"]))
        .map(ToOwned::to_owned)
        .collect();

    // Collect all CA/cert nodes from source
    let source_nodes: Vec<XmlNode> = source
        .children
        .iter()
        .filter(|n| n.tag == section_tag)
        .filter(|n| n.get_text(&["refid"]).is_some())
        .cloned()
        .collect();

    // Transfer each missing dependency
    for missing in missing_ids {
        // Skip if already present (may have been inserted by base merge)
        if existing.contains(missing) {
            continue;
        }

        // Find matching node in source and transfer it
        if let Some(node) = source_nodes
            .iter()
            .find(|n| n.get_text(&["refid"]) == Some(missing.as_str()))
        {
            out.children.push(node.clone());
            existing.insert(missing.clone());
        }
    }
}

/// Transfer system user entries by username.
///
/// Copies `<user>` nodes from `<system>` in source to output, matching by
/// `<name>`. Only transfers users that:
/// 1. Are referenced by OpenVPN config
/// 2. Don't already exist in the target
///
/// Users are stored in `<system><user>` and identified by their `<name>` child.
///
/// # Arguments
///
/// * `out` - Output config being built
/// * `source` - Source config to extract users from
/// * `target_tree` - Original target config (to check what already exists)
/// * `missing_users` - List of usernames that are missing in the target
fn transfer_users(
    out: &mut XmlNode,
    source: &XmlNode,
    target_tree: &XmlNode,
    missing_users: &[String],
) {
    if missing_users.is_empty() {
        return;
    }

    // Collect existing usernames from the original target (not output, which may have been modified)
    let existing: BTreeSet<&str> = target_tree
        .get_child("system")
        .map(|s| {
            s.children
                .iter()
                .filter(|n| n.tag == "user")
                .filter_map(|u| u.get_text(&["name"]))
                .collect()
        })
        .unwrap_or_default();

    // Collect all user nodes from source
    let source_users: Vec<XmlNode> = source
        .get_child("system")
        .map(|s| {
            s.children
                .iter()
                .filter(|n| n.tag == "user")
                .filter(|u| u.get_text(&["name"]).is_some())
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    // Find <system> section in output
    let Some(system_out) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };

    // Transfer each missing user
    for missing in missing_users {
        // Skip if user already exists in target
        if existing.contains(missing.as_str()) {
            continue;
        }

        // Find matching user in source and transfer
        if let Some(user_node) = source_users
            .iter()
            .find(|u| u.get_text(&["name"]) == Some(missing.as_str()))
        {
            system_out.children.push(user_node.clone());
        }
    }
}
