use thiserror::Error;
use xml_diff_core::{DiffEntry, XmlNode};

use crate::transform::{
    aliases, certs, dhcp, ipsec, openvpn, ppps, section_sync, staticroutes, system_identity,
    system_users, tailscale, users, wireguard,
};

mod openvpn_transfer;
mod pathing;

/// Merge destination side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeTarget {
    /// Build output from left and insert missing right nodes.
    Left,
    /// Build output from right and insert missing left nodes.
    Right,
}

/// Merge-time transfer behavior for dependency-backed sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeOptions {
    pub transfer_users: bool,
    pub transfer_certs: bool,
    pub transfer_cas: bool,
}

impl Default for MergeOptions {
    fn default() -> Self {
        Self {
            transfer_users: true,
            transfer_certs: true,
            transfer_cas: true,
        }
    }
}

/// Errors produced while applying safe merge actions.
#[derive(Debug, Error)]
pub enum MergeError {
    /// Path could not be interpreted for insertion.
    #[error("unsupported diff path for merge: {0}")]
    UnsupportedPath(String),
    /// Parent path did not exist in target tree.
    #[error("parent path not found in target tree: {0}")]
    ParentNotFound(String),
}

/// Apply safe insert-only actions and return merged output tree.
pub fn apply_safe_merge(
    left: &XmlNode,
    right: &XmlNode,
    entries: &[DiffEntry],
    target: MergeTarget,
    options: MergeOptions,
) -> Result<XmlNode, MergeError> {
    let mut out = match target {
        MergeTarget::Left => left.clone(),
        MergeTarget::Right => right.clone(),
    };

    for entry in entries {
        match (target, entry) {
            (MergeTarget::Right, DiffEntry::OnlyLeft { path, node })
            | (MergeTarget::Left, DiffEntry::OnlyRight { path, node }) => {
                let parent_path = pathing::split_parent_path(path)
                    .ok_or_else(|| MergeError::UnsupportedPath(path.clone()))?;
                let parent = if parent_path == left.tag || parent_path == right.tag {
                    &mut out
                } else {
                    let normalized_parent =
                        pathing::normalize_root_path(&parent_path, &out.tag, &left.tag, &right.tag);
                    pathing::find_node_mut_by_path(&mut out, &normalized_parent)
                        .ok_or_else(|| MergeError::ParentNotFound(parent_path.clone()))?
                };
                parent.children.push(node.clone());
            }
            _ => {}
        }
    }

    openvpn_transfer::apply_openvpn_dependency_transfer(&mut out, left, right, target, options);
    let (source, destination_baseline) = match target {
        MergeTarget::Right => (left, right),
        MergeTarget::Left => (right, left),
    };
    section_sync::sync_shared_top_level_sections(&mut out, source);
    match out.tag.as_str() {
        "opnsense" => {
            system_identity::to_opnsense(&mut out, source, destination_baseline);
            users::to_opnsense(&mut out, source, destination_baseline);
            system_users::to_opnsense(&mut out, source, destination_baseline);
            aliases::to_opnsense(&mut out, source, destination_baseline);
            tailscale::to_opnsense(&mut out, source, destination_baseline);
            openvpn::to_opnsense(&mut out, source, destination_baseline);
            ppps::to_opnsense(&mut out, source, destination_baseline);
            wireguard::to_opnsense(&mut out, source, destination_baseline);
            ipsec::to_opnsense(&mut out, source, destination_baseline);
            staticroutes::to_opnsense(&mut out, source, destination_baseline);
            dhcp::relay::to_opnsense(&mut out, source, destination_baseline);
            certs::to_opnsense(&mut out, source, destination_baseline);
        }
        "pfsense" => {
            system_identity::to_pfsense(&mut out, source, destination_baseline);
            users::to_pfsense(&mut out, source, destination_baseline);
            system_users::to_pfsense(&mut out, source, destination_baseline);
            aliases::to_pfsense(&mut out, source, destination_baseline);
            tailscale::to_pfsense(&mut out, source, destination_baseline);
            openvpn::to_pfsense(&mut out, source, destination_baseline);
            ppps::to_pfsense(&mut out, source, destination_baseline);
            wireguard::to_pfsense(&mut out, source, destination_baseline);
            ipsec::to_pfsense(&mut out, source, destination_baseline);
            staticroutes::to_pfsense(&mut out, source, destination_baseline);
            dhcp::relay::to_pfsense(&mut out, source, destination_baseline);
            certs::to_pfsense(&mut out, source, destination_baseline);
        }
        _ => {}
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{apply_safe_merge, MergeOptions, MergeTarget};
    use xml_diff_core::{diff, parse, DiffEntry};

    #[test]
    fn merges_only_left_nodes_into_right_target() {
        let left =
            parse(br#"<root><items><item><id>1</id></item><item><id>2</id></item></items></root>"#)
                .expect("left parse");
        let right =
            parse(br#"<root><items><item><id>1</id></item></items></root>"#).expect("right parse");
        let entries = diff(&left, &right);
        assert!(entries
            .iter()
            .any(|e| matches!(e, DiffEntry::OnlyLeft { .. })));

        let merged = apply_safe_merge(
            &left,
            &right,
            &entries,
            MergeTarget::Right,
            MergeOptions::default(),
        )
        .expect("merge");
        let items = merged.get_child("items").expect("items exists");
        assert_eq!(items.get_children("item").len(), 2);
    }

    #[test]
    fn transfers_openvpn_cert_dependency_by_default() {
        let left = parse(
            br#"<pfsense>
                <system/>
                <openvpn><openvpn-server><certref>cert-pf</certref></openvpn-server></openvpn>
                <cert><refid>cert-pf</refid></cert>
            </pfsense>"#,
        )
        .expect("left parse");
        let right = parse(
            br#"<opnsense>
                <system/>
                <openvpn><openvpn-server><certref>other-cert</certref></openvpn-server></openvpn>
                <cert><refid>other-cert</refid></cert>
            </opnsense>"#,
        )
        .expect("right parse");

        let entries = diff(&left, &right);
        let merged = apply_safe_merge(
            &left,
            &right,
            &entries,
            MergeTarget::Right,
            MergeOptions::default(),
        )
        .expect("merge");

        let cert_ids: Vec<&str> = merged
            .children
            .iter()
            .filter(|n| n.tag == "cert")
            .filter_map(|n| n.get_text(&["refid"]))
            .collect();
        assert!(cert_ids.contains(&"cert-pf"));
    }

    #[test]
    fn can_disable_openvpn_cert_dependency_transfer() {
        let left = parse(
            br#"<pfsense>
                <system/>
                <openvpn><openvpn-server><certref>cert-pf</certref></openvpn-server></openvpn>
                <cert><refid>cert-pf</refid></cert>
            </pfsense>"#,
        )
        .expect("left parse");
        let right = parse(
            br#"<opnsense>
                <system/>
                <openvpn><openvpn-server><certref>other-cert</certref></openvpn-server></openvpn>
                <cert><refid>other-cert</refid></cert>
            </opnsense>"#,
        )
        .expect("right parse");

        let entries = diff(&left, &right);
        let merged = apply_safe_merge(
            &left,
            &right,
            &entries,
            MergeTarget::Right,
            MergeOptions {
                transfer_certs: false,
                ..MergeOptions::default()
            },
        )
        .expect("merge");

        let cert_ids: Vec<&str> = merged
            .children
            .iter()
            .filter(|n| n.tag == "cert")
            .filter_map(|n| n.get_text(&["refid"]))
            .collect();
        assert!(!cert_ids.contains(&"cert-pf"));
    }

    #[test]
    fn does_not_duplicate_cert_when_already_inserted_by_merge() {
        let left = parse(
            br#"<pfsense>
                <system/>
                <openvpn><openvpn-server><certref>cert-pf</certref></openvpn-server></openvpn>
                <cert><refid>cert-pf</refid></cert>
            </pfsense>"#,
        )
        .expect("left parse");
        let right = parse(
            br#"<opnsense>
                <system/>
                <openvpn><openvpn-server><certref>other-cert</certref></openvpn-server></openvpn>
                <cert><refid>other-cert</refid></cert>
            </opnsense>"#,
        )
        .expect("right parse");

        let entries = diff(&left, &right);
        let merged = apply_safe_merge(
            &left,
            &right,
            &entries,
            MergeTarget::Right,
            MergeOptions::default(),
        )
        .expect("merge");

        let cert_pf_count = merged
            .children
            .iter()
            .filter(|n| n.tag == "cert" && n.get_text(&["refid"]) == Some("cert-pf"))
            .count();
        assert_eq!(cert_pf_count, 1);
    }

    #[test]
    fn transfers_nested_opnsense_ipsec_sections_when_missing() {
        let left = parse(
            br#"<opnsense><OPNsense><IPsec><general/></IPsec><Swanctl><Connections/></Swanctl></OPNsense></opnsense>"#,
        )
        .expect("left parse");
        let right = parse(br#"<pfsense><system/></pfsense>"#).expect("right parse");

        let entries = diff(&left, &right);
        let merged = apply_safe_merge(
            &left,
            &right,
            &entries,
            MergeTarget::Right,
            MergeOptions::default(),
        )
        .expect("merge");

        let nested_ipsec = merged
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("IPsec"));
        let nested_swanctl = merged
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Swanctl"));
        assert!(nested_ipsec.is_some());
        assert!(nested_swanctl.is_some());
    }

    #[test]
    fn transfers_pfsense_aliases_to_opnsense_nested_aliases() {
        let left = parse(
            br#"<pfsense><aliases><alias><name>site_hosts</name></alias></aliases></pfsense>"#,
        )
        .expect("left parse");
        let right = parse(br#"<opnsense><system/></opnsense>"#).expect("right parse");

        let entries = diff(&left, &right);
        let merged = apply_safe_merge(
            &left,
            &right,
            &entries,
            MergeTarget::Right,
            MergeOptions::default(),
        )
        .expect("merge");

        let nested = merged
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("Firewall"))
            .and_then(|fw| fw.get_child("Alias"))
            .and_then(|a| a.get_child("aliases"));
        assert!(nested.is_some());
        assert_eq!(nested.expect("aliases").get_children("alias").len(), 1);
    }
}
