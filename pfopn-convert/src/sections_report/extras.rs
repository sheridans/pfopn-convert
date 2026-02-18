//! Heuristic "extras" detection for section analysis.
//!
//! This module detects patterns that suggest sections may have moved, been
//! renamed, or have dependency gaps between configs. These "extras" help users
//! understand structural changes beyond simple added/removed sections.
//!
//! ## Detection Categories
//!
//! - **Nested presence** — Section name appears nested in other tree
//! - **Rename candidates** — Section names that look related (fuzzy matching)
//! - **Mapping presence** — Known platform mappings detected
//! - **Backend transitions** — DHCP backend changes (ISC ↔ Kea)
//! - **VPN dependency gaps** — Missing CAs, certs, users for OpenVPN/IPsec
//! - **Plugin gaps** — Plugins present on one side but not the other
//!
//! ## Use Case
//!
//! When a section appears in "left_only" or "right_only", extras detection
//! searches for evidence that it may have moved or been renamed rather than
//! truly deleted/added.

use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

use crate::backend_detect::{backend_transition, detect_dhcp_backend, BackendDetection};
use crate::ipsec_dependencies::{compare_ipsec_dependencies, IpsecDependencyGap};
use crate::known_mappings::KnownSectionMapping;
use crate::openvpn_dependencies::{
    compare_openvpn_dependencies, OpenVpnDependencyGap, OpenVpnDependencyReport,
};
use crate::plugin_detect::{detect_plugins, PluginInventory};
use crate::wireguard_dependencies::compare_wireguard_dependencies;

use super::wireguard::build_wireguard_extras;
use super::{ExtraFinding, ExtraGroup};
use crate::sections_report::paths::{find_paths_by_canonical_tag, is_fuzzy_rename_candidate};

/// Build all extra findings from multiple detection strategies.
///
/// Combines findings from:
/// - Base extras (nested, renamed, mapped sections)
/// - DHCP backend transitions
/// - OpenVPN dependency gaps
/// - IPsec dependency gaps
/// - WireGuard configuration gaps
/// - Plugin compatibility gaps
///
/// # Arguments
///
/// * `left` - Left config root
/// * `right` - Right config root
/// * `left_only` - Sections only in left
/// * `right_only` - Sections only in right
/// * `left_sections` - All left sections
/// * `mappings` - Known section mappings
///
/// # Returns
///
/// Vector of all extra findings
pub(crate) fn build_all_extras(
    left: &XmlNode,
    right: &XmlNode,
    left_only: &[String],
    right_only: &[String],
    left_sections: &[String],
    mappings: &[KnownSectionMapping],
) -> Vec<ExtraFinding> {
    let mut extras = build_base_extras(left, right, left_only, right_only, left_sections, mappings);
    extras.extend(build_backend_extras(
        &detect_dhcp_backend(left),
        &detect_dhcp_backend(right),
    ));
    extras.extend(build_vpn_extras(&compare_openvpn_dependencies(left, right)));
    extras.extend(build_ipsec_extras(&compare_ipsec_dependencies(left, right)));
    extras.extend(build_wireguard_extras(&compare_wireguard_dependencies(
        left, right,
    )));
    extras.extend(build_plugin_extras(
        &detect_plugins(left),
        &detect_plugins(right),
    ));
    extras
}

/// Group extra findings by section name.
///
/// Collects all findings for the same section into a single group for
/// easier reporting and analysis.
///
/// # Arguments
///
/// * `extras` - Flat list of findings to group
///
/// # Returns
///
/// Vector of groups, each containing all findings for one section
pub(crate) fn group_extras(extras: &[ExtraFinding]) -> Vec<ExtraGroup> {
    let mut map: BTreeMap<String, Vec<ExtraFinding>> = BTreeMap::new();
    for finding in extras {
        map.entry(finding.section.clone())
            .or_default()
            .push(finding.clone());
    }
    map.into_iter()
        .map(|(section, findings)| ExtraGroup { section, findings })
        .collect()
}

/// Build base extras from structural analysis.
///
/// Detects:
/// - **Nested presence** — Section name appears nested in opposite tree
/// - **Rename candidates** — Fuzzy name matching between left/right only sections
/// - **Mapping presence** — Known platform mappings detected in nested paths
///
/// # Arguments
///
/// * `left` - Left config root
/// * `right` - Right config root
/// * `left_only` - Sections only in left
/// * `right_only` - Sections only in right
/// * `left_sections` - All left sections
/// * `mappings` - Known section mappings between platforms
///
/// # Returns
///
/// Vector of structural findings
fn build_base_extras(
    left: &XmlNode,
    right: &XmlNode,
    left_only: &[String],
    right_only: &[String],
    left_sections: &[String],
    mappings: &[KnownSectionMapping],
) -> Vec<ExtraFinding> {
    let mut out = Vec::new();
    for section in left_only {
        let paths = find_paths_by_canonical_tag(right, section);
        if !paths.is_empty() {
            out.push(ExtraFinding {
                kind: "nested_presence".to_string(),
                section: section.clone(),
                side: "left_only".to_string(),
                paths: paths.into_iter().take(8).collect(),
                reason: "section name appears nested in right tree".to_string(),
            });
        }
    }
    for section in right_only {
        let paths = find_paths_by_canonical_tag(left, section);
        if !paths.is_empty() {
            out.push(ExtraFinding {
                kind: "nested_presence".to_string(),
                section: section.clone(),
                side: "right_only".to_string(),
                paths: paths.into_iter().take(8).collect(),
                reason: "section name appears nested in left tree".to_string(),
            });
        }
    }
    for l in left_only {
        for r in right_only {
            if is_fuzzy_rename_candidate(l, r) {
                out.push(ExtraFinding {
                    kind: "rename_candidate".to_string(),
                    section: format!("{l} -> {r}"),
                    side: "cross".to_string(),
                    paths: Vec::new(),
                    reason: "names look related by normalization/token overlap".to_string(),
                });
            }
        }
    }
    for mapping in mappings {
        if !left_sections.iter().any(|s| s == &mapping.left) {
            continue;
        }
        for candidate in &mapping.right {
            let paths = find_paths_by_canonical_tag(right, candidate);
            if !paths.is_empty() {
                out.push(ExtraFinding {
                    kind: "mapping_presence".to_string(),
                    section: format!("{} -> {}", mapping.left, candidate),
                    side: "cross".to_string(),
                    paths: paths.into_iter().take(8).collect(),
                    reason: format!("known mapping candidate present: {}", mapping.note),
                });
            }
        }
    }
    out.sort_by(|a, b| a.section.cmp(&b.section).then_with(|| a.kind.cmp(&b.kind)));
    out
}

/// Build DHCP backend transition findings.
///
/// Detects backend changes between configs:
/// - **isc→kea** — Legacy ISC DHCP to Kea migration
/// - **kea→isc** — Kea to legacy ISC (downgrade)
/// - **mixed→kea/isc** — Mixed backend state
///
/// Provides migration hints for each transition type.
///
/// # Arguments
///
/// * `left` - Left backend detection
/// * `right` - Right backend detection
///
/// # Returns
///
/// Vector of backend transition findings with migration hints
fn build_backend_extras(left: &BackendDetection, right: &BackendDetection) -> Vec<ExtraFinding> {
    let transition = backend_transition(left, right);
    let mut out = vec![ExtraFinding {
        kind: "backend_transition".to_string(),
        section: "dhcp".to_string(),
        side: "cross".to_string(),
        paths: Vec::new(),
        reason: format!(
            "detected dhcp backend transition {transition} (left={}, right={})",
            left.reason, right.reason
        ),
    }];
    match transition.as_str() {
        "isc->kea" => out.push(ExtraFinding {
            kind: "dhcp_migration_hint".to_string(),
            section: "dhcp".to_string(),
            side: "cross".to_string(),
            paths: vec![
                "left: dhcpd/dhcpdv6/dhcpd6".to_string(),
                "right: OPNsense.Kea.dhcp4/dhcp6".to_string(),
            ],
            reason: "legacy ISC to Kea migration: verify ranges/reservations/options parity"
                .to_string(),
        }),
        "kea->isc" => out.push(ExtraFinding {
            kind: "dhcp_migration_hint".to_string(),
            section: "dhcp".to_string(),
            side: "cross".to_string(),
            paths: vec![
                "left: Kea subtree".to_string(),
                "right: dhcpd/dhcpdv6/dhcpd6".to_string(),
            ],
            reason:
                "Kea to legacy ISC migration: verify static mappings and DHCP options are retained"
                    .to_string(),
        }),
        "mixed->kea" | "isc->mixed" | "mixed->isc" | "kea->mixed" => out.push(ExtraFinding {
            kind: "dhcp_migration_hint".to_string(),
            section: "dhcp".to_string(),
            side: "cross".to_string(),
            paths: vec!["review both legacy and Kea sections".to_string()],
            reason:
                "mixed backend state detected; prefer explicit target backend before conversion"
                    .to_string(),
        }),
        _ => {}
    }
    out
}

/// Build OpenVPN dependency gap findings.
///
/// Detects:
/// - **Disabled configs** — Disabled OpenVPN instances still carry dependencies
/// - **Missing CAs** — Certificate authorities referenced but not present
/// - **Missing certs** — Certificates referenced but not present
/// - **Missing users** — System users referenced but not present
///
/// # Arguments
///
/// * `report` - OpenVPN dependency comparison report
///
/// # Returns
///
/// Vector of VPN dependency findings
fn build_vpn_extras(report: &OpenVpnDependencyReport) -> Vec<ExtraFinding> {
    let mut out = Vec::new();
    if report.left.disabled_instances > 0 {
        out.push(ExtraFinding {
            kind: "vpn_disabled_config_present".to_string(),
            section: "openvpn".to_string(),
            side: "left".to_string(),
            paths: vec![format!(
                "disabled_instances={}",
                report.left.disabled_instances
            )],
            reason: "disabled OpenVPN configs still carry users/certs/CAs and should be migrated"
                .to_string(),
        });
    }
    if report.right.disabled_instances > 0 {
        out.push(ExtraFinding {
            kind: "vpn_disabled_config_present".to_string(),
            section: "openvpn".to_string(),
            side: "right".to_string(),
            paths: vec![format!(
                "disabled_instances={}",
                report.right.disabled_instances
            )],
            reason: "disabled OpenVPN configs still carry users/certs/CAs and should be migrated"
                .to_string(),
        });
    }
    push_gap_finding(&mut out, &report.left_to_right);
    push_gap_finding(&mut out, &report.right_to_left);
    out
}

/// Push OpenVPN dependency gap finding if gaps exist.
///
/// Only adds a finding if at least one dependency is missing.
///
/// # Arguments
///
/// * `out` - Output vector to append to
/// * `gap` - Gap detection result
fn push_gap_finding(out: &mut Vec<ExtraFinding>, gap: &OpenVpnDependencyGap) {
    if gap.missing_ca_ids.is_empty()
        && gap.missing_cert_ids.is_empty()
        && gap.missing_usernames.is_empty()
    {
        return;
    }
    let mut paths = Vec::new();
    for ca in &gap.missing_ca_ids {
        paths.push(format!("missing_ca: {ca}"));
    }
    for cert in &gap.missing_cert_ids {
        paths.push(format!("missing_cert: {cert}"));
    }
    for user in &gap.missing_usernames {
        paths.push(format!("missing_user: {user}"));
    }
    out.push(ExtraFinding {
        kind: "vpn_dependency_gap".to_string(),
        section: "openvpn".to_string(),
        side: gap.direction.clone(),
        paths: paths.into_iter().take(12).collect(),
        reason:
            "OpenVPN references do not exist on target side; migrate system users, certs and CAs"
                .to_string(),
    });
}

/// Build plugin compatibility gap findings.
///
/// Detects plugins present on one side but not declared/configured on the other.
/// Helps identify plugins that need manual migration or installation on target.
///
/// # Arguments
///
/// * `left` - Left plugin inventory
/// * `right` - Right plugin inventory
///
/// # Returns
///
/// Vector of plugin support gap findings
fn build_plugin_extras(left: &PluginInventory, right: &PluginInventory) -> Vec<ExtraFinding> {
    let mut out = Vec::new();
    for left_plugin in &left.plugins {
        let Some(right_plugin) = right
            .plugins
            .iter()
            .find(|p| p.plugin == left_plugin.plugin)
        else {
            continue;
        };
        let left_present = left_plugin.declared || left_plugin.configured;
        let right_present = right_plugin.declared || right_plugin.configured;
        if left_present && !right_present {
            out.push(ExtraFinding {
                kind: "plugin_support_gap".to_string(),
                section: left_plugin.plugin.clone(),
                side: "left_to_right".to_string(),
                paths: left_plugin.evidence.iter().take(6).cloned().collect(),
                reason: "plugin is present on left but not declared/configured on right"
                    .to_string(),
            });
        }
        if right_present && !left_present {
            out.push(ExtraFinding {
                kind: "plugin_support_gap".to_string(),
                section: right_plugin.plugin.clone(),
                side: "right_to_left".to_string(),
                paths: right_plugin.evidence.iter().take(6).cloned().collect(),
                reason: "plugin is present on right but not declared/configured on left"
                    .to_string(),
            });
        }
    }
    out
}

/// Build IPsec dependency gap findings.
///
/// Detects missing CAs, certificates, and interfaces referenced by IPsec configs.
///
/// # Arguments
///
/// * `report` - IPsec dependency comparison report
///
/// # Returns
///
/// Vector of IPsec dependency findings
fn build_ipsec_extras(
    report: &crate::ipsec_dependencies::IpsecDependencyReport,
) -> Vec<ExtraFinding> {
    let mut out = Vec::new();
    push_ipsec_gap_finding(&mut out, &report.left_to_right);
    push_ipsec_gap_finding(&mut out, &report.right_to_left);
    out
}

/// Push IPsec dependency gap finding if gaps exist.
///
/// Only adds a finding if at least one dependency is missing.
///
/// # Arguments
///
/// * `out` - Output vector to append to
/// * `gap` - Gap detection result
fn push_ipsec_gap_finding(out: &mut Vec<ExtraFinding>, gap: &IpsecDependencyGap) {
    if gap.missing_ca_ids.is_empty()
        && gap.missing_cert_ids.is_empty()
        && gap.missing_interfaces.is_empty()
    {
        return;
    }
    let mut paths = Vec::new();
    for ca in &gap.missing_ca_ids {
        paths.push(format!("missing_ca: {ca}"));
    }
    for cert in &gap.missing_cert_ids {
        paths.push(format!("missing_cert: {cert}"));
    }
    for iface in &gap.missing_interfaces {
        paths.push(format!("missing_interface: {iface}"));
    }
    out.push(ExtraFinding {
        kind: "ipsec_dependency_gap".to_string(),
        section: "ipsec".to_string(),
        side: gap.direction.clone(),
        paths: paths.into_iter().take(12).collect(),
        reason: "IPsec references do not exist on target side; migrate certs/CAs/interfaces"
            .to_string(),
    });
}
