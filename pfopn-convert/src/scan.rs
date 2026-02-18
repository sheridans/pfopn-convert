//! Configuration scanning and migration readiness assessment.
//!
//! Provides tools to analyze a firewall configuration and assess its readiness
//! for migration to another platform. The scan identifies:
//!
//! - Platform and version information
//! - DHCP backend (ISC vs Kea)
//! - Supported vs unsupported config sections
//! - Plugin compatibility and target platform support
//! - Migration blockers and recommendations
//!
//! ## Scan Workflow
//!
//! 1. Detect platform (pfSense/OPNsense) and version
//! 2. Identify DHCP backend
//! 3. Catalog top-level config sections
//! 4. Check plugin compatibility with target platform
//! 5. Generate migration recommendations
//!
//! The scan provides a go/no-go assessment before attempting conversion.

use std::collections::BTreeSet;

use serde::Serialize;
use xml_diff_core::XmlNode;

use crate::backend_detect::detect_dhcp_backend;
use crate::detect::{detect_config, detect_version_info, ConfigFlavor, VersionDetection};
use crate::plugin_detect::detect_plugins;
use crate::scan_plugins::{
    detect_known_plugins_present, detect_missing_target_compat, detect_unsupported_plugins,
    load_default_plugin_matrix_with_source,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub platform: String,
    pub version: VersionDetection,
    pub target_version: Option<String>,
    pub dhcp_backend: String,
    pub backend_reason: String,
    pub mappings_source: String,
    pub target_platform: Option<String>,
    pub top_level_sections: Vec<String>,
    pub supported_sections: Vec<String>,
    pub review_sections: Vec<String>,
    pub known_plugins_present: Vec<String>,
    pub unsupported_plugins: Vec<String>,
    pub missing_target_compat: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Build a migration readiness scan report.
///
/// Analyzes a configuration to assess readiness for migration to a target
/// platform. Uses current detected version for compatibility checks.
///
/// # Arguments
///
/// * `root` - Configuration root to scan
/// * `target` - Optional target platform ("pfsense" or "opnsense")
///
/// # Returns
///
/// Complete scan report with platform info, sections, plugins, and recommendations
pub fn build_scan_report(root: &XmlNode, target: Option<&str>) -> ScanReport {
    build_scan_report_with_version(root, target, None, None)
}

/// Build a scan report with explicit target version.
///
/// Like `build_scan_report` but allows specifying the target platform version
/// for more accurate compatibility checks.
///
/// # Arguments
///
/// * `root` - Configuration root to scan
/// * `target` - Optional target platform ("pfsense" or "opnsense")
/// * `target_version` - Optional explicit target version string
///
/// # Returns
///
/// Complete scan report with version-aware compatibility analysis
pub fn build_scan_report_with_version(
    root: &XmlNode,
    target: Option<&str>,
    target_version: Option<&str>,
    mappings_dir: Option<&std::path::Path>,
) -> ScanReport {
    let platform = match detect_config(root) {
        ConfigFlavor::PfSense => "pfsense",
        ConfigFlavor::OpnSense => "opnsense",
        ConfigFlavor::Unknown => "unknown",
    }
    .to_string();
    let version = detect_version_info(root);
    let backend = detect_dhcp_backend(root);
    let top_level_sections = collect_top_sections(root);

    let supported_set: BTreeSet<String> = supported_sections_for_platform(&platform)
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let mut supported_sections = top_level_sections
        .iter()
        .filter(|s| supported_set.contains(*s))
        .cloned()
        .collect::<Vec<_>>();
    supported_sections.extend(derived_supported_sections(
        root,
        &platform,
        &supported_sections,
    ));
    supported_sections.sort();
    supported_sections.dedup();
    let review_sections = top_level_sections
        .iter()
        .filter(|s| is_review_section(root, s, &supported_set))
        .cloned()
        .collect::<Vec<_>>();

    let plugin_inventory = detect_plugins(root);
    let (plugin_matrix, mappings_source) = load_default_plugin_matrix_with_source(mappings_dir);
    let known_plugins_present =
        detect_known_plugins_present(root, &platform, &plugin_inventory, &plugin_matrix);
    let unsupported_plugins = detect_unsupported_plugins(root, &platform, &plugin_matrix);
    let missing_target_compat =
        detect_missing_target_compat(&known_plugins_present, &platform, target, &plugin_matrix);

    let mut recommendations = Vec::new();
    if !unsupported_plugins.is_empty() {
        recommendations.push(
            "unsupported plugins detected; expect manual migration for those plugin configs"
                .to_string(),
        );
    }
    if !review_sections.is_empty() {
        recommendations.push(
            "some top-level sections are not in the current supported set; review with sections --extras"
                .to_string(),
        );
    }
    if !missing_target_compat.is_empty() {
        recommendations.push(
            "plugins present in source are not marked compatible with selected target".to_string(),
        );
    }
    if recommendations.is_empty() {
        recommendations.push(
            "no immediate blockers detected; run diff/convert for full validation".to_string(),
        );
    }

    ScanReport {
        platform,
        version,
        target_version: target_version.map(ToOwned::to_owned),
        dhcp_backend: backend.mode,
        backend_reason: backend.reason,
        mappings_source,
        target_platform: target.map(ToOwned::to_owned),
        top_level_sections,
        supported_sections,
        review_sections,
        known_plugins_present,
        unsupported_plugins,
        missing_target_compat,
        recommendations,
    }
}

pub fn render_scan_text(report: &ScanReport, verbose: bool) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "scan platform={} version={} version_source={} version_confidence={}",
        report.platform, report.version.value, report.version.source, report.version.confidence
    ));
    out.push(format!(
        "backend mode={} reason={}",
        report.dhcp_backend, report.backend_reason
    ));
    if verbose {
        out.push(format!("Using mappings: {}", report.mappings_source));
    }
    if let Some(to) = &report.target_platform {
        out.push(format!("target_platform={to}"));
    }
    if let Some(target_version) = &report.target_version {
        out.push(format!("target_version={target_version}"));
    }
    out.push("supported_sections".to_string());
    append_list(&mut out, &report.supported_sections);
    out.push("review_sections".to_string());
    append_list(&mut out, &report.review_sections);
    out.push("known_plugins_present".to_string());
    append_list(&mut out, &report.known_plugins_present);
    out.push("unsupported_plugins".to_string());
    append_list(&mut out, &report.unsupported_plugins);
    if report.target_platform.is_some() {
        out.push("missing_target_compat".to_string());
        append_list(&mut out, &report.missing_target_compat);
    }
    out.push("recommendations".to_string());
    append_list(&mut out, &report.recommendations);
    out.join("\n")
}

fn append_list(out: &mut Vec<String>, items: &[String]) {
    if items.is_empty() {
        out.push("- none".to_string());
        return;
    }
    for item in items {
        out.push(format!("- {item}"));
    }
}

fn collect_top_sections(root: &XmlNode) -> Vec<String> {
    let mut sections = root
        .children
        .iter()
        .map(|child| child.tag.clone())
        .collect::<Vec<_>>();
    sections.sort();
    sections.dedup();
    sections
}

fn supported_sections_for_platform(platform: &str) -> Vec<&'static str> {
    match platform {
        "pfsense" => vec![
            "system",
            "interfaces",
            "filter",
            "nat",
            "aliases",
            "openvpn",
            "ipsec",
            "dhcpbackend",
            "dhcpd",
            "dhcpdv6",
            "dhcpd6",
            "dhcrelay",
            "dhcp6relay",
            "cert",
            "ca",
            "installedpackages",
            "tailscale",
            "tailscaleauth",
            "ppps",
            "ovpnserver",
            "vlans",
            "virtualip",
            "wireguard",
            "ifgroups",
            "gateways",
            "staticroutes",
        ],
        "opnsense" => vec![
            "system",
            "interfaces",
            "filter",
            "nat",
            "openvpn",
            "ipsec",
            "dhcpd",
            "dhcpdv6",
            "dhcpd6",
            "dhcrelay",
            "dhcp6relay",
            "cert",
            "ca",
            "OPNsense",
            "dnsmasq",
            "wireguard",
            "tailscale",
            "ifgroups",
            "staticroutes",
            "ppps",
            "ovpnserver",
            "vlans",
            "virtualip",
        ],
        _ => vec![],
    }
}

fn derived_supported_sections(root: &XmlNode, platform: &str, existing: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if platform == "opnsense"
        && !existing.iter().any(|s| s == "gateways")
        && has_nested_opnsense_tag(root, "Gateways")
    {
        out.push("gateways".to_string());
    }
    if !existing.iter().any(|s| s == "bridges") && has_parseable_bridges(root) {
        out.push("bridges".to_string());
    }
    out
}

fn has_nested_opnsense_tag(root: &XmlNode, tag: &str) -> bool {
    root.get_child("OPNsense")
        .and_then(|opn| opn.get_child(tag))
        .is_some()
}

fn is_review_section(root: &XmlNode, section: &str, supported_set: &BTreeSet<String>) -> bool {
    if supported_set.contains(section) {
        return false;
    }
    if section.eq_ignore_ascii_case("gateways")
        && (root.get_child("gateways").is_some() || has_nested_opnsense_tag(root, "Gateways"))
    {
        return false;
    }
    if section.eq_ignore_ascii_case("bridges") && has_parseable_bridges(root) {
        return false;
    }
    true
}

fn has_parseable_bridges(root: &XmlNode) -> bool {
    let Some(bridges) = root.get_child("bridges") else {
        return false;
    };
    for bridged in bridges.children.iter().filter(|c| c.tag == "bridged") {
        let members = bridged
            .get_text(&["members"])
            .map(str::trim)
            .unwrap_or_default();
        if !members.is_empty() {
            return true;
        }
        let bridgeif = bridged
            .get_text(&["bridgeif"])
            .map(str::trim)
            .unwrap_or_default();
        if !bridgeif.is_empty() {
            return true;
        }
    }
    false
}
