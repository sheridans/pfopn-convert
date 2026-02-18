use serde::Serialize;
use xml_diff_core::XmlNode;

use crate::backend_detect::detect_dhcp_backend;
use crate::detect::{detect_config, detect_version_info, ConfigFlavor};
use crate::ipsec_dependencies::compare_ipsec_dependencies;
use crate::openvpn_dependencies::compare_openvpn_dependencies;
use crate::profile::load_profile_with_source;
use crate::scan::{build_scan_report_with_version, ScanReport};
use crate::verify_bridges::bridge_findings;
use crate::verify_interfaces::{
    interface_reference_findings, FindingSeverity, VerifyFinding as RefFinding,
};
use crate::verify_nat::nat_findings;
use crate::verify_profile::profile_findings;
use crate::verify_rule_dupes::rule_duplicate_findings;
use crate::verify_rule_refs::rule_reference_findings;
use crate::verify_wireguard::wireguard_findings;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VerifySeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyIssue {
    pub severity: VerifySeverity,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    pub platform: String,
    pub version: String,
    pub target_platform: Option<String>,
    pub profiles_source: Option<String>,
    pub errors: usize,
    pub warnings: usize,
    pub issues: Vec<VerifyIssue>,
}

pub fn build_verify_report(root: &XmlNode, target: Option<&str>) -> VerifyReport {
    build_verify_report_with_version(root, target, None, None)
}

pub fn build_verify_report_with_version(
    root: &XmlNode,
    target: Option<&str>,
    target_version: Option<&str>,
    profiles_dir: Option<&std::path::Path>,
) -> VerifyReport {
    let flavor = detect_config(root);
    let platform = match flavor {
        ConfigFlavor::PfSense => "pfsense",
        ConfigFlavor::OpnSense => "opnsense",
        ConfigFlavor::Unknown => "unknown",
    }
    .to_string();
    let detected_version = detect_version_info(root).value;
    let version = target_version.unwrap_or(&detected_version).to_string();
    let scan = build_scan_report_with_version(root, target, None, None);
    let profile_platform = target.unwrap_or(&platform);
    let (profile, profiles_source) =
        load_profile_with_source(profile_platform, &version, profiles_dir)
            .map_or((None, None), |(p, s)| (Some(p), Some(s)));

    let mut issues = Vec::new();
    if flavor == ConfigFlavor::Unknown {
        issues.push(err(
            "unknown_platform",
            "root tag is not recognized as pfsense/opnsense",
        ));
    }
    issues.extend(required_section_issues(root, &platform));
    issues.extend(plugin_issues(&scan));
    issues.extend(interface_issues(root));
    issues.extend(bridge_issues(root));
    issues.extend(nat_issues(root));
    issues.extend(rule_reference_issues(root));
    issues.extend(rule_duplicate_issues(root));
    issues.extend(wireguard_issues(root));
    issues.extend(dhcp_issues(root, &platform));
    if let Some(profile) = profile.as_ref() {
        issues.extend(profile_findings(root, profile).into_iter().map(map_finding));
    }
    issues.extend(openvpn_issues(root));
    issues.extend(ipsec_issues(root));

    let errors = issues
        .iter()
        .filter(|i| i.severity == VerifySeverity::Error)
        .count();
    let warnings = issues
        .iter()
        .filter(|i| i.severity == VerifySeverity::Warning)
        .count();

    VerifyReport {
        platform,
        version,
        target_platform: target.map(ToOwned::to_owned),
        profiles_source,
        errors,
        warnings,
        issues,
    }
}

pub fn render_verify_text(report: &VerifyReport, verbose: bool) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "verify platform={} version={} target={}",
        report.platform,
        report.version,
        report.target_platform.as_deref().unwrap_or("none")
    ));
    if verbose {
        let source = report.profiles_source.as_deref().unwrap_or("none");
        out.push(format!("Using profiles: {source}"));
    }
    out.push(format!(
        "result errors={} warnings={}",
        report.errors, report.warnings
    ));
    if report.issues.is_empty() {
        out.push("issues".to_string());
        out.push("- none".to_string());
        return out.join("\n");
    }
    out.push("issues".to_string());
    for issue in &report.issues {
        let sev = match issue.severity {
            VerifySeverity::Error => "error",
            VerifySeverity::Warning => "warning",
        };
        out.push(format!("- [{sev}] {}: {}", issue.code, issue.message));
    }
    out.join("\n")
}

fn required_section_issues(root: &XmlNode, platform: &str) -> Vec<VerifyIssue> {
    let required: &[&str] = match platform {
        "pfsense" | "opnsense" => &["system", "interfaces"],
        _ => &[],
    };
    let mut out = Vec::new();
    for section in required {
        if root.get_child(section).is_none() {
            out.push(err(
                "missing_required_section",
                &format!("required section '{section}' is missing"),
            ));
        }
    }
    out
}

fn plugin_issues(scan: &ScanReport) -> Vec<VerifyIssue> {
    let mut out = Vec::new();
    for plugin in &scan.unsupported_plugins {
        out.push(warn(
            "unsupported_plugin",
            &format!("unsupported plugin detected: {plugin}"),
        ));
    }
    for plugin in &scan.missing_target_compat {
        out.push(warn(
            "target_plugin_compat",
            &format!("plugin not marked compatible with target: {plugin}"),
        ));
    }
    out
}

fn interface_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    interface_reference_findings(root)
        .into_iter()
        .map(map_finding)
        .collect()
}

fn bridge_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    bridge_findings(root).into_iter().map(map_finding).collect()
}

fn nat_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    nat_findings(root).into_iter().map(map_finding).collect()
}

fn rule_reference_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    rule_reference_findings(root)
        .into_iter()
        .map(map_finding)
        .collect()
}

fn rule_duplicate_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    rule_duplicate_findings(root)
        .into_iter()
        .map(map_finding)
        .collect()
}

fn wireguard_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    wireguard_findings(root)
        .into_iter()
        .map(map_finding)
        .collect()
}

fn dhcp_issues(root: &XmlNode, platform: &str) -> Vec<VerifyIssue> {
    let mut out = Vec::new();
    let has_legacy = root.get_child("dhcpd").is_some()
        || root.get_child("dhcpdv6").is_some()
        || root.get_child("dhcpd6").is_some();
    let has_pfsense_kea = root.get_child("kea").is_some();
    let has_opnsense_kea = root
        .get_child("OPNsense")
        .and_then(|n| n.get_child("Kea"))
        .is_some();

    if platform == "pfsense" {
        let backend = root
            .get_child("dhcpbackend")
            .and_then(|n| n.text.as_deref())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if backend == "isc" && !has_legacy {
            out.push(err(
                "dhcp_backend_inconsistent",
                "pfSense backend is ISC but legacy DHCP sections are missing (dhcpd/dhcpdv6/dhcpd6)",
            ));
        }
        if backend == "isc" && has_pfsense_kea {
            out.push(err(
                "dhcp_backend_inconsistent",
                "pfSense backend is ISC but Kea section is still present",
            ));
        }
        if backend == "kea" && !has_pfsense_kea {
            out.push(warn(
                "dhcp_backend_advisory",
                "pfSense backend is Kea but top-level <kea> section is missing; verify DHCP backend state on target",
            ));
        }
        return out;
    }

    if platform == "opnsense" {
        let backend = detect_dhcp_backend(root).mode;
        if backend == "isc" {
            if !opnsense_has_declared_plugin(root, "os-isc-dhcp") {
                out.push(err(
                    "dhcp_backend_inconsistent",
                    "OPNsense appears to use ISC DHCP but os-isc-dhcp is not declared in system.firmware.plugins",
                ));
            }
            if !has_legacy {
                out.push(err(
                    "dhcp_backend_inconsistent",
                    "OPNsense appears to use ISC DHCP but legacy DHCP sections are missing (dhcpd/dhcpdv6/dhcpd6)",
                ));
            }
        }
        if backend == "kea" && !has_opnsense_kea {
            out.push(err(
                "dhcp_backend_inconsistent",
                "OPNsense appears to use Kea but OPNsense.Kea section is missing",
            ));
        }
    }

    out
}

fn openvpn_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    let report = compare_openvpn_dependencies(root, root);
    let mut out = Vec::new();
    for ca in report.left_to_right.missing_ca_ids {
        out.push(err(
            "openvpn_missing_ca",
            &format!("OpenVPN references missing CA '{ca}'"),
        ));
    }
    for cert in report.left_to_right.missing_cert_ids {
        out.push(err(
            "openvpn_missing_cert",
            &format!("OpenVPN references missing cert '{cert}'"),
        ));
    }
    for user in report.left_to_right.missing_usernames {
        out.push(err(
            "openvpn_missing_user",
            &format!("OpenVPN references missing user '{user}'"),
        ));
    }
    out
}

fn ipsec_issues(root: &XmlNode) -> Vec<VerifyIssue> {
    let report = compare_ipsec_dependencies(root, root);
    let mut out = Vec::new();
    for ca in report.left_to_right.missing_ca_ids {
        out.push(err(
            "ipsec_missing_ca",
            &format!("IPsec references missing CA '{ca}'"),
        ));
    }
    for cert in report.left_to_right.missing_cert_ids {
        out.push(err(
            "ipsec_missing_cert",
            &format!("IPsec references missing cert '{cert}'"),
        ));
    }
    for iface in report.left_to_right.missing_interfaces {
        out.push(err(
            "ipsec_missing_interface",
            &format!("IPsec references missing interface '{iface}'"),
        ));
    }
    out
}

fn err(code: &str, message: &str) -> VerifyIssue {
    VerifyIssue {
        severity: VerifySeverity::Error,
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn warn(code: &str, message: &str) -> VerifyIssue {
    VerifyIssue {
        severity: VerifySeverity::Warning,
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn map_finding(finding: RefFinding) -> VerifyIssue {
    VerifyIssue {
        severity: match finding.severity {
            FindingSeverity::Error => VerifySeverity::Error,
            FindingSeverity::Warning => VerifySeverity::Warning,
        },
        code: finding.code,
        message: finding.message,
    }
}

fn opnsense_has_declared_plugin(root: &XmlNode, plugin: &str) -> bool {
    let plugins = root
        .get_child("system")
        .and_then(|s| s.get_child("firmware"))
        .and_then(|f| f.get_text(&["plugins"]))
        .unwrap_or("");
    plugins
        .split([' ', ',', ';'])
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case(plugin))
}
