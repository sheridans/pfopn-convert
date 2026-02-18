use serde::Serialize;
use xml_diff_core::XmlNode;

use crate::conversion_summary::{summarize, ConversionSummary};
use crate::scan::{build_scan_report_with_version, ScanReport};
use crate::verify::{build_verify_report_with_version, VerifyReport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrateCheckItem {
    pub id: String,
    pub pass: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrateCheckReport {
    pub platform: String,
    pub target_platform: String,
    pub pass: bool,
    pub errors: usize,
    pub warnings: usize,
    pub summary: ConversionSummary,
    pub items: Vec<MigrateCheckItem>,
    pub verify: VerifyReport,
    pub scan: ScanReport,
}

pub fn build_migrate_check_report(root: &XmlNode, target: &str) -> MigrateCheckReport {
    build_migrate_check_report_with_version(root, target, None, None)
}

pub fn build_migrate_check_report_with_version(
    root: &XmlNode,
    target: &str,
    target_version: Option<&str>,
    profiles_dir: Option<&std::path::Path>,
) -> MigrateCheckReport {
    let verify = if target_version.is_some() {
        build_verify_report_with_version(root, Some(target), target_version, profiles_dir)
    } else {
        build_verify_report_with_version(root, Some(target), None, profiles_dir)
    };
    let scan = build_scan_report_with_version(root, Some(target), None, None);
    let summary = summarize(root);

    let items = vec![
        item(
            "platform_target_match",
            scan.platform == target,
            format!("detected={} target={target}", scan.platform),
        ),
        item(
            "required_sections",
            !has_issue(&verify, "missing_required_section"),
            "system/interfaces/filter baseline present".to_string(),
        ),
        item(
            "interface_integrity",
            !has_any_issue(
                &verify,
                &[
                    "duplicate_interface_assignment",
                    "missing_interface_reference",
                    "missing_gateway_interface",
                    "missing_route_interface",
                ],
            ),
            "interface refs and assignments are valid".to_string(),
        ),
        item(
            "bridge_integrity",
            !has_any_issue(&verify, &["empty_bridge_members", "missing_bridge_member"]),
            "bridge members are valid".to_string(),
        ),
        item(
            "rule_reference_integrity",
            !has_any_issue(
                &verify,
                &[
                    "missing_alias_reference",
                    "missing_gateway_reference",
                    "missing_route_gateway",
                    "missing_schedule_reference",
                ],
            ),
            "rule/route references resolve".to_string(),
        ),
        item(
            "nat_integrity",
            !has_any_issue(
                &verify,
                &[
                    "nat_missing_interface",
                    "nat_missing_associated_rule",
                    "nat_invalid_outbound_mode",
                ],
            ),
            "nat mode/bindings/associations are valid".to_string(),
        ),
        item(
            "dhcp_integrity",
            !has_issue(&verify, "dhcp_backend_inconsistent"),
            "dhcp backend policy and section layout are consistent".to_string(),
        ),
        item(
            "openvpn_integrity",
            !has_issue_prefix(&verify, "openvpn_missing_"),
            "openvpn refs resolve".to_string(),
        ),
        item(
            "ipsec_integrity",
            !has_issue_prefix(&verify, "ipsec_missing_"),
            "ipsec refs resolve".to_string(),
        ),
        item(
            "plugin_compatibility",
            scan.unsupported_plugins.is_empty() && scan.missing_target_compat.is_empty(),
            "no unsupported or target-incompatible plugins".to_string(),
        ),
        item(
            "profile_baseline",
            true,
            format!(
                "advisory profile warnings={}",
                count_issue_prefix(&verify, "profile_")
            ),
        ),
    ];

    let pass = verify.errors == 0 && items.iter().all(|i| i.pass);
    MigrateCheckReport {
        platform: scan.platform.clone(),
        target_platform: target.to_string(),
        pass,
        errors: verify.errors,
        warnings: verify.warnings,
        summary,
        items,
        verify,
        scan,
    }
}

pub fn render_migrate_check_text(report: &MigrateCheckReport, verbose: bool) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "migrate_check pass={} platform={} target={} errors={} warnings={}",
        report.pass, report.platform, report.target_platform, report.errors, report.warnings
    ));
    if verbose {
        let source = report.verify.profiles_source.as_deref().unwrap_or("none");
        out.push(format!("Using profiles: {source}"));
        out.push(format!("Using mappings: {}", report.scan.mappings_source));
    }
    out.push(format!(
        "counts interfaces={} bridges={} aliases={} rules={} routes={} vpns={}",
        report.summary.interfaces,
        report.summary.bridges,
        report.summary.aliases,
        report.summary.rules,
        report.summary.routes,
        report.summary.vpns
    ));
    out.push("items".to_string());
    for item in &report.items {
        let state = if item.pass { "PASS" } else { "FAIL" };
        out.push(format!("- [{state}] {}: {}", item.id, item.detail));
    }
    out.join("\n")
}

fn item(id: &str, pass: bool, detail: String) -> MigrateCheckItem {
    MigrateCheckItem {
        id: id.to_string(),
        pass,
        detail,
    }
}

fn has_issue(report: &VerifyReport, code: &str) -> bool {
    report.issues.iter().any(|i| i.code == code)
}

fn has_issue_prefix(report: &VerifyReport, prefix: &str) -> bool {
    report.issues.iter().any(|i| i.code.starts_with(prefix))
}

fn has_any_issue(report: &VerifyReport, codes: &[&str]) -> bool {
    report
        .issues
        .iter()
        .any(|i| codes.iter().any(|code| i.code == *code))
}

fn count_issue_prefix(report: &VerifyReport, prefix: &str) -> usize {
    report
        .issues
        .iter()
        .filter(|i| i.code.starts_with(prefix))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xml_diff_core::parse;

    const MINIMAL_PFSENSE: &[u8] =
        b"<pfsense><system/><interfaces><lan/></interfaces><filter/></pfsense>";

    #[test]
    fn profile_warnings_counted_when_target_version_set() {
        let root = parse(MINIMAL_PFSENSE).expect("parse");
        let report = build_migrate_check_report_with_version(&root, "pfsense", Some("99"), None);
        let profile_item = report
            .items
            .iter()
            .find(|i| i.id == "profile_baseline")
            .expect("profile_baseline item");
        assert!(
            profile_item.detail.contains("warnings=1"),
            "expected warnings=1, got: {}",
            profile_item.detail
        );
    }
}
