//! NAT configuration validation.
//!
//! Validates Network Address Translation (NAT) rules to ensure they're
//! properly configured and reference valid resources.
//!
//! ## Checks Performed
//!
//! 1. **Outbound mode validation** — Ensures outbound NAT mode is recognized
//! 2. **Interface references** — NAT rules reference valid interfaces
//! 3. **Associated rule IDs** — Port forwards reference valid filter rules
//!
//! ## NAT Rule Structure
//!
//! NAT rules can exist in two locations:
//! - `<nat><rule>` — Port forwarding rules
//! - `<nat><outbound><rule>` — Outbound NAT rules
//!
//! ## Associated Rules
//!
//! Port forwards often have associated filter rules that allow the forwarded
//! traffic. The `<associated-rule-id>` links them together.

use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

use crate::verify_interfaces::{collect_defined_interface_names, FindingSeverity, VerifyFinding};

/// Find all NAT configuration problems.
///
/// Validates NAT rules for:
/// - Valid outbound mode setting
/// - Interface references that exist
/// - Associated rule IDs that exist in filter rules
///
/// # Arguments
///
/// * `root` - Configuration root to validate
///
/// # Returns
///
/// Vector of findings (errors and warnings). Empty if no problems found.
pub fn nat_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    let Some(nat) = root.get_child("nat") else {
        return Vec::new();
    };

    // Collect context for validation
    let interfaces = collect_defined_interface_names(root);
    let associated_ids = collect_filter_associated_ids(root);

    // Run all NAT validation checks
    let mut out = Vec::new();
    out.extend(outbound_mode_findings(nat));
    out.extend(nat_interface_findings(nat, &interfaces));
    out.extend(nat_association_findings(nat, &associated_ids));
    out
}

/// Validate outbound NAT mode setting.
///
/// Checks that `<nat><outbound><mode>` contains a recognized value:
/// - automatic — Automatic outbound NAT
/// - hybrid — Hybrid outbound NAT
/// - manual — Manual outbound NAT rules
/// - disable/disabled — Outbound NAT disabled
/// - advanced — Advanced outbound NAT
///
/// # Arguments
///
/// * `nat` - NAT configuration node
///
/// # Returns
///
/// Warning if mode is unrecognized, empty otherwise
fn outbound_mode_findings(nat: &XmlNode) -> Vec<VerifyFinding> {
    let Some(mode) = nat
        .get_child("outbound")
        .and_then(|o| o.get_text(&["mode"]))
        .map(str::trim)
    else {
        return Vec::new();
    };
    if mode.is_empty() {
        return Vec::new();
    }
    let valid = [
        "automatic",
        "hybrid",
        "manual",
        "disable",
        "disabled",
        "advanced",
    ];
    if valid.iter().any(|v| mode.eq_ignore_ascii_case(v)) {
        return Vec::new();
    }
    vec![VerifyFinding {
        severity: FindingSeverity::Warning,
        code: "nat_invalid_outbound_mode".to_string(),
        message: format!("NAT outbound mode '{mode}' is not recognized"),
    }]
}

/// Find NAT rules that reference undefined interfaces.
///
/// Validates that each NAT rule's `<interface>` value refers to an
/// interface that exists. Checks both port forward rules and outbound rules.
///
/// # Arguments
///
/// * `nat` - NAT configuration node
/// * `interfaces` - Set of defined interface names
///
/// # Returns
///
/// Vector of error findings for each missing interface reference
fn nat_interface_findings(nat: &XmlNode, interfaces: &BTreeSet<String>) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    for (idx, rule) in collect_nat_rules(nat).into_iter().enumerate() {
        let Some(interface) = rule.get_text(&["interface"]) else {
            continue;
        };
        for token in split_tokens(interface) {
            if is_builtin_nat_interface(&token) || interfaces.contains(&token) {
                continue;
            }
            out.push(VerifyFinding {
                severity: FindingSeverity::Error,
                code: "nat_missing_interface".to_string(),
                message: format!("NAT rule #{idx} references missing interface '{token}'"),
            });
        }
    }
    out
}

/// Find NAT rules with invalid associated rule IDs.
///
/// Port forward rules often have associated filter rules that allow the
/// forwarded traffic. This validates that `<associated-rule-id>` values
/// reference actual filter rules.
///
/// # Arguments
///
/// * `nat` - NAT configuration node
/// * `associated_ids` - Set of associated-rule-id values from filter rules
///
/// # Returns
///
/// Vector of warning findings for each missing association
fn nat_association_findings(
    nat: &XmlNode,
    associated_ids: &BTreeSet<String>,
) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    for (idx, rule) in collect_nat_rules(nat).into_iter().enumerate() {
        let Some(assoc) = rule.get_text(&["associated-rule-id"]).map(str::trim) else {
            continue;
        };
        if assoc.is_empty() {
            continue;
        }
        if associated_ids.contains(assoc) {
            continue;
        }
        out.push(VerifyFinding {
            severity: FindingSeverity::Warning,
            code: "nat_missing_associated_rule".to_string(),
            message: format!("NAT rule #{idx} associated-rule-id '{assoc}' not found in filter"),
        });
    }
    out
}

/// Collect all NAT rules from both port forward and outbound sections.
///
/// NAT rules exist in:
/// - `<nat><rule>` — Port forwarding rules
/// - `<nat><outbound><rule>` — Outbound NAT rules
///
/// # Arguments
///
/// * `nat` - NAT configuration node
///
/// # Returns
///
/// Vector of references to all NAT rule nodes
fn collect_nat_rules(nat: &XmlNode) -> Vec<&XmlNode> {
    let mut out = nat
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .collect::<Vec<_>>();
    if let Some(outbound) = nat.get_child("outbound") {
        out.extend(outbound.children.iter().filter(|c| c.tag == "rule"));
    }
    out
}

/// Collect all associated-rule-id values from filter rules.
///
/// Filter rules can have `<associated-rule-id>` that links them to NAT
/// port forward rules. This collects all such IDs for validation.
///
/// # Arguments
///
/// * `root` - Configuration root
///
/// # Returns
///
/// Set of all associated-rule-id values found in filter rules
fn collect_filter_associated_ids(root: &XmlNode) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(filter) = root.get_child("filter") else {
        return out;
    };
    for rule in filter.children.iter().filter(|c| c.tag == "rule") {
        if let Some(id) = rule.get_text(&["associated-rule-id"]).map(str::trim) {
            if !id.is_empty() {
                out.insert(id.to_string());
            }
        }
    }
    out
}

/// Split a comma/space-separated interface list into tokens.
///
/// Interface values can contain multiple interfaces separated by
/// commas, spaces, tabs, or newlines.
///
/// # Arguments
///
/// * `raw` - Raw interface string
///
/// # Returns
///
/// Vector of normalized (lowercase, trimmed) interface tokens
fn split_tokens(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

/// Check if a token is a built-in NAT interface.
///
/// Some interface names are always valid for NAT rules even if not
/// explicitly defined (any, wan, lan).
///
/// # Arguments
///
/// * `token` - Interface token to check
///
/// # Returns
///
/// True if token is a built-in NAT interface
fn is_builtin_nat_interface(token: &str) -> bool {
    matches!(token, "any" | "wan" | "lan")
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::nat_findings;

    #[test]
    fn warns_on_unknown_outbound_mode() {
        let root =
            parse(br#"<pfsense><nat><outbound><mode>strange</mode></outbound></nat></pfsense>"#)
                .expect("parse");
        let findings = nat_findings(&root);
        assert!(findings
            .iter()
            .any(|f| f.code == "nat_invalid_outbound_mode"));
    }

    #[test]
    fn errors_on_missing_nat_interface() {
        let root = parse(
            br#"<pfsense><interfaces><lan/></interfaces><nat><rule><interface>opt9</interface></rule></nat></pfsense>"#,
        )
        .expect("parse");
        let findings = nat_findings(&root);
        assert!(findings.iter().any(|f| f.code == "nat_missing_interface"));
    }

    #[test]
    fn warns_on_missing_associated_rule() {
        let root = parse(
            br#"<pfsense><filter><rule><associated-rule-id>a</associated-rule-id></rule></filter><nat><rule><associated-rule-id>b</associated-rule-id></rule></nat></pfsense>"#,
        )
        .expect("parse");
        let findings = nat_findings(&root);
        assert!(findings
            .iter()
            .any(|f| f.code == "nat_missing_associated_rule"));
    }
}
