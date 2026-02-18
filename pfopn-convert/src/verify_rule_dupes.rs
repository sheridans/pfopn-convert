//! Firewall rule duplicate detection.
//!
//! Detects duplicate firewall rules by computing a fingerprint of each rule's
//! significant fields and finding rules with identical fingerprints.
//!
//! ## Rule Fingerprint
//!
//! A fingerprint includes all fields that affect rule matching behavior:
//! - Interface, action (pass/block), IP protocol (inet/inet6)
//! - Transport protocol, source/dest addresses and ports
//! - Direction, floating status, quick flag, disabled status
//! - Gateway, schedule
//!
//! ## Duplicate Detection Strategy
//!
//! 1. Compute fingerprint for each rule
//! 2. Group rules by identical fingerprints
//! 3. Report groups with 2+ rules as duplicates
//! 4. Special handling for default rules (prefixed with "Default ")
//!
//! ## Default Rule Overlap
//!
//! If a default rule and custom rule have the same fingerprint, this is
//! reported as "default_rule_overlap" (warning) rather than a duplicate,
//! since it's common for users to recreate default behavior.

use std::collections::BTreeMap;

use xml_diff_core::XmlNode;

use crate::verify_interfaces::{FindingSeverity, VerifyFinding};

/// Find duplicate firewall rules.
///
/// Computes a fingerprint for each rule and detects rules with identical
/// fingerprints. Handles default rule overlap as a special case.
///
/// # Arguments
///
/// * `root` - Configuration root to scan
///
/// # Returns
///
/// Vector of warnings for each duplicate or overlap detected.
pub fn rule_duplicate_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    let Some(filter) = root.get_child("filter") else {
        return Vec::new();
    };
    let rules = filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .collect::<Vec<_>>();
    // Group rules by fingerprint
    let mut by_fp: BTreeMap<RuleFingerprint, Vec<RuleMeta>> = BTreeMap::new();
    for (idx, rule) in rules.iter().enumerate() {
        by_fp.entry(fingerprint(rule)).or_default().push(RuleMeta {
            idx,
            tracker: text(rule, "tracker"),
            descr: text(rule, "descr"),
        });
    }

    // Report groups with multiple rules
    let mut out = Vec::new();
    for rows in by_fp.values() {
        if rows.len() < 2 {
            continue; // Not a duplicate, skip
        }

        // Check if this is a default rule overlapping custom rule
        let has_default = rows.iter().any(|r| is_default_descr(&r.descr));
        let has_non_default = rows.iter().any(|r| !is_default_descr(&r.descr));
        if has_default && has_non_default {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "default_rule_overlap".to_string(),
                message: format!(
                    "default rule overlaps custom rule signatures (trackers: {})",
                    trackers(rows)
                ),
            });
            continue;
        }

        // True duplicate (all default or all custom)
        out.push(VerifyFinding {
            severity: FindingSeverity::Warning,
            code: "duplicate_firewall_rule".to_string(),
            message: format!(
                "duplicate firewall rule signature detected (trackers: {})",
                trackers(rows)
            ),
        });
    }
    out
}

/// Rule fingerprint for duplicate detection.
///
/// Includes all fields that affect rule matching behavior. Rules with
/// identical fingerprints will match the same traffic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuleFingerprint {
    interface: String,
    action: String,
    ipprotocol: String,
    protocol: String,
    source: String,
    source_port: String,
    destination: String,
    destination_port: String,
    direction: String,
    floating: bool,
    quick: bool,
    disabled: bool,
    gateway: String,
    schedule: String,
}

#[derive(Debug, Clone)]
struct RuleMeta {
    idx: usize,
    tracker: String,
    descr: String,
}

/// Compute a rule's fingerprint from all matching-relevant fields.
fn fingerprint(rule: &XmlNode) -> RuleFingerprint {
    RuleFingerprint {
        interface: text(rule, "interface").to_ascii_lowercase(),
        action: text(rule, "type").to_ascii_lowercase(),
        ipprotocol: text(rule, "ipprotocol").to_ascii_lowercase(),
        protocol: text(rule, "protocol").to_ascii_lowercase(),
        source: side_addr(rule, "source").to_ascii_lowercase(),
        source_port: side_port(rule, "source").to_ascii_lowercase(),
        destination: side_addr(rule, "destination").to_ascii_lowercase(),
        destination_port: side_port(rule, "destination").to_ascii_lowercase(),
        direction: text(rule, "direction").to_ascii_lowercase(),
        floating: rule.get_child("floating").is_some(),
        quick: rule.get_child("quick").is_some(),
        disabled: rule.get_child("disabled").is_some(),
        gateway: text(rule, "gateway").to_ascii_lowercase(),
        schedule: first_non_empty_text(rule, &["sched", "schedule"]).to_ascii_lowercase(),
    }
}

fn side_addr(rule: &XmlNode, side: &str) -> String {
    let Some(node) = rule.get_child(side) else {
        return String::new();
    };
    if let Some(v) = node.get_text(&["address"]) {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if node.get_child("any").is_some() {
        return "any".to_string();
    }
    if let Some(v) = node.get_text(&["network"]) {
        let t = v.trim();
        if !t.is_empty() {
            return format!("network:{t}");
        }
    }
    String::new()
}

fn side_port(rule: &XmlNode, side: &str) -> String {
    rule.get_child(side)
        .and_then(|n| n.get_text(&["port"]))
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn text(node: &XmlNode, tag: &str) -> String {
    node.get_text(&[tag])
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn first_non_empty_text(node: &XmlNode, tags: &[&str]) -> String {
    for tag in tags {
        let value = text(node, tag);
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

fn is_default_descr(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    v.starts_with("default ")
}

fn trackers(rows: &[RuleMeta]) -> String {
    rows.iter()
        .map(|r| {
            if r.tracker.is_empty() {
                format!("idx{}", r.idx)
            } else {
                r.tracker.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::rule_duplicate_findings;

    #[test]
    fn ignores_ipv4_ipv6_default_pair_when_ipprotocol_differs() {
        let root = parse(
            br#"<pfsense><filter>
                <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><source><network>lan</network></source><destination><any/></destination><descr>Default allow LAN to any rule</descr></rule>
                <rule><type>pass</type><interface>lan</interface><ipprotocol>inet6</ipprotocol><source><network>lan</network></source><destination><any/></destination><descr>Default allow LAN IPv6 to any rule</descr></rule>
            </filter></pfsense>"#,
        )
        .expect("parse");
        let findings = rule_duplicate_findings(&root);
        assert!(findings.is_empty());
    }

    #[test]
    fn reports_exact_duplicate_signature() {
        let root = parse(
            br#"<pfsense><filter>
                <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><any/></destination><tracker>1</tracker><descr>Rule A</descr></rule>
                <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><source><any/></source><destination><any/></destination><tracker>2</tracker><descr>Rule B</descr></rule>
            </filter></pfsense>"#,
        )
        .expect("parse");
        let findings = rule_duplicate_findings(&root);
        assert!(findings.iter().any(|f| f.code == "duplicate_firewall_rule"));
    }
}
