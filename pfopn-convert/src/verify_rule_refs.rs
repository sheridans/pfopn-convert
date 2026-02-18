//! Firewall rule reference validation.
//!
//! Validates that firewall rules and static routes reference valid resources:
//! - **Aliases** — Firewall address aliases must exist
//! - **Gateways** — Gateways referenced in rules and routes must be defined
//! - **Schedules** — Time-based schedules must exist
//!
//! ## Reference Types
//!
//! - Filter rule addresses can reference aliases (e.g., "TRUSTED_HOSTS")
//! - Filter rules and static routes can specify gateways for routing
//! - Filter rules can have schedules for time-based activation
//!
//! ## Built-in References
//!
//! Some values are built-in and always valid (e.g., "any", "default", IP literals).
//! These are not validated against defined resources.

use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

use crate::verify_interfaces::{FindingSeverity, VerifyFinding};

/// Find all reference validation problems in firewall rules and routes.
///
/// Validates that:
/// - Rule addresses reference defined aliases
/// - Rule gateways reference defined gateways
/// - Route gateways reference defined gateways
/// - Rule schedules reference defined schedules
///
/// # Arguments
///
/// * `root` - Configuration root to validate
///
/// # Returns
///
/// Vector of findings (errors and warnings). Empty if no problems found.
pub fn rule_reference_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    // Collect all defined resources
    let aliases = collect_alias_names(root);
    let gateways = collect_gateway_names(root);
    let schedules = collect_schedule_names(root);
    let mut out = Vec::new();

    // Validate references in filter rules and static routes
    out.extend(filter_rule_alias_findings(root, &aliases));
    out.extend(filter_rule_gateway_findings(root, &gateways));
    out.extend(static_route_gateway_findings(root, &gateways));
    out.extend(filter_rule_schedule_findings(root, &schedules));
    out
}

/// Find firewall rules that reference undefined aliases.
fn filter_rule_alias_findings(root: &XmlNode, aliases: &BTreeSet<String>) -> Vec<VerifyFinding> {
    let Some(filter) = root.get_child("filter") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, rule) in filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .enumerate()
    {
        for side in ["source", "destination"] {
            let Some(addr) = rule.get_child(side).and_then(|n| n.get_text(&["address"])) else {
                continue;
            };
            for token in split_ref_tokens(addr) {
                if is_builtin_or_literal(&token) {
                    continue;
                }
                if !aliases.contains(&token.to_ascii_lowercase()) {
                    out.push(VerifyFinding {
                        severity: FindingSeverity::Error,
                        code: "missing_alias_reference".to_string(),
                        message: format!(
                            "filter rule #{idx} {side} references alias '{token}' that does not exist"
                        ),
                    });
                }
            }
        }
    }
    out
}

fn filter_rule_gateway_findings(root: &XmlNode, gateways: &BTreeSet<String>) -> Vec<VerifyFinding> {
    let Some(filter) = root.get_child("filter") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, rule) in filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .enumerate()
    {
        let Some(gateway) = rule.get_text(&["gateway"]) else {
            continue;
        };
        let gateway = gateway.trim();
        if gateway.is_empty() || is_builtin_or_literal(gateway) {
            continue;
        }
        if !gateways.contains(&gateway.to_ascii_lowercase()) {
            out.push(VerifyFinding {
                severity: FindingSeverity::Error,
                code: "missing_gateway_reference".to_string(),
                message: format!(
                    "filter rule #{idx} references gateway '{gateway}' that does not exist"
                ),
            });
        }
    }
    out
}

fn static_route_gateway_findings(
    root: &XmlNode,
    gateways: &BTreeSet<String>,
) -> Vec<VerifyFinding> {
    let Some(routes) = root.get_child("staticroutes") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, route) in routes.children.iter().enumerate() {
        let Some(gateway) = route.get_text(&["gateway"]) else {
            continue;
        };
        let gateway = gateway.trim();
        if gateway.is_empty() || is_builtin_or_literal(gateway) {
            continue;
        }
        if !gateways.contains(&gateway.to_ascii_lowercase()) {
            out.push(VerifyFinding {
                severity: FindingSeverity::Error,
                code: "missing_route_gateway".to_string(),
                message: format!(
                    "static route #{idx} references gateway '{gateway}' that does not exist"
                ),
            });
        }
    }
    out
}

fn filter_rule_schedule_findings(
    root: &XmlNode,
    schedules: &BTreeSet<String>,
) -> Vec<VerifyFinding> {
    let Some(filter) = root.get_child("filter") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, rule) in filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .enumerate()
    {
        let Some(sched) = rule
            .get_text(&["sched"])
            .or_else(|| rule.get_text(&["schedule"]))
        else {
            continue;
        };
        let sched = sched.trim();
        if sched.is_empty() {
            continue;
        }
        if !schedules.contains(&sched.to_ascii_lowercase()) {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "missing_schedule_reference".to_string(),
                message: format!(
                    "filter rule #{idx} references schedule '{sched}' that does not exist"
                ),
            });
        }
    }
    out
}

fn collect_alias_names(root: &XmlNode) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(aliases) = root.get_child("aliases") {
        for alias in aliases.children.iter().filter(|c| c.tag == "alias") {
            if let Some(name) = alias.get_text(&["name"]) {
                let n = name.trim().to_ascii_lowercase();
                if !n.is_empty() {
                    out.insert(n);
                }
            }
        }
    }
    if let Some(aliases) = root
        .get_child("OPNsense")
        .and_then(|o| o.get_child("Firewall"))
        .and_then(|f| f.get_child("Alias"))
        .and_then(|a| a.get_child("aliases"))
    {
        for alias in aliases.children.iter().filter(|c| c.tag == "alias") {
            if let Some(name) = alias.get_text(&["name"]) {
                let n = name.trim().to_ascii_lowercase();
                if !n.is_empty() {
                    out.insert(n);
                }
            }
        }
    }
    out
}

fn collect_gateway_names(root: &XmlNode) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(gateways) = root.get_child("gateways") {
        for gw in &gateways.children {
            if let Some(name) = gw.get_text(&["name"]) {
                let n = name.trim().to_ascii_lowercase();
                if !n.is_empty() {
                    out.insert(n);
                }
            }
        }
    }
    if let Some(gateways) = root
        .get_child("OPNsense")
        .and_then(|o| o.get_child("Gateways"))
    {
        for gw in &gateways.children {
            if let Some(name) = gw.get_text(&["name"]) {
                let n = name.trim().to_ascii_lowercase();
                if !n.is_empty() {
                    out.insert(n);
                }
            }
        }
    }
    out
}

fn collect_schedule_names(root: &XmlNode) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(schedules) = root.get_child("schedules") {
        for s in schedules.children.iter().filter(|c| c.tag == "schedule") {
            if let Some(name) = s.get_text(&["name"]) {
                let n = name.trim().to_ascii_lowercase();
                if !n.is_empty() {
                    out.insert(n);
                }
            }
        }
    }
    out
}

fn split_ref_tokens(raw: &str) -> Vec<String> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn is_builtin_or_literal(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    if v.is_empty() {
        return true;
    }
    if matches!(
        v.as_str(),
        "any"
            | "(self)"
            | "self"
            | "wanip"
            | "lanip"
            | "wan address"
            | "lan address"
            | "wan net"
            | "lan net"
            | "this firewall"
    ) {
        return true;
    }
    if v.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if is_dynamic_gateway_literal(&v) {
        return true;
    }
    if v.contains('/') {
        let mut parts = v.split('/');
        if let (Some(ip), Some(mask)) = (parts.next(), parts.next()) {
            if ip.parse::<std::net::IpAddr>().is_ok() && mask.parse::<u8>().is_ok() {
                return true;
            }
        }
    }
    false
}

fn is_dynamic_gateway_literal(v: &str) -> bool {
    v.ends_with("_dhcp") || v.ends_with("_dhcp6") || v.ends_with("_pppoe") || v.ends_with("_track6")
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::rule_reference_findings;

    #[test]
    fn detects_missing_alias_reference() {
        let root = parse(
            br#"<pfsense><aliases><alias><name>ok_alias</name></alias></aliases><filter><rule><source><address>missing_alias</address></source><destination><any/></destination></rule></filter></pfsense>"#,
        )
        .expect("parse");
        let findings = rule_reference_findings(&root);
        assert!(findings.iter().any(|f| f.code == "missing_alias_reference"));
    }

    #[test]
    fn detects_missing_gateway_reference() {
        let root = parse(
            br#"<pfsense><gateways><item><name>GW1</name></item></gateways><filter><rule><gateway>GW2</gateway></rule></filter></pfsense>"#,
        )
        .expect("parse");
        let findings = rule_reference_findings(&root);
        assert!(findings
            .iter()
            .any(|f| f.code == "missing_gateway_reference"));
    }

    #[test]
    fn warns_on_missing_schedule_reference() {
        let root =
            parse(br#"<pfsense><filter><rule><sched>workhours</sched></rule></filter></pfsense>"#)
                .expect("parse");
        let findings = rule_reference_findings(&root);
        assert!(findings
            .iter()
            .any(|f| f.code == "missing_schedule_reference"));
    }

    #[test]
    fn accepts_existing_schedule_reference() {
        let root = parse(
            br#"<pfsense>
                <schedules>
                  <schedule><name>workhours</name></schedule>
                </schedules>
                <filter>
                  <rule><sched>workhours</sched></rule>
                </filter>
            </pfsense>"#,
        )
        .expect("parse");
        let findings = rule_reference_findings(&root);
        assert!(!findings
            .iter()
            .any(|f| f.code == "missing_schedule_reference"));
    }
}
