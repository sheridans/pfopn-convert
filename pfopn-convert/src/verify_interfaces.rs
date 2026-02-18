//! Interface reference validation.
//!
//! Validates that all interface references in a firewall configuration point to
//! actually defined interfaces. This prevents runtime errors where firewall rules,
//! gateways, or routes reference non-existent interfaces.
//!
//! ## Checks Performed
//!
//! 1. **Duplicate assignments** — Same interface name assigned multiple times
//! 2. **Firewall rule references** — Rules reference interfaces that exist
//! 3. **Gateway references** — Gateways are bound to valid interfaces
//! 4. **Static route references** — Routes use valid interfaces
//!
//! ## Interface Discovery
//!
//! Interfaces are discovered from multiple sources:
//! - `<interfaces>` children (lan, wan, opt1, opt2, etc.)
//! - VPN pseudo-interfaces (openvpn, wireguard, tailscale)
//! - Built-in interfaces (any, floating, lo0, enc0, ipsec, etc.)
//! - Bridge interfaces (bridge0, bridge1, etc.)

use std::collections::{BTreeMap, BTreeSet};

use xml_diff_core::XmlNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub message: String,
}

/// Find all interface reference problems in a configuration.
///
/// Performs comprehensive interface validation across firewall rules, gateways,
/// and static routes. Returns all problems found.
///
/// # Arguments
///
/// * `root` - Configuration root to validate
///
/// # Returns
///
/// Vector of findings (errors and warnings). Empty if no problems found.
pub fn interface_reference_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    let defined = collect_defined_interface_names(root);
    out.extend(duplicate_interface_findings(root));
    out.extend(rule_interface_findings(root, &defined));
    out.extend(gateway_interface_findings(root, &defined));
    out.extend(route_interface_findings(root, &defined));
    out
}

/// Collect all interface names defined in the configuration.
///
/// Gathers interface names from:
/// - `<interfaces>` children (logical names: lan, wan, opt1, opt2, etc.)
/// - VPN sections (openvpn, wireguard, tailscale)
///
/// Names are normalized to lowercase for case-insensitive matching.
///
/// # Arguments
///
/// * `root` - Configuration root to scan
///
/// # Returns
///
/// Set of all defined interface names (lowercase)
pub fn collect_defined_interface_names(root: &XmlNode) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(interfaces) = root.get_child("interfaces") {
        for iface in &interfaces.children {
            out.insert(iface.tag.to_ascii_lowercase());
        }
    }
    if root.get_child("openvpn").is_some() {
        out.insert("openvpn".to_string());
    }
    if root.get_child("wireguard").is_some()
        || root
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("wireguard"))
            .is_some()
    {
        out.insert("wireguard".to_string());
    }
    if root.get_child("tailscale").is_some()
        || root.get_child("tailscaleauth").is_some()
        || root
            .get_child("installedpackages")
            .and_then(|ip| ip.get_child("tailscale"))
            .is_some()
        || root
            .get_child("OPNsense")
            .and_then(|opn| opn.get_child("tailscale"))
            .is_some()
    {
        out.insert("tailscale".to_string());
    }
    out
}

/// Find duplicate interface assignments.
///
/// Checks if the same logical interface name (e.g., "lan") is assigned
/// multiple times in `<interfaces>`. This is a configuration error.
///
/// # Arguments
///
/// * `root` - Configuration root to check
///
/// # Returns
///
/// Vector of error findings for each duplicated interface
fn duplicate_interface_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    let Some(interfaces) = root.get_child("interfaces") else {
        return Vec::new();
    };
    let mut counts = BTreeMap::new();
    for iface in &interfaces.children {
        *counts
            .entry(iface.tag.to_ascii_lowercase())
            .or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(name, count)| VerifyFinding {
            severity: FindingSeverity::Error,
            code: "duplicate_interface_assignment".to_string(),
            message: format!("interface '{name}' assigned {count} times"),
        })
        .collect()
}

/// Find firewall rules that reference undefined interfaces.
///
/// Validates that each `<rule><interface>` value refers to an interface
/// that actually exists. Interface values can be comma or space-separated
/// for multi-interface rules.
///
/// # Arguments
///
/// * `root` - Configuration root to check
/// * `defined` - Set of defined interface names
///
/// # Returns
///
/// Vector of error findings for each missing interface reference
fn rule_interface_findings(root: &XmlNode, defined: &BTreeSet<String>) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    let Some(filter) = root.get_child("filter") else {
        return out;
    };
    for (idx, rule) in filter
        .children
        .iter()
        .filter(|c| c.tag == "rule")
        .enumerate()
    {
        let Some(interface) = rule.get_text(&["interface"]) else {
            continue;
        };
        for token in split_tokens(interface) {
            if !is_interface_token_known(&token, defined) {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Error,
                    code: "missing_interface_reference".to_string(),
                    message: format!("filter rule #{idx} references missing interface '{token}'"),
                });
            }
        }
    }
    out
}

/// Find gateways that reference undefined interfaces.
///
/// Validates that each gateway's `<interface>` value refers to a valid
/// interface. Gateways must be bound to interfaces that exist.
///
/// # Arguments
///
/// * `root` - Configuration root to check
/// * `defined` - Set of defined interface names
///
/// # Returns
///
/// Vector of error findings for each missing interface reference
fn gateway_interface_findings(root: &XmlNode, defined: &BTreeSet<String>) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    let Some(gateways) = root.get_child("gateways") else {
        return out;
    };
    for gw in &gateways.children {
        let Some(interface) = gw.get_text(&["interface"]) else {
            continue;
        };
        for token in split_tokens(interface) {
            if !is_interface_token_known(&token, defined) {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Error,
                    code: "missing_gateway_interface".to_string(),
                    message: format!("gateway references missing interface '{token}'"),
                });
            }
        }
    }
    out
}

/// Find static routes that reference undefined interfaces.
///
/// Validates that each route's `<interface>` value refers to a valid
/// interface. Routes must use interfaces that exist.
///
/// # Arguments
///
/// * `root` - Configuration root to check
/// * `defined` - Set of defined interface names
///
/// # Returns
///
/// Vector of error findings for each missing interface reference
fn route_interface_findings(root: &XmlNode, defined: &BTreeSet<String>) -> Vec<VerifyFinding> {
    let mut out = Vec::new();
    let Some(routes) = root.get_child("staticroutes") else {
        return out;
    };
    for route in &routes.children {
        let Some(interface) = route.get_text(&["interface"]) else {
            continue;
        };
        for token in split_tokens(interface) {
            if !is_interface_token_known(&token, defined) {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Error,
                    code: "missing_route_interface".to_string(),
                    message: format!("static route references missing interface '{token}'"),
                });
            }
        }
    }
    out
}

/// Split a comma/space-separated interface list into tokens.
///
/// Interface values in XML can contain multiple interfaces separated by
/// commas, spaces, tabs, or newlines. This normalizes and splits them.
///
/// # Arguments
///
/// * `raw` - Raw interface string (e.g., "lan,wan" or "lan wan opt1")
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

/// Check if an interface token is valid.
///
/// An interface is valid if it's either:
/// 1. Defined in the configuration
/// 2. A built-in pseudo-interface (any, floating, lo0, enc0, ipsec, etc.)
/// 3. A bridge interface (bridge0, bridge1, etc.)
///
/// # Arguments
///
/// * `token` - Interface token to check (normalized lowercase)
/// * `defined` - Set of defined interface names
///
/// # Returns
///
/// True if interface is valid, false otherwise
fn is_interface_token_known(token: &str, defined: &BTreeSet<String>) -> bool {
    if defined.contains(token) {
        return true;
    }
    matches!(
        token,
        "any"
            | "floating"
            | "lo0"
            | "enc0"
            | "ipsec"
            | "openvpn"
            | "wireguard"
            | "tailscale"
            | "wanip"
            | "lanip"
    ) || is_bridge_token(token)
}

/// Check if a token represents a bridge interface.
///
/// Bridge interfaces follow the pattern "bridge" followed by digits
/// (e.g., "bridge0", "bridge1", "bridge42").
///
/// # Arguments
///
/// * `token` - Token to check
///
/// # Returns
///
/// True if token is a valid bridge interface name
fn is_bridge_token(token: &str) -> bool {
    let stripped = token.strip_prefix("bridge").unwrap_or(token);
    !stripped.is_empty() && stripped.chars().all(|ch| ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::interface_reference_findings;

    #[test]
    fn detects_missing_interface_references() {
        let root = parse(
            br#"<pfsense><interfaces><lan/></interfaces><filter><rule><interface>opt9</interface></rule></filter></pfsense>"#,
        )
        .expect("parse");
        let findings = interface_reference_findings(&root);
        assert!(findings
            .iter()
            .any(|f| f.code == "missing_interface_reference"));
    }
}
