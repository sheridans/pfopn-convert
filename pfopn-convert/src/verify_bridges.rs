//! Bridge interface validation.
//!
//! Validates that bridge configurations reference valid member interfaces.
//! Bridges combine multiple physical interfaces into a single logical interface.
//!
//! ## Bridge Structure
//!
//! - `<bridges><bridged>` — Each bridge definition
//! - `<members>` — Comma-separated list of interfaces to bridge
//! - `<bridgeif>` — Optional bridge interface name (bridge0, bridge1, etc.)
//!
//! ## Validation
//!
//! - Bridges must have at least one member
//! - All member interfaces must exist
//! - Bridge interface names (if specified) should follow convention

use xml_diff_core::XmlNode;

use crate::verify_interfaces::{collect_defined_interface_names, FindingSeverity, VerifyFinding};

/// Find all bridge configuration problems.
///
/// Validates that:
/// - Bridges have at least one member interface
/// - All member interfaces actually exist
/// - Bridge interface names are valid
///
/// # Arguments
///
/// * `root` - Configuration root to validate
///
/// # Returns
///
/// Vector of findings (errors and warnings). Empty if no problems found.
pub fn bridge_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    let Some(bridges) = root.get_child("bridges") else {
        return Vec::new();
    };

    // Collect defined interfaces for validation
    let defined = collect_defined_interface_names(root);
    let mut out = Vec::new();

    // Check each bridge definition
    for (idx, bridged) in bridges
        .children
        .iter()
        .filter(|c| c.tag == "bridged")
        .enumerate()
    {
        let members = bridged
            .get_text(&["members"])
            .map(split_members)
            .unwrap_or_default();
        let bridgeif = bridged
            .get_text(&["bridgeif"])
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();

        if members.is_empty() && bridgeif.is_empty() {
            out.push(VerifyFinding {
                severity: FindingSeverity::Error,
                code: "empty_bridge_members".to_string(),
                message: format!("bridge #{idx} has no members"),
            });
            continue;
        }

        for member in members {
            if !defined.contains(&member) {
                out.push(VerifyFinding {
                    severity: FindingSeverity::Error,
                    code: "missing_bridge_member".to_string(),
                    message: format!("bridge #{idx} references missing member '{member}'"),
                });
            }
        }
        if !bridgeif.is_empty() && !defined.contains(&bridgeif) && !is_bridge_token(&bridgeif) {
            out.push(VerifyFinding {
                severity: FindingSeverity::Warning,
                code: "missing_bridge_interface".to_string(),
                message: format!(
                    "bridge #{idx} bridgeif references missing interface '{bridgeif}'"
                ),
            });
        }
    }

    out
}

/// Split comma/space-separated bridge member list into tokens.
///
/// Bridge members are specified as a comma or space-separated list of
/// interface names.
///
/// # Arguments
///
/// * `raw` - Raw members string
///
/// # Returns
///
/// Vector of normalized (lowercase, trimmed) interface names
fn split_members(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

/// Check if a token is a valid bridge interface name.
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

    use super::bridge_findings;

    #[test]
    fn detects_empty_bridge_members() {
        let root = parse(
            br#"<pfsense><interfaces><lan/></interfaces><bridges><bridged/></bridges></pfsense>"#,
        )
        .expect("parse");
        let findings = bridge_findings(&root);
        assert!(findings.iter().any(|f| f.code == "empty_bridge_members"));
    }
}
