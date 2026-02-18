//! WireGuard VPN configuration validation.
//!
//! Validates that WireGuard VPN is properly configured. Some setups use
//! interface assignments, but they are not strictly required in all cases.
//!
//! ## WireGuard Configuration Locations
//!
//! - **pfSense:** `<wireguard>` at root level
//! - **OPNsense:** `<OPNsense><wireguard>` nested structure
//!
//! ## Interface Assignment
//!
//! If WireGuard is enabled, a corresponding interface assignment is commonly
//! used:
//! - Explicit wireguard interface tag
//! - Physical interface containing "wg" (tun_wg0, tun_wg1, etc.)

use crate::verify_interfaces::{FindingSeverity, VerifyFinding};
use xml_diff_core::XmlNode;

/// Find WireGuard configuration problems.
///
/// Validates that if WireGuard is enabled, there's a corresponding interface
/// assignment. Without an interface assignment, WireGuard configuration exists
/// but cannot be used.
///
/// # Arguments
///
/// * `root` - Configuration root to validate
///
/// # Returns
///
/// Warning if WireGuard is enabled but has no interface assignment.
/// Empty if WireGuard is disabled or has an assignment.
pub fn wireguard_findings(root: &XmlNode) -> Vec<VerifyFinding> {
    // Skip validation if WireGuard config doesn't exist or isn't enabled
    if !has_wireguard_config(root) || !wireguard_enabled(root) {
        return Vec::new();
    }

    // If enabled, check for interface assignment
    if has_wireguard_interface_assignment(root) {
        return Vec::new();
    }

    // Warning: WireGuard is enabled but has no interface assignment
    vec![VerifyFinding {
        severity: FindingSeverity::Warning,
        code: "wireguard_missing_interface_assignment".to_string(),
        message:
            "WireGuard appears enabled but no wireguard/tun_wg* interface assignment was found"
                .to_string(),
    }]
}

/// Check if WireGuard configuration exists.
///
/// Looks for WireGuard config in both pfSense and OPNsense locations.
///
/// # Arguments
///
/// * `root` - Configuration root
///
/// # Returns
///
/// True if WireGuard section exists (may not be enabled)
fn has_wireguard_config(root: &XmlNode) -> bool {
    root.get_child("wireguard").is_some()
        || root
            .get_child("OPNsense")
            .and_then(|n| n.get_child("wireguard"))
            .is_some()
}

/// Check if WireGuard is enabled in configuration.
///
/// Searches recursively for `<enabled>` elements with truthy values within
/// WireGuard configuration sections.
///
/// # Arguments
///
/// * `root` - Configuration root
///
/// # Returns
///
/// True if any WireGuard server/peer has enabled=1
fn wireguard_enabled(root: &XmlNode) -> bool {
    let mut stack: Vec<&XmlNode> = Vec::new();
    if let Some(top) = root.get_child("wireguard") {
        stack.push(top);
    }
    if let Some(nested) = root
        .get_child("OPNsense")
        .and_then(|n| n.get_child("wireguard"))
    {
        stack.push(nested);
    }

    while let Some(node) = stack.pop() {
        if node.tag.eq_ignore_ascii_case("enabled")
            && is_truthy(node.text.as_deref().unwrap_or_default())
        {
            return true;
        }
        for child in &node.children {
            stack.push(child);
        }
    }
    false
}

/// Check if WireGuard has a corresponding interface assignment.
///
/// Looks for interface assignments that indicate WireGuard usage:
/// - Interface named "wireguard"
/// - Interface with physical device containing "wg" (tun_wg0, etc.)
///
/// # Arguments
///
/// * `root` - Configuration root
///
/// # Returns
///
/// True if a WireGuard interface assignment exists
fn has_wireguard_interface_assignment(root: &XmlNode) -> bool {
    let Some(interfaces) = root.get_child("interfaces") else {
        return false;
    };
    interfaces.children.iter().any(|iface| {
        if iface.tag.eq_ignore_ascii_case("wireguard") {
            return true;
        }
        iface
            .get_text(&["if"])
            .map(|v| v.to_ascii_lowercase())
            .map(|v| v.contains("wg"))
            .unwrap_or(false)
    })
}

/// Check if a string represents a boolean true value.
///
/// Recognizes common truthy values: "1", "yes", "true", "enabled", "on"
/// (case-insensitive).
///
/// # Arguments
///
/// * `value` - String to check
///
/// # Returns
///
/// True if value is truthy
fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "enabled" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::wireguard_findings;
    use xml_diff_core::parse;

    #[test]
    fn warns_when_enabled_wireguard_has_no_interface_assignment() {
        let root = parse(
            br#"<opnsense><interfaces><wan/><lan/></interfaces><OPNsense><wireguard><server><servers><server><enabled>1</enabled></server></servers></server></wireguard></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let findings = wireguard_findings(&root);
        let finding = findings
            .iter()
            .find(|f| f.code == "wireguard_missing_interface_assignment")
            .expect("finding");
        assert_eq!(
            finding.severity,
            crate::verify_interfaces::FindingSeverity::Warning
        );
    }

    #[test]
    fn no_error_when_enabled_wireguard_has_assignment() {
        let root = parse(
            br#"<opnsense><interfaces><wireguard><if>tun_wg0</if></wireguard></interfaces><OPNsense><wireguard><server><servers><server><enabled>1</enabled></server></servers></server></wireguard></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let findings = wireguard_findings(&root);
        assert!(findings.is_empty());
    }
}
