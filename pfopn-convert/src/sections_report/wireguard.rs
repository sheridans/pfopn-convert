//! WireGuard configuration gap detection for section reports.
//!
//! This module detects WireGuard configuration presence and status differences
//! between two configs, helping identify:
//!
//! - **Unilateral config** — WireGuard present on one side but not the other
//! - **Disabled config** — WireGuard sections exist but all entries are disabled
//!
//! ## Use Case
//!
//! WireGuard configuration structure differs between pfSense and OPNsense.
//! Detecting these gaps helps users understand if WireGuard needs manual
//! migration or configuration on the target platform.

use crate::wireguard_dependencies::WireGuardDependencyReport;

use super::ExtraFinding;

/// Build WireGuard configuration gap findings.
///
/// Detects:
/// - WireGuard config present on one side but not the other
/// - WireGuard config present but all entries disabled (no active tunnels)
///
/// # Arguments
///
/// * `report` - WireGuard dependency comparison report
///
/// # Returns
///
/// Vector of WireGuard configuration gap findings
pub(super) fn build_wireguard_extras(report: &WireGuardDependencyReport) -> Vec<ExtraFinding> {
    let mut out = Vec::new();
    if report.left.configured && !report.right.configured {
        out.push(ExtraFinding {
            kind: "wireguard_dependency_gap".to_string(),
            section: "wireguard".to_string(),
            side: "left_to_right".to_string(),
            paths: report.left.paths.iter().take(6).cloned().collect(),
            reason: "WireGuard config exists on left but not on right".to_string(),
        });
    }
    if report.right.configured && !report.left.configured {
        out.push(ExtraFinding {
            kind: "wireguard_dependency_gap".to_string(),
            section: "wireguard".to_string(),
            side: "right_to_left".to_string(),
            paths: report.right.paths.iter().take(6).cloned().collect(),
            reason: "WireGuard config exists on right but not on left".to_string(),
        });
    }
    if report.left.configured && report.left.enabled_entries == 0 {
        out.push(ExtraFinding {
            kind: "wireguard_disabled_config_present".to_string(),
            section: "wireguard".to_string(),
            side: "left".to_string(),
            paths: report.left.paths.iter().take(4).cloned().collect(),
            reason: "WireGuard config is present but currently disabled on left".to_string(),
        });
    }
    if report.right.configured && report.right.enabled_entries == 0 {
        out.push(ExtraFinding {
            kind: "wireguard_disabled_config_present".to_string(),
            section: "wireguard".to_string(),
            side: "right".to_string(),
            paths: report.right.paths.iter().take(4).cloned().collect(),
            reason: "WireGuard config is present but currently disabled on right".to_string(),
        });
    }
    out
}
