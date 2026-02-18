//! DHCP relay agent configuration conversion.
//!
//! This module handles conversion of DHCP relay configuration between pfSense
//! and OPNsense formats. DHCP relay allows a DHCP server on one network to serve
//! DHCP requests from clients on another network.
//!
//! ## Platform Differences
//!
//! **pfSense:**
//! - Relay config stored in `<dhcrelay>` and `<dhcrelay6>` sections
//! - Each section contains interface lists and destination server addresses
//!
//! **OPNsense:**
//! - Same structure (`<dhcrelay>` and `<dhcrelay6>`) for compatibility
//! - Also supports relay via the `os-dhcrelay` plugin with enhanced UI
//! - Plugin config stored in `<OPNsense><dhcrelay>`

use xml_diff_core::XmlNode;

mod common;
mod to_opnsense;
mod to_pfsense;

#[cfg(test)]
mod tests;

/// Convert DHCP relay configuration to OPNsense format.
///
/// Syncs the base relay sections (`<dhcrelay>`, `<dhcrelay6>`) and maps any
/// pfSense-specific relay config to OPNsense plugin format if needed.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    common::sync_relay_sections(out, source);
    to_opnsense::map_pf_relay_to_opnsense_plugin(out, source);
}

/// Convert DHCP relay configuration to pfSense format.
///
/// Syncs the base relay sections and maps any OPNsense plugin relay config back
/// to pfSense's standard relay format.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    common::sync_relay_sections(out, source);
    to_pfsense::map_opnsense_plugin_to_pf_relay(out, source);
}
