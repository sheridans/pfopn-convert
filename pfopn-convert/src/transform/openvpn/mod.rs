//! OpenVPN configuration conversion between pfSense and OPNsense.
//!
//! This module handles bidirectional conversion of OpenVPN server and client
//! configurations, which have significantly different structures between the
//! two platforms.
//!
//! ## Platform Differences
//!
//! **pfSense OpenVPN structure:**
//! - Config lives in `<openvpn>` at the root level
//! - Uses `<openvpn-server>` for server instances
//! - Uses `<openvpn-client>` for client instances
//! - Each instance is a separate XML element with its own configuration
//! - Uses `<vpnid>` to uniquely identify instances
//! - Interface references use "ovpnsN" naming (e.g., ovpns1, ovpns2)
//!
//! **OPNsense OpenVPN structure:**
//! - Config lives in `<OPNsense><OpenVPN><Instances>`
//! - Uses `<Instance>` elements for both servers and clients
//! - Distinguished by `<role>` field: "server" or "client"
//! - Each instance has a UUID attribute for identification
//! - More structured with nested containers
//! - Interface references also use "ovpnsN" naming
//!
//! ## Round-Trip Preservation
//!
//! To support lossless pfSense → OPNsense → pfSense conversions:
//! - When converting from OPNsense to pfSense, the original pfSense config
//!   is detected via `<opnsense_instance_uuid>` markers
//! - The UUID linking allows proper restoration of the original structure
//! - This preserves pfSense-specific fields that don't exist in OPNsense's model
//!
//! ## Dual-Format Support
//!
//! OPNsense outputs maintain BOTH formats:
//! - Native OPNsense format at `<OPNsense><OpenVPN><Instances>`
//! - Compatible pfSense format at `<openvpn>` (for tools expecting it)
//! - Deduplication ensures only one `<openvpn>` element exists

use xml_diff_core::XmlNode;

mod common;
mod opn_to_pf;
mod pf_to_opn;

#[cfg(test)]
mod tests;

/// Convert OpenVPN configuration to OPNsense format.
///
/// Handles two input cases:
/// 1. Source already has OPNsense nested OpenVPN config → use it directly
/// 2. Source has pfSense OpenVPN config → map servers/clients to instances
///
/// The output contains:
/// - OPNsense native format: `<OPNsense><OpenVPN><Instances>`
/// - pfSense compatibility format: `<openvpn>` (normalized or preserved)
///
/// ## Round-Trip Detection
///
/// If the source pfSense config contains `<opnsense_instance_uuid>` markers
/// (from a previous OPNsense → pfSense → OPNsense conversion), the top-level
/// `<openvpn>` is normalized to avoid duplication with the nested structure.
///
/// # Arguments
///
/// * `out` - The output XML tree being constructed
/// * `source` - The source configuration (pfSense or OPNsense)
/// * `target` - The target template (used for default instance structure)
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, target: &XmlNode) {
    // Get OPNsense instances — either from source if already OPNsense format,
    // or by mapping pfSense servers/clients to instances
    let instances = common::source_opnsense_instances(source)
        .unwrap_or_else(|| pf_to_opn::map_pfsense_servers_to_opnsense_instances(source, target));
    if instances.children.is_empty() {
        return;
    }

    // Insert instances into the OPNsense nested structure
    let opn = common::ensure_child_mut(out, "OPNsense");
    let openvpn = common::ensure_child_mut(opn, "OpenVPN");
    common::upsert_child(openvpn, instances);

    // Handle top-level <openvpn> for pfSense compatibility
    if let Some(source_pf_openvpn) = common::source_pfsense_servers(source) {
        // If this came from OPNsense originally (has UUID markers), normalize it
        // Otherwise, preserve the pfSense structure as-is
        if !common::is_opnsense_origin_openvpn(&source_pf_openvpn) {
            common::upsert_child(out, source_pf_openvpn);
        } else {
            common::normalize_top_level_openvpn_for_opnsense(out);
        }
    } else {
        // No pfSense OpenVPN config found, create empty element for compatibility
        common::normalize_top_level_openvpn_for_opnsense(out);
    }
    // Ensure only one <openvpn> element exists
    common::dedupe_top_level_openvpn(out);
}

/// Convert OpenVPN configuration to pfSense format.
///
/// Handles two input cases:
/// 1. Source already has pfSense OpenVPN config → use it directly
/// 2. Source has OPNsense nested OpenVPN config → map instances to servers/clients
///
/// The output contains pfSense-style `<openvpn>` at the root level with
/// `<openvpn-server>` and `<openvpn-client>` children.
///
/// ## Instance to Server/Client Mapping
///
/// OPNsense instances are converted based on their `<role>` field:
/// - `role="server"` → `<openvpn-server>`
/// - `role="client"` → `<openvpn-client>`
///
/// Each instance's UUID is preserved in the output as `<opnsense_instance_uuid>`
/// to enable round-trip conversion back to OPNsense format.
///
/// # Arguments
///
/// * `out` - The output XML tree being constructed
/// * `source` - The source configuration (pfSense or OPNsense)
/// * `_target` - The target template (unused for pfSense conversion)
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _target: &XmlNode) {
    // Get pfSense servers — either from source if already pfSense format,
    // or by mapping OPNsense instances to servers/clients
    let servers = common::source_pfsense_servers(source)
        .unwrap_or_else(|| opn_to_pf::map_opnsense_instances_to_pfsense(source));
    if servers.children.is_empty() {
        return;
    }

    // Insert at root level
    common::upsert_child(out, servers);
    // Ensure only one <openvpn> element exists
    common::dedupe_top_level_openvpn(out);
}
