//! pfSense IPsec to OPNsense IPsec/Swanctl conversion.
//!
//! This module handles the conversion of IPsec VPN configurations from pfSense's
//! phase1/phase2 structure to OPNsense's Swanctl (strongSwan) format.
//!
//! ## Platform Differences
//!
//! **pfSense IPsec structure:**
//! - Uses `<phase1>` for IKE (Internet Key Exchange) tunnel configuration
//! - Uses `<phase2>` for ESP (Encapsulating Security Payload) child SA configuration
//! - Pre-shared keys embedded in phase1 entries
//! - Simpler, flatter structure based on racoon/charon legacy format
//!
//! **OPNsense IPsec structure:**
//! - Uses strongSwan's swanctl configuration model
//! - Splits into two top-level sections:
//!   - `<OPNsense><IPsec>` — General settings and pre-shared keys
//!   - `<OPNsense><Swanctl>` — Connection definitions, locals, remotes, children
//! - More granular control with separate local/remote authentication config
//! - Each connection has associated local, remote, and child elements linked by UUID
//!
//! ## Mapping Overview
//!
//! For each pfSense `<phase1>`:
//! - Creates an OPNsense `<Swanctl><Connection>` (IKE SA config)
//! - Creates a `<Swanctl><local>` (local endpoint auth)
//! - Creates a `<Swanctl><remote>` (remote endpoint auth)
//! - Extracts pre-shared key into `<OPNsense><IPsec><preSharedKeys>`
//!
//! For each matching pfSense `<phase2>` (matched by ikeid):
//! - Creates an OPNsense `<Swanctl><child>` (ESP child SA)
//! - Links it to the parent Connection via UUID
//!
//! All elements are assigned deterministic UUIDs based on their ikeid and index
//! to ensure stable identifiers across repeated conversions.

use xml_diff_core::XmlNode;

mod base;
mod mapper;
mod util;

/// Convert pfSense IPsec configuration to OPNsense IPsec and Swanctl format.
///
/// Returns a tuple of `(IPsec, Swanctl)` XML nodes:
/// - The first node contains OPNsense IPsec settings (general config, pre-shared keys)
/// - The second node contains OPNsense Swanctl config (connections, locals, remotes, children)
///
/// Both nodes should be inserted into the output tree under `<OPNsense>`.
///
/// # Example structure
///
/// Input (pfSense):
/// ```xml
/// <ipsec>
///   <phase1>
///     <ikeid>1</ikeid>
///     <remote-gateway>198.51.100.10</remote-gateway>
///     <authentication_method>pre_shared_key</authentication_method>
///     <pre-shared-key>secret</pre-shared-key>
///   </phase1>
///   <phase2>
///     <ikeid>1</ikeid>
///     <mode>tunnel</mode>
///     <localid><type>network</type><address>192.168.1.0</address><netbits>24</netbits></localid>
///   </phase2>
/// </ipsec>
/// ```
///
/// Output (OPNsense):
/// ```xml
/// <OPNsense>
///   <IPsec>
///     <general>...</general>
///     <preSharedKeys>
///       <preSharedKey uuid="...">
///         <Key>secret</Key>
///       </preSharedKey>
///     </preSharedKeys>
///   </IPsec>
///   <Swanctl>
///     <Connections>
///       <Connection uuid="...">
///         <remote_addrs>198.51.100.10</remote_addrs>
///       </Connection>
///     </Connections>
///     <locals><local uuid="...">...</local></locals>
///     <remotes><remote uuid="...">...</remote></remotes>
///     <children><child uuid="...">...</child></children>
///   </Swanctl>
/// </OPNsense>
/// ```
pub fn map_pf_ipsec_to_opnsense(source_ipsec: &XmlNode) -> (XmlNode, XmlNode) {
    mapper::map_pf_ipsec_to_opnsense(source_ipsec)
}
