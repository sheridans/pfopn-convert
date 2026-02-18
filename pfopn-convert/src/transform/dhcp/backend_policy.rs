use anyhow::{bail, Result};
use xml_diff_core::XmlNode;

use crate::backend_detect::detect_dhcp_backend;
use crate::detect::{detect_config, detect_version_info, ConfigFlavor};

/// User-requested DHCP backend preference.
///
/// This enum represents what the user explicitly requested via CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedDhcpBackend {
    /// Automatically select based on version and existing config
    Auto,
    /// Force use of Kea DHCP backend
    Kea,
    /// Force use of ISC DHCP backend
    Isc,
}

/// The actual DHCP backend that will be used for conversion.
///
/// After analyzing the requested backend, source config, and target config,
/// this represents the final backend decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveDhcpBackend {
    /// Use Kea DHCP format
    Kea,
    /// Use ISC DHCP format
    Isc,
}

/// Resolve which DHCP backend should be used based on user request and config state.
///
/// This function implements the backend selection logic that considers:
/// - User's explicit request (Auto, Kea, or Isc)
/// - Target platform and version (OPNsense 26+ defaults to Kea)
/// - Existing backend in source config (detected via markers)
/// - Existing backend in target config (Kea structure present?)
///
/// ## Selection Logic
///
/// **For OPNsense targets:**
/// - If user explicitly requested Kea or Isc, use that
/// - If Auto and target is OPNsense 26+, default to Kea
/// - If Auto and target is older, detect source backend and fall back to target backend
///
/// **For pfSense targets:**
/// - Same logic, but no version-based default (pfSense doesn't have native Kea yet)
///
/// # Arguments
///
/// * `requested` - User's backend preference
/// * `source` - Source configuration being converted
/// * `target` - Target configuration template
/// * `to_platform` - Target platform name ("opnsense" or "pfsense")
///
/// # Returns
///
/// The effective backend to use for conversion
pub fn resolve_effective_backend(
    requested: RequestedDhcpBackend,
    source: &XmlNode,
    target: &XmlNode,
    to_platform: &str,
) -> EffectiveDhcpBackend {
    if to_platform != "opnsense" {
        return match requested {
            RequestedDhcpBackend::Kea => EffectiveDhcpBackend::Kea,
            RequestedDhcpBackend::Isc => EffectiveDhcpBackend::Isc,
            RequestedDhcpBackend::Auto => {
                let source_mode = detect_dhcp_backend(source).mode;
                match source_mode.as_str() {
                    "kea" | "mixed" => EffectiveDhcpBackend::Kea,
                    "isc" => EffectiveDhcpBackend::Isc,
                    _ => match detect_dhcp_backend(target).mode.as_str() {
                        "kea" | "mixed" => EffectiveDhcpBackend::Kea,
                        _ => EffectiveDhcpBackend::Isc,
                    },
                }
            }
        };
    }

    match requested {
        RequestedDhcpBackend::Kea => EffectiveDhcpBackend::Kea,
        RequestedDhcpBackend::Isc => EffectiveDhcpBackend::Isc,
        RequestedDhcpBackend::Auto => {
            if is_opnsense_26_or_newer(target) {
                EffectiveDhcpBackend::Kea
            } else {
                let source_mode = detect_dhcp_backend(source).mode;
                match source_mode.as_str() {
                    "kea" | "mixed" => EffectiveDhcpBackend::Kea,
                    "isc" => EffectiveDhcpBackend::Isc,
                    _ => match detect_dhcp_backend(target).mode.as_str() {
                        "kea" | "mixed" => EffectiveDhcpBackend::Kea,
                        _ => EffectiveDhcpBackend::Isc,
                    },
                }
            }
        }
    }
}

/// Validate that the target config has the necessary structure for the chosen backend.
///
/// This function checks that the target configuration has all required elements
/// to support the effective backend. For example, if Kea is selected, the target
/// must have `<OPNsense><Kea>` structure. If ISC is selected for OPNsense 26+,
/// the target must have the `os-isc-dhcp` plugin declared.
///
/// ## Validation Rules
///
/// **For Kea backend:**
/// - OPNsense targets must have `<OPNsense><Kea>` subtree
/// - Skipped for pfSense targets (no native Kea support yet)
/// - Skipped for OPNsense <26 unless explicitly requested
///
/// **For ISC backend:**
/// - OPNsense 26+ targets must have `os-isc-dhcp` plugin in firmware.plugins
/// - Must have at least one of: `<dhcpd>`, `<dhcpdv6>`, or `<dhcpd6>`
/// - Skipped for OPNsense <26 unless explicitly requested
///
/// # Arguments
///
/// * `target` - Target configuration to validate
/// * `requested` - User's original backend request
/// * `backend` - The effective backend that was resolved
///
/// # Returns
///
/// `Ok(())` if target is ready, `Err` with descriptive message if not
pub fn ensure_backend_readiness(
    target: &XmlNode,
    requested: RequestedDhcpBackend,
    backend: EffectiveDhcpBackend,
) -> Result<()> {
    match backend {
        EffectiveDhcpBackend::Kea => {
            if detect_config(target) != ConfigFlavor::OpnSense {
                return Ok(());
            }
            if requested != RequestedDhcpBackend::Kea && !is_opnsense_26_or_newer(target) {
                return Ok(());
            }
            let has_kea = target
                .get_child("OPNsense")
                .and_then(|n| n.get_child("Kea"))
                .is_some();
            if !has_kea {
                bail!(
                    "target OPNsense config is missing OPNsense.Kea subtree required for Kea backend"
                );
            }
            Ok(())
        }
        EffectiveDhcpBackend::Isc => {
            if detect_config(target) != ConfigFlavor::OpnSense {
                return Ok(());
            }
            if requested != RequestedDhcpBackend::Isc && !is_opnsense_26_or_newer(target) {
                return Ok(());
            }
            if !opnsense_has_declared_plugin(target, "os-isc-dhcp") {
                bail!(
                    "target OPNsense config requires os-isc-dhcp plugin for ISC backend (system.firmware.plugins)"
                );
            }
            let has_legacy = target.get_child("dhcpd").is_some()
                || target.get_child("dhcpdv6").is_some()
                || target.get_child("dhcpd6").is_some();
            if !has_legacy {
                bail!(
                    "target OPNsense config missing legacy ISC DHCP sections (dhcpd/dhcpdv6/dhcpd6)"
                );
            }
            Ok(())
        }
    }
}

/// Enforce the chosen DHCP backend in the output configuration.
///
/// This function modifies the output XML tree to match the effective backend:
/// - Removes conflicting DHCP config sections
/// - Ensures required structure exists
/// - Sets backend markers and flags
///
/// ## For OPNsense output with Kea backend:
/// - Removes `<dhcpd>` (IPv4 ISC config)
/// - Optionally preserves `<dhcpdv6>` and `<dhcpd6>` if `preserve_ipv6_legacy` is true
/// - Ensures `<OPNsense><Kea>` structure exists
///
/// ## For OPNsense output with ISC backend:
/// - Disables Kea by setting `<OPNsense><Kea><dhcp4><general><enabled>` to "0"
/// - Also disables `<dhcp6><general><enabled>` to "0"
///
/// ## For pfSense output with Kea backend:
/// - Sets `<dhcpbackend>kea</dhcpbackend>` marker
/// - Ensures `<kea>` structure exists
/// - Removes conflicting ISC sections (`<dhcpd>`, `<dhcpdv6>`, `<dhcpd6>`)
///
/// ## For pfSense output with ISC backend:
/// - Sets `<dhcpbackend>isc</dhcpbackend>` marker
/// - Removes `<kea>` structure
///
/// # Arguments
///
/// * `root` - The output XML tree to modify
/// * `backend` - The effective backend to enforce
/// * `to_platform` - Target platform ("opnsense" or "pfsense")
/// * `preserve_ipv6_legacy` - If true, keep IPv6 ISC config even when using Kea
pub fn enforce_output_backend(
    root: &mut XmlNode,
    backend: EffectiveDhcpBackend,
    to_platform: &str,
    preserve_ipv6_legacy: bool,
) {
    if to_platform == "opnsense" {
        match backend {
            EffectiveDhcpBackend::Kea => {
                if preserve_ipv6_legacy {
                    root.children.retain(|c| c.tag != "dhcpd");
                } else {
                    root.children
                        .retain(|c| c.tag != "dhcpd" && c.tag != "dhcpdv6" && c.tag != "dhcpd6");
                }
                let opn = ensure_child_mut(root, "OPNsense");
                ensure_child_mut(opn, "Kea");
            }
            EffectiveDhcpBackend::Isc => {
                disable_opnsense_kea(root);
            }
        }
        return;
    }

    if to_platform == "pfsense" {
        match backend {
            EffectiveDhcpBackend::Kea => {
                set_or_insert_top_text(root, "dhcpbackend", "kea");
                if root.get_child("kea").is_none() {
                    root.children.push(XmlNode::new("kea"));
                }
                // Remove legacy ISC sections that conflict with Kea backend
                root.children
                    .retain(|c| c.tag != "dhcpd" && c.tag != "dhcpdv6" && c.tag != "dhcpd6");
            }
            EffectiveDhcpBackend::Isc => {
                set_or_insert_top_text(root, "dhcpbackend", "isc");
                root.children.retain(|c| c.tag != "kea");
            }
        }
    }
}

/// Check if the configuration contains legacy ISC DHCP data.
///
/// Returns `true` if any of the ISC DHCP config sections exist:
/// - `<dhcpd>` — IPv4 DHCP server config
/// - `<dhcpdv6>` — IPv6 DHCP server config (OPNsense naming)
/// - `<dhcpd6>` — IPv6 DHCP server config (alternative naming)
pub fn has_legacy_dhcp_data(root: &XmlNode) -> bool {
    root.get_child("dhcpd").is_some()
        || root.get_child("dhcpdv6").is_some()
        || root.get_child("dhcpd6").is_some()
}

/// Check if the target is OPNsense version 26 or newer.
///
/// OPNsense 26.x introduced Kea DHCP as the preferred backend and deprecated
/// ISC DHCP. This function helps determine if Kea should be the default.
///
/// # Returns
///
/// `true` if target is OPNsense with major version >= 26, `false` otherwise
fn is_opnsense_26_or_newer(target: &XmlNode) -> bool {
    if detect_config(target) != ConfigFlavor::OpnSense {
        return false;
    }
    let version = detect_version_info(target).value;
    let mut parts = version.split('.');
    let major = parts
        .next()
        .and_then(|m| m.trim().parse::<u32>().ok())
        .unwrap_or(0);
    major >= 26
}

/// Check if an OPNsense config has a specific plugin declared in firmware settings.
///
/// OPNsense plugins are listed in `<system><firmware><plugins>` as a space/comma/semicolon-
/// separated string. This function checks if a specific plugin is in that list.
///
/// # Arguments
///
/// * `root` - The configuration root
/// * `plugin` - Plugin name to search for (e.g., "os-isc-dhcp")
///
/// # Returns
///
/// `true` if the plugin is declared, `false` otherwise
fn opnsense_has_declared_plugin(root: &XmlNode, plugin: &str) -> bool {
    let plugins = root
        .get_child("system")
        .and_then(|s| s.get_child("firmware"))
        .and_then(|f| f.get_text(&["plugins"]))
        .unwrap_or("");
    plugins
        .split([' ', ',', ';'])
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case(plugin))
}

/// Get or create a mutable reference to a child node by tag name.
///
/// If the child exists, returns a reference to it. Otherwise, creates a new
/// empty child with the given tag and returns a reference to it.
fn ensure_child_mut<'a>(node: &'a mut XmlNode, tag: &str) -> &'a mut XmlNode {
    if let Some(pos) = node.children.iter().position(|c| c.tag == tag) {
        return &mut node.children[pos];
    }
    node.children.push(XmlNode::new(tag));
    let len = node.children.len();
    &mut node.children[len - 1]
}

/// Set or insert a top-level text element.
///
/// If an element with the given tag exists as a direct child of root, updates
/// its text value. Otherwise, creates a new element with the tag and text.
fn set_or_insert_top_text(root: &mut XmlNode, tag: &str, value: &str) {
    if let Some(node) = root.children.iter_mut().find(|c| c.tag == tag) {
        node.text = Some(value.to_string());
        return;
    }
    let mut node = XmlNode::new(tag);
    node.text = Some(value.to_string());
    root.children.push(node);
}

/// Disable Kea DHCP in an OPNsense configuration.
///
/// Sets `<enabled>0</enabled>` in both `<OPNsense><Kea><dhcp4><general>` and
/// `<OPNsense><Kea><dhcp6><general>` to disable Kea for both IPv4 and IPv6.
///
/// This is used when enforcing ISC backend - we disable Kea but keep its
/// structure intact (rather than deleting it) to preserve any custom settings.
fn disable_opnsense_kea(root: &mut XmlNode) {
    let Some(opn) = root.children.iter_mut().find(|c| c.tag == "OPNsense") else {
        return;
    };
    let Some(kea) = opn.children.iter_mut().find(|c| c.tag == "Kea") else {
        return;
    };
    for family in ["dhcp4", "dhcp6"] {
        let Some(family_node) = kea.children.iter_mut().find(|c| c.tag == family) else {
            continue;
        };
        let general_idx =
            if let Some(pos) = family_node.children.iter().position(|c| c.tag == "general") {
                pos
            } else {
                family_node.children.push(XmlNode::new("general"));
                family_node.children.len() - 1
            };
        let general = &mut family_node.children[general_idx];
        if let Some(enabled) = general.children.iter_mut().find(|c| c.tag == "enabled") {
            enabled.text = Some("0".to_string());
        } else {
            let mut enabled = XmlNode::new("enabled");
            enabled.text = Some("0".to_string());
            general.children.push(enabled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        enforce_output_backend, ensure_backend_readiness, has_legacy_dhcp_data,
        resolve_effective_backend, EffectiveDhcpBackend, RequestedDhcpBackend,
    };
    use xml_diff_core::parse;

    #[test]
    fn auto_defaults_to_kea_for_opnsense_26() {
        let target =
            parse(br#"<opnsense><version>26.1</version><OPNsense><Kea/></OPNsense></opnsense>"#)
                .expect("parse");
        let source = parse(br#"<pfsense><dhcpd/></pfsense>"#).expect("parse");
        let backend =
            resolve_effective_backend(RequestedDhcpBackend::Auto, &source, &target, "opnsense");
        assert_eq!(backend, EffectiveDhcpBackend::Kea);
    }

    #[test]
    fn auto_uses_detected_backend_for_older_opnsense() {
        let target =
            parse(br#"<opnsense><version>24.7</version><dhcpd/></opnsense>"#).expect("parse");
        let source = parse(br#"<pfsense><dhcpd/></pfsense>"#).expect("parse");
        let backend =
            resolve_effective_backend(RequestedDhcpBackend::Auto, &source, &target, "opnsense");
        assert_eq!(backend, EffectiveDhcpBackend::Isc);
    }

    #[test]
    fn auto_prefers_source_kea_for_older_opnsense() {
        let target =
            parse(br#"<opnsense><version>24.7</version><dhcpd/></opnsense>"#).expect("parse");
        let source =
            parse(br#"<pfsense><dhcpbackend>kea</dhcpbackend><dhcpd/></pfsense>"#).expect("parse");
        let backend =
            resolve_effective_backend(RequestedDhcpBackend::Auto, &source, &target, "opnsense");
        assert_eq!(backend, EffectiveDhcpBackend::Kea);
    }

    #[test]
    fn auto_prefers_source_kea_for_pfsense_target() {
        let source = parse(
            br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general></dhcp4></Kea></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let target = parse(br#"<pfsense><dhcpd/></pfsense>"#).expect("parse");
        let backend =
            resolve_effective_backend(RequestedDhcpBackend::Auto, &source, &target, "pfsense");
        assert_eq!(backend, EffectiveDhcpBackend::Kea);
    }

    #[test]
    fn legacy_detection_includes_dhcpd6_alias() {
        let root = parse(br#"<opnsense><dhcpd6/></opnsense>"#).expect("parse");
        assert!(has_legacy_dhcp_data(&root));
    }

    #[test]
    fn isc_readiness_accepts_dhcpd6_alias_on_opnsense() {
        let target = parse(
            br#"<opnsense><version>26.1</version><system><firmware><plugins>os-isc-dhcp</plugins></firmware></system><dhcpd6/></opnsense>"#,
        )
        .expect("parse");
        let result = ensure_backend_readiness(
            &target,
            RequestedDhcpBackend::Isc,
            EffectiveDhcpBackend::Isc,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn isc_enforcement_keeps_kea_container_but_disables_it() {
        let mut root = parse(
            br#"<opnsense><OPNsense><Kea><dhcp4><general><enabled>1</enabled></general></dhcp4><dhcp6><general><enabled>1</enabled></general></dhcp6></Kea></OPNsense></opnsense>"#,
        )
        .expect("parse");
        enforce_output_backend(&mut root, EffectiveDhcpBackend::Isc, "opnsense", false);

        assert_eq!(
            root.get_text(&["OPNsense", "Kea", "dhcp4", "general", "enabled"]),
            Some("0")
        );
        assert_eq!(
            root.get_text(&["OPNsense", "Kea", "dhcp6", "general", "enabled"]),
            Some("0")
        );
    }

    #[test]
    fn kea_enforcement_preserves_dhcpdv6_when_requested() {
        let mut root =
            parse(br#"<opnsense><dhcpd/><dhcpdv6/><dhcpd6/></opnsense>"#).expect("parse config");
        enforce_output_backend(&mut root, EffectiveDhcpBackend::Kea, "opnsense", true);

        assert!(root.get_child("dhcpdv6").is_some());
        assert!(root.get_child("dhcpd6").is_some());
        assert!(root.get_child("dhcpd").is_none());
    }

    #[test]
    fn kea_enforcement_removes_isc_for_pfsense() {
        let mut root =
            parse(br#"<pfsense><dhcpd/><dhcpdv6/><dhcpd6/></pfsense>"#).expect("parse config");
        enforce_output_backend(&mut root, EffectiveDhcpBackend::Kea, "pfsense", false);

        assert!(root.get_child("dhcpd").is_none());
        assert!(root.get_child("dhcpdv6").is_none());
        assert!(root.get_child("dhcpd6").is_none());
        assert!(root.get_child("kea").is_some());
        assert_eq!(root.get_text(&["dhcpbackend"]), Some("kea"));
    }

    #[test]
    fn kea_enforcement_removes_dhcpdv6_without_preserve_flag() {
        let mut root =
            parse(br#"<opnsense><dhcpd/><dhcpdv6/><dhcpd6/></opnsense>"#).expect("parse config");
        enforce_output_backend(&mut root, EffectiveDhcpBackend::Kea, "opnsense", false);

        assert!(root.get_child("dhcpdv6").is_none());
        assert!(root.get_child("dhcpd6").is_none());
        assert!(root.get_child("dhcpd").is_none());
    }
}
