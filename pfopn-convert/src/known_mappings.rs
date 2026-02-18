use std::fs;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

/// Canonical mapping metadata for known cross-platform section relationships.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KnownSectionMapping {
    pub left: String,
    pub right: Vec<String>,
    pub category: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
struct MappingFile {
    mapping: Vec<KnownSectionMapping>,
}

/// Errors returned when loading mapping files.
#[derive(Debug, Error)]
pub enum MappingLoadError {
    #[error("failed to read mappings file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse mappings file {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

/// Load section mappings from a TOML file.
pub fn load_section_mappings(path: &Path) -> Result<Vec<KnownSectionMapping>, MappingLoadError> {
    let raw = fs::read_to_string(path).map_err(|source| MappingLoadError::Io {
        path: path.display().to_string(),
        source,
    })?;

    parse_mappings(&raw, path.display().to_string())
}

/// Built-in fallback mappings.
pub fn default_section_mappings() -> Vec<KnownSectionMapping> {
    let embedded = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/mappings/sections.toml"
    ));
    match parse_mappings(embedded, "embedded mappings".to_string()) {
        Ok(mappings) if !mappings.is_empty() => mappings,
        _ => fallback_section_mappings(),
    }
}

fn parse_mappings(raw: &str, path: String) -> Result<Vec<KnownSectionMapping>, MappingLoadError> {
    let parsed: MappingFile =
        toml::from_str(raw).map_err(|source| MappingLoadError::Parse { path, source })?;
    Ok(parsed.mapping)
}

fn fallback_section_mappings() -> Vec<KnownSectionMapping> {
    vec![
        KnownSectionMapping {
            left: "installedpackages".to_string(),
            right: vec!["OPNsense".to_string()],
            category: "packages".to_string(),
            note: "pfSense packages typically move under OPNsense plugin container".to_string(),
        },
        KnownSectionMapping {
            left: "aliases".to_string(),
            right: vec!["Alias".to_string(), "aliases".to_string()],
            category: "firewall".to_string(),
            note: "OPNsense aliases are often nested under OPNsense.Firewall.Alias".to_string(),
        },
        KnownSectionMapping {
            left: "gateways".to_string(),
            right: vec!["Gateways".to_string(), "gateway".to_string()],
            category: "network".to_string(),
            note: "gateway definitions may live under OPNsense plugin subtree".to_string(),
        },
        KnownSectionMapping {
            left: "shaper".to_string(),
            right: vec!["TrafficShaper".to_string(), "shaper".to_string()],
            category: "firewall".to_string(),
            note: "traffic shaper settings frequently move to plugin namespace".to_string(),
        },
        KnownSectionMapping {
            left: "cron".to_string(),
            right: vec!["cron".to_string()],
            category: "system".to_string(),
            note: "cron commonly appears under OPNsense plugin tree".to_string(),
        },
        KnownSectionMapping {
            left: "dhcpd".to_string(),
            right: vec![
                "dhcpd".to_string(),
                "Kea".to_string(),
                "isc".to_string(),
                "DHCRelay".to_string(),
            ],
            category: "dhcp".to_string(),
            note: "legacy ISC DHCP may map to dhcpd, relay, or Kea-based settings".to_string(),
        },
        KnownSectionMapping {
            left: "dhcpdv6".to_string(),
            right: vec![
                "dhcpd6".to_string(),
                "dhcpdv6".to_string(),
                "Kea".to_string(),
                "isc".to_string(),
            ],
            category: "dhcp".to_string(),
            note: "IPv6 DHCP can appear as dhcpd6/dhcpdv6 or Kea/ISC variants".to_string(),
        },
        KnownSectionMapping {
            left: "dhcpd6".to_string(),
            right: vec![
                "dhcpd6".to_string(),
                "dhcpdv6".to_string(),
                "Kea".to_string(),
                "isc".to_string(),
            ],
            category: "dhcp".to_string(),
            note: "Legacy IPv6 DHCP naming varies between dhcpd6 and dhcpdv6; Kea/ISC may coexist"
                .to_string(),
        },
        KnownSectionMapping {
            left: "dnsmasq".to_string(),
            right: vec!["dnsmasq".to_string()],
            category: "dns".to_string(),
            note: "dnsmasq may be enabled directly or represented in plugin subtree".to_string(),
        },
        KnownSectionMapping {
            left: "tailscale".to_string(),
            right: vec!["tailscale".to_string()],
            category: "vpn".to_string(),
            note: "Tailscale plugin exists on both platforms; OPNsense typically stores it under OPNsense.tailscale".to_string(),
        },
        KnownSectionMapping {
            left: "tailscaleauth".to_string(),
            right: vec!["tailscale".to_string()],
            category: "vpn".to_string(),
            note: "pfSense tailscaleauth data maps into OPNsense tailscale settings/auth fields".to_string(),
        },
        KnownSectionMapping {
            left: "ipsec".to_string(),
            right: vec!["IPsec".to_string(), "Swanctl".to_string()],
            category: "vpn".to_string(),
            note: "IPsec is shared across both, with OPNsense often splitting data under IPsec and Swanctl".to_string(),
        },
        KnownSectionMapping {
            left: "vtimaps".to_string(),
            right: vec!["VTIs".to_string()],
            category: "vpn".to_string(),
            note: "pfSense vtimaps commonly correspond to OPNsense Swanctl VTIs".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        default_section_mappings, load_section_mappings, parse_mappings, MappingLoadError,
    };
    use std::fs;

    #[test]
    fn loads_valid_mappings_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sections.toml");
        fs::write(
            &path,
            r#"
[[mapping]]
left = "foo"
right = ["bar", "baz"]
category = "test"
note = "example"
"#,
        )
        .expect("write mappings");

        let mappings = load_section_mappings(&path).expect("mappings should parse");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].left, "foo");
        assert_eq!(mappings[0].right, vec!["bar", "baz"]);
    }

    #[test]
    fn returns_parse_error_for_invalid_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.toml");
        fs::write(&path, "not = [valid").expect("write broken file");

        let err = load_section_mappings(&path).expect_err("should fail parse");
        match err {
            MappingLoadError::Parse { .. } => {}
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn default_mappings_are_non_empty() {
        let defaults = default_section_mappings();
        assert!(!defaults.is_empty());
    }

    #[test]
    fn embedded_mappings_parse() {
        let embedded = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/mappings/sections.toml"
        ));
        let mappings = parse_mappings(embedded, "embedded mappings".to_string())
            .expect("embedded mappings should parse");
        assert!(mappings.iter().any(|m| m.left == "installedpackages"));
    }
}
