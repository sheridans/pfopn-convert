use std::fs;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginSupportStatus {
    Supported,
    Partial,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PluginMatrixEntry {
    pub id: String,
    #[serde(default)]
    pub pfsense_markers: Vec<String>,
    #[serde(default)]
    pub opnsense_markers: Vec<String>,
    #[serde(default)]
    pub compatible_targets: Vec<String>,
    pub status: PluginSupportStatus,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMatrix {
    pub entries: Vec<PluginMatrixEntry>,
}

#[derive(Debug, Deserialize)]
struct PluginMatrixFile {
    plugin: Vec<PluginMatrixEntry>,
}

#[derive(Debug, Error)]
pub enum PluginMatrixLoadError {
    #[error("failed to read plugin matrix {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse plugin matrix {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

pub fn load_plugin_matrix(path: &Path) -> Result<PluginMatrix, PluginMatrixLoadError> {
    let raw = fs::read_to_string(path).map_err(|source| PluginMatrixLoadError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_plugin_matrix(&raw, path.display().to_string())
}

pub fn default_plugin_matrix() -> PluginMatrix {
    let embedded = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/mappings/plugins.toml"
    ));
    match parse_plugin_matrix(embedded, "embedded plugin matrix".to_string()) {
        Ok(matrix) if !matrix.entries.is_empty() => matrix,
        _ => fallback_plugin_matrix(),
    }
}

fn parse_plugin_matrix(raw: &str, path: String) -> Result<PluginMatrix, PluginMatrixLoadError> {
    let parsed: PluginMatrixFile =
        toml::from_str(raw).map_err(|source| PluginMatrixLoadError::Parse { path, source })?;
    Ok(PluginMatrix {
        entries: parsed.plugin,
    })
}

fn fallback_plugin_matrix() -> PluginMatrix {
    PluginMatrix {
        entries: vec![
            PluginMatrixEntry {
                id: "wireguard".to_string(),
                pfsense_markers: vec!["wireguard".to_string()],
                opnsense_markers: vec!["os-wireguard".to_string(), "wireguard".to_string()],
                compatible_targets: vec!["pfsense".to_string(), "opnsense".to_string()],
                status: PluginSupportStatus::Supported,
                note: "Supported on both platforms".to_string(),
            },
            PluginMatrixEntry {
                id: "tailscale".to_string(),
                pfsense_markers: vec!["tailscale".to_string(), "tailscaleauth".to_string()],
                opnsense_markers: vec!["os-tailscale".to_string(), "tailscale".to_string()],
                compatible_targets: vec!["pfsense".to_string(), "opnsense".to_string()],
                status: PluginSupportStatus::Supported,
                note: "Supported on both platforms".to_string(),
            },
            PluginMatrixEntry {
                id: "openvpn".to_string(),
                pfsense_markers: vec![
                    "openvpn".to_string(),
                    "ovpnserver".to_string(),
                    "openvpn-client-export".to_string(),
                ],
                opnsense_markers: vec!["openvpn".to_string(), "os-openvpn-legacy".to_string()],
                compatible_targets: vec!["pfsense".to_string(), "opnsense".to_string()],
                status: PluginSupportStatus::Supported,
                note: "Core VPN support exists on both".to_string(),
            },
            PluginMatrixEntry {
                id: "ipsec".to_string(),
                pfsense_markers: vec!["ipsec".to_string()],
                opnsense_markers: vec!["ipsec".to_string(), "swanctl".to_string()],
                compatible_targets: vec!["pfsense".to_string(), "opnsense".to_string()],
                status: PluginSupportStatus::Partial,
                note: "Layouts differ, requires mapping".to_string(),
            },
            PluginMatrixEntry {
                id: "isc-dhcp".to_string(),
                pfsense_markers: vec![
                    "dhcpd".to_string(),
                    "dhcpdv6".to_string(),
                    "dhcpd6".to_string(),
                ],
                opnsense_markers: vec!["os-isc-dhcp".to_string(), "dhcpd".to_string()],
                compatible_targets: vec!["pfsense".to_string(), "opnsense".to_string()],
                status: PluginSupportStatus::Supported,
                note: "Legacy ISC backend on both".to_string(),
            },
            PluginMatrixEntry {
                id: "kea-dhcp".to_string(),
                pfsense_markers: vec!["dhcpbackend".to_string(), "kea".to_string()],
                opnsense_markers: vec!["os-kea".to_string(), "kea".to_string()],
                compatible_targets: vec!["pfsense".to_string(), "opnsense".to_string()],
                status: PluginSupportStatus::Partial,
                note: "Kea layout differs by platform".to_string(),
            },
            PluginMatrixEntry {
                id: "system_patches".to_string(),
                pfsense_markers: vec![
                    "system patches".to_string(),
                    "system_patches".to_string(),
                    "system_patches_pkg".to_string(),
                ],
                opnsense_markers: vec![],
                compatible_targets: vec!["pfsense".to_string()],
                status: PluginSupportStatus::Unsupported,
                note: "No known OPNsense equivalent".to_string(),
            },
            PluginMatrixEntry {
                id: "pfblockerng".to_string(),
                pfsense_markers: vec!["pfblockerng".to_string(), "pfblockerng-devel".to_string()],
                opnsense_markers: vec![],
                compatible_targets: vec!["pfsense".to_string()],
                status: PluginSupportStatus::Unsupported,
                note: "No direct OPNsense equivalent".to_string(),
            },
        ],
    }
}

impl PluginMatrix {
    pub fn find_by_id(&self, id: &str) -> Option<&PluginMatrixEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn find_by_marker(&self, platform: &str, marker: &str) -> Option<&PluginMatrixEntry> {
        let marker = marker.trim().to_ascii_lowercase();
        self.entries.iter().find(|entry| {
            let markers = match platform {
                "pfsense" => &entry.pfsense_markers,
                "opnsense" => &entry.opnsense_markers,
                _ => return false,
            };
            markers.iter().any(|m| m.to_ascii_lowercase() == marker)
        })
    }

    pub fn is_target_compatible(&self, id: &str, target: &str) -> bool {
        let Some(entry) = self.find_by_id(id) else {
            return false;
        };
        entry
            .compatible_targets
            .iter()
            .any(|t| t.eq_ignore_ascii_case(target))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{default_plugin_matrix, load_plugin_matrix, PluginSupportStatus};

    #[test]
    fn loads_plugin_matrix_from_toml() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("plugins.toml");
        fs::write(
            &path,
            r#"
[[plugin]]
id = "example"
pfsense_markers = ["pkg-example"]
opnsense_markers = ["os-example"]
compatible_targets = ["pfsense"]
status = "partial"
note = "example mapping"
"#,
        )
        .expect("write matrix");

        let matrix = load_plugin_matrix(&path).expect("load matrix");
        let entry = matrix.find_by_id("example").expect("entry");
        assert_eq!(entry.status, PluginSupportStatus::Partial);
        assert!(matrix.find_by_marker("pfsense", "pkg-example").is_some());
        assert!(!matrix.is_target_compatible("example", "opnsense"));
    }

    #[test]
    fn default_matrix_covers_core_plugin_ids() {
        let matrix = default_plugin_matrix();
        assert!(matrix.find_by_id("wireguard").is_some());
        assert!(matrix.find_by_id("tailscale").is_some());
        assert!(matrix.find_by_id("openvpn").is_some());
        assert!(matrix.find_by_id("ipsec").is_some());
        assert!(matrix.find_by_id("isc-dhcp").is_some());
        assert!(matrix.find_by_id("kea-dhcp").is_some());
    }

    #[test]
    fn embedded_matrix_includes_strongswan_marker() {
        let matrix = default_plugin_matrix();
        let entry = matrix.find_by_id("ipsec").expect("ipsec entry");
        assert!(entry
            .opnsense_markers
            .iter()
            .any(|m| m == "os-strongswan-legacy"));
    }
}
