use serde::Serialize;
use xml_diff_core::XmlNode;

/// Detected configuration family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFlavor {
    /// pfSense root format.
    PfSense,
    /// OPNsense root format.
    OpnSense,
    /// Unrecognized root format.
    Unknown,
}

/// Detected version value with provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionDetection {
    pub value: String,
    pub source: String,
    pub confidence: String,
}

/// Detect config family from the root tag.
pub fn detect_config(node: &XmlNode) -> ConfigFlavor {
    match node.tag.as_str() {
        "pfsense" => ConfigFlavor::PfSense,
        "opnsense" => ConfigFlavor::OpnSense,
        _ => ConfigFlavor::Unknown,
    }
}

/// Return the `<version>` child text if present.
pub fn detect_version(node: &XmlNode) -> Option<&str> {
    node.get_child("version").and_then(|v| v.text.as_deref())
}

/// Detect platform version with source metadata.
pub fn detect_version_info(node: &XmlNode) -> VersionDetection {
    if let Some(v) = detect_version(node).filter(|v| !v.trim().is_empty()) {
        return VersionDetection {
            value: v.to_string(),
            source: format!("{}.version", node.tag),
            confidence: "high".to_string(),
        };
    }

    if let Some(system) = node.get_child("system") {
        if let Some(v) = system
            .get_child("version")
            .and_then(|n| n.text.as_deref())
            .filter(|v| !v.trim().is_empty())
        {
            return VersionDetection {
                value: v.to_string(),
                source: format!("{}.system.version", node.tag),
                confidence: "medium".to_string(),
            };
        }

        if let Some(firmware) = system.get_child("firmware") {
            if let Some(attr) = firmware.attributes.get("version") {
                return VersionDetection {
                    value: attr.clone(),
                    source: format!("{}.system.firmware@version", node.tag),
                    confidence: "low".to_string(),
                };
            }
        }
    }

    VersionDetection {
        value: "unknown".to_string(),
        source: "not found".to_string(),
        confidence: "low".to_string(),
    }
}
