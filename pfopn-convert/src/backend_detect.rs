use serde::Serialize;
use xml_diff_core::XmlNode;

/// Best-effort DHCP backend identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackendDetection {
    pub mode: String,
    pub reason: String,
    pub evidence_paths: Vec<String>,
}

/// Detect DHCP backend mode from a config root.
pub fn detect_dhcp_backend(root: &XmlNode) -> BackendDetection {
    match root.tag.as_str() {
        "pfsense" => detect_pfsense_backend(root),
        "opnsense" => detect_opnsense_backend(root),
        _ => BackendDetection {
            mode: "unknown".to_string(),
            reason: "unsupported root tag for backend detection".to_string(),
            evidence_paths: vec![root.tag.clone()],
        },
    }
}

/// Describe backend transition between left and right inputs.
pub fn backend_transition(left: &BackendDetection, right: &BackendDetection) -> String {
    format!("{}->{}", left.mode, right.mode)
}

fn detect_pfsense_backend(root: &XmlNode) -> BackendDetection {
    if let Some(value) = root
        .get_child("dhcpbackend")
        .and_then(|n| n.text.as_deref())
    {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized == "kea" || normalized == "isc" {
            return BackendDetection {
                mode: normalized,
                reason: "pfsense explicit <dhcpbackend> value".to_string(),
                evidence_paths: vec!["pfsense.dhcpbackend".to_string()],
            };
        }
    }

    if has_legacy_dhcp_sections(root) {
        return BackendDetection {
            mode: "isc".to_string(),
            reason: "legacy dhcp sections present without explicit backend value".to_string(),
            evidence_paths: legacy_evidence_paths("pfsense"),
        };
    }

    BackendDetection {
        mode: "unknown".to_string(),
        reason: "no recognizable dhcp backend indicators found".to_string(),
        evidence_paths: Vec::new(),
    }
}

fn detect_opnsense_backend(root: &XmlNode) -> BackendDetection {
    let mut kea_paths = Vec::new();
    if is_opnsense_kea_enabled(root, &mut kea_paths) {
        if has_legacy_dhcp_sections(root) {
            return BackendDetection {
                mode: "mixed".to_string(),
                reason: "kea appears enabled while legacy dhcp sections are also present"
                    .to_string(),
                evidence_paths: {
                    let mut p = kea_paths;
                    p.extend(legacy_evidence_paths("opnsense"));
                    p
                },
            };
        }

        return BackendDetection {
            mode: "kea".to_string(),
            reason: "opnsense kea settings enabled".to_string(),
            evidence_paths: kea_paths,
        };
    }

    if has_legacy_dhcp_sections(root) {
        return BackendDetection {
            mode: "isc".to_string(),
            reason: "legacy dhcp sections present and kea appears disabled".to_string(),
            evidence_paths: legacy_evidence_paths("opnsense"),
        };
    }

    BackendDetection {
        mode: "unknown".to_string(),
        reason: "no recognizable dhcp backend indicators found".to_string(),
        evidence_paths: Vec::new(),
    }
}

fn is_opnsense_kea_enabled(root: &XmlNode, evidence: &mut Vec<String>) -> bool {
    let Some(opnsense_plugin) = root.get_child("OPNsense") else {
        return false;
    };
    let Some(kea) = opnsense_plugin.get_child("Kea") else {
        return false;
    };

    let checks = [
        ("dhcp4", "opnsense.OPNsense.Kea.dhcp4.general.enabled"),
        ("dhcp6", "opnsense.OPNsense.Kea.dhcp6.general.enabled"),
        (
            "ctrl_agent",
            "opnsense.OPNsense.Kea.ctrl_agent.general.enabled",
        ),
    ];

    let mut enabled_any = false;
    for (component, path) in checks {
        let Some(comp_node) = kea.get_child(component) else {
            continue;
        };
        let Some(general) = comp_node.get_child("general") else {
            continue;
        };
        let Some(enabled) = general.get_child("enabled") else {
            continue;
        };
        let Some(value) = enabled.text.as_deref() else {
            continue;
        };
        if is_truthy(value) {
            evidence.push(path.to_string());
            enabled_any = true;
        }
    }

    enabled_any
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "on" | "true" | "enabled" | "yes"
    )
}

fn has_legacy_dhcp_sections(root: &XmlNode) -> bool {
    root.get_child("dhcpd").is_some()
        || root.get_child("dhcpdv6").is_some()
        || root.get_child("dhcpd6").is_some()
}

fn legacy_evidence_paths(prefix: &str) -> Vec<String> {
    vec![
        format!("{prefix}.dhcpd"),
        format!("{prefix}.dhcpdv6"),
        format!("{prefix}.dhcpd6"),
    ]
}

#[cfg(test)]
mod tests {
    use super::detect_dhcp_backend;
    use xml_diff_core::parse;

    #[test]
    fn detects_pfsense_kea_via_explicit_flag() {
        let node =
            parse(br#"<pfsense><dhcpbackend>kea</dhcpbackend><dhcpd/></pfsense>"#).expect("parse");
        let backend = detect_dhcp_backend(&node);
        assert_eq!(backend.mode, "kea");
    }

    #[test]
    fn detects_opnsense_isc_when_kea_disabled() {
        let node = parse(
            br#"<opnsense><dhcpd/><dhcpdv6/><OPNsense><Kea><dhcp4><general><enabled>0</enabled></general></dhcp4></Kea></OPNsense></opnsense>"#,
        )
        .expect("parse");
        let backend = detect_dhcp_backend(&node);
        assert_eq!(backend.mode, "isc");
    }

    #[test]
    fn detects_pfsense_isc_from_dhcpd6_alias() {
        let node = parse(br#"<pfsense><dhcpd6/></pfsense>"#).expect("parse");
        let backend = detect_dhcp_backend(&node);
        assert_eq!(backend.mode, "isc");
    }
}
