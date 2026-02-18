use serde::Serialize;
use xml_diff_core::XmlNode;

use crate::detect::{detect_config, ConfigFlavor};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginState {
    pub plugin: String,
    pub declared: bool,
    pub configured: bool,
    pub enabled: bool,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginInventory {
    pub platform: String,
    pub plugins: Vec<PluginState>,
}

struct PluginDefinition {
    name: &'static str,
    pfsense_package_names: &'static [&'static str],
    pfsense_top_sections: &'static [&'static str],
    opnsense_package_names: &'static [&'static str],
    opnsense_plugin_sections: &'static [&'static str],
}

const PLUGINS: &[PluginDefinition] = &[
    PluginDefinition {
        name: "wireguard",
        pfsense_package_names: &["wireguard"],
        pfsense_top_sections: &["wireguard"],
        opnsense_package_names: &["os-wireguard"],
        opnsense_plugin_sections: &["Wireguard"],
    },
    PluginDefinition {
        name: "tailscale",
        pfsense_package_names: &["tailscale"],
        pfsense_top_sections: &["tailscale", "tailscaleauth"],
        opnsense_package_names: &["os-tailscale"],
        opnsense_plugin_sections: &["tailscale"],
    },
    PluginDefinition {
        name: "openvpn",
        pfsense_package_names: &[],
        pfsense_top_sections: &["openvpn", "ovpnserver"],
        opnsense_package_names: &["os-openvpn-client-export"],
        opnsense_plugin_sections: &["OpenVPN", "OpenVPNExport"],
    },
    PluginDefinition {
        name: "ipsec",
        pfsense_package_names: &[],
        pfsense_top_sections: &["ipsec"],
        opnsense_package_names: &[],
        opnsense_plugin_sections: &["IPsec", "Swanctl"],
    },
    PluginDefinition {
        name: "kea-dhcp",
        pfsense_package_names: &[],
        pfsense_top_sections: &["kea", "dhcpbackend"],
        opnsense_package_names: &["os-kea"],
        opnsense_plugin_sections: &["Kea"],
    },
    PluginDefinition {
        name: "isc-dhcp",
        pfsense_package_names: &[],
        pfsense_top_sections: &["dhcpd", "dhcpdv6", "dhcpd6"],
        opnsense_package_names: &["os-isc-dhcp"],
        opnsense_plugin_sections: &["dhcpd", "dhcpdv6", "dhcpd6", "DHCRelay"],
    },
];

pub fn detect_plugins(root: &XmlNode) -> PluginInventory {
    let platform = match detect_config(root) {
        ConfigFlavor::PfSense => "pfsense",
        ConfigFlavor::OpnSense => "opnsense",
        ConfigFlavor::Unknown => "unknown",
    };

    let mut plugins = Vec::new();
    for def in PLUGINS {
        let state = match detect_config(root) {
            ConfigFlavor::PfSense => detect_pfsense_plugin(def, root),
            ConfigFlavor::OpnSense => detect_opnsense_plugin(def, root),
            ConfigFlavor::Unknown => PluginState {
                plugin: def.name.to_string(),
                declared: false,
                configured: false,
                enabled: false,
                evidence: vec!["unknown platform".to_string()],
            },
        };
        plugins.push(state);
    }

    PluginInventory {
        platform: platform.to_string(),
        plugins,
    }
}

fn detect_pfsense_plugin(def: &PluginDefinition, root: &XmlNode) -> PluginState {
    let mut evidence = Vec::new();
    let installed = collect_pfsense_installed_packages(root);
    let mut declared = false;

    for package in def.pfsense_package_names {
        if installed.iter().any(|p| p.eq_ignore_ascii_case(package)) {
            declared = true;
            evidence.push(format!("installedpackages={package}"));
        }
    }

    let mut configured = false;
    for section in def.pfsense_top_sections {
        if root.get_child(section).is_some() {
            configured = true;
            evidence.push(format!("top_section={section}"));
        }
    }

    PluginState {
        plugin: def.name.to_string(),
        declared,
        configured,
        enabled: detect_enabled_state(root, def.pfsense_top_sections),
        evidence,
    }
}

fn detect_opnsense_plugin(def: &PluginDefinition, root: &XmlNode) -> PluginState {
    let mut evidence = Vec::new();
    let installed = collect_opnsense_declared_plugins(root);
    let mut declared = false;

    for package in def.opnsense_package_names {
        if installed.iter().any(|p| p.eq_ignore_ascii_case(package)) {
            declared = true;
            evidence.push(format!("firmware.plugins={package}"));
        }
    }

    let mut configured = false;
    for section in def.opnsense_plugin_sections {
        let paths = find_paths_by_tag(root, section);
        if !paths.is_empty() {
            configured = true;
            for path in paths.into_iter().take(4) {
                evidence.push(format!("path={path}"));
            }
        }
    }

    PluginState {
        plugin: def.name.to_string(),
        declared,
        configured,
        enabled: detect_enabled_state(root, def.opnsense_plugin_sections),
        evidence,
    }
}

fn detect_enabled_state(root: &XmlNode, section_candidates: &[&str]) -> bool {
    for section in section_candidates {
        let nodes = find_nodes_by_tag(root, section);
        for node in nodes {
            if subtree_has_enabled_true(node) {
                return true;
            }
            if subtree_has_disable_flag(node) {
                return false;
            }
        }
    }
    false
}

fn subtree_has_enabled_true(node: &XmlNode) -> bool {
    if node.tag.eq_ignore_ascii_case("enabled") {
        let value = node
            .text
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        return matches!(value.as_str(), "1" | "yes" | "true" | "enabled" | "on");
    }
    node.children.iter().any(subtree_has_enabled_true)
}

fn subtree_has_disable_flag(node: &XmlNode) -> bool {
    if node.tag.eq_ignore_ascii_case("disable") {
        return true;
    }
    node.children.iter().any(subtree_has_disable_flag)
}

fn collect_pfsense_installed_packages(root: &XmlNode) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(installed) = root.get_child("installedpackages") {
        for package in installed.children.iter().filter(|c| c.tag == "package") {
            if let Some(name) = package.get_text(&["name"]) {
                let name = name.trim();
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

fn collect_opnsense_declared_plugins(root: &XmlNode) -> Vec<String> {
    let Some(system) = root.get_child("system") else {
        return Vec::new();
    };
    let Some(firmware) = system.get_child("firmware") else {
        return Vec::new();
    };
    let Some(plugins) = firmware.get_text(&["plugins"]) else {
        return Vec::new();
    };

    plugins
        .split([' ', ',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn find_paths_by_tag(root: &XmlNode, target: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(root, root.tag.clone())];
    while let Some((node, path)) = stack.pop() {
        if node.tag.eq_ignore_ascii_case(target) {
            out.push(path.clone());
        }
        for child in &node.children {
            stack.push((child, format!("{path}.{}", child.tag)));
        }
    }
    out.sort();
    out
}

fn find_nodes_by_tag<'a>(root: &'a XmlNode, target: &str) -> Vec<&'a XmlNode> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.tag.eq_ignore_ascii_case(target) {
            out.push(node);
        }
        for child in &node.children {
            stack.push(child);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::detect_plugins;

    #[test]
    fn detects_opnsense_declared_and_configured_plugins() {
        let root = parse(
            br#"<opnsense>
                <system><firmware><plugins>os-isc-dhcp os-wireguard</plugins></firmware></system>
                <OPNsense><Wireguard><general><enabled>1</enabled></general></Wireguard></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");
        let inv = detect_plugins(&root);
        let wg = inv
            .plugins
            .iter()
            .find(|p| p.plugin == "wireguard")
            .expect("wireguard");
        assert!(wg.declared);
        assert!(wg.configured);
        assert!(wg.enabled);
    }

    #[test]
    fn detects_lowercase_wireguard_section() {
        let root = parse(
            br#"<opnsense>
                <system><firmware><plugins>os-wireguard</plugins></firmware></system>
                <OPNsense><wireguard><server><enabled>1</enabled></server></wireguard></OPNsense>
            </opnsense>"#,
        )
        .expect("parse");
        let inv = detect_plugins(&root);
        let wg = inv
            .plugins
            .iter()
            .find(|p| p.plugin == "wireguard")
            .expect("wireguard");
        assert!(wg.declared);
        assert!(wg.configured);
        assert!(wg.enabled);
    }

    #[test]
    fn detects_opnsense_isc_dhcp_configured_from_legacy_sections() {
        let root = parse(
            br#"<opnsense>
                <system><firmware><plugins>os-isc-dhcp</plugins></firmware></system>
                <dhcpd><lan><enable>1</enable></lan></dhcpd>
            </opnsense>"#,
        )
        .expect("parse");
        let inv = detect_plugins(&root);
        let isc = inv
            .plugins
            .iter()
            .find(|p| p.plugin == "isc-dhcp")
            .expect("isc-dhcp");
        assert!(isc.declared);
        assert!(isc.configured);
    }

    #[test]
    fn detects_opnsense_isc_dhcp_configured_from_dhcpd6_alias() {
        let root = parse(
            br#"<opnsense>
                <system><firmware><plugins>os-isc-dhcp</plugins></firmware></system>
                <dhcpd6><lan><enable>1</enable></lan></dhcpd6>
            </opnsense>"#,
        )
        .expect("parse");
        let inv = detect_plugins(&root);
        let isc = inv
            .plugins
            .iter()
            .find(|p| p.plugin == "isc-dhcp")
            .expect("isc-dhcp");
        assert!(isc.declared);
        assert!(isc.configured);
    }
}
