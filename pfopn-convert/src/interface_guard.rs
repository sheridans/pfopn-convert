use std::collections::BTreeMap;

use anyhow::{bail, Result};
use xml_diff_core::XmlNode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub name: String,
    pub descr: Option<String>,
    pub if_name: Option<String>,
    pub ipaddr: Option<String>,
    pub subnet: Option<String>,
    pub ipaddr_v6: Option<String>,
    pub subnet_v6: Option<String>,
}

pub fn collect_interfaces(root: &XmlNode) -> BTreeMap<String, InterfaceSpec> {
    let mut out = BTreeMap::new();
    let Some(interfaces) = root.get_child("interfaces") else {
        return out;
    };

    for iface in &interfaces.children {
        let spec = InterfaceSpec {
            name: iface.tag.clone(),
            descr: iface.get_text(&["descr"]).map(|s| s.trim().to_string()),
            if_name: iface.get_text(&["if"]).map(|s| s.trim().to_string()),
            ipaddr: iface.get_text(&["ipaddr"]).map(|s| s.trim().to_string()),
            subnet: iface.get_text(&["subnet"]).map(|s| s.trim().to_string()),
            ipaddr_v6: iface.get_text(&["ipaddrv6"]).map(|s| s.trim().to_string()),
            subnet_v6: iface.get_text(&["subnetv6"]).map(|s| s.trim().to_string()),
        };
        out.insert(spec.name.clone(), spec);
    }
    out
}

pub fn enforce_interface_compat(source: &XmlNode, target: &XmlNode) -> Result<()> {
    let source_map = collect_interfaces(source);
    let target_map = collect_interfaces(target);

    if source_map.is_empty() || target_map.is_empty() {
        bail!(
            "interface preflight failed: source_interfaces={} target_interfaces={}; provide --target-file with interfaces",
            source_map.len(),
            target_map.len()
        );
    }

    let mut missing = Vec::new();
    for (name, src) in &source_map {
        let Some(dst) = target_map.get(name) else {
            if src
                .if_name
                .as_deref()
                .map(is_virtual_if_name)
                .unwrap_or(false)
            {
                // Virtual-backed interfaces (vlan/wg/openvpn/etc) can be created from source config.
                continue;
            }
            missing.push(format_missing(name, src));
            continue;
        };
        let _ = dst;
    }

    if !missing.is_empty() {
        bail!(
            "interface preflight failed: missing target interfaces: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn is_virtual_if_name(if_name: &str) -> bool {
    let lower = if_name.trim().to_ascii_lowercase();
    if lower.contains('.') {
        // VLAN-style parent.tag device naming (e.g. igb0.50).
        return true;
    }
    if lower.contains("wg") {
        // WireGuard-style interface names can be custom and still virtual-backed.
        return true;
    }
    [
        "vlan", "bridge", "ovpns", "ovpnc", "openvpn", "wg", "tun_wg", "gif", "gre", "lagg", "tap",
        "tun", "enc", "ipsec", "lo",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn format_missing(name: &str, spec: &InterfaceSpec) -> String {
    let mut parts = Vec::new();
    if let Some(descr) = spec.descr.as_deref().filter(|d| !d.is_empty()) {
        parts.push(format!("descr={descr}"));
    }
    if let Some(if_name) = spec.if_name.as_deref().filter(|i| !i.is_empty()) {
        parts.push(format!("if={if_name}"));
    }
    if parts.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({})", parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::enforce_interface_compat;

    #[test]
    fn allows_subnet_differences() {
        let source =
            parse(br#"<pfsense><interfaces><lan><subnet>24</subnet></lan></interfaces></pfsense>"#)
                .expect("source parse");
        let target = parse(
            br#"<opnsense><interfaces><lan><subnet>25</subnet></lan></interfaces></opnsense>"#,
        )
        .expect("target parse");

        enforce_interface_compat(&source, &target).expect("subnet differences should not block");
    }

    #[test]
    fn allows_missing_logical_when_virtual_backed() {
        let source = parse(
            br#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan><opt1><if>vlan10</if><subnet>24</subnet></opt1></interfaces></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan></interfaces></opnsense>"#,
        )
        .expect("target parse");
        enforce_interface_compat(&source, &target).expect("virtual-backed missing should pass");
    }

    #[test]
    fn treats_dotted_vlan_style_if_name_as_virtual_backed() {
        let source = parse(
            br#"<pfsense><interfaces><lan><if>igb0</if><subnet>24</subnet></lan><opt3><if>igb0.50</if><subnet>24</subnet></opt3></interfaces></pfsense>"#,
        )
        .expect("source parse");
        let target = parse(
            br#"<opnsense><interfaces><lan><if>vtnet0</if><subnet>24</subnet></lan></interfaces></opnsense>"#,
        )
        .expect("target parse");
        enforce_interface_compat(&source, &target).expect("dotted vlan-backed missing should pass");
    }
}
