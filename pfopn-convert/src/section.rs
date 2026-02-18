use std::collections::HashMap;

/// Return default key-field mappings for better repeated-element matching.
pub fn default_key_fields() -> HashMap<String, String> {
    let mut key_fields = HashMap::new();
    key_fields.insert("rule".to_string(), "tracker".to_string());
    key_fields.insert("alias".to_string(), "name".to_string());
    key_fields
}

/// Map a logical section flag to concrete top-level tags.
pub fn section_tags(section: &str) -> Option<&'static [&'static str]> {
    match section {
        "system" => Some(&["system"]),
        "interfaces" => Some(&["interfaces"]),
        "firewall" => Some(&["filter", "nat", "shaper"]),
        "services" => Some(&["dnsmasq", "unbound", "dhcpd", "ntpd"]),
        "vpn" => Some(&["openvpn", "ipsec", "wireguard"]),
        "packages" => Some(&["installedpackages", "OPNsense"]),
        _ => None,
    }
}
