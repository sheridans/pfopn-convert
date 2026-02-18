use xml_diff_core::XmlNode;

/// Top-level config sections that should be copied wholesale from source to output.
///
/// The conversion process starts with a baseline target config (either pfSense or
/// OPNsense default), then applies transformations. However, for these sections,
/// we want the source config's version, not the baseline's defaults. This list
/// defines which sections are completely replaced.
const SYNCED_TOP_LEVEL_SECTIONS: &[&str] = &[
    "version",    // Config schema version
    "system",     // System identity, users, DNS, NTP, etc.
    "interfaces", // All interface assignments and settings
    "filter",     // Firewall rules
    "nat",        // NAT rules (port forwards, outbound NAT, 1:1 NAT)
    "dhcpd",      // DHCPv4 server config
    "dhcpdv6",    // DHCPv6 server config (OPNsense naming)
    "dhcpd6",     // DHCPv6 server config (pfSense naming)
    "dhcrelay",   // DHCP relay (IPv4)
    "dhcrelay6",  // DHCP relay (IPv6, OPNsense naming)
    "dhcp6relay", // DHCP relay (IPv6, pfSense naming)
    "snmpd",      // SNMP daemon config
    "syslog",     // Syslog/logging config
    "rrd",        // RRD graphs config
    "gateways",   // Gateway definitions for multi-WAN
];

/// Replace selected shared top-level sections in `out` with values from `source`.
///
/// This prevents destination baseline defaults from leaking into converted output
/// when those sections should be sourced from the input configuration.
///
/// The conversion process starts with a baseline target config, then modifies it.
/// For the sections listed in SYNCED_TOP_LEVEL_SECTIONS, we want the source's
/// version entirely, not the baseline's. This function performs that wholesale
/// replacement.
///
/// If a section exists in the source, it replaces (or adds) that section in `out`.
/// If a section doesn't exist in the source, it's removed from `out`.
pub fn sync_shared_top_level_sections(out: &mut XmlNode, source: &XmlNode) {
    for tag in SYNCED_TOP_LEVEL_SECTIONS {
        match source.get_child(tag).cloned() {
            Some(src_child) => upsert_top_child(out, src_child),
            None => remove_top_children(out, tag),
        }
    }
}

/// Insert or replace a top-level child node in the root.
fn upsert_top_child(root: &mut XmlNode, node: XmlNode) {
    if let Some(idx) = root.children.iter().position(|c| c.tag == node.tag) {
        root.children[idx] = node;
    } else {
        root.children.push(node);
    }
}

/// Remove all children with a given tag from the root.
fn remove_top_children(root: &mut XmlNode, tag: &str) {
    root.children.retain(|c| c.tag != tag);
}

#[cfg(test)]
mod tests {
    use super::sync_shared_top_level_sections;
    use xml_diff_core::parse;

    #[test]
    fn replaces_synced_sections_from_source() {
        let source = parse(
            br#"<pfsense><system><hostname>src</hostname></system><filter><rule><tracker>1</tracker></rule></filter></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><hostname>dst</hostname></system><filter><rule><tracker>2</tracker></rule></filter></opnsense>"#,
        )
        .expect("parse");

        sync_shared_top_level_sections(&mut out, &source);
        assert_eq!(out.get_text(&["system", "hostname"]), Some("src"));
        assert_eq!(out.get_text(&["filter", "rule", "tracker"]), Some("1"));
    }

    #[test]
    fn syncs_dhcpd6_alias_from_source() {
        let source = parse(br#"<pfsense><dhcpd6><lan><enable>1</enable></lan></dhcpd6></pfsense>"#)
            .expect("parse");
        let mut out =
            parse(br#"<opnsense><dhcpd6><lan><enable>0</enable></lan></dhcpd6></opnsense>"#)
                .expect("parse");

        sync_shared_top_level_sections(&mut out, &source);
        assert_eq!(out.get_text(&["dhcpd6", "lan", "enable"]), Some("1"));
    }

    #[test]
    fn removes_synced_sections_absent_in_source() {
        let source = parse(br#"<pfsense><system/></pfsense>"#).expect("parse");
        let mut out = parse(br#"<opnsense><system/><snmpd><enable>1</enable></snmpd></opnsense>"#)
            .expect("parse");

        sync_shared_top_level_sections(&mut out, &source);
        assert!(out.get_child("snmpd").is_none());
    }
}
