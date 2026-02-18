use xml_diff_core::XmlNode;

/// Copy system identity and network settings to OPNsense output.
///
/// Transfers hostname, domain, DNS servers, NTP servers, and DNS settings from
/// the source config to the output. These settings are platform-agnostic and
/// work the same way in both pfSense and OPNsense.
pub fn to_opnsense(out: &mut XmlNode, source: &XmlNode, _destination_baseline: &XmlNode) {
    copy_identity_fields(out, source);
}

/// Copy system identity and network settings to pfSense output.
///
/// Transfers hostname, domain, DNS servers, NTP servers, and DNS settings from
/// the source config to the output. These settings are platform-agnostic and
/// work the same way in both pfSense and OPNsense.
pub fn to_pfsense(out: &mut XmlNode, source: &XmlNode, _destination_baseline: &XmlNode) {
    copy_identity_fields(out, source);
}

/// Copy system identity fields from source to output.
///
/// Fields copied:
/// - hostname: The firewall's hostname (e.g., "fw-prod")
/// - domain: The DNS domain (e.g., "example.com")
/// - timeservers: Space-separated NTP server list (e.g., "0.pool.ntp.org 1.pool.ntp.org")
/// - dnsserver: DNS resolver addresses (can have multiple <dnsserver> elements)
/// - dnsallowoverride: Whether to allow DNS servers from DHCP/PPP to override static config
/// - dns1gw through dns8gw: Which gateway each DNS server should use (multi-WAN routing)
fn copy_identity_fields(out: &mut XmlNode, source: &XmlNode) {
    let Some(src_system) = source.get_child("system") else {
        return;
    };
    let Some(dst_system) = out.children.iter_mut().find(|n| n.tag == "system") else {
        return;
    };

    // Copy simple single-value fields
    for field in ["hostname", "domain", "timeservers"] {
        let Some(value) = src_system.get_text(&[field]).map(str::trim) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        set_or_insert_text_child(dst_system, field, value);
    }

    // Copy DNS-related settings (these can appear multiple times or have complex structure)
    for field in [
        "dnsallowoverride",         // Allow DNS override from DHCP/PPP
        "dnsallowoverride_exclude", // Interfaces to exclude from DNS override
        "dns1gw",                   // Gateway for first DNS server
        "dns2gw",                   // Gateway for second DNS server
        "dns3gw",
        "dns4gw",
        "dns5gw",
        "dns6gw",
        "dns7gw",
        "dns8gw",
    ] {
        sync_all_children_by_tag(dst_system, src_system, field);
    }

    // Copy all <dnsserver> elements (there can be multiple)
    sync_all_children_by_tag(dst_system, src_system, "dnsserver");
}

/// Set or insert a text child element in a node.
///
/// If a child with the given tag already exists, update its text content.
/// Otherwise, create a new child element with that tag and text.
fn set_or_insert_text_child(node: &mut XmlNode, tag: &str, value: &str) {
    if let Some(child) = node.children.iter_mut().find(|c| c.tag == tag) {
        child.text = Some(value.to_string());
        return;
    }
    let mut child = XmlNode::new(tag);
    child.text = Some(value.to_string());
    node.children.push(child);
}

/// Copy all children with a given tag from src to dst, replacing any existing ones.
///
/// This is used for fields that can appear multiple times (like <dnsserver>) or
/// fields where we want to ensure the destination exactly matches the source.
fn sync_all_children_by_tag(dst: &mut XmlNode, src: &XmlNode, tag: &str) {
    // Remove all existing children with this tag
    dst.children.retain(|c| c.tag != tag);

    // Copy all matching children from source
    for child in &src.children {
        if child.tag == tag {
            dst.children.push(child.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::{to_opnsense, to_pfsense};

    #[test]
    fn copies_hostname_and_domain_to_opnsense() {
        let source = parse(
            br#"<pfsense><system><hostname>gw-a</hostname><domain>example.net</domain></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><hostname>dst</hostname><domain>dst.local</domain></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "hostname"]), Some("gw-a"));
        assert_eq!(out.get_text(&["system", "domain"]), Some("example.net"));
    }

    #[test]
    fn copies_timeservers() {
        let source = parse(
            br#"<pfsense><system><timeservers>1.1.1.1 2.2.2.2</timeservers></system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system><timeservers>0.pool.ntp.org</timeservers></system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(
            out.get_text(&["system", "timeservers"]),
            Some("1.1.1.1 2.2.2.2")
        );
    }

    #[test]
    fn copies_hostname_and_domain_to_pfsense() {
        let source = parse(
            br#"<opnsense><system><hostname>fw-opn</hostname><domain>corp.example</domain></system></opnsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<pfsense><system><hostname>dst</hostname><domain>dst.local</domain></system></pfsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_pfsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "hostname"]), Some("fw-opn"));
        assert_eq!(out.get_text(&["system", "domain"]), Some("corp.example"));
    }

    #[test]
    fn copies_dns_general_settings_and_servers() {
        let source = parse(
            br#"<pfsense><system>
                <dnsallowoverride>1</dnsallowoverride>
                <dnsallowoverride_exclude/>
                <dnsserver>1.1.1.1</dnsserver>
                <dnsserver>8.8.8.8</dnsserver>
                <dns1gw>none</dns1gw>
                <dns2gw>wan</dns2gw>
            </system></pfsense>"#,
        )
        .expect("parse");
        let mut out = parse(
            br#"<opnsense><system>
                <dnsallowoverride>0</dnsallowoverride>
                <dnsserver>9.9.9.9</dnsserver>
                <dns1gw>foo</dns1gw>
            </system></opnsense>"#,
        )
        .expect("parse");
        let baseline = out.clone();

        to_opnsense(&mut out, &source, &baseline);
        assert_eq!(out.get_text(&["system", "dnsallowoverride"]), Some("1"));
        assert_eq!(out.get_text(&["system", "dns1gw"]), Some("none"));
        assert_eq!(out.get_text(&["system", "dns2gw"]), Some("wan"));
        let dnsservers: Vec<String> = out
            .get_child("system")
            .expect("system")
            .children
            .iter()
            .filter(|c| c.tag == "dnsserver")
            .map(|c| c.text.clone().unwrap_or_default())
            .collect();
        assert_eq!(
            dnsservers,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }
}
