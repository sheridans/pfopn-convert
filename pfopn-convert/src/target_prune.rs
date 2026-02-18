use std::collections::BTreeSet;

use xml_diff_core::XmlNode;

pub fn prune_imported_incompatible_sections(
    out: &mut XmlNode,
    target_platform: &str,
    target_baseline: &XmlNode,
) -> Vec<String> {
    let baseline = collect_top_level_tags(target_baseline);
    let allowed = allowed_sections(target_platform);

    let mut removed = Vec::new();
    out.children.retain(|child| {
        let keep = baseline.contains(&child.tag) || allowed.contains(child.tag.as_str());
        if !keep {
            removed.push(child.tag.clone());
        }
        keep
    });

    removed.sort();
    removed.dedup();
    removed
}

fn collect_top_level_tags(root: &XmlNode) -> BTreeSet<String> {
    root.children.iter().map(|c| c.tag.clone()).collect()
}

fn allowed_sections(platform: &str) -> BTreeSet<&'static str> {
    match platform {
        "opnsense" => BTreeSet::from([
            "version",
            "system",
            "interfaces",
            "filter",
            "nat",
            "OPNsense",
            "dhcpd",
            "dhcpdv6",
            "dhcrelay",
            "dhcrelay6",
            "dhcp6relay",
            "vlans",
            "openvpn",
            "ipsec",
            "cert",
            "ca",
            "ifgroups",
            "bridges",
            "staticroutes",
            "gateways",
            "hasync",
            "revision",
        ]),
        "pfsense" => BTreeSet::from([
            "version",
            "system",
            "interfaces",
            "filter",
            "nat",
            "aliases",
            "installedpackages",
            "dhcpbackend",
            "dhcpd",
            "dhcpdv6",
            "dhcrelay",
            "dhcrelay6",
            "dhcp6relay",
            "vlans",
            "openvpn",
            "ipsec",
            "cert",
            "ca",
            "ifgroups",
            "bridges",
            "staticroutes",
            "gateways",
            "hasync",
            "revision",
        ]),
        _ => BTreeSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use xml_diff_core::parse;

    use super::prune_imported_incompatible_sections;

    #[test]
    fn prunes_pfsense_packages_when_target_is_opnsense() {
        let mut out =
            parse(br#"<opnsense><system/><interfaces/><installedpackages/><openvpn/></opnsense>"#)
                .expect("parse");
        let target = parse(br#"<opnsense><system/><interfaces/></opnsense>"#).expect("target");

        let removed = prune_imported_incompatible_sections(&mut out, "opnsense", &target);
        assert!(removed.contains(&"installedpackages".to_string()));
        assert!(out.get_child("installedpackages").is_none());
    }

    #[test]
    fn prunes_opnsense_container_when_target_is_pfsense() {
        let mut out = parse(br#"<pfsense><system/><interfaces/><OPNsense/><openvpn/></pfsense>"#)
            .expect("parse");
        let target = parse(br#"<pfsense><system/><interfaces/></pfsense>"#).expect("target");

        let removed = prune_imported_incompatible_sections(&mut out, "pfsense", &target);
        assert!(removed.contains(&"OPNsense".to_string()));
        assert!(out.get_child("OPNsense").is_none());
    }

    #[test]
    fn keeps_opnsense_container_when_target_is_opnsense() {
        let mut out =
            parse(br#"<opnsense><system/><interfaces/><OPNsense/></opnsense>"#).expect("parse");
        let target = parse(br#"<opnsense><system/><interfaces/></opnsense>"#).expect("target");

        let removed = prune_imported_incompatible_sections(&mut out, "opnsense", &target);
        assert!(!removed.contains(&"OPNsense".to_string()));
        assert!(out.get_child("OPNsense").is_some());
    }

    #[test]
    fn keeps_dhcp_relay_sections_even_if_absent_on_baseline() {
        let mut out = parse(
            br#"<opnsense><system/><interfaces/><dhcrelay><enable>1</enable></dhcrelay><dhcp6relay><enable>1</enable></dhcp6relay></opnsense>"#,
        )
        .expect("parse");
        let target = parse(br#"<opnsense><system/><interfaces/></opnsense>"#).expect("target");

        let removed = prune_imported_incompatible_sections(&mut out, "opnsense", &target);
        assert!(!removed.contains(&"dhcrelay".to_string()));
        assert!(!removed.contains(&"dhcp6relay".to_string()));
        assert!(out.get_child("dhcrelay").is_some());
        assert!(out.get_child("dhcp6relay").is_some());
    }
}
