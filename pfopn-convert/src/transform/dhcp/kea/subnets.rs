use xml_diff_core::XmlNode;

use super::util::{ensure_child_mut, set_or_insert_text_child};

/// Add default (empty) IPv4 DHCP option placeholders to a Kea subnet.
///
/// Kea requires explicit option-data entries even if they're empty. This function
/// creates empty placeholders for common DHCPv4 options like DNS servers, domain
/// name, routers (gateways), NTP servers, etc.
///
/// These placeholders are later populated with actual values during option migration.
pub(crate) fn push_option_data_v4_defaults(subnet: &mut XmlNode) {
    let option_data = ensure_child_mut(subnet, "option_data");
    for key in [
        "domain_name_servers",
        "domain_search",
        "routers",
        "static_routes",
        "classless_static_route",
        "domain_name",
        "ntp_servers",
        "time_servers",
        "tftp_server_name",
        "boot_file_name",
        "v6_only_preferred",
        "v4_dnr",
    ] {
        set_or_insert_text_child(option_data, key, "");
    }
}

/// Add default (empty) IPv6 DHCP option placeholders to a Kea subnet.
///
/// Similar to `push_option_data_v4_defaults` but for DHCPv6 options.
/// Creates empty entries for DNS servers, domain search, etc.
pub(crate) fn push_option_data_v6_defaults(subnet: &mut XmlNode) {
    let option_data = ensure_child_mut(subnet, "option_data");
    for key in ["dns_servers", "domain_search", "v6_dnr"] {
        set_or_insert_text_child(option_data, key, "");
    }
}

/// Find a subnet's UUID by its CIDR notation.
///
/// Searches through subnets (either `<subnet4>` or `<subnet6>`) to find one
/// with a matching `<subnet>` value (e.g., "192.168.1.0/24").
///
/// Returns the subnet's UUID if found, used to link reservations to subnets.
pub(crate) fn find_subnet_uuid_by_cidr(subnets: &XmlNode, tag: &str, cidr: &str) -> Option<String> {
    for subnet in subnets.get_children(tag) {
        let subnet_cidr = subnet.get_text(&["subnet"]).map(str::trim).unwrap_or("");
        if subnet_cidr == cidr {
            if let Some(uuid) = subnet.attributes.get("uuid") {
                return Some(uuid.clone());
            }
        }
    }
    None
}

/// Find a mutable reference to a subnet by its UUID.
///
/// Searches through subnets to find one with a matching UUID attribute.
/// Used when applying options or reservations to a specific subnet.
pub(crate) fn find_subnet_mut_by_uuid<'a>(
    subnets: &'a mut XmlNode,
    tag: &str,
    uuid: &str,
) -> Option<&'a mut XmlNode> {
    let pos = subnets
        .children
        .iter()
        .position(|c| c.tag == tag && c.attributes.get("uuid").map(String::as_str) == Some(uuid))?;
    Some(&mut subnets.children[pos])
}
