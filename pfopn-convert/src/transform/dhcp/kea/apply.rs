use std::collections::{BTreeSet, HashMap};
use std::net::Ipv6Addr;

use anyhow::Result;
use xml_diff_core::XmlNode;

use super::model::{OptsV4, OptsV6, StaticMapV4, StaticMapV6};
use super::subnets::find_subnet_mut_by_uuid;
use super::util::{
    ensure_child_mut, expand_ipv6_in_prefix, normalize_domain_search, push_text_child,
    set_or_insert_text_child,
};

/// Apply IPv4 static mappings (reservations) to Kea configuration.
///
/// Creates `<reservation>` entries in `<dhcp4><reservations>` for each static
/// mapping extracted from ISC DHCP. Each reservation:
/// - Links to a subnet via UUID
/// - Associates MAC address with IP address
/// - Optionally includes hostname, client ID, and description
///
/// ## Conflict Handling
///
/// Skips reservations where the IP address already exists in Kea config
/// (from previous migration or manual configuration). This prevents duplicate
/// IP assignments.
///
/// # Arguments
///
/// * `dhcp4` - The Kea DHCPv4 configuration node
/// * `maps` - Static mappings extracted from ISC DHCP
/// * `subnet_uuid_by_iface` - Map of interface name → subnet UUID for linking
///
/// # Returns
///
/// A tuple of (added_count, skipped_conflicts_count)
///
/// # Errors
///
/// Returns error if a mapping references an interface that doesn't have a Kea subnet.
pub(crate) fn apply_isc_reservations_v4(
    dhcp4: &mut XmlNode,
    maps: &[StaticMapV4],
    subnet_uuid_by_iface: &HashMap<String, String>,
) -> Result<(usize, usize)> {
    let mut added = 0;
    let mut skipped_conflicts = 0;
    let reservations = ensure_child_mut(dhcp4, "reservations");
    let mut existing_ips = BTreeSet::new();
    for node in reservations.get_children("reservation") {
        if let Some(ip) = node.get_text(&["ip_address"]) {
            existing_ips.insert(ip.trim().to_string());
        }
    }
    for map in maps {
        if existing_ips.contains(map.ipaddr.as_str()) {
            skipped_conflicts += 1;
            continue;
        }
        let Some(subnet_id) = subnet_uuid_by_iface.get(&map.iface) else {
            anyhow::bail!(
                "cannot migrate DHCPv4 reservation {} (iface={}): no matching Kea subnet",
                map.ipaddr,
                map.iface
            );
        };
        let mut res = XmlNode::new("reservation");
        push_text_child(&mut res, "hw_address", &map.mac);
        push_text_child(&mut res, "ip_address", &map.ipaddr);
        push_text_child(&mut res, "subnet", subnet_id);
        if !map.hostname.is_empty() {
            push_text_child(&mut res, "hostname", &map.hostname);
        }
        if !map.cid.is_empty() {
            push_text_child(&mut res, "client_id", &map.cid);
        }
        if !map.descr.is_empty() {
            push_text_child(&mut res, "description", &map.descr);
        }
        reservations.children.push(res);
        existing_ips.insert(map.ipaddr.clone());
        added += 1;
    }
    Ok((added, skipped_conflicts))
}

/// Apply IPv6 static mappings (reservations) to Kea configuration.
///
/// Creates `<reservation>` entries in `<dhcp6><reservations>` for each static
/// mapping extracted from ISC DHCP. Each reservation:
/// - Links to a subnet via UUID
/// - Associates DUID with IPv6 address
/// - Optionally includes hostname, description, and domain search
///
/// ## IPv6 Address Expansion
///
/// If the static mapping uses abbreviated IPv6 notation, it's expanded using
/// the interface's subnet prefix to ensure the full address is stored in Kea.
///
/// ## Conflict Handling
///
/// Skips reservations where either the IP address OR DUID already exists in
/// Kea config. This prevents duplicate assignments on either key.
///
/// # Arguments
///
/// * `dhcp6` - The Kea DHCPv6 configuration node
/// * `maps` - Static mappings extracted from ISC DHCP
/// * `subnet_uuid_by_iface` - Map of interface name → subnet UUID for linking
/// * `iface_networks_v6` - Interface network info for IPv6 address expansion
///
/// # Returns
///
/// A tuple of (added_count, skipped_conflicts_count)
///
/// # Errors
///
/// Returns error if a mapping references an interface that doesn't have a Kea subnet.
pub(crate) fn apply_isc_reservations_v6(
    dhcp6: &mut XmlNode,
    maps: &[StaticMapV6],
    subnet_uuid_by_iface: &HashMap<String, String>,
    iface_networks_v6: &HashMap<String, (Ipv6Addr, u8)>,
) -> Result<(usize, usize)> {
    let mut added = 0;
    let mut skipped_conflicts = 0;
    let reservations = ensure_child_mut(dhcp6, "reservations");
    let mut existing_ips = BTreeSet::new();
    let mut existing_duids = BTreeSet::new();
    for node in reservations.get_children("reservation") {
        if let Some(ip) = node.get_text(&["ip_address"]) {
            existing_ips.insert(ip.trim().to_string());
        }
        if let Some(duid) = node.get_text(&["duid"]) {
            existing_duids.insert(duid.trim().to_string());
        }
    }
    for map in maps {
        if existing_ips.contains(map.ipaddr.as_str()) || existing_duids.contains(map.duid.as_str())
        {
            skipped_conflicts += 1;
            continue;
        }
        let Some(subnet_id) = subnet_uuid_by_iface.get(&map.iface) else {
            anyhow::bail!(
                "cannot migrate DHCPv6 reservation {} (iface={}): no matching Kea subnet",
                map.ipaddr,
                map.iface
            );
        };
        let ip_value = if let Some((network, prefix)) = iface_networks_v6.get(&map.iface) {
            expand_ipv6_in_prefix(&map.ipaddr, *network, *prefix)
                .unwrap_or_else(|| map.ipaddr.clone())
        } else {
            map.ipaddr.clone()
        };
        let mut res = XmlNode::new("reservation");
        push_text_child(&mut res, "duid", &map.duid);
        push_text_child(&mut res, "ip_address", &ip_value);
        push_text_child(&mut res, "subnet", subnet_id);
        if !map.hostname.is_empty() {
            push_text_child(&mut res, "hostname", &map.hostname);
        }
        if !map.descr.is_empty() {
            push_text_child(&mut res, "description", &map.descr);
        }
        if !map.domain_search.is_empty() {
            push_text_child(
                &mut res,
                "domain_search",
                &normalize_domain_search(&map.domain_search),
            );
        }
        reservations.children.push(res);
        existing_ips.insert(ip_value);
        existing_duids.insert(map.duid.clone());
        added += 1;
    }
    Ok((added, skipped_conflicts))
}

/// Apply IPv4 DHCP options to Kea subnets.
///
/// Populates the `<option_data>` section of each Kea subnet with DHCP options
/// extracted from ISC DHCP configuration:
/// - `domain_name_servers` — DNS servers
/// - `routers` — Default gateway
/// - `domain_name` — Domain name
/// - `domain_search` — Domain search list
/// - `ntp_servers` — NTP servers
///
/// Options are applied per-subnet based on the interface-to-subnet mapping.
///
/// # Arguments
///
/// * `dhcp4` - The Kea DHCPv4 configuration node
/// * `subnet_uuid_by_iface` - Map of interface name → subnet UUID
/// * `opts_by_iface` - DHCP options extracted from ISC DHCP, keyed by interface
///
/// # Returns
///
/// Count of subnets that had options applied
///
/// # Errors
///
/// Returns error if an interface's subnet UUID doesn't match any existing subnet.
pub(crate) fn apply_isc_options_v4_to_subnets(
    dhcp4: &mut XmlNode,
    subnet_uuid_by_iface: &HashMap<String, String>,
    opts_by_iface: &HashMap<String, OptsV4>,
) -> Result<usize> {
    let mut applied = 0;
    let subnets = ensure_child_mut(dhcp4, "subnets");
    for (iface, opts) in opts_by_iface {
        let Some(uuid) = subnet_uuid_by_iface.get(iface) else {
            anyhow::bail!(
                "cannot apply DHCPv4 options for iface '{}': no matching Kea subnet",
                iface
            );
        };
        if let Some(subnet) = find_subnet_mut_by_uuid(subnets, "subnet4", uuid) {
            let option_data = ensure_child_mut(subnet, "option_data");
            if !opts.dns_servers.is_empty() {
                set_or_insert_text_child(
                    option_data,
                    "domain_name_servers",
                    &opts.dns_servers.join(","),
                );
            }
            if let Some(v) = &opts.routers {
                set_or_insert_text_child(option_data, "routers", v);
            }
            if let Some(v) = &opts.domain_name {
                set_or_insert_text_child(option_data, "domain_name", v);
            }
            if let Some(v) = &opts.domain_search {
                set_or_insert_text_child(option_data, "domain_search", v);
            }
            if !opts.ntp_servers.is_empty() {
                set_or_insert_text_child(option_data, "ntp_servers", &opts.ntp_servers.join(","));
            }
            applied += 1;
        } else {
            anyhow::bail!(
                "cannot apply DHCPv4 options for iface '{}': Kea subnet UUID '{}' missing",
                iface,
                uuid
            );
        }
    }
    Ok(applied)
}

/// Apply IPv6 DHCP options to Kea subnets.
///
/// Populates the `<option_data>` section of each Kea subnet with DHCPv6 options
/// extracted from ISC DHCP configuration:
/// - `dns_servers` — DNS servers
/// - `domain_search` — Domain search list
///
/// Options are applied per-subnet based on the interface-to-subnet mapping.
///
/// # Arguments
///
/// * `dhcp6` - The Kea DHCPv6 configuration node
/// * `subnet_uuid_by_iface` - Map of interface name → subnet UUID
/// * `opts_by_iface` - DHCP options extracted from ISC DHCP, keyed by interface
///
/// # Returns
///
/// Count of subnets that had options applied
///
/// # Errors
///
/// Returns error if an interface's subnet UUID doesn't match any existing subnet.
pub(crate) fn apply_isc_options_v6_to_subnets(
    dhcp6: &mut XmlNode,
    subnet_uuid_by_iface: &HashMap<String, String>,
    opts_by_iface: &HashMap<String, OptsV6>,
) -> Result<usize> {
    let mut applied = 0;
    let subnets = ensure_child_mut(dhcp6, "subnets");
    for (iface, opts) in opts_by_iface {
        let Some(uuid) = subnet_uuid_by_iface.get(iface) else {
            anyhow::bail!(
                "cannot apply DHCPv6 options for iface '{}': no matching Kea subnet",
                iface
            );
        };
        if let Some(subnet) = find_subnet_mut_by_uuid(subnets, "subnet6", uuid) {
            let option_data = ensure_child_mut(subnet, "option_data");
            if !opts.dns_servers.is_empty() {
                set_or_insert_text_child(option_data, "dns_servers", &opts.dns_servers.join(","));
            }
            if let Some(v) = &opts.domain_search {
                set_or_insert_text_child(option_data, "domain_search", v);
            }
            applied += 1;
        } else {
            anyhow::bail!(
                "cannot apply DHCPv6 options for iface '{}': Kea subnet UUID '{}' missing",
                iface,
                uuid
            );
        }
    }
    Ok(applied)
}
