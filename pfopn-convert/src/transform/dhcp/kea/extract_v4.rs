use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

use xml_diff_core::XmlNode;

use super::extract_common::isc_iface_enabled;
use super::model::{OptsV4, StaticMapV4};
use super::util::normalize_domain_search;

/// Extract all IPv4 static mappings (DHCP reservations) from ISC DHCP config.
///
/// Searches the `<dhcpd>` section for all enabled interfaces and collects
/// their `<staticmap>` entries. Each static mapping assigns a fixed IP address
/// to a specific MAC address.
///
/// Returns a vector of all static mappings across all interfaces.
pub(crate) fn extract_isc_staticmaps_v4(root: &XmlNode) -> Vec<StaticMapV4> {
    let Some(dhcpd) = root.get_child("dhcpd") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for iface in &dhcpd.children {
        if !isc_iface_enabled(iface) {
            continue;
        }
        let iface_name = iface.tag.clone();
        for staticmap in iface.get_children("staticmap") {
            let Some(mac) = staticmap.get_text(&["mac"]).map(str::trim) else {
                continue;
            };
            let Some(ip) = staticmap.get_text(&["ipaddr"]).map(str::trim) else {
                continue;
            };
            if mac.is_empty() || ip.is_empty() {
                continue;
            }
            let hostname = staticmap
                .get_text(&["hostname"])
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let cid = staticmap
                .get_text(&["cid"])
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let descr = staticmap
                .get_text(&["descr"])
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            out.push(StaticMapV4 {
                iface: iface_name.clone(),
                mac: mac.to_string(),
                ipaddr: ip.to_string(),
                hostname,
                cid,
                descr,
            });
        }
    }
    out
}

/// Extract all IPv4 dynamic address ranges (pools) from ISC DHCP config.
///
/// Collects `<range><from>...</from><to>...</to></range>` entries for each
/// enabled interface. These ranges define the pool of addresses available for
/// dynamic DHCP assignment.
///
/// Returns a map of interface name → list of (from_ip, to_ip) range pairs.
pub(crate) fn extract_isc_ranges_v4(root: &XmlNode) -> HashMap<String, Vec<(String, String)>> {
    let Some(dhcpd) = root.get_child("dhcpd") else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for iface in &dhcpd.children {
        if !isc_iface_enabled(iface) {
            continue;
        }
        for range in iface.get_children("range") {
            let Some(from) = range.get_text(&["from"]).map(str::trim) else {
                continue;
            };
            let Some(to) = range.get_text(&["to"]).map(str::trim) else {
                continue;
            };
            if from.is_empty() || to.is_empty() {
                continue;
            }
            out.entry(iface.tag.clone())
                .or_insert_with(Vec::new)
                .push((from.to_string(), to.to_string()));
        }
    }
    out
}

/// Extract IPv4 network information for each interface.
///
/// Reads `<interfaces>` to get each interface's IP address and subnet mask.
/// Calculates the network address from the IP and mask to determine the
/// subnet CIDR (e.g., 192.168.1.0/24).
///
/// This information is crucial for creating Kea subnets, as Kea requires
/// subnet CIDR notation rather than interface-based configuration.
///
/// Returns a map of interface name → (network address, prefix length).
pub(crate) fn extract_iface_networks_v4(root: &XmlNode) -> HashMap<String, (Ipv4Addr, u8)> {
    let mut out = HashMap::new();
    let Some(interfaces) = root.get_child("interfaces") else {
        return out;
    };
    for iface in &interfaces.children {
        let Some(ip) = iface
            .get_text(&["ipaddr"])
            .and_then(|v| v.trim().parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        let prefix = iface
            .get_text(&["subnet"])
            .and_then(|v| v.trim().parse::<u8>().ok())
            .unwrap_or(24);
        if prefix > 32 {
            continue;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = Ipv4Addr::from(u32::from(ip) & mask);
        out.insert(iface.tag.clone(), (network, prefix));
    }
    out
}

/// Extract IPv4 DHCP options from ISC DHCP config.
///
/// Collects DHCP options configured for each enabled interface:
/// - `<dnsserver>` — DNS servers
/// - `<gateway>` — Default gateway (router)
/// - `<domain>` — Domain name
/// - `<domainsearchlist>` — Domain search list
/// - `<ntpserver>` — NTP servers
///
/// Returns a map of interface name → DHCP options.
/// Only includes interfaces that have at least one option configured.
pub(crate) fn extract_isc_options_v4(root: &XmlNode) -> HashMap<String, OptsV4> {
    let Some(dhcpd) = root.get_child("dhcpd") else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for iface in &dhcpd.children {
        if !isc_iface_enabled(iface) {
            continue;
        }
        let mut opts = OptsV4::default();
        for child in &iface.children {
            match child.tag.as_str() {
                "dnsserver" => {
                    if let Some(v) = child
                        .text
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        opts.dns_servers.push(v.to_string());
                    }
                }
                "gateway" => {
                    if let Some(v) = child
                        .text
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        opts.routers = Some(v.to_string());
                    }
                }
                "domain" => {
                    if let Some(v) = child
                        .text
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        opts.domain_name = Some(v.to_string());
                    }
                }
                "domainsearchlist" => {
                    if let Some(v) = child
                        .text
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        opts.domain_search = Some(normalize_domain_search(v));
                    }
                }
                "ntpserver" => {
                    if let Some(v) = child
                        .text
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                    {
                        opts.ntp_servers.push(v.to_string());
                    }
                }
                _ => {}
            }
        }
        if !opts.dns_servers.is_empty()
            || opts.routers.is_some()
            || opts.domain_name.is_some()
            || opts.domain_search.is_some()
            || !opts.ntp_servers.is_empty()
        {
            out.insert(iface.tag.clone(), opts);
        }
    }
    out
}

/// Determine which interfaces actually need DHCP enabled.
///
/// An interface "demands" DHCP if it has any of:
/// - Static mappings (reservations)
/// - Dynamic ranges (pools)
/// - DHCP options configured
///
/// Returns a sorted set of interface names that need Kea subnets created.
pub(crate) fn demanded_ifaces_v4(
    maps: &[StaticMapV4],
    ranges: &HashMap<String, Vec<(String, String)>>,
    opts: &HashMap<String, OptsV4>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for m in maps {
        out.insert(m.iface.clone());
    }
    for k in ranges.keys() {
        out.insert(k.clone());
    }
    for k in opts.keys() {
        out.insert(k.clone());
    }
    out
}
