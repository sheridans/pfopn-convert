use std::collections::{BTreeSet, HashMap};
use std::net::Ipv6Addr;

use xml_diff_core::XmlNode;

use super::extract_common::isc_iface_enabled;
use super::model::{OptsV6, StaticMapV6};
use super::util::{ipv6_mask, normalize_domain_search};

/// Extract all IPv6 static mappings (DHCP reservations) from ISC DHCP config.
///
/// Searches both `<dhcpdv6>` and `<dhcpd6>` sections for all enabled interfaces
/// and collects their `<staticmap>` entries. Each static mapping assigns a fixed
/// IPv6 address to a specific DUID (DHCP Unique Identifier).
///
/// Returns a vector of all static mappings across all interfaces.
pub(crate) fn extract_isc_staticmaps_v6(root: &XmlNode) -> Vec<StaticMapV6> {
    let mut out = Vec::new();
    for container in dhcpv6_legacy_sections(root) {
        for iface in &container.children {
            if !isc_iface_enabled(iface) {
                continue;
            }
            let iface_name = iface.tag.clone();
            for staticmap in iface.get_children("staticmap") {
                let Some(duid) = staticmap.get_text(&["duid"]).map(str::trim) else {
                    continue;
                };
                let Some(ip) = staticmap.get_text(&["ipaddrv6"]).map(str::trim) else {
                    continue;
                };
                if duid.is_empty() || ip.is_empty() {
                    continue;
                }
                let hostname = staticmap
                    .get_text(&["hostname"])
                    .map(str::trim)
                    .unwrap_or("")
                    .to_string();
                let descr = staticmap
                    .get_text(&["descr"])
                    .map(str::trim)
                    .unwrap_or("")
                    .to_string();
                let domain_search = staticmap
                    .get_text(&["domainsearchlist"])
                    .map(str::trim)
                    .unwrap_or("")
                    .to_string();
                out.push(StaticMapV6 {
                    iface: iface_name.clone(),
                    duid: duid.to_string(),
                    ipaddr: ip.to_string(),
                    hostname,
                    descr,
                    domain_search,
                });
            }
        }
    }
    out
}

/// Extract all IPv6 dynamic address ranges (pools) from ISC DHCP config.
///
/// Collects `<range><from>...</from><to>...</to></range>` entries for each
/// enabled interface. IPv6 ranges may use abbreviated notation that's expanded
/// later during migration.
///
/// Returns a map of interface name → list of (from_ip, to_ip) range pairs.
pub(crate) fn extract_isc_ranges_v6(root: &XmlNode) -> HashMap<String, Vec<(String, String)>> {
    let mut out = HashMap::new();
    for container in dhcpv6_legacy_sections(root) {
        for iface in &container.children {
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
    }
    out
}

/// Extract IPv6 network information for each interface.
///
/// Reads `<interfaces>` to get each interface's IPv6 address and prefix length.
/// Calculates the network address from the IP and prefix to determine the
/// subnet CIDR (e.g., fd00::/64).
///
/// Skips interfaces configured with:
/// - "track6" (delegated prefix tracking)
/// - "dhcp6" (DHCPv6 client mode)
///
/// Returns a map of interface name → (network address, prefix length).
pub(crate) fn extract_iface_networks_v6(root: &XmlNode) -> HashMap<String, (Ipv6Addr, u8)> {
    let mut out = HashMap::new();
    let Some(interfaces) = root.get_child("interfaces") else {
        return out;
    };
    for iface in &interfaces.children {
        let Some(ip_raw) = iface.get_text(&["ipaddrv6"]).map(str::trim) else {
            continue;
        };
        if ip_raw.is_empty()
            || ip_raw.eq_ignore_ascii_case("track6")
            || ip_raw.eq_ignore_ascii_case("dhcp6")
        {
            continue;
        }
        let Some(ip) = ip_raw.parse::<Ipv6Addr>().ok() else {
            continue;
        };
        let prefix = iface
            .get_text(&["subnetv6"])
            .and_then(|v| v.trim().parse::<u8>().ok())
            .unwrap_or(64);
        if prefix > 128 {
            continue;
        }
        let mask = ipv6_mask(prefix);
        let network = Ipv6Addr::from(u128::from(ip) & mask);
        out.insert(iface.tag.clone(), (network, prefix));
    }
    out
}

/// Collect interfaces that have prefix delegation (PD) configuration.
///
/// IPv6 prefix delegation allows routers to request and receive IPv6 prefixes
/// from upstream. This function detects interfaces configured with `<prefixrange>`
/// entries, which indicates PD usage.
///
/// This is used during migration to determine if an interface has enough
/// information to create a Kea subnet even if it lacks a static IPv6 address.
///
/// Returns a map of interface name → true for interfaces with PD config.
pub(crate) fn collect_prefixrange_intent(root: &XmlNode) -> HashMap<String, bool> {
    let mut out = HashMap::new();
    for container in dhcpv6_legacy_sections(root) {
        for iface in &container.children {
            for prefix in iface.get_children("prefixrange") {
                let from = prefix.get_text(&["from"]).map(str::trim).unwrap_or("");
                let to = prefix.get_text(&["to"]).map(str::trim).unwrap_or("");
                let prefixlength = prefix
                    .get_text(&["prefixlength"])
                    .map(str::trim)
                    .unwrap_or("");
                if (!from.is_empty() || !to.is_empty()) && !prefixlength.is_empty() {
                    out.insert(iface.tag.clone(), true);
                }
            }
        }
    }
    out
}

/// Extract IPv6 DHCP options from ISC DHCP config.
///
/// Collects DHCPv6 options configured for each enabled interface:
/// - `<dnsserver>` — DNS servers
/// - `<domainsearchlist>` — Domain search list
///
/// Returns a map of interface name → DHCP options.
/// Only includes interfaces that have at least one option configured.
pub(crate) fn extract_isc_options_v6(root: &XmlNode) -> HashMap<String, OptsV6> {
    let mut out = HashMap::new();
    for container in dhcpv6_legacy_sections(root) {
        for iface in &container.children {
            if !isc_iface_enabled(iface) {
                continue;
            }
            let mut opts = OptsV6::default();
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
                    _ => {}
                }
            }
            if !opts.dns_servers.is_empty() || opts.domain_search.is_some() {
                let entry = out.entry(iface.tag.clone()).or_insert_with(OptsV6::default);
                merge_opts_v6(entry, &opts);
            }
        }
    }
    out
}

/// Determine which interfaces actually need DHCPv6 enabled.
///
/// An interface "demands" DHCPv6 if it has any of:
/// - Static mappings (reservations)
/// - Dynamic ranges (pools)
/// - DHCP options configured
/// - Prefix delegation configured
///
/// Returns a sorted set of interface names that need Kea subnets created.
pub(crate) fn demanded_ifaces_v6(
    maps: &[StaticMapV6],
    ranges: &HashMap<String, Vec<(String, String)>>,
    opts: &HashMap<String, OptsV6>,
    prefix_intent: &HashMap<String, bool>,
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
    for k in prefix_intent.keys() {
        out.insert(k.clone());
    }
    out
}

/// Get all DHCPv6 configuration sections from the root.
///
/// ISC DHCP for IPv6 can be stored in either `<dhcpdv6>` or `<dhcpd6>`
/// (legacy naming variation). This function returns both if they exist.
fn dhcpv6_legacy_sections(root: &XmlNode) -> Vec<&XmlNode> {
    let mut out = Vec::new();
    if let Some(n) = root.get_child("dhcpdv6") {
        out.push(n);
    }
    if let Some(n) = root.get_child("dhcpd6") {
        out.push(n);
    }
    out
}

/// Merge IPv6 DHCP options from source into destination.
///
/// Combines DNS servers (avoiding duplicates) and domain search list.
/// Used when multiple config sections provide options for the same interface.
fn merge_opts_v6(dst: &mut OptsV6, src: &OptsV6) {
    for dns in &src.dns_servers {
        if !dst.dns_servers.iter().any(|d| d == dns) {
            dst.dns_servers.push(dns.clone());
        }
    }
    if dst.domain_search.is_none() {
        dst.domain_search = src.domain_search.clone();
    }
}
