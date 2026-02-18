/// IPv4 DHCP static mapping (reservation) extracted from ISC DHCP config.
///
/// Represents a fixed IP address assignment for a specific MAC address.
#[derive(Debug, Clone)]
pub(crate) struct StaticMapV4 {
    pub(crate) iface: String,
    pub(crate) mac: String,
    pub(crate) ipaddr: String,
    pub(crate) hostname: String,
    pub(crate) cid: String,
    pub(crate) descr: String,
}

/// IPv6 DHCP static mapping (reservation) extracted from ISC DHCP config.
///
/// Represents a fixed IPv6 address assignment for a specific DUID (DHCP Unique Identifier).
#[derive(Debug, Clone)]
pub(crate) struct StaticMapV6 {
    pub(crate) iface: String,
    pub(crate) duid: String,
    pub(crate) ipaddr: String,
    pub(crate) hostname: String,
    pub(crate) descr: String,
    pub(crate) domain_search: String,
}

/// IPv4 DHCP options extracted from ISC DHCP config.
///
/// Contains global or per-interface DHCP options like DNS servers, routers (gateways),
/// domain name, and NTP servers.
#[derive(Debug, Clone, Default)]
pub(crate) struct OptsV4 {
    pub(crate) dns_servers: Vec<String>,
    pub(crate) routers: Option<String>,
    pub(crate) domain_name: Option<String>,
    pub(crate) domain_search: Option<String>,
    pub(crate) ntp_servers: Vec<String>,
}

/// IPv6 DHCP options extracted from ISC DHCP config.
///
/// Contains DHCPv6 options like DNS servers and domain search list.
#[derive(Debug, Clone, Default)]
pub(crate) struct OptsV6 {
    pub(crate) dns_servers: Vec<String>,
    pub(crate) domain_search: Option<String>,
}
