//! ISC DHCP to Kea DHCP migration for OPNsense.
//!
//! This module handles the complex task of migrating DHCP server configuration from
//! ISC DHCP (dhcpd) format to Kea DHCP format within OPNsense configurations.
//!
//! ## Background
//!
//! OPNsense traditionally used ISC DHCP (same as pfSense), but starting with version 26.x,
//! OPNsense deprecated ISC DHCP in favor of Kea DHCP. Kea is the modern DHCP server from
//! ISC with a more structured configuration format and enhanced features.
//!
//! ## Migration Process
//!
//! The migration extracts DHCP configuration from ISC format and recreates it in Kea format:
//!
//! 1. **Extract ISC configuration:**
//!    - Static mappings (DHCP reservations)
//!    - Dynamic ranges (address pools)
//!    - Interface networks (subnets)
//!    - DHCP options (DNS servers, domain, etc.)
//!
//! 2. **Create Kea subnets:**
//!    - One subnet per interface with DHCP enabled
//!    - Derives subnet CIDR from interface IP and netmask
//!    - Converts address ranges to Kea pool format
//!
//! 3. **Apply reservations:**
//!    - Converts ISC static mappings to Kea reservations
//!    - Links reservations to appropriate subnets
//!    - Handles MAC address, IP address, and hostname
//!
//! 4. **Apply options:**
//!    - Converts ISC DHCP options to Kea option-data format
//!    - Applies per-subnet or globally as appropriate
//!
//! ## Data Structure Differences
//!
//! **ISC DHCP (pfSense/OPNsense legacy):**
//! ```xml
//! <dhcpd>
//!   <lan>
//!     <enable/>
//!     <range><from>192.168.1.100</from><to>192.168.1.200</to></range>
//!     <staticmap>
//!       <mac>00:11:22:33:44:55</mac>
//!       <ipaddr>192.168.1.50</ipaddr>
//!     </staticmap>
//!   </lan>
//! </dhcpd>
//! ```
//!
//! **Kea DHCP (OPNsense 26+):**
//! ```xml
//! <OPNsense><Kea>
//!   <dhcp4>
//!     <subnets>
//!       <subnet4 uuid="...">
//!         <subnet>192.168.1.0/24</subnet>
//!         <pools>192.168.1.100-192.168.1.200</pools>
//!       </subnet4>
//!     </subnets>
//!     <reservations>
//!       <reservation uuid="...">
//!         <hw_address>00:11:22:33:44:55</hw_address>
//!         <ip_address>192.168.1.50</ip_address>
//!         <subnet>...</subnet>
//!       </reservation>
//!     </reservations>
//!   </dhcp4>
//! </Kea></OPNsense>
//! ```
//!
//! ## Module Organization
//!
//! - **extract_v4** — Extract IPv4 DHCP config from ISC format
//! - **extract_v6** — Extract IPv6 DHCP config from ISC format
//! - **apply** — Apply extracted config to Kea structure
//! - **subnets** — Subnet creation and management utilities
//! - **util** — Common utilities for Kea config manipulation
//! - **model** — Data structures representing extracted config

use std::collections::HashMap;

use anyhow::Result;
use xml_diff_core::XmlNode;

mod apply;
mod extract_common;
mod extract_v4;
mod extract_v6;
mod model;
mod subnets;
mod util;

#[cfg(test)]
mod tests;

/// Severity level for migration warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationSeverity {
    /// Critical error that prevents migration
    Error,
    /// Non-fatal issue that should be reviewed
    Warning,
}

/// A warning or error encountered during migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationWarning {
    /// Human-readable description of the issue
    pub message: String,
    /// Severity level
    pub severity: MigrationSeverity,
}

/// Statistics and results from an ISC to Kea migration.
///
/// Tracks what was migrated successfully and any issues encountered.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeaMigrationStats {
    /// Number of IPv4 static mappings (reservations) successfully migrated
    pub reservations_added_v4: usize,
    /// Number of IPv6 static mappings (reservations) successfully migrated
    pub reservations_added_v6: usize,
    /// Number of IPv4 reservations skipped due to conflicts (duplicate MAC/IP)
    pub reservations_skipped_conflict_v4: usize,
    /// Number of IPv6 reservations skipped due to conflicts
    pub reservations_skipped_conflict_v6: usize,
    /// Number of IPv4 subnets created
    pub subnets_added_v4: usize,
    /// Number of IPv6 subnets created
    pub subnets_added_v6: usize,
    /// Number of IPv4 DHCP options applied
    pub options_applied_v4: usize,
    /// Number of IPv6 DHCP options applied
    pub options_applied_v6: usize,
    /// Warnings and errors encountered during migration
    pub warnings: Vec<MigrationWarning>,
    /// Interfaces where DHCPv6 config was preserved in legacy format due to migration issues
    pub preserved_dhcpdv6_ifaces: Vec<String>,
}

/// Migrate ISC DHCP configuration to Kea DHCP format for OPNsense.
///
/// This is the main entry point for ISC → Kea migration. It extracts all DHCP
/// configuration from ISC format (`<dhcpd>`, `<dhcpdv6>`, `<dhcpd6>`) and recreates
/// it in Kea format (`<OPNsense><Kea><dhcp4>` and `<dhcp6>`).
///
/// ## Process Overview
///
/// **For IPv4:**
/// 1. Extract static mappings, ranges, interface networks, and options from `<dhcpd>`
/// 2. Create Kea `<subnet4>` entries for each interface with DHCP enabled
/// 3. Apply address pools (ranges) to subnets
/// 4. Create `<reservation>` entries for static mappings
/// 5. Apply DHCP options (DNS, domain, etc.) to subnets
/// 6. Enable Kea DHCPv4 on migrated interfaces
///
/// **For IPv6:**
/// 1. Extract static mappings, ranges, interface networks, and options from `<dhcpdv6>`/`<dhcpd6>`
/// 2. Create Kea `<subnet6>` entries for each interface
/// 3. Handle IPv6 address expansion (short notation → full addresses)
/// 4. Apply reservations and options
/// 5. Enable Kea DHCPv6 on migrated interfaces
/// 6. Preserve legacy config for interfaces that can't be migrated (missing prefix info)
///
/// ## Error Handling
///
/// - Returns `Err` if critical migration issues occur (e.g., missing interface network config)
/// - Non-fatal issues are collected in `stats.warnings`
/// - IPv6 interfaces that can't be migrated are preserved in ISC format and logged
///
/// ## UUID Generation
///
/// Kea requires UUIDs for subnets and reservations. This function generates deterministic
/// UUIDs using `migrated-subnet4-{id}`, `migrated-subnet6-{id}`, etc. to ensure idempotent
/// conversions.
///
/// # Arguments
///
/// * `out` - The output XML tree to modify (must have OPNsense root)
/// * `source` - The source configuration containing ISC DHCP config
///
/// # Returns
///
/// Migration statistics including counts of migrated items and any warnings
///
/// # Errors
///
/// Returns error if:
/// - Required interface network information is missing for IPv4
/// - Critical Kea structure creation fails
pub fn migrate_isc_to_kea_opnsense(
    out: &mut XmlNode,
    source: &XmlNode,
) -> Result<KeaMigrationStats> {
    let mut stats = KeaMigrationStats::default();
    let mut next_id = util::next_synthetic_id(1);

    // ====== IPv4 Migration ======
    {
        // Step 1: Extract all ISC DHCPv4 configuration from source
        let maps_v4 = extract_v4::extract_isc_staticmaps_v4(source); // Static IP mappings
        let ranges_v4 = extract_v4::extract_isc_ranges_v4(source); // Dynamic address pools
        let iface_networks_v4 = extract_v4::extract_iface_networks_v4(source); // Interface IP/subnet
        let opts_v4 = extract_v4::extract_isc_options_v4(source); // DHCP options (DNS, etc.)

        // Determine which interfaces actually need DHCP (have mappings, ranges, or options)
        let demanded_ifaces_v4 = extract_v4::demanded_ifaces_v4(&maps_v4, &ranges_v4, &opts_v4);
        let mut subnet_uuid_by_iface_v4 = HashMap::new();

        // Step 2: Ensure Kea structure exists in output
        let kea = util::ensure_opnsense_kea(out);
        let dhcp4 = util::ensure_child_mut(kea, "dhcp4");
        util::ensure_child_mut(dhcp4, "subnets");
        util::ensure_child_mut(dhcp4, "reservations");
        util::ensure_child_mut(dhcp4, "general");

        // Step 3: Create a Kea subnet for each interface that needs DHCP
        for iface in &demanded_ifaces_v4 {
            let Some((network, prefix)) = iface_networks_v4.get(iface) else {
                anyhow::bail!(
                    "cannot migrate DHCPv4 interface '{}': missing interfaces.{}.ipaddr/subnet",
                    iface,
                    iface
                );
            };
            let cidr = format!("{network}/{prefix}");

            // Check if a subnet for this CIDR already exists (from previous migration or manual config)
            let existing = {
                let subnets = util::ensure_child_mut(dhcp4, "subnets");
                subnets::find_subnet_uuid_by_cidr(subnets, "subnet4", &cidr)
            };
            if let Some(uuid) = existing {
                subnet_uuid_by_iface_v4.insert(iface.clone(), uuid);
                continue; // Reuse existing subnet
            }

            // Create new subnet with deterministic UUID
            let uuid = format!("migrated-subnet4-{next_id}");
            next_id += 1;
            let mut subnet = XmlNode::new("subnet4");
            subnet.attributes.insert("uuid".to_string(), uuid.clone());
            util::push_text_child(&mut subnet, "subnet", &cidr);
            util::push_text_child(&mut subnet, "option_data_autocollect", "1");
            subnets::push_option_data_v4_defaults(&mut subnet);
            util::push_text_child(&mut subnet, "match-client-id", "1");
            if let Some(ranges) = ranges_v4.get(iface) {
                let pools = ranges
                    .iter()
                    .map(|(from, to)| format!("{from}-{to}"))
                    .collect::<Vec<_>>()
                    .join(",");
                if !pools.is_empty() {
                    util::push_text_child(&mut subnet, "pools", &pools);
                }
            }
            util::ensure_child_mut(dhcp4, "subnets")
                .children
                .push(subnet);
            subnet_uuid_by_iface_v4.insert(iface.clone(), uuid);
            stats.subnets_added_v4 += 1;
        }

        // Step 4: Apply DHCP options (DNS servers, domain name, etc.) to subnets
        stats.options_applied_v4 +=
            apply::apply_isc_options_v4_to_subnets(dhcp4, &subnet_uuid_by_iface_v4, &opts_v4)?;

        // Step 5: Apply static IP reservations (MAC → IP mappings)
        let (added_v4, skipped_v4) =
            apply::apply_isc_reservations_v4(dhcp4, &maps_v4, &subnet_uuid_by_iface_v4)?;
        stats.reservations_added_v4 += added_v4;
        stats.reservations_skipped_conflict_v4 += skipped_v4;

        // Step 6: Enable Kea DHCPv4 on interfaces that were migrated
        if !subnet_uuid_by_iface_v4.is_empty() || stats.reservations_added_v4 > 0 {
            let general = util::ensure_child_mut(dhcp4, "general");
            util::enable_family_interfaces(general, &subnet_uuid_by_iface_v4);
        }
    }

    // ====== IPv6 Migration ======
    {
        let maps_v6 = extract_v6::extract_isc_staticmaps_v6(source);
        let ranges_v6 = extract_v6::extract_isc_ranges_v6(source);
        let iface_networks_v6 = extract_v6::extract_iface_networks_v6(source);
        let opts_v6 = extract_v6::extract_isc_options_v6(source);
        let prefixrange_intent = extract_v6::collect_prefixrange_intent(source);
        let demanded_ifaces_v6 =
            extract_v6::demanded_ifaces_v6(&maps_v6, &ranges_v6, &opts_v6, &prefixrange_intent);
        let mut subnet_uuid_by_iface_v6 = HashMap::new();

        let kea = util::ensure_opnsense_kea(out);
        let dhcp6 = util::ensure_child_mut(kea, "dhcp6");
        util::ensure_child_mut(dhcp6, "subnets");
        util::ensure_child_mut(dhcp6, "reservations");
        util::ensure_child_mut(dhcp6, "general");

        for iface in &demanded_ifaces_v6 {
            let Some((network, prefix)) = iface_networks_v6.get(iface) else {
                let has_static = iface_networks_v6.contains_key(iface);
                let has_pd = prefixrange_intent.contains_key(iface);
                let reason = format_v6_readiness_reason(has_static, has_pd);
                stats.warnings.push(MigrationWarning {
                    message: format!(
                        "DHCPv6 range on {iface} but unable to determine IPv6 prefix ({reason}); preserving legacy block; no Kea dhcp6 for {iface}."
                    ),
                    severity: MigrationSeverity::Warning,
                });
                stats.preserved_dhcpdv6_ifaces.push(iface.clone());
                continue;
            };
            let cidr = format!("{network}/{prefix}");
            let existing = {
                let subnets = util::ensure_child_mut(dhcp6, "subnets");
                subnets::find_subnet_uuid_by_cidr(subnets, "subnet6", &cidr)
            };
            if let Some(uuid) = existing {
                subnet_uuid_by_iface_v6.insert(iface.clone(), uuid);
                continue;
            }

            let uuid = format!("migrated-subnet6-{next_id}");
            next_id += 1;
            let mut subnet = XmlNode::new("subnet6");
            subnet.attributes.insert("uuid".to_string(), uuid.clone());
            util::push_text_child(&mut subnet, "subnet", &cidr);
            subnets::push_option_data_v6_defaults(&mut subnet);
            if let Some(ranges) = ranges_v6.get(iface) {
                let pools = ranges
                    .iter()
                    .map(|(from, to)| {
                        let from_exp = util::expand_ipv6_in_prefix(from, *network, *prefix)
                            .unwrap_or_else(|| from.clone());
                        let to_exp = util::expand_ipv6_in_prefix(to, *network, *prefix)
                            .unwrap_or_else(|| to.clone());
                        format!("{from_exp}-{to_exp}")
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                if !pools.is_empty() {
                    util::push_text_child(&mut subnet, "pools", &pools);
                }
            }
            util::push_text_child(&mut subnet, "interface", iface);
            util::push_text_child(&mut subnet, "description", "");
            util::ensure_child_mut(dhcp6, "subnets")
                .children
                .push(subnet);
            subnet_uuid_by_iface_v6.insert(iface.clone(), uuid);
            stats.subnets_added_v6 += 1;
        }

        stats.options_applied_v6 +=
            apply::apply_isc_options_v6_to_subnets(dhcp6, &subnet_uuid_by_iface_v6, &opts_v6)?;
        let (added_v6, skipped_v6) = apply::apply_isc_reservations_v6(
            dhcp6,
            &maps_v6,
            &subnet_uuid_by_iface_v6,
            &iface_networks_v6,
        )?;
        stats.reservations_added_v6 += added_v6;
        stats.reservations_skipped_conflict_v6 += skipped_v6;

        if !subnet_uuid_by_iface_v6.is_empty() || stats.reservations_added_v6 > 0 {
            let general = util::ensure_child_mut(dhcp6, "general");
            util::enable_family_interfaces(general, &subnet_uuid_by_iface_v6);
        }
    }

    fn format_v6_readiness_reason(has_static: bool, has_pd: bool) -> String {
        let mut missing = Vec::new();
        if !has_static {
            missing.push("no static IPv6");
        }
        if !has_pd {
            missing.push("no PD indicators");
        }
        if missing.is_empty() {
            missing.push("unknown prefix source");
        }
        missing.join(" or ")
    }

    Ok(stats)
}
