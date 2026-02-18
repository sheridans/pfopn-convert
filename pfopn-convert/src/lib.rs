//! pfSense and OPNsense firewall configuration conversion and analysis.
//!
//! This library provides tools for comparing, converting, and validating firewall
//! configurations between pfSense and OPNsense. Both platforms share a common
//! ancestry (m0n0wall) but have diverged over time, making direct migration
//! challenging. This library automates what it can and identifies what requires
//! manual intervention.
//!
//! # Architecture
//!
//! The library is organized into several functional areas:
//!
//! ## Detection & Analysis
//!
//! - [`detect`] — Auto-detect platform (pfSense/OPNsense) and version
//! - [`backend_detect`] — Detect DHCP backend (ISC vs Kea)
//! - [`plugin_detect`] — Identify installed plugins and their status
//! - [`scan`] — Assess migration readiness and compatibility
//! - [`analyze`] — Analyze diff results for actionable recommendations
//!
//! ## Transformation
//!
//! - [`transform`] — Platform-specific configuration transformations
//!   - Bidirectional conversion for all major config sections
//!   - VPN configuration (OpenVPN, IPsec, WireGuard, Tailscale)
//!   - DHCP backend migration (ISC → Kea)
//!   - Interface assignments and references
//!   - Firewall rules, NAT, aliases, routes
//! - [`merge`] — Intelligent merging of configurations with dependency transfer
//!
//! ## Validation
//!
//! - [`verify`] — Main verification orchestration
//! - [`verify_interfaces`] — Interface reference validation
//! - [`verify_nat`] — NAT configuration validation
//! - [`verify_bridges`] — Bridge interface validation
//! - [`verify_wireguard`] — WireGuard VPN validation
//! - [`verify_rule_dupes`] — Duplicate firewall rule detection
//! - [`verify_rule_refs`] — Firewall rule reference validation
//! - [`verify_profile`] — Platform-specific profile validation
//!
//! ## Reporting
//!
//! - [`report`] — Terminal-friendly colored diff output
//! - [`sections_report`] — Section-level analysis and mapping hints
//! - [`conversion_summary`] — Post-conversion summary statistics
//! - [`inspect`] — Configuration tree visualization
//!
//! ## Utilities
//!
//! - [`known_mappings`] — Known section name mappings between platforms
//! - [`plugin_matrix`] — Plugin compatibility matrix
//! - [`profile`] — Platform version profiles
//! - [`section`] — Section metadata and key field definitions
//! - [`interface_guard`] — Interface compatibility checks
//!
//! # Workflow
//!
//! The typical conversion workflow:
//!
//! 1. **Scan** source config to assess migration readiness
//! 2. **Detect** platform, version, and DHCP backend
//! 3. **Verify** source config is valid before conversion
//! 4. **Transform** config sections to target platform format
//! 5. **Merge** source into target baseline with dependency transfer
//! 6. **Verify** output config is valid for target platform
//! 7. **Report** what was converted and what needs manual review
//!
//! # Examples
//!
//! ```ignore
//! use pfopn_convert::scan::build_scan_report;
//! use pfopn_convert::verify::build_verify_report;
//! use xml_diff_core::parse_file;
//!
//! // Scan for migration readiness
//! let config = parse_file("pfsense-config.xml")?;
//! let scan = build_scan_report(&config, Some("opnsense"));
//! println!("Platform: {}, DHCP: {}", scan.platform, scan.dhcp_backend);
//!
//! // Verify config validity
//! let report = build_verify_report(&config, Some("opnsense"));
//! println!("Errors: {}, Warnings: {}", report.errors, report.warnings);
//! ```
//!
//! # Built on xml-diff-core
//!
//! This library uses `xml-diff-core` for generic XML parsing, diffing, and tree
//! manipulation. All firewall-specific logic is contained in this crate.

pub mod analyze;
pub mod backend_detect;
pub mod conversion_summary;
pub mod detect;
pub mod inspect;
pub mod interface_guard;
pub mod ipsec_dependencies;
pub mod known_mappings;
pub mod merge;
pub mod migrate_check;
pub mod openvpn_dependencies;
pub mod plugin_detect;
pub mod plugin_matrix;
pub mod profile;
pub mod report;
pub mod scan;
mod scan_plugins;
pub mod section;
pub mod sections_report;
pub mod transform;
pub mod verify;
pub mod verify_bridges;
pub mod verify_interfaces;
pub mod verify_nat;
pub mod verify_profile;
pub mod verify_rule_dupes;
pub mod verify_rule_refs;
pub mod verify_wireguard;
pub mod wireguard_dependencies;
