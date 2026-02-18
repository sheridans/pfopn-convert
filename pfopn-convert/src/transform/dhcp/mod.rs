//! DHCP configuration handling for pfSense and OPNsense.
//!
//! This module manages DHCP server configuration conversion between pfSense and OPNsense,
//! including support for multiple DHCP backends and migration between them.
//!
//! ## DHCP Backend Differences
//!
//! **pfSense:**
//! - Uses ISC DHCP (dhcpd) exclusively
//! - Configuration stored in `<dhcpd>` section
//! - Per-interface subnets with static mappings
//!
//! **OPNsense:**
//! - Supports two backends:
//!   - **ISC DHCP (legacy)** — Compatible with pfSense format
//!   - **Kea DHCP (modern)** — New structured format with enhanced features
//! - Legacy config stored in `<dhcpd>` (same as pfSense)
//! - Kea config stored in `<OPNsense><Kea>` with separate IPv4/IPv6 sections
//! - Backend selection via `<OPNsense><Kea><general><enabled>`
//!
//! ## Module Organization
//!
//! - **backend_policy** — Determines which DHCP backend to use and enforces backend preferences
//! - **disable** — Handles disabling DHCP on interfaces when needed
//! - **kea** — ISC DHCP to Kea migration and Kea-specific configuration
//! - **relay** — DHCP relay agent configuration conversion
//!
//! ## Conversion Strategy
//!
//! When converting to OPNsense:
//! 1. Detect existing backend (ISC or Kea) in source and target
//! 2. Apply backend policy (prefer Kea, allow ISC, or enforce Kea)
//! 3. If Kea is enabled/enforced, migrate ISC config to Kea format
//! 4. Otherwise, preserve ISC format as-is
//!
//! When converting to pfSense:
//! - Extract ISC DHCP config from OPNsense (converting from Kea if necessary)
//! - pfSense only supports ISC, so Kea configs must be downgraded
//!
//! ## Backend Policy
//!
//! The backend policy controls DHCP conversion behavior:
//! - **PreferKea** — Use Kea if target has it enabled, otherwise use ISC
//! - **AllowIsc** — Keep ISC format, don't migrate to Kea
//! - **EnforceKea** — Always migrate to Kea, even if not enabled in target

pub mod backend_policy;
pub mod disable;
pub mod kea;
pub mod relay;

pub use backend_policy::{
    enforce_output_backend, ensure_backend_readiness, has_legacy_dhcp_data,
    resolve_effective_backend, EffectiveDhcpBackend, RequestedDhcpBackend,
};
pub use disable::apply as disable_all;
pub use kea::{migrate_isc_to_kea_opnsense, KeaMigrationStats, MigrationSeverity};
