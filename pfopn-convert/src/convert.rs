//! Firewall configuration conversion orchestration.
//!
//! This module implements the main conversion workflow that transforms a firewall
//! configuration from one platform (pfSense or OPNsense) to another. The conversion
//! process is complex and multi-staged:
//!
//! ## Conversion Pipeline
//!
//! 1. **Parse & Validate** — Load source and target configs, validate platforms
//! 2. **DHCP Backend Resolution** — Determine which DHCP backend to use (ISC/Kea)
//! 3. **Interface Compatibility Check** — Ensure interfaces are compatible
//! 4. **Diff & Merge** — Compute differences, apply safe merge operations
//! 5. **Transform Pipeline** — Apply platform-specific transformations:
//!    - Interface settings and presence normalization
//!    - Logical interface reference updates (OPNsense assignments)
//!    - Device reference normalization
//!    - Platform-specific cleanup (pfBlocker, VLANs, WireGuard, bridges, ifgroups)
//! 6. **DHCP Migration** — Migrate ISC DHCP to Kea if needed
//! 7. **Write Output** — Serialize and write final configuration
//!
//! ## DHCP Backend Handling
//!
//! The converter supports both ISC DHCP and Kea DHCP backends. OPNsense 26+ defaults
//! to Kea but can fall back to ISC if migration fails. The pipeline handles:
//! - Auto-detection of source backend
//! - User-requested backend (auto/kea/isc)
//! - Automatic fallback on migration errors (in auto mode)
//! - Preservation of legacy DHCPv6 when needed
//!
//! ## Merge Strategy
//!
//! The merge always builds from the target config and selectively inserts elements
//! from the source. This preserves target platform defaults while incorporating
//! source configuration data. Dependencies (users, certs, CAs) are transferred
//! automatically unless disabled via CLI flags.

use anyhow::{bail, Context, Result};
use xml_diff_core::{diff_with_options, parse_file, write_file, DiffOptions, XmlNode};

use crate::cli::{ConvertArgs, Platform};
use crate::conversion_summary::{
    render as render_conversion_summary, summarize as summarize_conversion,
};
use crate::interface_guard::enforce_interface_compat;
use crate::path_guard::ensure_output_not_same;
use crate::target_prune::prune_imported_incompatible_sections;
use pfopn_convert::backend_detect::detect_dhcp_backend;
use pfopn_convert::detect::{detect_config, ConfigFlavor};
use pfopn_convert::merge::{apply_safe_merge, MergeOptions, MergeTarget};
use pfopn_convert::transform::{
    bridges, device_refs, dhcp, ifgroups, interface_presence, interface_settings, lan_ip,
    logical_refs, opnsense_assignments, pfblocker, vlan_ifnames, wireguard,
};

/// Execute the main configuration conversion workflow.
///
/// Orchestrates the complete conversion pipeline from source platform to target
/// platform. The conversion is staged and applies multiple transformations in a
/// specific order to ensure consistency.
///
/// ## Conversion Stages
///
/// 1. **Validation** — Ensures output path differs from inputs, platforms differ
/// 2. **DHCP Backend Resolution** — Determines ISC vs Kea backend strategy
/// 3. **Diff & Merge** — Computes differences, merges source into target baseline
/// 4. **Transform Pipeline** — Applies ordered platform-specific transformations
/// 5. **DHCP Migration** — Migrates ISC DHCP to Kea for OPNsense 26+ if needed
/// 6. **Output** — Writes final config and displays summary
///
/// ## Error Handling
///
/// - Fails if source and target are the same platform
/// - Fails if Kea backend is requested but cannot be used
/// - Fails if Kea-only source is being converted to ISC without legacy data
/// - Auto-falls back to ISC on Kea migration errors (only in auto mode)
///
/// # Arguments
///
/// * `args` - CLI arguments specifying conversion parameters
///
/// # Returns
///
/// Success or error describing what went wrong
///
/// # Errors
///
/// Returns error if:
/// - Output path conflicts with input paths
/// - Source/target configs cannot be parsed
/// - Platforms cannot be detected or are the same
/// - DHCP backend requirements cannot be met
/// - Interface compatibility check fails
/// - Kea migration fails (in non-auto mode)
/// - Output file cannot be written
pub fn run_convert(args: ConvertArgs) -> Result<()> {
    // Validate that output path doesn't overwrite inputs
    let mut inputs = vec![args.input.as_path()];
    if let Some(path) = &args.target_file {
        inputs.push(path.as_path());
    }
    ensure_output_not_same(&args.output, &inputs)?;

    // Parse source configuration
    let input = parse_file(&args.input)
        .with_context(|| format!("failed to parse {}", args.input.display()))?;

    // Determine source and target platforms
    let from = resolve_from_platform(args.from, &input)?;
    let to = normalize_to_platform(args.to)?;
    if from == to {
        bail!(
            "from and to are the same platform ({from}); conversion requires different platforms"
        );
    }

    // Load or create target baseline config
    let target = resolve_target(&args, to)?;

    // Resolve DHCP backend strategy (ISC vs Kea)
    let requested_backend = match args.backend {
        crate::cli::DhcpBackend::Auto => dhcp::RequestedDhcpBackend::Auto,
        crate::cli::DhcpBackend::Kea => dhcp::RequestedDhcpBackend::Kea,
        crate::cli::DhcpBackend::Isc => dhcp::RequestedDhcpBackend::Isc,
    };
    let source_backend = detect_dhcp_backend(&input);
    let mut effective_backend =
        dhcp::resolve_effective_backend(requested_backend, &input, &target, to);
    dhcp::ensure_backend_readiness(&target, requested_backend, effective_backend)?;

    // Ensure source and target have compatible interface assignments
    enforce_interface_compat(&input, &target)?;

    // Compute differences between source and target
    let opts = DiffOptions {
        include_identical: false,
        ..DiffOptions::default()
    };
    let entries = diff_with_options(&input, &target, &opts);

    // Configure dependency transfer options
    let merge_options = MergeOptions {
        transfer_users: !args.no_transfer_users,
        transfer_certs: !args.no_transfer_certs,
        transfer_cas: !args.no_transfer_cas,
    };

    // Merge source config into target baseline (builds from target, inserts from source)
    let mut out = apply_safe_merge(&input, &target, &entries, MergeTarget::Right, merge_options)
        .with_context(|| "failed while applying safe conversion merge")?;

    // Update root tag to match target platform
    out.tag = to.to_string();

    // Apply interface-level transformations
    interface_settings::apply(&mut out, &input, &target, None);
    interface_presence::prune_missing(&mut out, &target);

    // Build logical interface mapping for OPNsense (wan/lan/opt -> device references)
    let logical_map = if to == "opnsense" {
        let map = opnsense_assignments::normalize(&mut out);
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    } else {
        None
    };

    // Update references that use logical interface names
    logical_refs::apply(&mut out, logical_map.as_ref());

    // Remove sections incompatible with target platform
    prune_imported_incompatible_sections(&mut out, to, &target);

    // Update device references (physical interface names)
    device_refs::apply(&mut out, &input, &target, None);

    // Apply platform-specific cleanup and normalization
    if to == "opnsense" {
        pfblocker::prune_pfblocker_floating_rules_for_opnsense(&mut out);
        vlan_ifnames::normalize_opnsense_vlan_ifnames(&mut out);
        wireguard::normalize_opnsense_interface_names(&mut out);
        bridges::normalize_for_opnsense(&mut out);
        ifgroups::normalize_for_opnsense(&mut out);
    } else {
        bridges::normalize_for_pfsense(&mut out);
        ifgroups::normalize_for_pfsense(&mut out);
    }

    // Override LAN IP if requested
    if let Some(new_lan_ip) = &args.lan_ip {
        lan_ip::apply(&mut out, new_lan_ip)?;
    }

    // Handle DHCP backend configuration based on target platform
    if to == "pfsense" && effective_backend == dhcp::EffectiveDhcpBackend::Kea {
        // pfSense with Kea: copy Kea config from source
        seed_pfsense_kea_from_source(&mut out, &input);
    }

    if to == "opnsense" && effective_backend == dhcp::EffectiveDhcpBackend::Kea {
        // OPNsense 26+ with Kea: attempt ISC → Kea migration
        match dhcp::migrate_isc_to_kea_opnsense(&mut out, &input) {
            Ok(stats) => {
                let mut final_backend = effective_backend;

                // Check if migration produced fatal errors
                let error_warning_present = stats
                    .warnings
                    .iter()
                    .any(|w| w.severity == dhcp::MigrationSeverity::Error);

                // Fall back to ISC if errors occurred
                if error_warning_present && final_backend == dhcp::EffectiveDhcpBackend::Kea {
                    final_backend = dhcp::EffectiveDhcpBackend::Isc;
                    eprintln!(
                        "warning: Kea migration skipped due to fatal errors; falling back to ISC backend"
                    );
                }

                // Preserve legacy DHCPv6 for interfaces that couldn't migrate
                let preserve_legacy_ipv6 = final_backend == dhcp::EffectiveDhcpBackend::Kea
                    && !stats.preserved_dhcpdv6_ifaces.is_empty();

                dhcp::enforce_output_backend(&mut out, final_backend, to, preserve_legacy_ipv6);
                effective_backend = final_backend;

                // Display migration warnings
                for warning in &stats.warnings {
                    eprintln!("warning: {}", warning.message);
                }
                print_dhcp_migration_summary(&stats, final_backend, preserve_legacy_ipv6);
            }
            Err(err) if requested_backend == dhcp::RequestedDhcpBackend::Auto => {
                // In auto mode, fall back to ISC on migration failure
                eprintln!(
                    "warning: Kea migration failed in auto mode ({err}); falling back to ISC backend"
                );
                effective_backend = dhcp::EffectiveDhcpBackend::Isc;
                dhcp::enforce_output_backend(&mut out, effective_backend, to, false);
            }
            Err(err) => return Err(err), // In explicit mode, fail on migration error
        }
    } else {
        // No migration needed, just enforce the backend
        dhcp::enforce_output_backend(&mut out, effective_backend, to, false);
    }

    // Validate that Kea-only sources can't be downgraded to ISC without legacy data
    if effective_backend == dhcp::EffectiveDhcpBackend::Isc
        && source_backend.mode == "kea"
        && !dhcp::has_legacy_dhcp_data(&input)
    {
        if to == "pfsense" {
            bail!(
                "cannot convert Kea-only source to pfSense ISC without source legacy DHCP data; use --backend kea or provide ISC-backed source"
            );
        }
        if to == "opnsense" {
            bail!(
                "cannot convert Kea-only source to OPNsense ISC without source legacy DHCP data; use --backend kea or provide ISC-backed source"
            );
        }
    }

    // Optionally disable all DHCP if requested
    if args.disable_dhcp {
        dhcp::disable_all(&mut out);
    }

    // Write final configuration
    write_file(&out, &args.output)
        .with_context(|| format!("failed to write output XML {}", args.output.display()))?;

    // Display conversion summary
    println!("{}", render_conversion_summary(summarize_conversion(&out)));
    Ok(())
}

/// Resolve source platform from CLI argument or auto-detection.
///
/// If the platform is explicitly specified (pfsense/opnsense), returns that value.
/// If set to Auto, detects platform from the XML root tag.
///
/// # Arguments
///
/// * `platform` - CLI-specified platform or Auto
/// * `node` - Parsed XML root to inspect if auto-detecting
///
/// # Returns
///
/// Platform identifier as "pfsense" or "opnsense"
///
/// # Errors
///
/// Returns error if Auto is used but the root tag cannot be recognized.
fn resolve_from_platform(platform: Platform, node: &XmlNode) -> Result<&'static str> {
    match platform {
        Platform::Pfsense => Ok("pfsense"),
        Platform::Opnsense => Ok("opnsense"),
        Platform::Auto => match detect_config(node) {
            ConfigFlavor::PfSense => Ok("pfsense"),
            ConfigFlavor::OpnSense => Ok("opnsense"),
            ConfigFlavor::Unknown => bail!("unable to auto-detect platform from root tag"),
        },
    }
}

/// Normalize target platform from CLI argument.
///
/// The target platform must be explicitly specified (pfsense/opnsense).
/// Auto is not allowed for the target.
///
/// # Arguments
///
/// * `platform` - CLI-specified target platform
///
/// # Returns
///
/// Platform identifier as "pfsense" or "opnsense"
///
/// # Errors
///
/// Returns error if Auto is specified for --to.
fn normalize_to_platform(platform: Platform) -> Result<&'static str> {
    match platform {
        Platform::Pfsense => Ok("pfsense"),
        Platform::Opnsense => Ok("opnsense"),
        Platform::Auto => bail!("--to cannot be auto; specify pfsense or opnsense"),
    }
}

/// Resolve target baseline configuration.
///
/// The target config provides the baseline structure for the output. The converter
/// merges source config elements into this baseline rather than starting from scratch.
///
/// ## Resolution Strategy
///
/// 1. If `--target-file` is provided, loads and validates that file
/// 2. If `--minimal-template` is set, creates an empty root node (dev/testing only)
/// 3. Otherwise, fails with error requiring one of the above
///
/// # Arguments
///
/// * `args` - CLI arguments containing target-file and minimal-template flags
/// * `to` - Target platform identifier ("pfsense" or "opnsense")
///
/// # Returns
///
/// Parsed target configuration tree
///
/// # Errors
///
/// Returns error if:
/// - Target file cannot be parsed
/// - Target file platform doesn't match `to` parameter
/// - Neither --target-file nor --minimal-template is provided
fn resolve_target(args: &ConvertArgs, to: &str) -> Result<XmlNode> {
    if let Some(path) = &args.target_file {
        let parsed =
            parse_file(path).with_context(|| format!("failed to parse {}", path.display()))?;
        let target_flavor = resolve_from_platform(Platform::Auto, &parsed)?;
        if target_flavor != to {
            bail!(
                "target-file platform ({target_flavor}) does not match --to ({to}); provide a matching baseline file"
            );
        }
        return Ok(parsed);
    }

    if args.minimal_template {
        return Ok(XmlNode::new(to));
    }

    bail!(
        "missing --target-file; provide a destination baseline config or use --minimal-template for dev/testing"
    );
}

/// Print human-readable DHCP migration summary to stdout.
///
/// Displays the outcome of an ISC → Kea DHCP migration, including:
/// - IPv4 and IPv6 backend status (kea/isc-fallback/isc-legacy)
/// - Migration statistics (subnets, reservations, option sets)
/// - Skipped conflict counts
///
/// Only prints if there was actual migration activity or preserved interfaces.
///
/// # Arguments
///
/// * `stats` - Migration statistics from the Kea migration process
/// * `final_backend` - Effective backend after migration (may differ from requested)
/// * `preserve_legacy_ipv6` - Whether legacy DHCPv6 was preserved for some interfaces
fn print_dhcp_migration_summary(
    stats: &dhcp::KeaMigrationStats,
    final_backend: dhcp::EffectiveDhcpBackend,
    preserve_legacy_ipv6: bool,
) {
    let has_v4_activity = stats.subnets_added_v4 > 0
        || stats.reservations_added_v4 > 0
        || stats.options_applied_v4 > 0;
    let has_v6_activity = stats.subnets_added_v6 > 0
        || stats.reservations_added_v6 > 0
        || stats.options_applied_v6 > 0;

    if !has_v4_activity && !has_v6_activity && stats.preserved_dhcpdv6_ifaces.is_empty() {
        return;
    }

    let v4_status = if final_backend == dhcp::EffectiveDhcpBackend::Isc {
        "isc-fallback".to_string()
    } else if has_v4_activity {
        format!(
            "kea ({} subnet{}, {} reservation{}, {} option set{})",
            stats.subnets_added_v4,
            if stats.subnets_added_v4 == 1 { "" } else { "s" },
            stats.reservations_added_v4,
            if stats.reservations_added_v4 == 1 {
                ""
            } else {
                "s"
            },
            stats.options_applied_v4,
            if stats.options_applied_v4 == 1 {
                ""
            } else {
                "s"
            },
        )
    } else {
        "kea (no changes)".to_string()
    };

    let v6_status = if preserve_legacy_ipv6 {
        format!("isc-legacy ({})", stats.preserved_dhcpdv6_ifaces.join(", "))
    } else if final_backend == dhcp::EffectiveDhcpBackend::Isc {
        "isc-fallback".to_string()
    } else if has_v6_activity {
        format!(
            "kea ({} subnet{}, {} reservation{}, {} option set{})",
            stats.subnets_added_v6,
            if stats.subnets_added_v6 == 1 { "" } else { "s" },
            stats.reservations_added_v6,
            if stats.reservations_added_v6 == 1 {
                ""
            } else {
                "s"
            },
            stats.options_applied_v6,
            if stats.options_applied_v6 == 1 {
                ""
            } else {
                "s"
            },
        )
    } else {
        "kea (no changes)".to_string()
    };

    println!("dhcp migration: v4={v4_status} v6={v6_status}");

    if stats.reservations_skipped_conflict_v4 > 0 || stats.reservations_skipped_conflict_v6 > 0 {
        println!(
            "dhcp migration: skipped_conflicts v4={} v6={}",
            stats.reservations_skipped_conflict_v4, stats.reservations_skipped_conflict_v6
        );
    }
}

/// Seed pfSense Kea configuration from source config.
///
/// When converting to pfSense with Kea backend, this copies the Kea configuration
/// section from the source (if present) to the output. This preserves existing
/// Kea settings when migrating between platforms.
///
/// ## Source Discovery
///
/// Looks for Kea config in:
/// 1. `<kea>` at root level (pfSense format)
/// 2. `<OPNsense><Kea>` (OPNsense format)
///
/// If found, copies the section and normalizes the tag to `<kea>`.
///
/// # Arguments
///
/// * `out` - Output config being built
/// * `source` - Source config to extract Kea settings from
fn seed_pfsense_kea_from_source(out: &mut XmlNode, source: &XmlNode) {
    let source_kea = source
        .get_child("kea")
        .cloned()
        .or_else(|| {
            source
                .get_child("OPNsense")
                .and_then(|opn| opn.get_child("Kea"))
                .cloned()
        })
        .map(|mut node| {
            node.tag = "kea".to_string();
            node
        });
    let Some(source_kea) = source_kea else {
        return;
    };
    out.children.retain(|c| c.tag != "kea");
    out.children.push(source_kea);
}
