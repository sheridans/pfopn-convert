use std::fs;

use anyhow::{bail, Context, Result};
use clap::Parser;
use pfopn_convert::analyze::{analyze, summarize_analysis, AnalysisEntry, RecommendedAction};
use pfopn_convert::backend_detect::{backend_transition, detect_dhcp_backend};
use pfopn_convert::detect::{detect_config, detect_version_info, ConfigFlavor};
use pfopn_convert::inspect::render_tree;
use pfopn_convert::known_mappings::{
    default_section_mappings, load_section_mappings, KnownSectionMapping,
};
use pfopn_convert::merge::{apply_safe_merge, MergeOptions, MergeTarget};
use pfopn_convert::plugin_detect::detect_plugins;
use pfopn_convert::report::{
    render_analysis, render_section_inventory, render_section_stats, render_summary, render_text,
};
use pfopn_convert::section::{default_key_fields, section_tags};
use pfopn_convert::sections_report::{
    build_inventory, extras_json_report, summarize_by_section, SectionStats,
};
use xml_diff_core::{diff_with_options, parse_file, write_file, DiffEntry, DiffOptions};

mod cli;
mod conversion_summary;
mod convert;
mod interface_guard;
mod migrate_check_cmd;
mod path_guard;
mod scan_cmd;
mod target_prune;
mod verify_cmd;

use cli::{Cli, Command, DiffArgs, InspectArgs, MergeTo, OutputFormat, SectionsArgs};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Diff(args) => run_diff(args),
        Command::Inspect(args) => run_inspect(args),
        Command::Sections(args) => run_sections(args),
        Command::Scan(args) => scan_cmd::run_scan(args),
        Command::Verify(args) => verify_cmd::run_verify(args),
        Command::MigrateCheck(args) => migrate_check_cmd::run_migrate_check(args),
        Command::Convert(args) => convert::run_convert(args),
    }
}

fn run_diff(args: DiffArgs) -> Result<()> {
    let left = parse_file(&args.file1)
        .with_context(|| format!("failed to parse {}", args.file1.display()))?;
    let right = parse_file(&args.file2)
        .with_context(|| format!("failed to parse {}", args.file2.display()))?;

    let opts = DiffOptions {
        include_identical: args.verbose,
        ignore_paths: args.ignore,
        key_fields: default_key_fields(),
        ..DiffOptions::default()
    };

    let mut entries = diff_with_options(&left, &right, &opts);
    if let Some(section) = &args.section {
        entries = filter_section(entries, section);
    }

    let analysis = analyze(&entries);
    let section_stats = summarize_by_section(&entries, &analysis);
    let left_backend = detect_dhcp_backend(&left);
    let right_backend = detect_dhcp_backend(&right);
    let transition = backend_transition(&left_backend, &right_backend);

    if args.strict
        && analysis
            .iter()
            .any(|a| a.action == RecommendedAction::ConflictManual)
    {
        bail!("strict mode failed: manual conflicts detected");
    }

    if let Some(plan_path) = args.plan {
        let plan_json = serde_json::to_string_pretty(&analysis)?;
        fs::write(&plan_path, plan_json)
            .with_context(|| format!("failed to write plan file {}", plan_path.display()))?;
    }

    if let Some(out_path) = args.output {
        path_guard::ensure_output_not_same(&out_path, &[&args.file1, &args.file2])?;
        let target = match args.merge_to {
            MergeTo::Left => MergeTarget::Left,
            MergeTo::Right => MergeTarget::Right,
        };
        let merge_options = MergeOptions {
            transfer_users: !args.no_transfer_users,
            transfer_certs: !args.no_transfer_certs,
            transfer_cas: !args.no_transfer_cas,
        };

        let merged = apply_safe_merge(&left, &right, &entries, target, merge_options)
            .with_context(|| "failed while applying safe merge actions")?;
        write_file(&merged, &out_path)
            .with_context(|| format!("failed to write output XML {}", out_path.display()))?;
    }

    if args.quiet || args.summary {
        println!(
            "left_backend={} right_backend={} backend_transition={}",
            left_backend.mode, right_backend.mode, transition
        );
        println!("{}", render_summary(&entries));
        println!("{}", summarize_analysis(&analysis));
        if args.section_summary {
            println!();
            println!("Section Summary");
            println!("{}", render_section_stats(&section_stats));
        }
        return Ok(());
    }

    match args.format {
        OutputFormat::Text => {
            println!("{}", render_text(&entries));
            println!();
            println!("Action Analysis");
            println!("{}", render_analysis(&analysis));
            if args.section_summary {
                println!();
                println!("Section Summary");
                println!("{}", render_section_stats(&section_stats));
            }
        }
        OutputFormat::Json => {
            let report = DiffReport {
                entries,
                analysis,
                section_stats,
                left_backend,
                right_backend,
                backend_transition: transition,
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    Ok(())
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    let node = parse_file(&args.file)
        .with_context(|| format!("failed to parse {}", args.file.display()))?;

    if args.detect {
        let flavor = match detect_config(&node) {
            ConfigFlavor::PfSense => "pfsense",
            ConfigFlavor::OpnSense => "opnsense",
            ConfigFlavor::Unknown => "unknown",
        };
        let version = detect_version_info(&node);
        let backend = detect_dhcp_backend(&node);
        println!(
            "type={flavor} version={} version_source={} version_confidence={} dhcp_backend={} backend_reason={}",
            version.value, version.source, version.confidence, backend.mode, backend.reason
        );
    }

    if args.plugins {
        let inventory = detect_plugins(&node);
        println!("plugins platform={}", inventory.platform);
        for plugin in inventory.plugins {
            println!(
                "- {} declared={} configured={} enabled={}",
                plugin.plugin, plugin.declared, plugin.configured, plugin.enabled
            );
            for evidence in plugin.evidence {
                println!("  evidence: {evidence}");
            }
        }
    }

    let target = if let Some(section) = args.section {
        node.get_child(&section)
            .with_context(|| format!("section '{}' not found", section))?
    } else {
        &node
    };

    print!("{}", render_tree(target, args.depth));
    Ok(())
}

fn run_sections(args: SectionsArgs) -> Result<()> {
    let left = parse_file(&args.file1)
        .with_context(|| format!("failed to parse {}", args.file1.display()))?;
    let right = parse_file(&args.file2)
        .with_context(|| format!("failed to parse {}", args.file2.display()))?;

    let (mappings, mappings_source) =
        resolve_mappings(args.mappings_file.as_deref(), args.mappings_dir.as_deref());
    let inventory = build_inventory(
        &left,
        &right,
        args.extras || args.extras_json,
        &mappings,
        mappings_source.clone(),
    );
    if args.extras_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&extras_json_report(&inventory))?
        );
        return Ok(());
    }
    match args.format {
        OutputFormat::Text => {
            if args.verbose {
                println!("Using mappings: {}", mappings_source);
            }
            println!("{}", render_section_inventory(&inventory));
        }
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&inventory)?),
    }

    Ok(())
}

fn resolve_mappings(
    path: Option<&std::path::Path>,
    mappings_dir: Option<&std::path::Path>,
) -> (Vec<KnownSectionMapping>, String) {
    let chosen = if let Some(path) = path {
        path.to_path_buf()
    } else if let Some(dir) = mappings_dir {
        dir.join("sections.toml")
    } else {
        return (default_section_mappings(), "embedded".to_string());
    };

    match load_section_mappings(&chosen) {
        Ok(mappings) => (mappings, format!("file:{}", chosen.display())),
        Err(err) => {
            eprintln!(
                "warning: failed to load mappings from {} ({err}); using embedded defaults",
                chosen.display()
            );
            (default_section_mappings(), "embedded".to_string())
        }
    }
}

fn filter_section(entries: Vec<DiffEntry>, section: &str) -> Vec<DiffEntry> {
    let filters: Vec<String> = section_tags(section)
        .map(|tags| tags.iter().map(|tag| format!(".{tag}")).collect())
        .unwrap_or_else(|| vec![format!(".{section}")]);

    entries
        .into_iter()
        .filter(|entry| {
            let path = diff_path(entry);
            filters
                .iter()
                .any(|needle| path.contains(needle) || path.starts_with(&needle[1..]))
        })
        .collect()
}

fn diff_path(entry: &DiffEntry) -> &str {
    match entry {
        DiffEntry::Identical { path }
        | DiffEntry::Modified { path, .. }
        | DiffEntry::OnlyLeft { path, .. }
        | DiffEntry::OnlyRight { path, .. }
        | DiffEntry::Structural { path, .. } => path,
    }
}

#[derive(Debug, serde::Serialize)]
struct DiffReport {
    entries: Vec<DiffEntry>,
    analysis: Vec<AnalysisEntry>,
    section_stats: Vec<SectionStats>,
    left_backend: pfopn_convert::backend_detect::BackendDetection,
    right_backend: pfopn_convert::backend_detect::BackendDetection,
    backend_transition: String,
}
