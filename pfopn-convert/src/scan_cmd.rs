use anyhow::{Context, Result};
use pfopn_convert::scan::{build_scan_report_with_version, render_scan_text};
use xml_diff_core::parse_file;

use crate::cli::{OutputFormat, ScanArgs, ScanTarget};

pub fn run_scan(args: ScanArgs) -> Result<()> {
    let node = parse_file(&args.file)
        .with_context(|| format!("failed to parse {}", args.file.display()))?;
    let to = args.to.map(scan_target_name);
    let report = build_scan_report_with_version(
        &node,
        to,
        args.target_version.as_deref(),
        args.mappings_dir.as_deref(),
    );

    match args.format {
        OutputFormat::Text => println!("{}", render_scan_text(&report, args.verbose)),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(())
}

fn scan_target_name(target: ScanTarget) -> &'static str {
    match target {
        ScanTarget::Pfsense => "pfsense",
        ScanTarget::Opnsense => "opnsense",
    }
}
