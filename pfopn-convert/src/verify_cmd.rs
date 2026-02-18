use anyhow::{bail, Context, Result};
use pfopn_convert::verify::{build_verify_report_with_version, render_verify_text};
use xml_diff_core::parse_file;

use crate::cli::{OutputFormat, ScanTarget, VerifyArgs};

pub fn run_verify(args: VerifyArgs) -> Result<()> {
    let node = parse_file(&args.file)
        .with_context(|| format!("failed to parse {}", args.file.display()))?;
    let to = args.to.map(scan_target_name);
    let report = build_verify_report_with_version(
        &node,
        to,
        args.target_version.as_deref(),
        args.profiles_dir.as_deref(),
    );

    match args.format {
        OutputFormat::Text => println!("{}", render_verify_text(&report, args.verbose)),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    if report.errors > 0 {
        bail!("verify failed: {} errors", report.errors);
    }
    if args.strict && report.warnings > 0 {
        bail!("verify failed in strict mode: {} warnings", report.warnings);
    }
    Ok(())
}

fn scan_target_name(target: ScanTarget) -> &'static str {
    match target {
        ScanTarget::Pfsense => "pfsense",
        ScanTarget::Opnsense => "opnsense",
    }
}
