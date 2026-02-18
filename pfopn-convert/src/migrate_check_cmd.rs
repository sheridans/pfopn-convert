use anyhow::{bail, Context, Result};
use pfopn_convert::migrate_check::{
    build_migrate_check_report_with_version, render_migrate_check_text,
};
use xml_diff_core::parse_file;

use crate::cli::{MigrateCheckArgs, OutputFormat, ScanTarget};

pub fn run_migrate_check(args: MigrateCheckArgs) -> Result<()> {
    let node = parse_file(&args.file)
        .with_context(|| format!("failed to parse {}", args.file.display()))?;
    let target = scan_target_name(args.to);
    let report = build_migrate_check_report_with_version(
        &node,
        target,
        args.target_version.as_deref(),
        args.profiles_dir.as_deref(),
    );

    match args.format {
        OutputFormat::Text => println!("{}", render_migrate_check_text(&report, args.verbose)),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    if !report.pass {
        bail!("migrate-check failed: one or more required checks did not pass");
    }
    if args.strict && report.warnings > 0 {
        bail!(
            "migrate-check failed in strict mode: {} warnings",
            report.warnings
        );
    }
    Ok(())
}

fn scan_target_name(target: ScanTarget) -> &'static str {
    match target {
        ScanTarget::Pfsense => "pfsense",
        ScanTarget::Opnsense => "opnsense",
    }
}
