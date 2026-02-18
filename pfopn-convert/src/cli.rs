use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "pfopn-convert")]
#[command(about = "Compare and inspect firewall XML configurations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Compare two XML files and show differences.
    Diff(DiffArgs),
    /// Show parsed structure of a single XML file.
    Inspect(InspectArgs),
    /// List top-level sections and suggest mapping hints between two files.
    Sections(SectionsArgs),
    /// Scan one config and report migration readiness.
    Scan(ScanArgs),
    /// Verify one config for pre-restore readiness.
    Verify(VerifyArgs),
    /// Strict go/no-go migration gate for one config.
    MigrateCheck(MigrateCheckArgs),
    /// Convert one config toward a target platform.
    Convert(ConvertArgs),
}

#[derive(Parser, Debug)]
pub struct DiffArgs {
    pub file1: PathBuf,
    pub file2: PathBuf,
    #[arg(long)]
    pub section: Option<String>,
    #[arg(long)]
    pub ignore: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    #[arg(long)]
    pub summary: bool,
    #[arg(short, long)]
    pub verbose: bool,
    #[arg(short, long)]
    pub quiet: bool,
    #[arg(long)]
    pub plan: Option<PathBuf>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub strict: bool,
    #[arg(long, value_enum, default_value_t = MergeTo::Right)]
    pub merge_to: MergeTo,
    /// Do not transfer referenced system users for OpenVPN dependencies.
    #[arg(long)]
    pub no_transfer_users: bool,
    /// Do not transfer referenced certificates for OpenVPN dependencies.
    #[arg(long)]
    pub no_transfer_certs: bool,
    /// Do not transfer referenced CAs for OpenVPN dependencies.
    #[arg(long)]
    pub no_transfer_cas: bool,
    /// Show per-section summary table.
    #[arg(long)]
    pub section_summary: bool,
}

#[derive(Parser, Debug)]
pub struct InspectArgs {
    pub file: PathBuf,
    #[arg(long)]
    pub section: Option<String>,
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
    #[arg(long)]
    pub detect: bool,
    /// Show common plugin detection (declared/configured/enabled).
    #[arg(long)]
    pub plugins: bool,
}

#[derive(Parser, Debug)]
pub struct SectionsArgs {
    pub file1: PathBuf,
    pub file2: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    #[arg(long)]
    pub verbose: bool,
    /// Enable heuristic extras (moved/renamed section hints).
    #[arg(long)]
    pub extras: bool,
    /// Emit grouped extras/unmatched payload as JSON.
    #[arg(long)]
    pub extras_json: bool,
    /// Optional mappings TOML file. Defaults to pfopn-convert/mappings/sections.toml if present.
    #[arg(long, conflicts_with = "mappings_dir")]
    pub mappings_file: Option<PathBuf>,
    /// Optional mappings directory (expects sections.toml, plugins.toml).
    #[arg(long, conflicts_with = "mappings_file")]
    pub mappings_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum ScanTarget {
    Pfsense,
    Opnsense,
}

#[derive(Parser, Debug)]
pub struct ScanArgs {
    /// Config file to inspect.
    pub file: PathBuf,
    /// Optional target platform for compatibility hints.
    #[arg(long, value_enum)]
    pub to: Option<ScanTarget>,
    /// Optional target version metadata override (informational only).
    #[arg(long)]
    pub target_version: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Optional mappings directory (expects sections.toml, plugins.toml).
    #[arg(long)]
    pub mappings_dir: Option<PathBuf>,
    /// Show data source metadata.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Parser, Debug)]
pub struct VerifyArgs {
    /// Config file to verify.
    pub file: PathBuf,
    /// Optional target platform for compatibility checks.
    #[arg(long, value_enum)]
    pub to: Option<ScanTarget>,
    /// Optional target schema/profile version override (for example 24.7, 2.7.2).
    #[arg(long)]
    pub target_version: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Optional profiles directory (expects <dir>/<platform>/<version>.toml).
    #[arg(long)]
    pub profiles_dir: Option<PathBuf>,
    /// Show data source metadata.
    #[arg(long)]
    pub verbose: bool,
    /// Treat warnings as failures.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Parser, Debug)]
pub struct MigrateCheckArgs {
    /// Config file to evaluate for restore readiness.
    pub file: PathBuf,
    /// Required target platform.
    #[arg(long, value_enum)]
    pub to: ScanTarget,
    /// Optional target schema/profile version override (for example 24.7, 2.7.2).
    #[arg(long)]
    pub target_version: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Optional profiles directory (expects <dir>/<platform>/<version>.toml).
    #[arg(long)]
    pub profiles_dir: Option<PathBuf>,
    /// Show data source metadata.
    #[arg(long)]
    pub verbose: bool,
    /// Treat warnings as failures.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum MergeTo {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Platform {
    Auto,
    Pfsense,
    Opnsense,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum DhcpBackend {
    Auto,
    Kea,
    Isc,
}

#[derive(Parser, Debug)]
pub struct ConvertArgs {
    /// Source config file to convert.
    pub input: PathBuf,
    /// Output file path.
    #[arg(short, long)]
    pub output: PathBuf,
    /// Source platform (`auto` detects from root tag).
    #[arg(long, value_enum, default_value_t = Platform::Auto)]
    pub from: Platform,
    /// Destination platform.
    #[arg(long, value_enum)]
    pub to: Platform,
    /// Target baseline/template config (required unless --minimal-template is set).
    #[arg(long)]
    pub target_file: Option<PathBuf>,
    /// Build from a minimal target root instead of requiring --target-file (dev/testing only).
    #[arg(long)]
    pub minimal_template: bool,
    /// Do not transfer referenced system users for OpenVPN dependencies.
    #[arg(long)]
    pub no_transfer_users: bool,
    /// Do not transfer referenced certificates for OpenVPN dependencies.
    #[arg(long)]
    pub no_transfer_certs: bool,
    /// Do not transfer referenced CAs for OpenVPN dependencies.
    #[arg(long)]
    pub no_transfer_cas: bool,
    /// Set LAN IPv4 address on generated output and remap LAN DHCP IPv4 values accordingly.
    #[arg(long)]
    pub lan_ip: Option<String>,
    /// Disable DHCP services in generated output (safety guard for lab restores).
    #[arg(long)]
    pub disable_dhcp: bool,
    /// DHCP backend policy for target conversion.
    #[arg(long, value_enum, default_value_t = DhcpBackend::Auto)]
    pub backend: DhcpBackend,
}
