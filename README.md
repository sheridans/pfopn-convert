# pfopn-convert

![CI](https://github.com/sheridans/pfopn-convert/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/sheridans/pfopn-convert?display_name=tag)

CLI for migrating firewall configs between pfSense and OPNsense, with section-aware diff analysis and pre-restore validation.

> WARNING: This tool can break network connectivity or lock you out if used incorrectly. It is intended for restore/migration onto fresh destination installs. Do not restore to production systems unless you fully understand the generated changes and have rollback access.

## Build

```bash
cargo build --release
```

Add `target/release/pfopn-convert` to your PATH, or run it directly from that path.

## Safe Migration Workflow

`convert` is baseline-merge by design. You need:

1. `source` export: live config from the platform you are migrating from.
2. `target baseline` export: fresh/default config export from the destination platform/version.

Then:

1. run `convert` with `--target-file <target-baseline.xml>` to generate a new output XML.
2. run `verify` and `migrate-check` on that output.
3. restore/import the generated output on the destination firewall.

## Quick Start (Do This)

`pfSense -> OPNsense`:

```bash
pfopn-convert convert /path/source-pfsense.xml \
  --from pfsense \
  --to opnsense \
  --target-file /path/opnsense-fresh.xml \
  --output /tmp/converted-opnsense.xml

pfopn-convert verify /tmp/converted-opnsense.xml --to opnsense --strict
```

`OPNsense -> pfSense`:

```bash
pfopn-convert convert /path/source-opnsense.xml \
  --from opnsense \
  --to pfsense \
  --target-file /path/pfsense-fresh.xml \
  --output /tmp/converted-pfsense.xml

pfopn-convert verify /tmp/converted-pfsense.xml --to pfsense --strict
```

Then restore the generated XML on destination.
Optional flags for initial migration:
- `--lan-ip <IPv4>` only if you want to change the LAN IP/subnet in the output.
- `--disable-dhcp` only if you want DHCP services off in the generated output.

## Prerequisites

- Before you run this, set up the destination firewall and give its network ports the right names (like `wan` and `lan`).
- If the hardware is different, the port device names will change (for example `igb0` becomes `vtnet0`).
- The tool matches by the logical names (`wan`, `lan`, `opt1`), not by device names. The destination baseline decides the rename.
- This is intentional so configs still work when hardware device names change during migration.
- If a required physical port isn’t assigned in the destination baseline, the convert step will fail.

## Before Restore

- Take a full config backup of the destination firewall before any restore.
- If testing in VM/lab, take a VM snapshot before first import.
- If restore reports interface assignment warnings, reboot the destination and restore the same generated XML a second time.
- This appears to be an intermittent OPNsense interface/apply behavior.

This is intended for safe migration to a different system first (for example lab/VM hardware), so
you do not risk your live source firewall during initial validation.
Use a fresh/default destination install for the baseline export whenever possible. Existing
destination config state (especially bridges, prior interface assignments, gateways, or
plugin-managed objects) can conflict with imported assignments and break post-restore behavior.

Example (`pfSense -> OPNsense`):

```bash
pfopn-convert convert pfsense-live.xml \
  --to opnsense \
  --target-file opnsense-fresh.xml \
  --output converted-opnsense.xml
```

## Commands

### `diff`
Compare two XML files and emit differences plus action analysis.

```bash
pfopn-convert diff <FILE1> <FILE2> [OPTIONS]
```

Options:

- `--section <name>`: focus on one logical section (`system`, `interfaces`, `firewall`, `services`, `vpn`, `packages`)
- `--ignore <path-or-tag>`: ignore path/tag (repeatable)
- `--format <text|json>`: output format
- `--summary`: print only counts
- `--section-summary`: print per-section counts sorted by conflict density
- `--plan <file>`: write action plan JSON
- `--output <file>`: write merged XML using safe insert-only actions
- `--merge-to <left|right>`: destination side for merge output (default `right`)
- default `--output` behavior also transfers OpenVPN dependencies required for migration:
  - referenced system users
  - referenced certs
  - referenced CAs
  - and transfers missing WireGuard config sections (pfSense `<wireguard>` / OPNsense `<OPNsense><wireguard>`)
- opt-out flags:
  - `--no-transfer-users`
  - `--no-transfer-certs`
  - `--no-transfer-cas`
- `--strict`: fail if any manual conflicts remain
- `-v, --verbose`: include identical entries
- `-q, --quiet`: minimal output

### `inspect`
Show parsed structure and optional config detection.

```bash
pfopn-convert inspect <FILE> [--detect] [--plugins] [--section <name>] [--depth <N>]
```

- `--plugins`: show common plugin state detection (`declared`, `configured`, `enabled`) for migration planning.
  - includes `wireguard`, `openvpn`, `ipsec`, `kea-dhcp`, `isc-dhcp`, and `tailscale`.

### `convert`
Convert one file toward a target platform.

```bash
pfopn-convert convert <INPUT> --output <FILE> --from <auto|pfsense|opnsense> --to <pfsense|opnsense> --target-file <FILE> [--backend <auto|kea|isc>]
```

- `--from auto` detects source from root tag; `--to` must be explicit.
- `--target-file` is required: provide a fresh/default config export from the destination platform.
- `--output` is required: path for the generated XML.
- `--backend auto|kea|isc` controls DHCP backend policy; `auto` defaults to Kea for OPNsense 26.x targets.
- `--lan-ip <IPv4>` is optional; use it only if you want to change LAN IP/subnet and remap LAN DHCP ranges.
- `--disable-dhcp` is optional; use it only if you want DHCP services off in the generated output.
- The tool lines up interfaces by names like `wan` and `lan`. The baseline tells it which device name (`igb0`, `vtnet0`) to use.
- preflight fails if required physical-interface-backed logical assignments are missing from the target baseline; virtual-backed interfaces (VLAN, WireGuard, OpenVPN) can be created from source.

### `sections`
List top-level sections in both files, plus mapping hints.

```bash
pfopn-convert sections <FILE1> <FILE2> [--format <text|json>] [--extras] [--extras-json] [--verbose] [--mappings-file <path> | --mappings-dir <dir>]
```

- `--extras`: enable heuristic hints for likely moved/renamed sections by scanning nested paths.
  - also emits OpenVPN migration checks:
  - `vpn_disabled_config_present` when disabled OpenVPN instances exist
  - `vpn_dependency_gap` when referenced users/certs/CAs are missing on target
  - also emits WireGuard migration checks:
  - `wireguard_dependency_gap` when WireGuard config exists on one side only
  - `wireguard_disabled_config_present` when config exists but no enabled entries are detected
  - and plugin compatibility checks:
  - `plugin_support_gap` when plugin presence differs between sides
  - and IPsec dependency checks:
  - `ipsec_dependency_gap` when referenced certs/CAs/interfaces are missing on the opposite side
- `--extras-json`: emit grouped extras plus unmatched section lists as JSON.
- `--mappings-file <path>`: load known section mappings from TOML file.
- `--mappings-dir <dir>`: load mappings from `<dir>/sections.toml`.
- defaults are embedded; `--mappings-file` and `--mappings-dir` are mutually exclusive.
- `--verbose`: show mapping source (`Using mappings: ...` in text mode).

### `scan`
Quick migration-readiness scan for a single config.

```bash
pfopn-convert scan <FILE> [--to <pfsense|opnsense>] [--target-version <VERSION>] [--format <text|json>] [--verbose] [--mappings-dir <dir>]
```

- reports detected platform/version/backend
- lists supported vs review-required top-level sections
- shows known plugins present and unsupported plugin packages (from plugin matrix + unknown package detection)
- with `--to`, includes target compatibility hints for detected plugins
- with `--target-version`, includes target schema version metadata in scan output (informational only)
- `--mappings-dir <dir>`: load plugin matrix from `<dir>/plugins.toml`.
- `--verbose`: show mapping source (`Using mappings: ...` in text mode).
- plugin matrix: embedded by default; can be overridden in future (no CLI flag yet)

### `verify`
Pre-restore validation gate for a single config.

```bash
pfopn-convert verify <FILE> [--to <pfsense|opnsense>] [--target-version <VERSION>] [--format <text|json>] [--strict] [--verbose]
```

- exits non-zero when hard errors are found
- checks required sections and internal reference integrity for OpenVPN/IPsec dependencies
- checks interface/bridge integrity:
  - missing interface references in rules/gateways/static routes
  - empty bridge members
- checks rule reference integrity:
  - missing alias references in filter rules
  - missing gateway references in filter/static route entries
  - missing schedule references in filter rules (warning)
- checks firewall rule signature collisions:
  - duplicate rule signatures (warning)
  - default-rule overlaps with custom signatures (warning)
- checks WireGuard readiness:
  - errors if WireGuard appears enabled but no `wireguard`/`tun_wg*` interface assignment exists
- warns on unsupported plugins and target compatibility gaps
- `--target-version` overrides profile selection for expected-schema checks
  (`<exact>.toml` -> `<major>.toml` -> `default.toml`)
- `--strict` also fails on warnings
- `--profiles-dir <path>`: override embedded profiles with files from `<path>/<platform>/<version>.toml`
- `--verbose`: show profile source (`Using profiles: ...` in text mode).

### `migrate-check`
Go/no-go pre-restore check with explicit PASS/FAIL items.

```bash
pfopn-convert migrate-check <FILE> --to <pfsense|opnsense> [--target-version <VERSION>] [--format <text|json>] [--strict] [--verbose]
```

- combines scan + verify checks into one report
- fails non-zero when required checks fail
- reports conversion-style counts (`interfaces`, `bridges`, `aliases`, `rules`, `routes`, `vpns`)
- includes advisory expected-schema baseline checks from profiles:
  - `pfopn-convert/profiles/pfsense/default.toml`
  - `pfopn-convert/profiles/opnsense/default.toml`
- `--target-version` overrides profile selection (`<exact>.toml` -> `<major>.toml` -> `default.toml`)
- `--strict` also fails when warnings exist
- `--profiles-dir <path>`: override embedded profiles with files from `<path>/<platform>/<version>.toml`
- `--verbose`: show profile + mapping sources (`Using profiles: ...`, `Using mappings: ...` in text mode).

## Support Status

Current support level by area:

| Area | Status |
|---|---|
| `system` | partial |
| `interfaces` | supported-with-checks |
| `filter` / `nat` | partial |
| `aliases` | supported |
| `dhcpd` / `dhcpdv6` | supported-with-checks |
| `openvpn` | supported-with-checks |
| `ipsec` | supported-with-checks |
| `wireguard` | supported-with-checks |
| `tailscale` | supported-with-checks |
| `gateways` | supported-with-checks |
| `staticroutes` | supported-with-checks |
| `ifgroups` | supported-with-checks |
| packages/plugins (general) | partial |

`scan` is the authoritative first-run readiness report for what is supported vs requires manual review in a given file.

Mappings and plugin matrix are embedded by default.
You can override section mappings with `--mappings-file` or `--mappings-dir`.
`--mappings-file` and `--mappings-dir` are mutually exclusive.
Profiles can be overridden with `--profiles-dir`.

Plain English:
- “Mappings” are just a small list that tells the tool how section names line up between pfSense and OPNsense.
- “Profiles” are simple rules for what sections/fields must exist for a given platform/version.

## Example Workflow

1. Inventory sections and naming gaps:
```bash
pfopn-convert sections pfsense.xml opnsense.xml
```

2. Get high-level and per-section counts:
```bash
pfopn-convert diff pfsense.xml opnsense.xml --summary --section-summary
```

3. Export machine-readable report and plan:
```bash
pfopn-convert diff pfsense.xml opnsense.xml --format json --plan /tmp/plan.json > /tmp/report.json
```

4. Produce safe insert-only merged output for review:
```bash
pfopn-convert diff pfsense.xml opnsense.xml --output /tmp/merged.xml --merge-to right
```

## Output Semantics

Diff counts:

- `modified`: same path exists in both, values differ
- `only_left`: path exists only in first file
- `only_right`: path exists only in second file
- `structural`: structure/tag mismatch

Analysis counts:

- `insert_left_to_right`: safe insert candidate
- `insert_right_to_left`: safe insert candidate
- `conflict_manual`: requires manual or handler-driven mapping
- `noop`: no action required

Backend metadata:

- summary output includes `left_backend`, `right_backend`, and `backend_transition`
- `inspect --detect` includes `version_source`, `version_confidence`, `dhcp_backend`, and `backend_reason`

## Support

If this tool saves you time, feel free to buy me a coffee:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?style=flat&logo=buy-me-a-coffee)](https://buymeacoffee.com/sheridans)
