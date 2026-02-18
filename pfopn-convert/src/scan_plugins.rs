use std::collections::BTreeSet;
use xml_diff_core::XmlNode;

use crate::plugin_detect::PluginInventory;
use crate::plugin_matrix::{
    default_plugin_matrix, load_plugin_matrix, PluginMatrix, PluginSupportStatus,
};

pub(crate) fn detect_known_plugins_present(
    root: &XmlNode,
    platform: &str,
    known: &PluginInventory,
    matrix: &PluginMatrix,
) -> Vec<String> {
    let mut out = known
        .plugins
        .iter()
        .filter(|p| p.declared || p.configured)
        .map(|p| p.plugin.clone())
        .collect::<BTreeSet<_>>();

    for marker in collect_declared_plugin_markers(root, platform) {
        if let Some(entry) = matrix.find_by_marker(platform, &marker) {
            out.insert(entry.id.clone());
        }
    }

    out.into_iter().collect()
}

pub(crate) fn detect_unsupported_plugins(
    root: &XmlNode,
    platform: &str,
    matrix: &PluginMatrix,
) -> Vec<String> {
    let mut out = BTreeSet::new();
    for marker in collect_declared_plugin_markers(root, platform) {
        match matrix.find_by_marker(platform, &marker) {
            Some(entry) if entry.status == PluginSupportStatus::Unsupported => {
                out.insert(entry.id.clone());
            }
            Some(_) => {}
            None => {
                out.insert(marker.to_ascii_lowercase());
            }
        }
    }
    out.into_iter().collect()
}

pub(crate) fn detect_missing_target_compat(
    present: &[String],
    source_platform: &str,
    target: Option<&str>,
    matrix: &PluginMatrix,
) -> Vec<String> {
    let Some(target) = target else {
        return Vec::new();
    };
    if source_platform == target {
        return Vec::new();
    }

    let mut out = Vec::new();
    for plugin in present {
        if !matrix.is_target_compatible(plugin, target) {
            out.push(plugin.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn load_default_plugin_matrix_with_source(
    mappings_dir: Option<&std::path::Path>,
) -> (PluginMatrix, String) {
    let Some(dir) = mappings_dir else {
        return (default_plugin_matrix(), "embedded".to_string());
    };
    let path = dir.join("plugins.toml");
    match load_plugin_matrix(&path) {
        Ok(matrix) => (matrix, format!("file:{}", path.display())),
        Err(err) => {
            eprintln!(
                "warning: failed to load plugin matrix from {} ({err}); using embedded defaults",
                path.display()
            );
            (default_plugin_matrix(), "embedded".to_string())
        }
    }
}

fn collect_declared_plugin_markers(root: &XmlNode, platform: &str) -> Vec<String> {
    match platform {
        "pfsense" => collect_pfsense_installed_packages(root),
        "opnsense" => collect_opnsense_declared_plugins(root),
        _ => Vec::new(),
    }
}

fn collect_pfsense_installed_packages(root: &XmlNode) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(installed) = root.get_child("installedpackages") {
        for package in installed.children.iter().filter(|c| c.tag == "package") {
            if let Some(name) = package.get_text(&["name"]) {
                let n = name.trim();
                if !n.is_empty() {
                    out.push(n.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

fn collect_opnsense_declared_plugins(root: &XmlNode) -> Vec<String> {
    root.get_child("system")
        .and_then(|s| s.get_child("firmware"))
        .and_then(|f| f.get_text(&["plugins"]))
        .unwrap_or("")
        .split([',', ';', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}
