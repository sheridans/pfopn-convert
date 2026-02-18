use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExpectedProfile {
    #[serde(default)]
    pub required_sections: Vec<String>,
    #[serde(default)]
    pub rule_required_fields: Vec<String>,
    #[serde(default)]
    pub firewall_order_key: Option<String>,
    #[serde(default)]
    pub gateway_required_fields: Vec<String>,
    #[serde(default)]
    pub route_required_fields: Vec<String>,
    #[serde(default)]
    pub route_required_any_fields: Vec<String>,
    #[serde(default)]
    pub bridge_require_members: bool,
    #[serde(default)]
    pub deprecated_sections: Vec<String>,
}

pub fn load_profile(platform: &str, version: &str) -> Option<ExpectedProfile> {
    load_profile_with_source(platform, version, None).map(|(profile, _)| profile)
}

pub fn load_profile_with_source(
    platform: &str,
    version: &str,
    profiles_dir: Option<&Path>,
) -> Option<(ExpectedProfile, String)> {
    let mut names = Vec::new();
    if !version.trim().is_empty() {
        names.push(format!("{}.toml", version.trim()));
        if let Some((major, _)) = version.trim().split_once('.') {
            names.push(format!("{major}.toml"));
        }
    }
    names.push("default.toml".to_string());

    for name in names {
        if let Some(dir) = profiles_dir {
            let path = profile_path(dir, platform, &name);
            if let Ok(profile) = load_profile_file(&path) {
                return Some((profile, format!("file:{}", path.display())));
            }
        }
        if let Some(profile) = load_embedded_profile(platform, &name) {
            return Some((profile, "embedded".to_string()));
        }
    }

    None
}

fn load_embedded_profile(platform: &str, name: &str) -> Option<ExpectedProfile> {
    let raw = match (platform, name) {
        ("pfsense", "default.toml") => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/profiles/pfsense/default.toml"
        ))),
        ("pfsense", "99.toml") => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/profiles/pfsense/99.toml"
        ))),
        ("opnsense", "default.toml") => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/profiles/opnsense/default.toml"
        ))),
        ("opnsense", "99.toml") => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/profiles/opnsense/99.toml"
        ))),
        _ => None,
    }?;

    parse_profile(raw).ok()
}

fn profile_path(base: &Path, platform: &str, name: &str) -> PathBuf {
    base.join(platform).join(name)
}

fn load_profile_file(path: &Path) -> Result<ExpectedProfile, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    parse_profile(&raw).map_err(Into::into)
}

fn parse_profile(raw: &str) -> Result<ExpectedProfile, toml::de::Error> {
    toml::from_str::<ExpectedProfile>(raw)
}

#[cfg(test)]
mod tests {
    use super::{load_embedded_profile, load_profile, load_profile_with_source};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn falls_back_to_major_version_profile() {
        let profile = load_profile("pfsense", "99.1").expect("profile");
        assert!(profile
            .required_sections
            .iter()
            .any(|s| s == "future_section_99"));
    }

    #[test]
    fn falls_back_to_default_profile() {
        let profile = load_profile("pfsense", "not-a-version").expect("profile");
        assert!(!profile
            .required_sections
            .iter()
            .any(|s| s == "future_section_99"));
    }

    #[test]
    fn embedded_profile_loads() {
        let profile = load_embedded_profile("pfsense", "default.toml").expect("embedded profile");
        assert!(profile.required_sections.iter().any(|s| s == "system"));
    }

    #[test]
    fn profile_source_reports_embedded() {
        let (_, source) =
            load_profile_with_source("pfsense", "not-a-version", None).expect("embedded profile");
        assert_eq!(source, "embedded");
    }

    #[test]
    fn profile_source_reports_override_dir() {
        let dir = tempdir().expect("tempdir");
        let base = dir.path();
        let path = base.join("pfsense").join("default.toml");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(
            &path,
            r#"
required_sections = ["system"]
rule_required_fields = []
gateway_required_fields = []
route_required_fields = []
route_required_any_fields = []
bridge_require_members = false
deprecated_sections = []
"#,
        )
        .expect("write profile");

        let (_, source) =
            load_profile_with_source("pfsense", "not-a-version", Some(base)).expect("profile");
        assert!(source.starts_with("file:"));
    }
}
