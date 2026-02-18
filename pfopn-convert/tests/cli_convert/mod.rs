use std::path::PathBuf;
use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use xml_diff_core::parse;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

fn path_as_str(path: &Path) -> &str {
    path.to_str().expect("path should be valid utf-8")
}

mod basics;
mod mappings;
mod interfaces;
mod dhcp;
