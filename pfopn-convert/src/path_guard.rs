use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

pub fn ensure_output_not_same(output: &Path, inputs: &[&Path]) -> Result<()> {
    let out_norm = normalize_for_compare(output)
        .with_context(|| format!("failed to normalize output path {}", output.display()))?;

    for input in inputs {
        let in_norm = normalize_for_compare(input)
            .with_context(|| format!("failed to normalize input path {}", input.display()))?;
        if out_norm == in_norm {
            bail!(
                "refusing to overwrite source file: output {} matches input {}",
                output.display(),
                input.display()
            );
        }
    }
    Ok(())
}

fn normalize_for_compare(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        // canonicalize resolves symlinks and `..` for paths that exist on disk.
        return path
            .canonicalize()
            .with_context(|| format!("canonicalize {}", path.display()));
    }

    // For paths that don't yet exist (e.g. the output file), we can't canonicalize.
    // We do a best-effort join with cwd; note that `..` sequences are NOT resolved here,
    // so this check can be fooled by e.g. `--output ../dir/../file.xml`. Acceptable for
    // a CLI tool where the user controls both paths.
    let base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().context("current_dir")?
    };

    Ok(base.join(path))
}
