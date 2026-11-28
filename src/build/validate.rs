//! Path validation for recipe-declared build mounts.
use crate::recipe::Recipe;
use anyhow::{bail, Result};
use std::fs;
use std::path::Path;

/// Refuses writable paths that point at host system trees.
pub(super) fn validate_writable(recipe: &Recipe) -> Result<()> {
    for path in &recipe.build.writable {
        if !Path::new(path).exists() {
            bail!("build.writable path does not exist: {path}");
        }
        let canonical = fs::canonicalize(path)?;
        let probe = Path::new(path.trim_end_matches('/'));
        let probe = if probe.as_os_str().is_empty() {
            Path::new("/")
        } else {
            probe
        };
        if canonical != probe {
            bail!(
                "build.writable path traverses a symlink: {path} -> {}",
                canonical.display()
            );
        }
    }
    const PROTECTED: [&str; 21] = [
        "etc", "root", "home", "usr", "boot", "proc", "sys", "dev", "var", "bin", "sbin", "lib",
        "lib32", "lib64", "libx32", "run", "opt", "srv", "mnt", "media", "tmp",
    ];
    for path in &recipe.build.writable {
        let trimmed = path.trim_matches('/');
        let blocked = trimmed.is_empty()
            || PROTECTED
                .iter()
                .any(|root| trimmed == *root || trimmed.starts_with(&format!("{root}/")));
        if blocked {
            bail!("build.writable may not name {path}: system directories stay read-only");
        }
    }
    Ok(())
}

/// Refuses read paths that resolve through a symlink or into a protected tree.
pub(super) fn validate_read(recipe: &Recipe) -> Result<()> {
    for path in &recipe.build.read {
        let probe = Path::new(path);
        if !probe.exists() {
            continue;
        }
        let canonical = fs::canonicalize(probe)?;
        if canonical != probe {
            bail!(
                "build.read path traverses a symlink: {path} -> {}",
                canonical.display()
            );
        }
        let resolved = format!("/{}", canonical.to_string_lossy().trim_start_matches('/'));
        if crate::policy::is_protected_path(&resolved) {
            bail!("build.read may not expose protected path {resolved}");
        }
    }
    Ok(())
}
