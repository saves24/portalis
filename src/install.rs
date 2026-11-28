//! Installing staged packages: the entry, recovery, the index and the ledger.

use crate::db::Db;
use crate::elf::{record_needs, record_sonames};
use crate::paths::Paths;
use crate::proc::live_paths_in_use;
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

mod activate;
mod generations;
mod hooks;
mod journal;
mod links;
mod operations;
mod plan;
mod preflight;
mod remove;
mod rollback;

#[cfg(test)]
mod tests;

pub use activate::{activate_pending, activate_pending_named};
pub use operations::recover_operations;
pub(crate) use operations::OperationMarker;
pub use plan::{install, InstallOptions};
pub use remove::remove;
pub use rollback::rollback;

use generations::{generations_to_keep, protected_generations};
use links::{move_file, relink_after_failed_remove, warn_missing_backup};

/// Undoes activations a crash left half-applied; write commands call this.
pub fn recover_interrupted(paths: &Paths, db: &crate::db::Db) -> Result<usize> {
    journal::replay(paths, &paths.target_root(), Some(db))
}

/// What stood at a live path before this attempt replaced it.
pub(crate) use journal::Previous;

/// Records that an activation is in progress, and clears that record when it
/// ends, including when it ends by returning early.
struct ActivationMarker {
    path: Option<PathBuf>,
}

impl ActivationMarker {
    fn start(paths: &Paths, name: &str, version: &str) -> Result<Self> {
        let path = paths.state_dir().join("activating");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.write_all(format!("{name} {version}\n").as_bytes())?;
        file.sync_all()?;
        crate::util::sync_dir(&paths.state_dir())?;
        Ok(Self { path: Some(path) })
    }

    /// Drops the record once the activation has committed.
    fn finish(mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for ActivationMarker {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

/// Drops the activation records and the operation marker that a write command
/// refuses to run past, naming each one it removes.
pub fn discard_recovery(paths: &Paths) -> Result<usize> {
    let mut dropped = 0usize;
    let dir = paths.state_dir();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            let journal = (name.starts_with("activation-journal-")
                || name.starts_with("operation-journal-"))
                && name.ends_with(".jsonl");
            if !journal {
                continue;
            }
            if fs::remove_file(entry.path()).is_ok() {
                say!("dropped  {}", entry.path().display());
                dropped += 1;
            }
        }
    }
    for name in ["operation", "activating"] {
        let marker = dir.join(name);
        if fs::remove_file(&marker).is_ok() {
            say!("dropped  {}", marker.display());
            dropped += 1;
        }
    }
    if dropped == 0 {
        say!("nothing  to discard");
    } else {
        say!("note     the paths the dropped records named are no longer rolled back;");
        say!("         reinstall the affected packages if the tree looks wrong");
    }
    Ok(dropped)
}

/// Rebuilds the derived edge tables that the query views read.
pub fn reindex(db: &Db, paths: &Paths) -> Result<()> {
    db.in_transaction(|db| {
        sync_depends_locked(db, paths)?;
        let packages = db.packages()?;
        for pkg in &packages {
            record_sonames(db, &pkg.name)?;
        }
        for pkg in &packages {
            record_needs(db, &pkg.name)?;
        }
        db.mark_indexed()?;
        Ok(())
    })
}

/// Rebuilds the derived edge tables when they are missing.
pub fn ensure_index(db: &Db, paths: &Paths) -> Result<()> {
    if db.edges_indexed() {
        return Ok(());
    }
    reindex(db, paths)
}

/// Rewrites the declared edges of every installed package from its recipe.
pub fn sync_depends(db: &Db, paths: &Paths) -> Result<()> {
    db.in_transaction(|db| sync_depends_locked(db, paths))
}

fn sync_depends_locked(db: &Db, paths: &Paths) -> Result<()> {
    let packages = db.packages()?;
    let stale = db.package_names_with_edges()?;
    let mut kept = Vec::new();
    for pkg in &packages {
        let path = paths.recipe_file(&pkg.name);
        let recipe = if path.exists() {
            crate::recipe::Recipe::load(&path).ok()
        } else {
            None
        };
        match recipe {
            Some(recipe) => db.set_depends(&pkg.name, &recipe.package.depends)?,
            // A package with no recipe and no recorded edges keeps nothing.
            None if path.exists() || stale.contains(&pkg.name) => kept.push(pkg.name.clone()),
            None => {}
        }
    }
    let installed: std::collections::HashSet<String> =
        packages.iter().map(|pkg| pkg.name.clone()).collect();
    for pkg in stale.iter().filter(|name| !installed.contains(*name)) {
        db.clear_depends(pkg)?;
    }
    if !kept.is_empty() {
        eprintln!(
            "warning: kept declared edges for {} package(s) without a readable recipe: {}",
            kept.len(),
            kept.join(", ")
        );
    }
    Ok(())
}

/// Drops the staged copy of a package and leaves the installed version alone.
pub fn drop_staged(name: &str, db: &Db) -> Result<()> {
    if !db.pending_packages()?.iter().any(|pkg| pkg.name == name) {
        bail!("nothing is staged for {name}");
    }
    db.drop_pending(name)?;
    match db.package(name)? {
        Some(_) => say!("dropped  {name} (staged copy; the installed version stays)"),
        None => say!("dropped  {name} (was staged, never activated)"),
    }
    Ok(())
}

/// True when no replaced file is mapped or executed.
pub fn activation_blocked(paths: &Paths, files: &[crate::recipe::ManifestFile]) -> Result<bool> {
    if files.iter().any(|file| {
        file.path.starts_with("/boot/")
            || file.path.starts_with("/lib/modules/")
            || file.path.starts_with("/usr/lib/modules/")
    }) {
        return Ok(true);
    }
    let in_use = match live_paths_in_use(paths) {
        Ok(set) => set,
        // a failed scan counts as "in use"
        Err(error) => {
            eprintln!("warning: {error:#}");
            eprintln!("         the transaction is staged for shutdown");
            return Ok(true);
        }
    };
    Ok(files.iter().any(|file| in_use.contains(&file.path)))
}
