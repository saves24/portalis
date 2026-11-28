//! Turning a staged package into live links, and undoing it when a step fails.
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::hooks::run_hooks;
use super::journal::Entry;
use super::operations::OperationJournal;
use super::{
    generations_to_keep, move_file, protected_generations, ActivationMarker, OperationMarker,
    Previous,
};
use crate::db::Db;
use crate::elf::record_elf_links;
use crate::links::{
    ensure_live_directory, live_path, remove_live_directory, repair_links, safe_symlink,
};
use crate::paths::Paths;

/// Applies every staged package to the live tree.
pub fn activate_pending(db: &mut Db, paths: &Paths) -> Result<usize> {
    activate_pending_where(db, paths, None)
}

/// Applies the staged copy of one package to the live tree.
pub fn activate_pending_named(db: &mut Db, paths: &Paths, name: &str) -> Result<usize> {
    activate_pending_where(db, paths, Some(name))
}

fn activate_pending_where(db: &mut Db, paths: &Paths, only: Option<&str>) -> Result<usize> {
    let target_root = paths.target_root();
    let staged: Vec<_> = db
        .pending_packages()?
        .into_iter()
        .filter(|pkg| only.is_none_or(|name| pkg.name == name))
        .collect();
    if staged.is_empty() {
        say!("activate nothing staged");
        repair_links(db, paths)?;
        return Ok(0);
    }

    let mut applied = 0usize;
    let mut applied_names: Vec<String> = Vec::new();
    for pkg in &staged {
        match activate_one(db, paths, &target_root, pkg) {
            Ok(true) => {
                if let Err(error) =
                    crate::stage::expose_etc(Path::new(&pkg.store_path), &pkg.name, paths)
                {
                    eprintln!(
                        "warning: the etc link for {} was not exposed: {error:#}",
                        pkg.name
                    );
                }
                applied += 1;
                applied_names.push(pkg.name.clone());
            }
            Ok(false) => {}
            Err(error) => {
                if let Err(repair) = repair_links(db, paths) {
                    eprintln!(
                        "warning: links were not rebuilt after a failed activation: {repair:#}"
                    );
                }
                for name in &applied_names {
                    if let Some(pkg) = db.package(name)? {
                        finish_activation(db, &pkg, &target_root);
                    }
                }
                if applied > 0 {
                    if let Err(error) = db.clear_index() {
                        eprintln!("warning: the derived index could not be invalidated: {error:#}");
                    }
                }
                return Err(error);
            }
        }
    }
    if let Err(error) = repair_links(db, paths) {
        eprintln!("warning: links were not rebuilt after activation: {error:#}");
    }
    for name in applied_names {
        if let Some(pkg) = db.package(&name)? {
            finish_activation(db, &pkg, &target_root);
        }
    }
    if applied > 0 {
        if let Err(error) = db.clear_index() {
            eprintln!("warning: the derived index could not be invalidated: {error:#}");
        }
    }
    Ok(applied)
}

/// Restores the live paths an activation replaced: a link goes back, a file
/// comes out of the backup directory, a new path is removed. A path whose
/// backup is missing is left exactly as it is.
pub(super) fn restore_created(target_root: &Path, created: &[(String, Previous)]) {
    for (path, previous) in created {
        let step = (|| -> Result<()> {
            match previous {
                Previous::Missing => crate::links::remove_in_live(target_root, path)?,
                Previous::Symlink { target } => {
                    crate::links::remove_in_live(target_root, path)?;
                    crate::links::safe_symlink(target_root, path, target)?;
                }
                Previous::Restored { backup } => {
                    let backup = Path::new(backup);
                    let live = crate::links::live_path(target_root, path);
                    if fs::symlink_metadata(&live)
                        .map(|m| m.is_file())
                        .unwrap_or(false)
                    {
                        if let Some(parent) = backup.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::rename(&live, backup)?;
                    }
                }
                Previous::Displaced { backup } => {
                    let backup = Path::new(backup);
                    if backup.exists() {
                        crate::links::remove_in_live(target_root, path)?;
                        crate::links::restore_backup(target_root, path, backup)?;
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = step {
            eprintln!("warning: {path} was not put back: {error:#}");
        }
    }
}

/// Applies one staged package: its live links, its ledger rows, then its hooks.
///
/// A package whose files are still unmanaged stays staged and is reported; the
/// activation marker is dropped however this returns.
fn activation_plan(
    paths: &Paths,
    target_root: &Path,
    entries: &[(String, String, String, u32, String)],
) -> Vec<super::journal::Entry> {
    entries
        .iter()
        .map(|entry| {
            let path = entry.0.clone();
            let live = live_path(target_root, &path);
            let previous = match fs::read_link(&live) {
                Ok(target) => super::journal::Previous::Symlink {
                    target: target.to_string_lossy().to_string(),
                },
                Err(_) if fs::symlink_metadata(&live).is_ok() => {
                    super::journal::Previous::Displaced {
                        backup: paths
                            .state_dir()
                            .join("backup")
                            .join(path.trim_start_matches('/'))
                            .display()
                            .to_string(),
                    }
                }
                Err(_) => super::journal::Previous::Missing,
            };
            super::journal::Entry { path, previous }
        })
        .collect()
}

fn apply_entries(
    db: &Db,
    pkg: &crate::db::PackageRow,
    paths: &Paths,
    target_root: &Path,
    entries: &[(String, String, String, u32, String)],
    plan: &[super::journal::Entry],
    created: &mut Vec<(String, Previous)>,
) -> Result<usize> {
    let mut kept = 0usize;
    for (entry, planned) in entries.iter().zip(plan.iter()) {
        let path = entry.0.clone();
        let config = entry.4 == "config";
        let kept_before = kept;
        apply_pending_file(db, pkg, paths, target_root, entry.clone(), &mut kept)?;
        // a path the step left alone (an unmanaged file it skipped) is not
        // something a rollback may touch
        if !config && kept == kept_before {
            created.push((path, planned.previous.clone()));
        }
    }
    Ok(kept)
}

fn apply_directories(
    db: &Db,
    pkg: &crate::db::PackageRow,
    target_root: &Path,
) -> Result<Vec<String>> {
    let Some(manifest) = db.pending_manifest(&pkg.name)? else {
        return Ok(Vec::new());
    };
    let mut created = Vec::new();
    for dir in &manifest.dirs {
        if crate::policy::is_protected_path(&dir.path) {
            remove_directories(target_root, &created);
            bail!("refusing to create protected directory {}", dir.path);
        }
        match ensure_live_directory(target_root, &dir.path, dir.mode) {
            Ok(true) => created.push(dir.path.clone()),
            Ok(false) => {}
            Err(error) => {
                remove_directories(target_root, &created);
                return Err(error).with_context(|| format!("creating {}", dir.path));
            }
        }
    }
    Ok(created)
}

fn remove_directories(target_root: &Path, directories: &[String]) {
    for directory in directories.iter().rev() {
        if let Err(error) = remove_live_directory(target_root, directory) {
            eprintln!("warning: {directory} was not removed: {error:#}");
        }
    }
}

fn settle_activation(
    db: &mut Db,
    paths: &Paths,
    pkg: &crate::db::PackageRow,
    target_root: &Path,
    journal: &mut super::journal::Journal,
    shipped: &std::collections::BTreeSet<String>,
) -> Result<usize> {
    db.promote_pending(&pkg.name)?;
    db.clear_pending(&pkg.name)?;
    db.commit()?;
    if let Err(error) = journal.commit() {
        eprintln!("warning: the activation record was not marked as committed: {error:#}");
    }
    let label = format!("activation of {} {}", pkg.name, pkg.version);
    let marker = OperationMarker::start(paths, &label)?;
    let mut record = OperationJournal::begin(paths, &label)?;
    db.begin()?;
    let dropped = match drop_unshipped_files(db, target_root, &pkg.name, shipped, &mut record) {
        Ok(dropped) => {
            if let Err(error) = db.commit() {
                record.keep();
                marker.keep();
                return Err(error);
            }
            if let Err(error) = record.commit() {
                marker.keep();
                return Err(error);
            }
            marker.finish();
            dropped
        }
        Err(error) => {
            db.abort();
            record.keep();
            marker.keep();
            return Err(error);
        }
    };
    if let Err(error) = db.snapshot(&format!("activate {} {}", pkg.name, pkg.version)) {
        eprintln!("warning: the activation generation was not recorded: {error:#}");
    }
    let keep = generations_to_keep(paths);
    if let Err(error) = db.prune_generations(keep, &protected_generations(paths)) {
        eprintln!("warning: old generations were not pruned: {error:#}");
    }
    Ok(dropped)
}

fn finish_activation(db: &Db, pkg: &crate::db::PackageRow, target_root: &Path) {
    if let Err(error) = record_elf_links(db, &pkg.name) {
        eprintln!(
            "warning: library edges not recorded for {}: {error}",
            pkg.name
        );
    }
    for warning in run_hooks(&pkg.hooks, target_root) {
        eprintln!("warning: {warning}");
    }
}

fn activate_one(
    db: &mut Db,
    paths: &Paths,
    target_root: &Path,
    pkg: &crate::db::PackageRow,
) -> Result<bool> {
    let marker = ActivationMarker::start(paths, &pkg.name, &pkg.version)?;
    let entries = db.pending_of(&pkg.name)?;
    let shipped: std::collections::BTreeSet<String> =
        entries.iter().map(|entry| entry.0.clone()).collect();
    // The plan is on disk before the first move; the header names the store this
    // activation installs.
    let mut journal = super::journal::Journal::begin(
        paths,
        &pkg.name,
        &pkg.version,
        &pkg.store_path,
        Some(&*db),
    )?;
    let plan = activation_plan(paths, target_root, &entries);
    journal.write_plan(&plan)?;
    db.begin()?;
    let created_dirs = match apply_directories(db, pkg, target_root) {
        Ok(created) => created,
        Err(error) => {
            db.abort();
            return Err(error);
        }
    };
    let mut created: Vec<(String, Previous)> = Vec::new();
    let kept = match apply_entries(db, pkg, paths, target_root, &entries, &plan, &mut created) {
        Ok(kept) => kept,
        Err(error) => {
            restore_created(target_root, &created);
            remove_directories(target_root, &created_dirs);
            db.abort();
            if let Err(error) = repair_links(db, paths) {
                eprintln!("warning: links were not rebuilt from the ledger: {error:#}");
            }
            return Err(error);
        }
    };
    if kept > 0 && pkg.state != crate::db::PackageState::StagedForced {
        // put back what this attempt replaced, then roll the ledger back
        restore_created(target_root, &created);
        remove_directories(target_root, &created_dirs);
        db.abort();
        let _ = repair_links(db, paths);
        say!(
            "keep     {} staged: {kept} files are still unmanaged (re-run with PORTALIS_FORCE=1)",
            pkg.name
        );
        journal.finish();
        return Ok(false);
    }
    let dropped = match settle_activation(db, paths, pkg, target_root, &mut journal, &shipped) {
        Ok(dropped) => dropped,
        Err(error) => {
            // the tree already carries the new links: put back what this attempt
            // replaced, then rebuild from the ledger the rollback restored
            db.abort();
            restore_created(target_root, &created);
            remove_directories(target_root, &created_dirs);
            if let Err(error) = repair_links(db, paths) {
                eprintln!("warning: links were not rebuilt from the ledger: {error:#}");
            }
            return Err(error);
        }
    };
    if dropped > 0 {
        say!("removed  {} files this version no longer ships", dropped);
    }
    marker.finish();
    journal.finish();
    Ok(true)
}

/// Creates a backup directory with owner-only permissions.
fn ensure_private_dir(root: &Path, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let relative = path.strip_prefix(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("refusing to traverse backup symlink {}", current.display())
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => bail!("{} is not a directory", current.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .with_context(|| format!("creating {}", current.display()))?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", current.display()));
            }
        }
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("closing {}", current.display()))?;
    }
    Ok(())
}

/// Removes the records and the live links of files that an earlier version of
/// this package shipped and the new one does not.
///
/// A link is dropped only when it still points where the record says; a file the
/// user replaced is left in place, and only its record goes away.
pub(super) fn drop_unshipped_files(
    db: &crate::db::Db,
    target_root: &Path,
    pkg: &str,
    shipped: &std::collections::BTreeSet<String>,
    record: &mut OperationJournal,
) -> Result<usize> {
    let mut dropped = 0usize;
    let adopted: std::collections::HashMap<String, String> =
        db.adopted_of(pkg)?.into_iter().collect();
    for (path, _sha, link_target, _mode) in db.files_of(pkg)? {
        if shipped.contains(&path) {
            continue;
        }
        // Removes the live entry, then its ownership row.
        let live = crate::links::live_path(target_root, &path);
        let mut removed_link = false;
        if let Ok(meta) = fs::symlink_metadata(&live) {
            if meta.file_type().is_symlink() {
                if let Ok(current) = fs::read_link(&live) {
                    if current.to_string_lossy() == link_target {
                        record.record(&Entry {
                            path: path.clone(),
                            previous: Previous::Symlink {
                                target: current.to_string_lossy().to_string(),
                            },
                        })?;
                        crate::links::remove_in_live(target_root, &path)?;
                        removed_link = true;
                        dropped += 1;
                    }
                }
            }
        }
        db.delete_file(pkg, &path)?;
        if removed_link {
            if let Some(backup) = adopted.get(&path) {
                let backup = Path::new(backup);
                if backup.exists() {
                    let meta = fs::symlink_metadata(backup)
                        .with_context(|| format!("reading backup {}", backup.display()))?;
                    let previous = if meta.file_type().is_symlink() {
                        Previous::Symlink {
                            target: fs::read_link(backup)
                                .with_context(|| format!("reading backup {}", backup.display()))?
                                .to_string_lossy()
                                .to_string(),
                        }
                    } else {
                        Previous::Restored {
                            backup: backup.to_string_lossy().to_string(),
                        }
                    };
                    record.record(&Entry {
                        path: path.clone(),
                        previous,
                    })?;
                    crate::links::restore_backup(target_root, &path, backup)?;
                    say!("restored {path} (this package had taken it over)");
                } else {
                    super::warn_missing_backup(&path, backup);
                }
                db.clear_adopted_path(pkg, &path)?;
            }
        }
    }
    Ok(dropped)
}

pub(super) fn apply_pending_file(
    db: &Db,
    pkg: &crate::db::PackageRow,
    paths: &Paths,
    target_root: &Path,
    entry: (String, String, String, u32, String),
    kept: &mut usize,
) -> Result<()> {
    let (path, sha, link_target, mode, kind) = entry;
    let live = live_path(target_root, &path);
    let resolved = crate::links::resolved_live_target(target_root, &path)
        .with_context(|| format!("resolving the parent of {path}"))?;
    let root_canonical = std::fs::canonicalize(target_root)
        .with_context(|| format!("resolving {}", target_root.display()))?;
    let relative = resolved.strip_prefix(&root_canonical).unwrap_or(&resolved);
    let protected = format!("/{}", relative.display()).replace("//", "/");
    if crate::policy::is_protected_path(&protected) {
        bail!(
            "refusing to activate {path}: it resolves to protected path {}",
            resolved.display()
        );
    }
    if kind == "symlink" {
        crate::policy::validate_link_target(
            target_root,
            &path,
            &link_target,
            Some(Path::new(&pkg.store_path)),
        )?;
    }
    if kind == "config" {
        let store_file = PathBuf::from(&link_target);
        crate::links::ensure_live_dir(target_root, &path)?;
        if fs::symlink_metadata(&live).is_ok() && fs::metadata(&live).is_err() {
            bail!(
                "{path} is a symlink whose target does not exist; refusing to write the \
                 packaged default through it"
            );
        }
        let default_is_link = fs::symlink_metadata(&store_file)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if default_is_link {
            if !live.exists() && fs::symlink_metadata(&live).is_err() {
                let target = fs::read_link(&store_file)?;
                crate::policy::validate_link_target(
                    target_root,
                    &path,
                    &target.to_string_lossy(),
                    Some(Path::new(&pkg.store_path)),
                )?;
                safe_symlink(target_root, &path, &target.to_string_lossy())?;
                say!("config   {path} (symlink created)");
            }
            return Ok(());
        }
        if fs::symlink_metadata(&live).is_err() {
            let written = crate::links::copy_into_live(target_root, &path, &store_file, None)?;
            say!("config   {written} (copied once)");
        } else {
            let live_sha = crate::util::sha256_file(&live)?;
            let default_sha = crate::util::sha256_file(&store_file)?;
            if live_sha != default_sha {
                let written =
                    crate::links::copy_into_live(target_root, &path, &store_file, Some("pacnew"))?;
                say!("config   {path} differs, default written to {written}");
            }
        }
        return Ok(());
    }

    // the store has to still hold the file before anything under the live root
    // changes: a missing one means the package was purged or cleaned
    if kind != "symlink" && !Path::new(&link_target).exists() {
        bail!("staged file is missing from the store: {link_target}");
    }
    if mode != 0 {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&link_target, fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode of {}", link_target))?;
    }
    let mut adopted_backup: Option<PathBuf> = None;
    if let Ok(meta) = fs::symlink_metadata(&live) {
        if meta.file_type().is_symlink() {
            if let Some((owner, _)) = db.pending_owner(&path)? {
                if owner != pkg.name {
                    bail!("refusing to replace {path}: it is staged by another package ({owner})");
                }
            }
            match db.owner(&path)? {
                Some((owner, _)) if owner == pkg.name => {}
                Some((owner, _)) => {
                    bail!("refusing to replace {path}: it is linked by another package ({owner})")
                }
                None if pkg.state == crate::db::PackageState::StagedForced => {}
                None => bail!("refusing to replace {path}: the existing link is unowned"),
            }
            // safe_symlink swaps the link through a temporary name.
        } else if pkg.state == crate::db::PackageState::StagedForced {
            // The backup keeps the live path without its leading slash.
            let backup_root = paths.state_dir().join("backup");
            let backup = backup_root.join(path.trim_start_matches('/'));
            if let Some(parent) = backup.parent() {
                ensure_private_dir(&backup_root, parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            if backup.exists() {
                // an earlier adoption already kept the original; leave the
                // current file in place
                say!("keep     {path} (earlier backup stays the original)");
                *kept += 1;
                return Ok(());
            } else {
                move_file(&live, &backup)?;
                if let Err(error) = db.set_adopted(&pkg.name, &path, &backup.to_string_lossy()) {
                    // put the file back when the ledger did not record the adoption
                    if let Err(restore) = move_file(&backup, &live) {
                        eprintln!(
                            "warning: could not put {path} back: {restore}; the original stays at {}",
                            backup.display()
                        );
                    }
                    return Err(error);
                }
                adopted_backup = Some(backup);
            }
        } else {
            say!("skip     {path} (unmanaged file appeared, not replacing)");
            *kept += 1;
            return Ok(());
        }
    }
    if let Err(error) = safe_symlink(target_root, &path, &link_target) {
        if let Some(backup) = adopted_backup {
            // put the original back when the link could not be created
            if let Err(restore) = move_file(&backup, &live) {
                eprintln!(
                    "warning: could not put {path} back: {restore}; the original stays at {}",
                    backup.display()
                );
            }
        }
        return Err(error);
    }
    let manifest_file = crate::recipe::ManifestFile {
        path: path.clone(),
        sha256: sha,
        mode,
        link: None,
    };
    if let Err(error) = db.insert_file(&pkg.name, &manifest_file, &link_target) {
        let _ = crate::links::remove_in_live(target_root, &path);
        if let Some(backup) = adopted_backup {
            if let Err(restore) = move_file(&backup, &live) {
                eprintln!(
                    "warning: could not put {path} back: {restore}; the original stays at {}",
                    backup.display()
                );
            }
            let _ = db.clear_adopted_path(&pkg.name, &path);
        }
        return Err(error);
    }
    Ok(())
}
