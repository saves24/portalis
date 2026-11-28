//! Removing an installed package, and the clean-up that follows it.
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    generations_to_keep, protected_generations, relink_after_failed_remove, warn_missing_backup,
};
use crate::db::Db;
use crate::links::{live_path, remove_live_directory, repair_links};
use crate::paths::Paths;
use crate::proc::{is_critical_path, live_paths_in_use, processes_using};

/// True when a retained generation still names this store, or when the
/// generation manifest could not be read.
fn still_in_generations(paths: &Paths, db: &Db, store: &Path) -> bool {
    let Some(name) = store.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return true;
    };
    match crate::commands::referenced_stores(paths, db) {
        Ok((used, unreadable)) => unreadable > 0 || used.contains(&name),
        Err(_) => true,
    }
}

fn preflight(
    name: &str,
    db: &Db,
    paths: &Paths,
    purge: bool,
    force: bool,
) -> Result<Option<(bool, crate::db::PackageRow)>> {
    let had_pending = db.pending_packages()?.iter().any(|p| p.name == name);
    let pkg = match db.package(name)? {
        Some(row) => row,
        None => {
            if had_pending {
                db.drop_pending(name)?;
                say!("dropped  {name} (was staged, never activated)");
                return Ok(None);
            }
            bail!("package not installed: {name}");
        }
    };
    if !force {
        let recipe_file = paths.recipe_file(name);
        if recipe_file.exists() {
            let recipe = crate::recipe::Recipe::load(&recipe_file).with_context(|| {
                format!("reading the recipe for {name} at {}", recipe_file.display())
            })?;
            if recipe.package.hold {
                bail!(
                    "refusing to remove {name}: its recipe marks it held (package.hold = true)\n\
                     pass --force if that is really what you want"
                );
            }
        }
    }
    if !force {
        let users = db.users_of(name)?;
        if !users.is_empty() {
            bail!(
                "refusing to remove {name}: {} installed package(s) depend on it ({})\n\
                 remove them first, or pass --force",
                users.len(),
                users.join(", ")
            );
        }
    }
    if purge && !force {
        let users = processes_using(Path::new(&pkg.store_path))?;
        if !users.is_empty() {
            let list = users
                .iter()
                .map(|(pid, cmd)| format!("{pid} ({cmd})"))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "refusing to purge {}: store is in use by {list}\n\
                 stop those processes first, or pass --force",
                pkg.name
            );
        }
    }
    Ok(Some((had_pending, pkg)))
}

fn refuse_busy(
    name: &str,
    files: &[(String, String, String, u32)],
    paths: &Paths,
    force: bool,
) -> Result<()> {
    if force {
        return Ok(());
    }
    let in_use = live_paths_in_use(paths).context("cannot tell which files are in use")?;
    let busy: Vec<&String> = files
        .iter()
        .map(|(path, _sha, _link, _mode)| path)
        .filter(|path| is_critical_path(path, &in_use))
        .collect();
    if !busy.is_empty() {
        let shown: Vec<String> = busy.iter().take(5).map(|p| p.to_string()).collect();
        bail!(
            "refusing to remove {name}: {} file(s) are in use or on the boot chain ({}{})\n\
             stop the programs first, or pass --force",
            busy.len(),
            shown.join(", "),
            if busy.len() > shown.len() {
                ", …"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn unlink_files(
    target_root: &Path,
    files: &[(String, String, String, u32)],
    adopted: &std::collections::HashMap<String, String>,
    record: &mut Option<super::operations::OperationJournal>,
) -> Result<(usize, usize, usize)> {
    let mut removed = 0usize;
    let mut kept = 0usize;
    let mut restored = 0usize;
    for (path, _sha, link_target, _mode) in files {
        let live = live_path(target_root, path);
        match fs::symlink_metadata(&live) {
            Ok(meta) if meta.file_type().is_symlink() => match fs::read_link(&live) {
                Ok(current) => {
                    if current.to_string_lossy() == *link_target {
                        if let Some(journal) = record.as_mut() {
                            journal.record(&super::journal::Entry {
                                path: path.clone(),
                                previous: super::journal::Previous::Symlink {
                                    target: link_target.clone(),
                                },
                            })?;
                        }
                        crate::links::remove_in_live(target_root, path)?;
                        removed += 1;
                        // Restores the adopted original.
                        if let Some(backup) = adopted.get(path) {
                            let backup = Path::new(backup);
                            if backup.exists() {
                                if let Some(journal) = record.as_mut() {
                                    journal.record(&super::journal::Entry {
                                        path: path.clone(),
                                        previous: super::journal::Previous::Restored {
                                            backup: backup.display().to_string(),
                                        },
                                    })?;
                                }
                                crate::links::restore_backup(target_root, path, backup)?;
                                restored += 1;
                            } else {
                                warn_missing_backup(path, backup);
                            }
                        }
                    } else {
                        kept += 1;
                    }
                }
                Err(error) => {
                    eprintln!(
                        "warning: cannot read the link at {}: {error}",
                        live.display()
                    );
                    kept += 1;
                }
            },
            Ok(_) => kept += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", live.display()));
            }
        }
    }
    Ok((removed, kept, restored))
}

/// Removes the package's `/usr/portalis/etc` link when it still names this package.
pub(super) fn remove_etc_link(paths: &Paths, name: &str) -> Result<()> {
    let link = paths.store_etc().join(name);
    match fs::read_link(&link) {
        Ok(target) => {
            let text = target.to_string_lossy();
            if text.starts_with(&format!("../packages/{name}-")) {
                fs::remove_file(&link).with_context(|| format!("removing {}", link.display()))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("reading {}", link.display())),
    }
    Ok(())
}

fn purge_store(
    pkg: &crate::db::PackageRow,
    db: &Db,
    paths: &Paths,
    purge: bool,
    force: bool,
) -> Result<bool> {
    let mut store_kept = !purge;
    if !purge {
        return Ok(store_kept);
    }
    let store = PathBuf::from(&pkg.store_path);
    if fs::symlink_metadata(&store)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        eprintln!(
            "warning: {} was unlinked, but its store path is a symlink; the store was kept",
            pkg.name
        );
        return Ok(true);
    }
    let store = if store.exists() {
        fs::canonicalize(&store).with_context(|| format!("resolving {}", store.display()))?
    } else {
        store
    };
    // Keeps the store when it is in use or its scan fails.
    let mut keep: Option<String> = None;
    if !force {
        match processes_using(&store) {
            Ok(users) if !users.is_empty() => {
                let list = users
                    .iter()
                    .map(|(pid, cmd)| format!("{pid} ({cmd})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                keep = Some(format!("its store is in use by {list}"));
            }
            Ok(_) => {}
            Err(error) => {
                keep = Some(format!("its store could not be checked ({error:#})"));
            }
        }
    }
    match keep {
        Some(reason) => {
            eprintln!(
                "warning: {} was unlinked, but {reason}; the store was kept",
                pkg.name
            );
            store_kept = true;
        }
        None if still_in_generations(paths, db, &store) => {
            eprintln!(
                "warning: {} was unlinked, but a retained generation still refers to {}; \
                 the store was kept",
                pkg.name, pkg.store_path
            );
            store_kept = true;
        }
        None if store == paths.store() || !store.starts_with(paths.store()) => {
            eprintln!(
                "warning: {} was unlinked, but {} is outside the store; it was kept",
                pkg.name, pkg.store_path
            );
            store_kept = true;
        }
        None => match fs::remove_dir_all(&store) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("deleting {}", store.display()));
            }
        },
    }
    Ok(store_kept)
}

/// The directory list a manifest records, when it is readable.
fn manifest_directories(db: &Db, name: &str) -> Result<Vec<crate::recipe::ManifestDir>> {
    let Some(canonical) = db.manifest_of(name)? else {
        return Ok(Vec::new());
    };
    match serde_json::from_str::<crate::recipe::BuildManifest>(&canonical) {
        Ok(manifest) => Ok(manifest.dirs),
        Err(error) => {
            eprintln!("warning: manifest for {name} could not be read: {error:#}");
            Ok(Vec::new())
        }
    }
}

/// The recorded state with this package removed, hashed for the journal.
fn removal_digest(db: &Db, name: &str) -> Result<String> {
    let mut target_state = db.current_state()?;
    target_state.packages.retain(|pkg| pkg.name != name);
    target_state.files.retain(|file| file.pkg != name);
    target_state.manifests.retain(|(pkg, _)| pkg != name);
    target_state.adopted.retain(|(pkg, _, _)| pkg != name);
    Ok(crate::util::sha256_bytes(&serde_json::to_vec(
        &target_state,
    )?))
}

/// Drops the directories this package created and left empty.
fn remove_directories(target_root: &Path, directories: &[crate::recipe::ManifestDir]) {
    for directory in directories.iter().rev() {
        if crate::policy::is_protected_path(&directory.path) {
            continue;
        }
        if let Err(error) = remove_live_directory(target_root, &directory.path) {
            eprintln!("warning: {} was not removed: {error:#}", directory.path);
        }
    }
}

/// Records the removal as a generation and prunes old ones.
fn record_removal(db: &Db, paths: &Paths, name: &str) {
    if let Err(error) = db.snapshot(&format!("remove {name}")) {
        eprintln!("warning: {name} was removed, but its generation record failed: {error:#}");
    }
    let keep = generations_to_keep(paths);
    if let Err(error) = db.prune_generations(keep, &protected_generations(paths)) {
        eprintln!("warning: old generations were not pruned: {error:#}");
    }
}

pub fn remove(name: &str, db: &Db, paths: &Paths, purge: bool, force: bool) -> Result<()> {
    let Some((_had_pending, pkg)) = preflight(name, db, paths, purge, force)? else {
        return Ok(());
    };
    let target_root = paths.target_root();
    let files = db.files_of(name)?;
    let directories = manifest_directories(db, name)?;
    refuse_busy(name, &files, paths, force)?;
    // The staged copy is removed with the package row.
    let adopted: std::collections::HashMap<String, String> =
        db.adopted_of(name)?.into_iter().collect();
    let target_digest = removal_digest(db, name)?;
    let marker = super::OperationMarker::start(paths, &format!("remove of {name}"))?;
    let mut record = Some(super::operations::OperationJournal::begin(
        paths,
        &format!("remove of {name}"),
    )?);
    if let Some(journal) = record.as_mut() {
        journal.target(&target_digest)?;
    }
    let (removed, kept, restored) = match unlink_files(&target_root, &files, &adopted, &mut record)
    {
        Ok(counts) => counts,
        Err(error) => {
            // Repairs links from the database after a failed unlink.
            if let Err(repair) = repair_links(db, paths) {
                if let Some(journal) = record.take() {
                    journal.keep();
                }
                marker.keep();
                return Err(error.context(format!(
                    "removing {name} failed and the links could not be reconciled: {repair:#}"
                )));
            }
            return Err(error);
        }
    };
    if let Err(error) = db.delete_package(name) {
        let (relinked, skipped) = relink_after_failed_remove(&target_root, &files);
        if skipped > 0 {
            if let Some(journal) = record.take() {
                journal.keep();
            }
            marker.keep();
        }
        return Err(error.context(format!(
            "removing {name} failed while updating the database; {relinked} link(s) recreated, \
             {skipped} left as they were"
        )));
    }
    if let Some(journal) = record.take() {
        if let Err(error) = journal.commit() {
            marker.keep();
            return Err(error);
        }
    }
    if let Err(error) = remove_etc_link(paths, name) {
        eprintln!("warning: the etc link for {name} was not removed: {error:#}");
    }
    remove_directories(&target_root, &directories);
    record_removal(db, paths, name);
    let store_kept = purge_store(&pkg, db, paths, purge, force)?;
    say!("unlinked {removed} files, kept {kept} (modified or user-owned)");
    if restored > 0 {
        say!("restored {restored} file(s) this package had taken over");
    }
    if purge && !store_kept {
        say!("store    removed {}", pkg.store_path);
    } else if purge {
        say!("store    kept {} (see the warning above)", pkg.store_path);
    } else {
        say!("store    kept {} (use --purge to delete)", pkg.store_path);
    }
    if let Err(error) = db.clear_index() {
        eprintln!("warning: the derived index could not be invalidated: {error:#}");
    }
    marker.finish();
    crate::json::done(serde_json::json!({
        "package": name,
        "unlinked": removed,
        "kept": kept,
        "restored": restored,
        "store": if store_kept { "kept" } else { "removed" },
    }));
    Ok(())
}
