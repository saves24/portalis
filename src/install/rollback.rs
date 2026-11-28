//! Rolling the tree back to a recorded generation.
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::hooks::run_ld_cache_hooks;
use super::{generations_to_keep, protected_generations, reindex, warn_missing_backup};
use crate::db::Db;
use crate::links::remove_in_live;
use crate::links::{live_path, repair_links, safe_symlink};
use crate::paths::Paths;

fn refuse_busy_rollback(
    id: i64,
    current: &[crate::db::FileRow],
    desired: &std::collections::BTreeMap<String, String>,
    paths: &Paths,
) -> Result<()> {
    // a path this generation drops must not be in use or on the boot chain: the
    // same rule install and remove follow
    let in_use =
        crate::proc::live_paths_in_use(paths).context("cannot tell which files are in use")?;
    let busy: Vec<String> = current
        .iter()
        .map(|file| &file.path)
        .filter(|path| !desired.contains_key(*path))
        .filter(|path| crate::proc::is_critical_path(path, &in_use))
        .cloned()
        .chain(
            desired
                .iter()
                .filter(|(path, target)| {
                    let live = live_path(&paths.target_root(), path);
                    fs::read_link(&live)
                        .map(|current| current.to_string_lossy() != target.as_str())
                        .unwrap_or(true)
                })
                .map(|(path, _)| path)
                .filter(|path| crate::proc::is_critical_path(path, &in_use))
                .cloned(),
        )
        .collect();
    if !busy.is_empty() {
        let shown: Vec<String> = busy.iter().take(5).map(|path| path.to_string()).collect();
        bail!(
            "refusing to roll back to generation {id}: {} file(s) are in use or on the boot chain ({}{})\n\
             stop the programs first",
            busy.len(),
            shown.join(", "),
            if busy.len() > shown.len() { ", …" } else { "" }
        );
    }
    Ok(())
}

fn restore_adopted(
    db: &mut Db,
    target_root: &Path,
    state: &crate::db::State,
    current: &[(String, String, String)],
) -> Result<()> {
    let kept: std::collections::HashSet<(&str, &str)> = state
        .adopted
        .iter()
        .map(|(pkg, path, _)| (pkg.as_str(), path.as_str()))
        .collect();
    for (pkg, path, backup) in current {
        if kept.contains(&(pkg.as_str(), path.as_str())) {
            continue;
        }
        let backup = Path::new(backup);
        let live = live_path(target_root, path);
        if !backup.exists() {
            warn_missing_backup(path, backup);
            continue;
        }
        if fs::symlink_metadata(&live).is_err() {
            crate::links::restore_backup(target_root, path, backup)
                .with_context(|| format!("restoring {}", live.display()))?;
            say!("restored {path} (this package had taken it over)");
        }
        if db.package(pkg)?.is_some() {
            db.clear_adopted_path(pkg, path)?;
        }
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AdoptedRecovery {
    signature: String,
    entries: Vec<(String, String, String)>,
}

fn recovery_path(paths: &Paths, id: i64) -> PathBuf {
    paths
        .state_dir()
        .join(format!("rollback-adopted-{id}.json"))
}

fn recovery_signature(state: &crate::db::State) -> Result<String> {
    let mut copy = state.clone();
    copy.adopted.clear();
    Ok(crate::util::sha256_bytes(&serde_json::to_vec(&copy)?))
}

fn write_recovery(
    path: &Path,
    signature: &str,
    entries: &[(String, String, String)],
) -> Result<()> {
    let body = AdoptedRecovery {
        signature: signature.to_string(),
        entries: entries.to_vec(),
    };
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(&serde_json::to_vec(&body)?)?;
    file.sync_all()?;
    if let Some(dir) = path.parent() {
        crate::util::sync_dir(dir)?;
    }
    Ok(())
}

fn restore_entry(db: &Db, target_root: &Path, pkg: &str, path: &str, backup: &Path) -> Result<()> {
    if !backup.exists() {
        warn_missing_backup(path, backup);
        return Ok(());
    }
    let live = live_path(target_root, path);
    if fs::symlink_metadata(&live).is_err() {
        crate::links::restore_backup(target_root, path, backup)
            .with_context(|| format!("restoring {}", live.display()))?;
        say!("restored {path} (this package had taken it over)");
    }
    if db.package(pkg)?.is_some() {
        db.clear_adopted_path(pkg, path)?;
    }
    Ok(())
}

/// Completes an adopted-file restore that a rollback could not finish.
pub(super) fn recover_adopted(db: &Db, paths: &Paths) -> Result<()> {
    let entries = match fs::read_dir(paths.state_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("rollback-adopted-") || !name.ends_with(".json") {
            continue;
        }
        let marker = entry.path();
        let body: AdoptedRecovery = serde_json::from_slice(
            &fs::read(&marker).with_context(|| format!("reading {}", marker.display()))?,
        )
        .with_context(|| format!("parsing {}", marker.display()))?;
        let current = db.current_state()?;
        if recovery_signature(&current)? != body.signature {
            let _ = fs::remove_file(&marker);
            continue;
        }
        for (pkg, path, backup) in &body.entries {
            restore_entry(db, &paths.target_root(), pkg, path, Path::new(backup))?;
        }
        fs::remove_file(&marker)?;
        if let Some(dir) = marker.parent() {
            let _ = crate::util::sync_dir(dir);
        }
    }
    Ok(())
}

/// Reads the generation this rollback targets and refuses a busy tree.
fn validate_rollback(
    db: &Db,
    paths: &Paths,
    id: i64,
) -> Result<(
    crate::db::State,
    std::collections::BTreeMap<String, String>,
    Vec<crate::db::FileRow>,
)> {
    let state = match db.state_of(id)? {
        Some(s) => s,
        None => bail!("generation not found: {id}"),
    };
    let desired: std::collections::BTreeMap<String, String> = state
        .files
        .iter()
        .map(|f| (f.path.clone(), f.link_target.clone()))
        .collect();
    let current = db.current_files()?;
    refuse_busy_rollback(id, &current, &desired, paths)?;
    Ok((state, desired, current))
}

/// Every adopted backup the current packages hold.
fn adopted_entries(db: &Db) -> Result<Vec<(String, String, String)>> {
    Ok(db
        .packages()?
        .into_iter()
        .map(|row| {
            let name = row.name.clone();
            db.adopted_of(&name).map(move |entries| {
                entries
                    .into_iter()
                    .map(move |(path, backup)| (name.clone(), path, backup))
            })
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect())
}

/// The generation a rollback restores, and the rows it reconciles.
struct RestoreFiles<'a> {
    id: i64,
    state: &'a crate::db::State,
    current: &'a [crate::db::FileRow],
    current_adopted: &'a [(String, String, String)],
}

/// Records the adopted files this generation drops and rewrites the database.
fn restore_files(
    db: &mut Db,
    paths: &Paths,
    target_root: &Path,
    input: RestoreFiles<'_>,
    record: &mut Option<super::operations::OperationJournal>,
) -> Result<Option<PathBuf>, (anyhow::Error, bool)> {
    let RestoreFiles {
        id,
        state,
        current,
        current_adopted,
    } = input;
    let kept: std::collections::HashSet<(&str, &str)> = state
        .adopted
        .iter()
        .map(|(pkg, path, _)| (pkg.as_str(), path.as_str()))
        .collect();
    let to_restore: Vec<(String, String, String)> = current_adopted
        .iter()
        .filter(|(pkg, path, _)| !kept.contains(&(pkg.as_str(), path.as_str())))
        .cloned()
        .collect();
    let recovery = if to_restore.is_empty() {
        None
    } else {
        let path = recovery_path(paths, id);
        let signature = match recovery_signature(state) {
            Ok(signature) => signature,
            Err(error) => return Err((error, false)),
        };
        match write_recovery(&path, &signature, &to_restore) {
            Ok(()) => Some(path),
            Err(error) => {
                if let Some(journal) = record.take() {
                    journal.keep();
                }
                return Err((error, true));
            }
        }
    };

    if let Err(error) = db.replace_state(state) {
        let mut journal = record.take();
        if let Some(path) = &recovery {
            let _ = fs::remove_file(path);
        }
        // the tree already shows the older generation; point it back at the
        // records that survived the failed write, configuration paths included
        restore_rows(target_root, current);
        if let Err(repair) = repair_links(db, paths) {
            if let Some(journal) = journal.take() {
                journal.keep();
            }
            return Err((
                error.context(format!(
                    "recording the generation failed and the links could not be reconciled: {repair:#}"
                )),
                true,
            ));
        }
        return Err((error, false));
    }
    if let Err(error) = restore_adopted(db, target_root, state, current_adopted) {
        if let Some(journal) = record.take() {
            journal.keep();
        }
        return Err((error.context("adopted backups were not restored"), true));
    }
    Ok(recovery)
}

/// The generation row a rollback writes, plus what it changed in the tree.
struct GenerationCommit<'a> {
    id: i64,
    state: &'a crate::db::State,
    current_names: Vec<String>,
    recovery: Option<PathBuf>,
    removed: usize,
    linked: usize,
}

/// Finishes a rollback whose database row is already written.
fn commit_generation(
    db: &mut Db,
    paths: &Paths,
    target_root: &Path,
    commit: GenerationCommit<'_>,
    record: &mut Option<super::operations::OperationJournal>,
    marker: super::OperationMarker,
) -> Result<()> {
    let GenerationCommit {
        id,
        state,
        current_names,
        recovery,
        removed,
        linked,
    } = commit;
    if let Some(path) = &recovery {
        let _ = fs::remove_file(path);
        if let Some(dir) = path.parent() {
            let _ = crate::util::sync_dir(dir);
        }
    }
    if let Some(journal) = record.take() {
        if let Err(error) = journal.commit() {
            marker.keep();
            return Err(error);
        }
    }
    let target_names: std::collections::HashSet<&str> =
        state.packages.iter().map(|row| row.name.as_str()).collect();
    for name in current_names {
        if !target_names.contains(name.as_str()) {
            if let Err(error) = super::remove::remove_etc_link(paths, &name) {
                eprintln!("warning: the etc link for {name} was not removed: {error:#}");
            }
        }
    }
    for pkg in db.packages()? {
        if let Err(error) = crate::stage::expose_etc(Path::new(&pkg.store_path), &pkg.name, paths) {
            eprintln!(
                "warning: the etc link for {} was not refreshed: {error:#}",
                pkg.name
            );
        }
    }
    // rebuild both derived tables after replace_state emptied them
    if let Err(error) = reindex(db, paths) {
        eprintln!("warning: derived tables not rebuilt: {error}");
    }
    if let Err(error) = db.snapshot(&format!("rollback to generation {id}")) {
        eprintln!(
            "warning: rollback reached generation {id}, but its generation record failed: {error:#}"
        );
    }
    let keep = generations_to_keep(paths);
    if let Err(error) = db.prune_generations(keep, &protected_generations(paths)) {
        eprintln!("warning: old generations were not pruned: {error:#}");
    }
    for warning in run_ld_cache_hooks(target_root) {
        eprintln!("warning: {warning}");
    }
    say!("rollback generation {id}: {linked} linked, {removed} unlinked");
    marker.finish();
    crate::json::done(serde_json::json!({
        "generation": id,
        "linked": linked,
        "unlinked": removed,
    }));
    Ok(())
}

pub fn rollback(id: i64, db: &mut Db, paths: &Paths) -> Result<()> {
    let (state, desired, current) = validate_rollback(db, paths, id)?;
    let target_root = paths.target_root();

    let marker = super::OperationMarker::start(paths, &format!("rollback to generation {id}"))?;
    let mut record = Some(super::operations::OperationJournal::begin(
        paths,
        &format!("rollback to generation {id}"),
    )?);
    let target_digest = crate::util::sha256_bytes(&serde_json::to_vec(&state)?);
    if let Some(journal) = record.as_mut() {
        journal.target(&target_digest)?;
    }
    let (removed, linked) = match reapply_links(&target_root, &desired, &current, &mut record) {
        Ok(counts) => counts,
        Err(error) => {
            // the tree was already partly rewritten; bring the links back in step
            // with the database before reporting the failure
            if let Err(repair) = repair_links(db, paths) {
                if let Some(journal) = record.take() {
                    journal.keep();
                }
                marker.keep();
                return Err(error.context(format!(
                    "rollback failed and the links could not be reconciled: {repair:#}"
                )));
            }
            return Err(error);
        }
    };

    let current_adopted = adopted_entries(db)?;
    let current_names: Vec<String> = db.packages()?.into_iter().map(|row| row.name).collect();
    let recovery = match restore_files(
        db,
        paths,
        &target_root,
        RestoreFiles {
            id,
            state: &state,
            current: &current,
            current_adopted: &current_adopted,
        },
        &mut record,
    ) {
        Ok(recovery) => recovery,
        Err((error, keep_marker)) => {
            if keep_marker {
                marker.keep();
            }
            return Err(error);
        }
    };
    commit_generation(
        db,
        paths,
        &target_root,
        GenerationCommit {
            id,
            state: &state,
            current_names,
            recovery,
            removed,
            linked,
        },
        &mut record,
        marker,
    )
}

fn reapply_links(
    target_root: &Path,
    desired: &std::collections::BTreeMap<String, String>,
    current: &[crate::db::FileRow],
    record: &mut Option<super::operations::OperationJournal>,
) -> Result<(usize, usize)> {
    let mut unlinked: Vec<(String, String)> = Vec::new();
    for file in current {
        if desired.contains_key(&file.path) {
            continue;
        }
        let live = live_path(target_root, &file.path);
        if let Ok(meta) = fs::symlink_metadata(&live) {
            if meta.file_type().is_symlink() {
                if let Some(journal) = record.as_mut() {
                    let target = fs::read_link(&live)
                        .map(|t| t.to_string_lossy().to_string())
                        .unwrap_or_else(|_| file.link_target.clone());
                    journal.record(&super::journal::Entry {
                        path: file.path.clone(),
                        previous: super::journal::Previous::Symlink { target },
                    })?;
                }
                crate::links::remove_in_live(target_root, &file.path)?;
                unlinked.push((file.path.clone(), file.link_target.clone()));
            }
        }
    }

    let mut linked: Vec<String> = Vec::new();
    for (path, link_target) in desired {
        let live = live_path(target_root, path);
        if let Ok(meta) = fs::symlink_metadata(&live) {
            if !meta.file_type().is_symlink() {
                say!("skip     {path} (user owned file)");
                continue;
            }
        }
        if let Some(journal) = record.as_mut() {
            let previous = match fs::symlink_metadata(&live) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    let target = fs::read_link(&live)?;
                    super::journal::Previous::Symlink {
                        target: target.to_string_lossy().to_string(),
                    }
                }
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    super::journal::Previous::Missing
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", live.display()));
                }
            };
            journal.record(&super::journal::Entry {
                path: path.clone(),
                previous,
            })?;
        }
        crate::policy::validate_link_target(target_root, path, link_target, None)?;
        if let Err(error) = safe_symlink(target_root, path, link_target) {
            // Links created by this attempt are dropped, then the ones it removed
            // are recreated.
            for made in linked.iter().rev() {
                if let Err(cleanup) = remove_in_live(target_root, made) {
                    eprintln!("warning: {made} was not cleared: {cleanup:#}");
                }
            }
            for (old_path, old_target) in unlinked.iter().rev() {
                if let Err(cleanup) =
                    crate::policy::validate_link_target(target_root, old_path, old_target, None)
                        .and_then(|()| safe_symlink(target_root, old_path, old_target))
                {
                    eprintln!("warning: {old_path} was not pointed back: {cleanup:#}");
                }
            }
            return Err(error);
        }
        linked.push(path.clone());
    }

    Ok((unlinked.len(), linked.len()))
}

/// Points every recorded path back at its store file. Real files are left
/// alone; only links are rewritten.
fn restore_rows(target_root: &Path, rows: &[crate::db::FileRow]) {
    for row in rows {
        let live = live_path(target_root, &row.path);
        if fs::symlink_metadata(&live)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(true)
        {
            if let Err(error) =
                crate::policy::validate_link_target(target_root, &row.path, &row.link_target, None)
                    .and_then(|()| safe_symlink(target_root, &row.path, &row.link_target))
            {
                eprintln!("warning: {} was not pointed back: {error:#}", row.path);
            }
        }
    }
}
