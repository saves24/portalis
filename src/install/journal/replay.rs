//! Replaying and undoing activation and operation records.
use super::{drop_journal, Entry, Previous, COMMIT, PREFIX};
use crate::links::{live_path, remove_in_live};
use crate::paths::Paths;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Undoes one record a command wrote before it rewrote the tree; answers how
/// many paths it put back and keeps the record when one cannot be.
pub(crate) fn replay_record(path: &Path, target_root: &Path) -> Result<usize> {
    replay_file(path, target_root, None, true)
}

/// Undoes every activation a crash left half-applied, and answers how many
/// paths it put back.
pub(crate) fn replay(
    paths: &Paths,
    target_root: &Path,
    db: Option<&crate::db::Db>,
) -> Result<usize> {
    let dir = paths.state_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", dir.display()));
        }
    };
    let mut restored = 0usize;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(PREFIX) || !name.ends_with(".jsonl") {
            continue;
        }
        restored += replay_file(&entry.path(), target_root, db, false)?;
    }
    Ok(restored)
}

/// Rejects a journal that is not a root-owned regular file.
fn checked_journal(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !meta.file_type().is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        anyhow::bail!(
            "journal is not a root-owned regular file: {}",
            path.display()
        );
    }
    Ok(())
}

/// Undoes one journal, and answers how many paths it put back.
pub(super) fn replay_file(
    journal: &Path,
    target_root: &Path,
    db: Option<&crate::db::Db>,
    reverse: bool,
) -> Result<usize> {
    checked_journal(journal)?;
    let mut restored = 0usize;
    {
        let text = fs::read_to_string(journal)
            .with_context(|| format!("reading {}", journal.display()))?;
        // a record whose store the database holds is dropped, not replayed
        let installed = landed(db, &text)?;
        if committed(&text, installed) {
            drop_journal(journal);
            return Ok(0);
        }
        if let (Some(db), Some(target)) = (db, target_digest(&text)) {
            if db.state_digest()? == target {
                drop_journal(journal);
                return Ok(0);
            }
        }
        let mut failed = false;
        let mut damaged = false;
        let torn_tail = !text.ends_with('\n');
        let mut lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect();
        // the last record was cut by the crash: it never reached the tree
        if torn_tail {
            lines.pop();
        }
        if reverse {
            lines.reverse();
        }
        for line in lines {
            let plan = match serde_json::from_str::<Entry>(line) {
                Ok(plan) => plan,
                Err(error) => {
                    // the record names a path this replay cannot identify
                    damaged = true;
                    eprintln!(
                        "warning: {} holds a record that cannot be read ({error})",
                        journal.display()
                    );
                    continue;
                }
            };
            if crate::policy::is_protected_path(&plan.path) {
                damaged = true;
                eprintln!(
                    "warning: {} names a protected path; the record is kept",
                    journal.display()
                );
                continue;
            }
            match undo(&plan, target_root, reverse) {
                Ok(count) => restored += count,
                Err(error) => {
                    failed = true;
                    eprintln!("warning: {} was not put back: {error:#}", plan.path);
                }
            }
        }
        // a record with an entry that could not be undone, or one that cannot be
        // read, stays for the next try
        if failed || damaged {
            eprintln!(
                "warning: {} was kept so the next write command can try again",
                journal.display()
            );
        } else {
            drop_journal(journal);
        }
        if damaged {
            return Err(crate::error::Coded::new(
                crate::error::Code::RecoveryBlocked,
                format!(
                    "{} holds a record that cannot be read; the paths it names were left as they are.\n\
                     inspect or remove that record before running a write command",
                    journal.display()
                ),
            )
            .into());
        }
        if failed {
            return Err(crate::error::Coded::new(
                crate::error::Code::RecoveryBlocked,
                format!(
                    "{} holds a record whose path was not put back; the record is kept for the next try",
                    journal.display()
                ),
            )
            .into());
        }
    }
    Ok(restored)
}

/// Answers whether the record belongs to an activation that reached the
/// database.
pub(super) fn committed(text: &str, installed: bool) -> bool {
    installed || text.lines().any(|line| line.trim() == COMMIT)
}

/// The package and the store a journal header names.
pub(super) struct Header<'a> {
    pub(super) package: &'a str,
    pub(super) store: &'a str,
}

/// The database digest an activation recorded before it changed the tree.
fn start_digest(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("# start "))
}

/// The database digest an operation journal records, if it has one.
fn target_digest(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("# target "))
}

/// Answers whether the package and the store a journal header names.
pub(super) fn header_of(text: &str) -> Option<Header<'_>> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with('#'))?;
    // the store is the rest of the line: a store path may hold spaces
    let mut parts = line
        .trim_start()
        .trim_start_matches('#')
        .trim()
        .splitn(3, ' ');
    let package = parts.next()?;
    parts.next()?;
    let store = parts.next()?.trim();
    Some(Header { package, store })
}

/// Answers whether the database already holds the store a record names.
pub(super) fn landed(db: Option<&crate::db::Db>, text: &str) -> Result<bool> {
    let (Some(db), Some(header)) = (db, header_of(text)) else {
        return Ok(false);
    };
    if let Some(start) = start_digest(text) {
        if db.state_digest()? == start {
            return Ok(false);
        }
        return Ok(true);
    }
    Ok(db
        .package(header.package)?
        .map(|row| row.store_path == header.store)
        .unwrap_or(false))
}

fn undo(plan: &Entry, target_root: &Path, recreate: bool) -> Result<usize> {
    let live = live_path(target_root, &plan.path);
    let installed = matches!(
        fs::symlink_metadata(&live).map(|meta| meta.file_type().is_symlink()),
        Ok(true)
    );
    match &plan.previous {
        Previous::Displaced { backup } => undo_displaced(target_root, plan, backup, &live),
        Previous::Restored { backup } => undo_restored(plan, backup, &live),
        Previous::Symlink { target } => {
            undo_symlink(target_root, plan, target, &live, installed, recreate)
        }
        Previous::Missing => undo_missing(target_root, plan, installed),
    }
}

/// Puts back what a displaced live path held.
fn undo_displaced(target_root: &Path, plan: &Entry, backup: &str, live: &Path) -> Result<usize> {
    let backup = Path::new(backup);
    if !backup.exists() {
        // a regular file at the live path is the restored one; anything
        // else cannot be confirmed
        let restored = fs::symlink_metadata(live)
            .map(|meta| meta.file_type().is_file())
            .unwrap_or(false);
        return if restored {
            Ok(0)
        } else {
            Err(crate::error::Coded::new(
                crate::error::Code::RecoveryBlocked,
                format!(
                    "{} has neither its backup nor the file it held; the record is kept",
                    plan.path
                ),
            )
            .into())
        };
    }
    remove_in_live(target_root, &plan.path).with_context(|| format!("clearing {}", plan.path))?;
    if backup.is_dir() {
        crate::links::restore_backup(target_root, &plan.path, backup)
            .with_context(|| format!("restoring {} back", plan.path))?;
    } else {
        crate::links::copy_into_live(target_root, &plan.path, backup, None)
            .with_context(|| format!("copying {} back", plan.path))?;
        if let Err(error) = fs::remove_file(backup) {
            eprintln!(
                "warning: {} is back but its backup {} was kept: {error}",
                plan.path,
                backup.display()
            );
        }
    }
    Ok(1)
}

/// Puts a restored original back into the backup area.
fn undo_restored(plan: &Entry, backup: &str, live: &Path) -> Result<usize> {
    let backup = Path::new(backup);
    let meta = match fs::symlink_metadata(live) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", live.display()));
        }
    };
    if !meta.file_type().is_file() && !meta.file_type().is_dir() {
        return Err(crate::error::Coded::new(
            crate::error::Code::RecoveryBlocked,
            format!(
                "{} is not the file this record restored; the record is kept",
                plan.path
            ),
        )
        .into());
    }
    if backup.exists() {
        return Err(crate::error::Coded::new(
            crate::error::Code::RecoveryBlocked,
            format!(
                "{} already has a backup; the record is kept",
                backup.display()
            ),
        )
        .into());
    }
    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::rename(live, backup)
        .with_context(|| format!("putting {} back to {}", plan.path, backup.display()))?;
    if let Some(parent) = live.parent() {
        let _ = crate::util::sync_dir(parent);
    }
    if let Some(parent) = backup.parent() {
        let _ = crate::util::sync_dir(parent);
    }
    Ok(1)
}

/// Points the path back at the link target the record names.
fn undo_symlink(
    target_root: &Path,
    plan: &Entry,
    target: &str,
    live: &Path,
    installed: bool,
    recreate: bool,
) -> Result<usize> {
    // the path held a link before, and it goes back pointing where it did
    if !installed {
        if recreate && fs::symlink_metadata(live).is_err() {
            crate::links::safe_symlink(target_root, &plan.path, target)?;
            return Ok(1);
        }
        return Ok(0);
    }
    remove_in_live(target_root, &plan.path).with_context(|| format!("clearing {}", plan.path))?;
    crate::links::safe_symlink(target_root, &plan.path, target)
        .with_context(|| format!("pointing {} at {target}", plan.path))?;
    Ok(1)
}

/// Clears a path the record says was absent before.
fn undo_missing(target_root: &Path, plan: &Entry, installed: bool) -> Result<usize> {
    if !installed {
        return Ok(0);
    }
    remove_in_live(target_root, &plan.path).with_context(|| format!("clearing {}", plan.path))?;
    Ok(1)
}
