//! Moving live entries and relinking them after a failed remove.

use crate::links::{live_path, safe_symlink};
use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) fn warn_missing_backup(path: &str, backup: &Path) {
    eprintln!(
        "warning: {path} was taken over but its backup {} is missing; the path stays empty",
        backup.display()
    );
}

/// Moves a file, falling back to copy-and-remove when the two paths sit on
/// different filesystems (the state directory is often its own mount).
pub(super) fn move_file(from: &Path, to: &Path) -> Result<()> {
    let sync_parents = || -> Result<()> {
        let from_parent = from
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent", from.display()))?;
        crate::util::sync_dir(from_parent)?;
        let to_parent = to
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent", to.display()))?;
        if to_parent != from_parent {
            crate::util::sync_dir(to_parent)?;
        }
        Ok(())
    };
    if fs::rename(from, to).is_ok() {
        sync_parents()?;
        return Ok(());
    }
    let meta = fs::symlink_metadata(from).with_context(|| format!("reading {}", from.display()))?;
    let sequence = MOVE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = to.with_file_name(format!(".portalis-move-{}-{sequence}", std::process::id()));
    let result = (|| -> Result<()> {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(from)?;
            std::os::unix::fs::symlink(&target, &temporary)?;
        } else if meta.is_dir() {
            crate::archive::copy_tree(from, &temporary)?;
        } else {
            fs::copy(from, &temporary)?;
            std::fs::set_permissions(&temporary, meta.permissions())?;
            std::os::unix::fs::chown(&temporary, Some(meta.uid()), Some(meta.gid()))?;
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temporary)?
                .sync_all()?;
        }
        fs::rename(&temporary, to)?;
        if meta.is_dir() {
            fs::remove_dir_all(from)?;
        } else {
            fs::remove_file(from)?;
        }
        Ok(())
    })();
    if result.is_err() {
        if meta.is_dir() {
            let _ = fs::remove_dir_all(&temporary);
        } else {
            let _ = fs::remove_file(&temporary);
        }
    }
    result?;
    sync_parents()?;
    Ok(())
}

static MOVE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Recreates the links an interrupted remove already deleted. Paths that now hold
/// a restored original or a user file are left untouched.
pub(super) fn relink_after_failed_remove(
    target_root: &Path,
    files: &[(String, String, String, u32)],
) -> (usize, usize) {
    let mut relinked = 0usize;
    let mut skipped = 0usize;
    for (path, _sha, link_target, _mode) in files {
        let live = live_path(target_root, path);
        if fs::symlink_metadata(&live).is_ok() {
            skipped += 1;
            continue;
        }
        if let Some(parent) = live.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                eprintln!("warning: cannot recreate {}: {error}", parent.display());
                skipped += 1;
                continue;
            }
        }
        match crate::policy::validate_link_target(target_root, path, link_target, None)
            .and_then(|()| safe_symlink(target_root, path, link_target))
        {
            Ok(()) => relinked += 1,
            Err(error) => {
                eprintln!("warning: cannot relink {path}: {error:#}");
                skipped += 1;
            }
        }
    }
    (relinked, skipped)
}
