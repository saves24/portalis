//! Copying a tree without following links.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// Distinguishes temporary file names inside one process.
static COPY_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut dirs: Vec<(std::path::PathBuf, u32, u32, u32)> = Vec::new();
    let mut hardlinks: std::collections::HashMap<(u64, u64), std::path::PathBuf> =
        std::collections::HashMap::new();
    ensure_dir_nofollow(to)?;
    for entry in walkdir::WalkDir::new(from).follow_links(false) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(from)?;
        let target = to.join(rel);
        if entry.file_type().is_dir() {
            ensure_dir_nofollow(&target)?;
            let meta = entry.metadata()?;
            dirs.push((target, meta.mode() & 0o7777, meta.uid(), meta.gid()));
        } else if entry.file_type().is_symlink() {
            let source = fs::symlink_metadata(entry.path())?;
            match fs::symlink_metadata(&target) {
                Ok(meta) if meta.is_dir() => {
                    bail!(
                        "refusing to replace directory {} with a symlink",
                        target.display()
                    )
                }
                Ok(_) => fs::remove_file(&target)
                    .with_context(|| format!("removing {}", target.display()))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", target.display()))
                }
            }
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, &target)
                .with_context(|| format!("linking {}", target.display()))?;
            std::os::unix::fs::lchown(&target, Some(source.uid()), Some(source.gid()))
                .with_context(|| format!("setting the owner of {}", target.display()))?;
        } else {
            let meta = entry.metadata()?;
            let key = (meta.dev(), meta.ino());
            if let Some(existing) = hardlinks.get(&key) {
                match fs::symlink_metadata(&target) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        bail!("refusing to write through symlink {}", target.display())
                    }
                    Ok(meta) if meta.is_dir() => {
                        bail!("refusing to replace directory {}", target.display())
                    }
                    Ok(_) => fs::remove_file(&target)
                        .with_context(|| format!("removing {}", target.display()))?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| format!("reading {}", target.display()))
                    }
                }
                fs::hard_link(existing, &target)
                    .with_context(|| format!("linking {}", target.display()))?;
            } else {
                copy_file_nofollow(entry.path(), &target)?;
                hardlinks.insert(key, target);
            }
        }
    }
    // Deepest first.
    dirs.sort_by_key(|(path, _, _, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode, uid, gid) in dirs {
        std::os::unix::fs::chown(&path, Some(uid), Some(gid))
            .with_context(|| format!("setting the owner of {}", path.display()))?;
        fs::set_permissions(
            &path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(mode),
        )
        .with_context(|| format!("setting the mode of {}", path.display()))?;
    }
    Ok(())
}

fn ensure_dir_nofollow(path: &Path) -> Result<()> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("refusing to traverse symlink {}", current.display())
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
    }
    Ok(())
}

fn copy_file_nofollow(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if let Some(parent) = target.parent() {
        ensure_dir_nofollow(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(target) {
        if meta.file_type().is_symlink() {
            bail!("refusing to write through symlink {}", target.display());
        }
        if meta.is_dir() {
            bail!(
                "refusing to replace directory {} with a file",
                target.display()
            );
        }
    }
    let sequence = COPY_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary =
        target.with_file_name(format!(".portalis-copy-{}-{sequence}", std::process::id()));
    let mut input =
        fs::File::open(source).with_context(|| format!("opening {}", source.display()))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        let meta = input.metadata()?;
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
        std::os::unix::fs::chown(&temporary, Some(meta.uid()), Some(meta.gid()))?;
        fs::set_permissions(
            &temporary,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(mode),
        )?;
        fs::rename(&temporary, target)
            .with_context(|| format!("moving {}", temporary.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
