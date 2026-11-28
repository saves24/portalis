//! Live-tree paths: parent directories, copies and removals.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) fn open_dir_at(dir: RawFd, name: &str) -> Result<OwnedFd> {
    let name = CString::new(name)?;
    // Safety: openat only uses the directory descriptor and a NUL-terminated
    // name; the returned descriptor is owned by the caller.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: fd was just returned by openat and is not used elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens a directory below `root_fd`, one no-follow component at a time.
fn open_relative_dir(root_fd: RawFd, relative: &Path) -> Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    // Safety: dup gives an independent descriptor for the same directory.
    let duplicate = unsafe { libc::dup(root_fd) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: duplicate is a fresh descriptor owned here.
    let mut dir = unsafe { OwnedFd::from_raw_fd(duplicate) };
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!(
                "resolved path has an invalid component: {}",
                relative.display()
            );
        };
        dir = open_dir_at(dir.as_raw_fd(), &name.to_string_lossy())?;
    }
    Ok(dir)
}

/// Flushes a directory entry change made through `dir`.
pub(super) fn sync_dir_fd(dir: RawFd) -> Result<()> {
    // Safety: fsync only reads the descriptor.
    if unsafe { libc::fsync(dir) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) fn mkdir_at(dir: RawFd, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    // Safety: mkdirat only reads the name string and uses the directory fd.
    let rc = unsafe { libc::mkdirat(dir, name.as_ptr(), 0o755) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) fn open_live_parent_dir(root: &Path, dirs: &[&str]) -> Result<OwnedFd> {
    let root_canonical =
        fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
    let root_name = CString::new(root_canonical.as_os_str().as_encoded_bytes())?;
    // Safety: open only reads the path and returns an owned descriptor.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: root_fd came from open above and is not used elsewhere.
    let mut dir = unsafe { OwnedFd::from_raw_fd(root_fd) };
    let mut current = root_canonical.clone();
    for component in dirs {
        match open_dir_at(dir.as_raw_fd(), component) {
            Ok(next) => {
                dir = next;
                current.push(component);
            }
            Err(error) => {
                let code = error
                    .downcast_ref::<std::io::Error>()
                    .and_then(|error| error.raw_os_error());
                if matches!(code, Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
                    let candidate = fs::canonicalize(current.join(component))?;
                    if !candidate.starts_with(&root_canonical) {
                        bail!(
                            "symlinked parent escapes {}: {}",
                            root.display(),
                            candidate.display()
                        );
                    }
                    let relative = candidate
                        .strip_prefix(&root_canonical)
                        .with_context(|| format!("resolving {}", candidate.display()))?;
                    use std::os::unix::fs::OpenOptionsExt;
                    let reopened = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                        .open(&root_canonical)?;
                    dir = open_relative_dir(reopened.as_raw_fd(), relative)?;
                    current = candidate;
                } else if code == Some(libc::ENOENT) {
                    mkdir_at(dir.as_raw_fd(), component)?;
                    dir = open_dir_at(dir.as_raw_fd(), component)?;
                    current.push(component);
                } else {
                    return Err(error);
                }
            }
        }
    }
    Ok(dir)
}

/// Splits a live path into its parent components and its own name.
fn split_live(rel: &str) -> Result<(&str, Vec<&str>)> {
    let components: Vec<&str> = rel
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if components.contains(&"..") {
        bail!("live path contains a parent component: {rel}");
    }
    match components.split_last() {
        Some((name, dirs)) => Ok((name, dirs.to_vec())),
        None => bail!("empty live path"),
    }
}

/// Creates the parent directories of `rel` under `root`, refusing any symlinked
/// component that leads outside it.
pub(crate) fn ensure_live_dir(root: &Path, rel: &str) -> Result<()> {
    let (_, dirs) = split_live(rel)?;
    let _ = open_live_parent_dir(root, &dirs)?;
    Ok(())
}

/// Creates one directory below `root`; answers whether it was created now.
pub(crate) fn ensure_live_directory(root: &Path, rel: &str, mode: u32) -> Result<bool> {
    let (name, dirs) = split_live(rel)?;
    let parent = open_live_parent_dir(root, &dirs)?;
    let name = CString::new(name)?;
    // Safety: mkdirat only reads its arguments.
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if rc == 0 {
        let directory = open_dir_at(parent.as_raw_fd(), &name.to_string_lossy())?;
        let mode = if mode & 0o777 == 0 {
            0o755
        } else {
            mode & 0o777
        };
        // Safety: the descriptor belongs to the directory just created.
        if unsafe { libc::fchmod(directory.as_raw_fd(), mode) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        sync_dir_fd(parent.as_raw_fd())?;
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        let _directory = open_dir_at(parent.as_raw_fd(), &name.to_string_lossy())?;
        return Ok(false);
    }
    Err(error.into())
}

/// Removes one empty directory below `root`.
pub(crate) fn remove_live_directory(root: &Path, rel: &str) -> Result<()> {
    let (name, dirs) = split_live(rel)?;
    let parent = open_live_parent_dir(root, &dirs)?;
    let name = CString::new(name)?;
    // Safety: unlinkat reads the name and the directory descriptor, and
    // AT_REMOVEDIR only removes an empty directory.
    let rc = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error.into());
    }
    sync_dir_fd(parent.as_raw_fd())?;
    Ok(())
}

/// Removes the entry at `rel`, addressing it through its parent directory.
pub(crate) fn remove_in_live(root: &Path, rel: &str) -> Result<()> {
    let (name, dirs) = split_live(rel)?;
    let dir = open_live_parent_dir(root, &dirs)?;
    let name = CString::new(name)?;
    // Safety: unlinkat reads the name and the directory descriptor, and never
    // follows the final component.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error.into());
    }
    Ok(())
}

/// Copies `source` to `rel` through its parent directory: the content goes to a
/// temporary name first and is moved into place. `extension` replaces the file's
/// own extension (used for `.pacnew`).
pub(crate) fn copy_into_live(
    root: &Path,
    rel: &str,
    source: &Path,
    extension: Option<&str>,
) -> Result<String> {
    let (name, dirs) = split_live(rel)?;
    let dir = open_live_parent_dir(root, &dirs)?;
    let final_name = match extension {
        Some(ext) => {
            let stem = name
                .rsplit_once('.')
                .map(|(stem, _)| stem)
                .filter(|stem| !stem.is_empty())
                .unwrap_or(name);
            format!("{stem}.{ext}")
        }
        None => name.to_string(),
    };
    static STAGING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = STAGING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = CString::new(format!(".portalis-copy-{}-{sequence}", std::process::id()))?;
    // Safety: openat creates a fresh file below the parent directory, without
    // following anything already at that name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            staging.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: fd was just created above and is owned here.
    let mut out = unsafe { std::fs::File::from_raw_fd(fd) };
    let copied = (|| -> Result<()> {
        let mut input =
            std::fs::File::open(source).with_context(|| format!("opening {}", source.display()))?;
        let source_meta = input.metadata()?;
        std::io::copy(&mut input, &mut out)?;
        // Safety: fchown only changes the owner of the descriptor above.
        if unsafe { libc::fchown(fd, source_meta.uid(), source_meta.gid()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Safety: fchmod only changes the mode of the descriptor above.
        if unsafe { libc::fchmod(fd, source_meta.mode() & 0o7777) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        out.sync_all()?;
        Ok(())
    })();
    if let Err(error) = copied {
        drop(out);
        // Safety: the staging name belongs to this call.
        unsafe { libc::unlinkat(dir.as_raw_fd(), staging.as_ptr(), 0) };
        return Err(error);
    }
    drop(out);
    let final_c = CString::new(final_name.clone())?;
    // RENAME_NOREPLACE keeps an existing entry for the plain copy; a pacnew is
    // meant to replace an older one.
    let flags = if extension.is_some() {
        0
    } else {
        libc::RENAME_NOREPLACE
    };
    // Safety: both names live in the directory the descriptor refers to.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir.as_raw_fd(),
            staging.as_ptr(),
            dir.as_raw_fd(),
            final_c.as_ptr(),
            flags,
        ) as i32
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        // Safety: the staging name belongs to this call.
        unsafe { libc::unlinkat(dir.as_raw_fd(), staging.as_ptr(), 0) };
        if error.raw_os_error() == Some(libc::EEXIST) {
            bail!("refusing to overwrite the file that appeared at {rel}");
        }
        return Err(error.into());
    }
    sync_dir_fd(dir.as_raw_fd())?;
    let parent = rel.trim_end_matches(name);
    Ok(format!("{parent}{final_name}"))
}

/// Directories on the way to `rel` that a non-root account could replace: mode
/// bits for group or other, without the sticky bit that protects the entries in
/// them. The final component is not a parent and is left out.
pub(crate) fn writable_parents(root: &Path, rel: &str) -> Vec<String> {
    let parts: Vec<&str> = rel
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let mut bad = Vec::new();
    let mut current = root.to_path_buf();
    let mut shown = String::new();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current = current.join(part);
        shown.push('/');
        shown.push_str(part);
        let Ok(meta) = fs::symlink_metadata(&current) else {
            // a component that does not exist yet is created by this install
            break;
        };
        if meta.file_type().is_symlink() {
            // Judges the directory the link resolves to.
            match fs::canonicalize(&current) {
                Ok(target) if target.starts_with(root) => current = target,
                _ => {
                    bad.push(shown.clone());
                    break;
                }
            }
            let Ok(resolved) = fs::metadata(&current) else {
                break;
            };
            let mode = resolved.mode();
            let shared = mode & 0o022 != 0;
            let sticky = mode & 0o1000 != 0;
            if (shared || resolved.uid() != 0) && !sticky {
                bad.push(shown.clone());
            }
            continue;
        }
        if !meta.is_dir() {
            break;
        }
        let mode = meta.mode();
        let shared = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        if (shared || meta.uid() != 0) && !sticky {
            bad.push(shown.clone());
        }
    }
    bad
}

pub(crate) fn live_path(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

/// Resolves a live path's parent and appends its final name.
pub(crate) fn resolved_live_target(root: &Path, absolute: &str) -> Result<PathBuf> {
    let path = Path::new(absolute);
    let Some(parent) = path.parent() else {
        return Ok(live_path(root, absolute));
    };
    let parent = resolved_live_path(root, &parent.to_string_lossy())?;
    Ok(parent.join(path.file_name().unwrap_or_default()))
}

/// Resolves symlinked components of a live path without creating anything.
pub(crate) fn resolved_live_path(root: &Path, absolute: &str) -> Result<PathBuf> {
    fn normalize(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for part in path.components() {
            match part {
                std::path::Component::RootDir => out.push("/"),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::Normal(name) => out.push(name),
                _ => {}
            }
        }
        out
    }

    let root = fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
    let mut current = root.clone();
    for part in absolute
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
    {
        current = current.join(part);
        let mut depth = 0usize;
        loop {
            let meta = match fs::symlink_metadata(&current) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", current.display()))
                }
            };
            if !meta.file_type().is_symlink() {
                break;
            }
            depth += 1;
            if depth > 40 {
                bail!("symlink chain is too deep: {}", current.display());
            }
            let target = fs::read_link(&current)?;
            let base = current.parent().unwrap_or(&root);
            current = normalize(&if target.is_absolute() {
                target
            } else {
                base.join(target)
            });
            if !current.starts_with(&root) {
                bail!(
                    "live path escapes {}: {}",
                    root.display(),
                    current.display()
                );
            }
        }
    }
    Ok(current)
}
