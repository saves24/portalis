//! Live-tree links: creating them safely and repairing the ones a transaction missed.

use crate::db::Db;
use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_NEXT_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// True when `target`, resolved next to `live`, lands inside `store_path`.
fn resolves_inside(live: &std::path::Path, target: &str, store_path: &str) -> bool {
    let Some(base) = live.parent() else {
        return false;
    };
    let joined = base.join(target);
    let Ok(resolved) = joined.canonicalize() else {
        return false;
    };
    let Ok(store) = std::path::Path::new(store_path).canonicalize() else {
        return false;
    };
    resolved.starts_with(&store)
}

pub(crate) fn repair_links(db: &Db, paths: &Paths) -> Result<()> {
    let target_root = paths.target_root();
    let mut fixed = 0usize;
    let mut missing = 0usize;
    for pkg in db.packages()? {
        let recipe_path = paths.recipes().join(format!("{}.port", pkg.name));
        let preserve = if recipe_path.is_file() {
            match crate::recipe::Recipe::load(&recipe_path) {
                Ok(recipe) => recipe.files.preserve,
                Err(error) => {
                    eprintln!(
                        "warning: links for {} were not repaired: {error:#}",
                        pkg.name
                    );
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        for (path, _sha, link_target, _mode) in db.files_of(&pkg.name)? {
            if preserve.iter().any(|p| p == &path) {
                continue;
            }
            if crate::policy::is_protected_path(&path)
                || (link_target.starts_with('/') && crate::policy::is_protected_path(&link_target))
            {
                continue;
            }
            let desired = format!("{}{}", pkg.store_path, path);
            if fs::symlink_metadata(&desired).is_err() {
                continue;
            }
            let store_root = paths.store().to_string_lossy().to_string();
            let live = live_path(&target_root, &path);
            let mut rewrote = false;
            match fs::symlink_metadata(&live) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    let current = match fs::read_link(&live) {
                        Ok(target) => target.to_string_lossy().to_string(),
                        Err(error) => {
                            eprintln!(
                                "warning: {} could not be read ({error}); it is pointed at its store path",
                                live.display()
                            );
                            String::new()
                        }
                    };
                    // A package-owned link keeps its own target; a link into the
                    // package store follows the store that owns the row.
                    if current != desired
                        && current.starts_with(&store_root)
                        && !resolves_inside(&live, &current, &pkg.store_path)
                    {
                        crate::policy::validate_link_target(
                            &target_root,
                            &path,
                            &desired,
                            Some(Path::new(&pkg.store_path)),
                        )?;
                        safe_symlink(&target_root, &path, &desired)?;
                        rewrote = true;
                        fixed += 1;
                    }
                }
                Err(_) => {
                    if !link_target.is_empty() {
                        crate::policy::validate_link_target(
                            &target_root,
                            &path,
                            &link_target,
                            Some(Path::new(&pkg.store_path)),
                        )?;
                        safe_symlink(&target_root, &path, &link_target)?;
                        rewrote = true;
                        fixed += 1;
                    }
                }
                Ok(_) => {
                    missing += 1;
                }
            }
            if rewrote && link_target.starts_with(&store_root) && link_target != desired {
                db.set_file_target(&pkg.name, &path, &desired)?;
            }
        }
    }
    say!("repaired {fixed} links, {missing} paths left as regular files");
    Ok(())
}

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
fn sync_dir_fd(dir: RawFd) -> Result<()> {
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

/// Restores a backup entry of any file type to its live path.
pub(crate) fn restore_backup(target_root: &Path, path: &str, backup: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(backup)
        .with_context(|| format!("reading backup {}", backup.display()))?;
    let live = live_path(target_root, path);
    if meta.file_type().is_symlink() {
        let target = fs::read_link(backup)?;
        safe_symlink(target_root, path, &target.to_string_lossy())?;
        fs::remove_file(backup)?;
    } else if meta.is_dir() {
        ensure_live_dir(target_root, path)?;
        crate::archive::copy_tree(backup, &live)?;
        fs::remove_dir_all(backup)?;
    } else {
        copy_into_live(target_root, path, backup, None)?;
        fs::remove_file(backup)?;
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

pub(crate) fn safe_symlink(root: &Path, rel: &str, target: &str) -> Result<()> {
    safe_symlink_inner(root, rel, target).with_context(|| format!("linking {rel}"))
}

fn safe_symlink_inner(root: &Path, rel: &str, target: &str) -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_LINK.with(|flag| flag.replace(false)) {
        bail!("injected link failure");
    }
    let components: Vec<&str> = rel
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if components.contains(&"..") {
        bail!("live path contains a parent component: {rel}");
    }
    let Some((name, dirs)) = components.split_last() else {
        bail!("empty live path");
    };
    let dir = open_live_parent_dir(root, dirs)?;
    let name = CString::new(*name)?;
    // Safety: a zeroed stat is a valid buffer for the call that fills it in.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // Safety: fstatat only writes into the provided stat buffer.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 && stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
        bail!("refusing to replace non-symlink {rel}");
    }
    let target = CString::new(target)?;
    // Build the new link under a temporary name and move it into place. The name
    // carries a counter as well as the pid.
    static STAGING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = STAGING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = CString::new(format!(".portalis-link-{}-{sequence}", std::process::id()))?;
    // Safety: symlinkat only reads the two NUL-terminated strings.
    let rc = unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), staging.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Re-checks the destination immediately before the rename.
    // Safety: a zeroed stat is a valid buffer for the call that fills it in.
    let mut fresh: libc::stat = unsafe { std::mem::zeroed() };
    // Safety: fstatat only writes into the provided stat buffer.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut fresh,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 && fresh.st_mode & libc::S_IFMT != libc::S_IFLNK {
        // Safety: the temporary entry is ours; removing it cannot race.
        unsafe { libc::unlinkat(dir.as_raw_fd(), staging.as_ptr(), 0) };
        bail!("refusing to replace non-symlink {rel}");
    }
    // Safety: renameat moves the staging name onto the live path, replacing a
    // symlink that sits there; it never follows either name.
    let rc = unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            staging.as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        // Safety: the temporary entry is ours; removing it cannot race.
        unsafe { libc::unlinkat(dir.as_raw_fd(), staging.as_ptr(), 0) };
        return Err(error.into());
    }
    sync_dir_fd(dir.as_raw_fd())?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{copy_into_live, remove_in_live, safe_symlink, writable_parents};
    use std::fs;
    use std::path::Path;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("portalis-links-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("etc")).unwrap();
        root
    }

    #[test]
    fn a_symlinked_parent_is_judged_by_its_target() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("symlink-parent");
        let shared = root.join("srv/share");
        fs::create_dir_all(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&shared, root.join("opt")).unwrap();
        let flagged = writable_parents(&root, "/opt/bin/tool");
        assert!(
            !flagged.is_empty(),
            "a world-writable target behind a symlinked parent went unnoticed"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_shared_parent_without_the_sticky_bit_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("writable");
        let open = root.join("srv");
        fs::create_dir_all(open.join("app")).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let found = super::writable_parents(&root, "/srv/app/bin");
        assert_eq!(
            found,
            vec!["/srv".to_string()],
            "a world-writable parent was missed"
        );

        fs::set_permissions(&open, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(
            super::writable_parents(&root, "/srv/app/bin").is_empty(),
            "a sticky directory was reported"
        );

        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(super::writable_parents(&root, "/srv/app/bin").is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_resolved_live_path_follows_a_symlinked_parent() {
        let root = scratch("resolved-parent");
        fs::create_dir_all(root.join("opt")).unwrap();
        std::os::unix::fs::symlink("../etc", root.join("opt/link")).unwrap();
        let resolved = super::resolved_live_target(&root, "/opt/link/evil").expect("resolve");
        assert_eq!(resolved, root.join("etc/evil"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_copy_never_lands_outside_the_root() {
        let root = scratch("escape");
        let outside = root.with_extension("outside");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        // etc/ssh is a symlink that leaves the root
        std::os::unix::fs::symlink(&outside, root.join("etc/ssh")).unwrap();
        let source = root.join("payload");
        fs::write(&source, b"x").unwrap();

        let refused = copy_into_live(&root, "/etc/ssh/config", &source, None);
        assert!(refused.is_err(), "a copy followed a symlinked parent");
        assert!(
            !outside.join("config").exists(),
            "the file landed outside the root"
        );
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_copy_does_not_overwrite_what_appeared_first() {
        let root = scratch("noreplace");
        let source = root.join("payload");
        fs::write(&source, b"new").unwrap();
        fs::write(root.join("etc/config"), b"user edit").unwrap();

        let refused = copy_into_live(&root, "/etc/config", &source, None);
        assert!(refused.is_err(), "an existing file was overwritten");
        assert_eq!(fs::read(root.join("etc/config")).unwrap(), b"user edit");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_copy_keeps_the_source_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = scratch("mode");
        let source = root.join("payload");
        fs::write(&source, b"secret").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        copy_into_live(&root, "/etc/secret", &source, None).expect("copy");
        let mode = fs::metadata(root.join("etc/secret"))
            .expect("copied file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the source mode was lost");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn removing_a_link_keeps_its_target() {
        let root = scratch("unlink");
        fs::write(root.join("etc/real"), b"keep").unwrap();
        std::os::unix::fs::symlink(root.join("etc/real"), root.join("etc/link")).unwrap();
        remove_in_live(&root, "/etc/link").expect("removes");
        assert!(!Path::new(&root.join("etc/link")).exists());
        assert_eq!(fs::read(root.join("etc/real")).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_link_cannot_be_placed_through_a_symlinked_parent() {
        let root = scratch("linkescape");
        let outside = root.with_extension("outside2");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc/ssh")).unwrap();
        let refused = safe_symlink(&root, "/etc/ssh/key", "/somewhere");
        assert!(refused.is_err(), "a link was placed outside the root");
        assert!(!outside.join("key").exists());
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_package_symlink_is_recreated_from_its_record() {
        let root = scratch("symlink-repair");
        let paths = crate::paths::Paths::at(root.clone());
        paths.ensure_layout().expect("layout");
        let db = crate::db::Db::open(&paths, crate::db::Access::Write).expect("db");
        let store = paths.store().join("linkpkg-1.0-aaaa");
        fs::create_dir_all(store.join("usr/lib")).expect("store");
        fs::write(store.join("usr/lib/real"), b"payload").expect("payload");
        std::os::unix::fs::symlink("real", store.join("usr/lib/link")).expect("store link");
        db.conn()
            .execute(
                "INSERT INTO packages (name, version, store_path, recipe_sha256, \
                 manifest_digest, installed_at, build_log) \
                 VALUES ('linkpkg', '1.0', ?1, 'x', 'y', 'now', 'log')",
                rusqlite::params![store.to_string_lossy().to_string()],
            )
            .expect("package row");
        db.conn()
            .execute(
                "INSERT INTO files (pkg, path, sha256, link_target, mode) \
                 VALUES ('linkpkg', '/usr/lib/link', '', 'real', 0)",
                [],
            )
            .expect("file row");

        super::repair_links(&db, &paths).expect("repair");

        let live = root.join("usr/lib/link");
        assert_eq!(
            fs::read_link(&live).expect("live link"),
            std::path::PathBuf::from("real")
        );
        let recorded: String = db
            .conn()
            .query_row(
                "SELECT link_target FROM files WHERE pkg = 'linkpkg' AND path = '/usr/lib/link'",
                [],
                |row| row.get(0),
            )
            .expect("recorded target");
        assert_eq!(recorded, "real", "the record was rewritten as a store path");
        let _ = fs::remove_dir_all(&root);
    }
}
