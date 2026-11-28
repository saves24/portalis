//! Creating links safely, and restoring backups.

use super::live::{copy_into_live, ensure_live_dir, live_path, open_live_parent_dir, sync_dir_fd};
#[cfg(test)]
use super::FAIL_NEXT_LINK;
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::Path;

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
