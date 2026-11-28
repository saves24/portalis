//! Unpacking member data below a root, through directory handles that never
//! follow a symlink.
use anyhow::{bail, Result};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;

use super::parse::{max_unpacked_bytes, MAX_MEMBERS, MAX_PATH_COMPONENTS};
use super::{Cursor, Kind, Member};

/// Unpacks every member below `root`. Paths are created only through directory
/// handles opened without following symlinks. A member that is not a file,
/// directory or link is refused.
pub fn extract<R: Read>(reader: &mut R, root: &Path) -> Result<usize> {
    extract_with_times(reader, root, true)
}

pub fn extract_without_times<R: Read>(reader: &mut R, root: &Path) -> Result<usize> {
    extract_with_times(reader, root, false)
}

fn extract_with_times<R: Read>(reader: &mut R, root: &Path, preserve_times: bool) -> Result<usize> {
    let root_file = std::fs::File::open(root)?;
    let root_fd = root_file.as_raw_fd();
    let mut cursor = Cursor::new(reader);
    let mut created = 0usize;
    let mut unpacked: u64 = 0;
    let mut path_components: usize = 0;
    let mut directories: Vec<(Vec<String>, u32, i64)> = Vec::new();

    while let Some(member) = cursor.next()? {
        if created >= MAX_MEMBERS {
            bail!("archive holds more than {MAX_MEMBERS} members");
        }
        let parts = safe_parts(&member.path)?;
        path_components = path_components.saturating_add(parts.len().max(1));
        if path_components > MAX_PATH_COMPONENTS {
            bail!("archive holds more than {MAX_PATH_COMPONENTS} path components");
        }
        unpacked = unpacked.saturating_add(member.size);
        let ceiling = max_unpacked_bytes();
        if unpacked > ceiling {
            bail!("archive expands past {ceiling} bytes");
        }
        if parts.is_empty() {
            // an archive built with `tar .` names its root "./"; there is
            // nothing to create for it
            if member.kind == Kind::Directory {
                continue;
            }
            bail!("archive member has no usable path: {}", member.path);
        }
        let Some((name, dirs)) = parts.split_last() else {
            bail!("archive member has no usable path: {}", member.path);
        };
        let dir = ensure_dirs(root_fd, dirs)?;
        let name_c = std::ffi::CString::new(name.as_str())?;

        match member.kind {
            Kind::Directory => {
                create_directory(dir.as_raw_fd(), &name_c, &parts, &member, &mut directories)?;
            }
            Kind::File => create_file(
                &mut cursor,
                dir.as_raw_fd(),
                &name_c,
                &member,
                preserve_times,
            )?,
            Kind::Symlink => create_symlink(dir.as_raw_fd(), &name_c, &member)?,
            Kind::HardLink => create_hardlink(root_fd, dir.as_raw_fd(), &name_c, &member)?,
            Kind::Unsupported(kind) => bail!(
                "archive member {} has an unsupported type ({kind})",
                member.path
            ),
        }
        if member.kind != Kind::File && member.size > 0 {
            // links and directories carry no data; the size the header claims is skipped
            cursor.skip_data(member.size)?;
        }
        created += 1;
    }

    // Directory modes and times are applied after their members are written,
    // deepest first.
    directories.sort_by_key(|(parts, _, _)| std::cmp::Reverse(parts.len()));
    for (parts, mode, mtime) in directories {
        let fd = ensure_dirs(root_fd, &parts)?;
        // an archive that carries no mode for its directory still gets one that
        // can be entered
        let mode = if mode & 0o777 == 0 { 0o755 } else { mode };
        // Safety: the descriptor belongs to this directory and fchmod only reads
        // it.
        if unsafe { libc::fchmod(fd.as_raw_fd(), mode) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if preserve_times {
            set_mtime(fd.as_raw_fd(), mtime)?;
        }
    }

    drop(root_file);
    Ok(created)
}

fn create_directory(
    dir_fd: std::os::fd::RawFd,
    name: &std::ffi::CString,
    parts: &[String],
    member: &Member,
    directories: &mut Vec<(Vec<String>, u32, i64)>,
) -> Result<()> {
    // created writable, then narrowed once the members below it are in place:
    // a 0555 directory could not receive its own contents
    // Safety: mkdirat only reads the arguments it is given.
    let rc = unsafe { libc::mkdirat(dir_fd, name.as_ptr(), 0o700) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
        // Safety: openat only reads its arguments; O_NOFOLLOW refuses a symlink.
        let fd = unsafe {
            libc::openat(
                dir_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Safety: fd came from openat above and is not used again.
        unsafe { libc::close(fd) };
    }
    directories.push((parts.to_vec(), member.mode & 0o7777, member.mtime));
    Ok(())
}

fn create_file<R: std::io::Read>(
    cursor: &mut Cursor<R>,
    dir_fd: std::os::fd::RawFd,
    name: &std::ffi::CString,
    member: &Member,
    preserve_times: bool,
) -> Result<()> {
    use std::os::fd::FromRawFd;
    let fd = open_member_at(dir_fd, name)?;
    // Safety: fd came from openat just above and is owned here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    cursor.copy_data(member.size, &mut file)?;
    // the archive's mode applies, minus the bits that change identity
    // Safety: fchmod only reads the descriptor and the mode.
    if unsafe { libc::fchmod(file.as_raw_fd(), member.mode & 0o777) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if preserve_times {
        set_mtime(file.as_raw_fd(), member.mtime)?;
    }
    Ok(())
}

fn create_symlink(
    dir_fd: std::os::fd::RawFd,
    name: &std::ffi::CString,
    member: &Member,
) -> Result<()> {
    let target = member.link_target.clone().unwrap_or_default();
    ensure_link_stays_inside(&member.path, &target)?;
    let target_c = std::ffi::CString::new(target)?;
    // Safety: symlinkat only reads both strings.
    let rc = unsafe { libc::symlinkat(target_c.as_ptr(), dir_fd, name.as_ptr()) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
        // Safety: name and dir_fd are valid for the entry just created.
        if unsafe { libc::unlinkat(dir_fd, name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Safety: the same strings and directory descriptor as the first call.
        let retry = unsafe { libc::symlinkat(target_c.as_ptr(), dir_fd, name.as_ptr()) };
        if retry != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn create_hardlink(
    root_fd: std::os::fd::RawFd,
    dir_fd: std::os::fd::RawFd,
    name: &std::ffi::CString,
    member: &Member,
) -> Result<()> {
    let target = member.link_target.clone().unwrap_or_default();
    let target_parts = safe_parts(&target)?;
    let (target_name, target_dirs) = target_parts
        .split_last()
        .ok_or_else(|| anyhow::anyhow!("hard link {} has no target", member.path))?;
    // The target is resolved through the same anchored walk as the rest.
    let target_dir = ensure_dirs(root_fd, target_dirs)?;
    let target_c = std::ffi::CString::new(target_name.as_str())?;
    // Only regular files may be hard-linked.
    // Safety: a zeroed stat is a valid buffer for the call that fills it in.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // Safety: fstatat only writes into the provided buffer.
    let rc = unsafe {
        libc::fstatat(
            target_dir.as_raw_fd(),
            target_c.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        bail!(
            "hard link {} points at something that is not a regular file: {target}",
            member.path
        );
    }
    // Safety: linkat only reads its arguments; without AT_SYMLINK_FOLLOW the
    // final name is not dereferenced either.
    let rc = unsafe {
        libc::linkat(
            target_dir.as_raw_fd(),
            target_c.as_ptr(),
            dir_fd,
            name.as_ptr(),
            0,
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
        // Safety: name and dir_fd are valid for the entry just created.
        if unsafe { libc::unlinkat(dir_fd, name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Safety: the same descriptors and strings as the first call.
        let retry = unsafe {
            libc::linkat(
                target_dir.as_raw_fd(),
                target_c.as_ptr(),
                dir_fd,
                name.as_ptr(),
                0,
            )
        };
        if retry != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_mtime(fd: std::os::fd::RawFd, seconds: i64) -> std::io::Result<()> {
    if seconds < 0 {
        return Ok(());
    }
    let stamp = libc::timespec {
        tv_sec: seconds,
        tv_nsec: 0,
    };
    // Safety: futimens only reads the descriptor and the two timestamps.
    let rc = unsafe { libc::futimens(fd, [stamp, stamp].as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Creates a member file under `dir_fd`, replacing an entry of the same name.
fn open_member_at(
    dir_fd: std::os::fd::RawFd,
    name: &std::ffi::CString,
) -> Result<std::os::fd::RawFd> {
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
    // Safety: openat only reads its arguments; O_NOFOLLOW stops a planted
    // symlink from redirecting the write.
    let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), flags, 0o600) };
    if fd >= 0 {
        return Ok(fd);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() != std::io::ErrorKind::AlreadyExists {
        return Err(error.into());
    }
    // Safety: unlinkat removes the named entry below the directory handle and
    // never follows it.
    if unsafe { libc::unlinkat(dir_fd, name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: the same openat call, now that nothing holds the name.
    let retry = unsafe { libc::openat(dir_fd, name.as_ptr(), flags, 0o600) };
    if retry < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(retry)
}

/// A lexical pre-filter on a link target: a target with more `..` components
/// than the member has depth is refused before the link is created. It cannot
/// see through an intermediate symlink — `crate::archive::validate_tree_links`
/// resolves every component after unpacking and is the check that holds.
fn ensure_link_stays_inside(path: &str, target: &str) -> Result<()> {
    if target.starts_with('/') {
        return Ok(());
    }
    // depth of the directory that holds the link, counted from normalised components
    let mut budget = safe_parts(path)?.len() as isize - 1;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                budget -= 1;
                if budget < 0 {
                    bail!("archive member {path} links outside the tree: {target}");
                }
            }
            _ => budget += 1,
        }
    }
    Ok(())
}

/// Splits a member path, refusing anything that could leave the tree.
fn safe_parts(path: &str) -> Result<Vec<String>> {
    if path.starts_with('/') {
        bail!("archive member has an absolute path: {path}");
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => bail!("archive member climbs out of the tree: {path}"),
            other => parts.push(other.to_string()),
        }
    }
    Ok(parts)
}

/// Opens, creating as needed, every directory in `dirs` without following links.
fn ensure_dirs(root_fd: std::os::fd::RawFd, dirs: &[String]) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // Safety: dup gives an independent descriptor for the same directory.
    let dup = unsafe { libc::dup(root_fd) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: dup returned a fresh descriptor that is owned from here on.
    let mut current = unsafe { OwnedFd::from_raw_fd(dup) };
    for name in dirs {
        let name_c = std::ffi::CString::new(name.as_str())?;
        // Safety: mkdirat only reads its arguments.
        let rc = unsafe { libc::mkdirat(current.as_raw_fd(), name_c.as_ptr(), 0o755) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        // Safety: openat only reads its arguments; O_NOFOLLOW refuses a symlink
        // standing in for the directory.
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Safety: fd came from openat just above and is owned from here on.
        current = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(current)
}
