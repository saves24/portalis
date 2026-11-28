//! Walking a link target one component at a time, without following anything
//! outside the root.

use super::targets::{allow_protected_paths, is_protected_link_target};
use super::trust::{
    check_component_trust, check_store_boundary, trusted_directory, ComponentTrust,
};
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub(super) enum LinkPart {
    Normal(OsString),
    Parent,
}

struct LinkFrame {
    name: OsString,
    dir: Option<OwnedFd>,
}

pub(super) fn link_parts(path: &Path) -> Result<VecDeque<LinkPart>> {
    let mut parts = VecDeque::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push_back(LinkPart::Normal(name.to_os_string())),
            Component::ParentDir => parts.push_back(LinkPart::Parent),
            Component::CurDir | Component::RootDir => {}
            Component::Prefix(_) => {
                bail!(
                    "link target has an unsupported component: {}",
                    path.display()
                )
            }
        }
    }
    Ok(parts)
}

fn lexical_link_path(root: &Path, parts: &VecDeque<LinkPart>, absolute: bool) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for part in parts {
        match part {
            LinkPart::Normal(name) => path.push(name),
            LinkPart::Parent => {
                if path == root {
                    if !absolute {
                        bail!("link target climbs out of {}", root.display());
                    }
                } else {
                    path.pop();
                }
            }
        }
    }
    Ok(path)
}

fn current_fd(root: RawFd, frames: &[LinkFrame]) -> Option<RawFd> {
    match frames.last() {
        Some(frame) => frame.dir.as_ref().map(AsRawFd::as_raw_fd),
        None => Some(root),
    }
}

fn frame_path(root: &Path, frames: &[LinkFrame], name: &OsString) -> PathBuf {
    let mut path = root.to_path_buf();
    for frame in frames {
        path.push(&frame.name);
    }
    path.push(name);
    path
}

fn resolved_path(root: &Path, frames: &[LinkFrame]) -> PathBuf {
    let mut path = root.to_path_buf();
    for frame in frames {
        path.push(&frame.name);
    }
    path
}

fn open_directory(path: &Path) -> Result<OwnedFd> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    // Safety: open only reads the NUL-terminated path.
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening {}", path.display()));
    }
    // Safety: fd was just returned and is owned by this value.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_directory_at(dir: RawFd, name: &CString) -> Result<OwnedFd> {
    // Safety: openat only reads the descriptor and the name.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| "opening a link component");
    }
    // Safety: fd was just returned and is owned by this value.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    // Safety: fstat writes only into this initialized structure.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

fn stat_at(dir: RawFd, name: &CString) -> io::Result<libc::stat> {
    // Safety: fstatat writes only into this initialized structure.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

fn read_link_at(dir: RawFd, name: &CString) -> Result<PathBuf> {
    let mut buffer = vec![0u8; 4096];
    // Safety: readlinkat writes at most buffer.len() bytes into the buffer.
    let length = unsafe {
        libc::readlinkat(
            dir,
            name.as_ptr(),
            buffer.as_mut_ptr() as *mut libc::c_char,
            buffer.len(),
        )
    };
    if length < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| "reading a link component");
    }
    let length = length as usize;
    if length == buffer.len() {
        bail!("link target is too long to inspect");
    }
    Ok(PathBuf::from(OsString::from_vec(buffer[..length].to_vec())))
}

fn is_symlink(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

fn is_directory(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

pub(super) fn absolute_target(target: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in Path::new(target).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => parts.push(name.to_string_lossy()),
            Component::ParentDir => {
                parts.pop()?;
            }
            _ => return None,
        }
    }
    Some(format!("/{}", parts.join("/")))
}

pub(super) fn normalise(path: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => parts.push(name.to_string_lossy().to_string()),
            Component::ParentDir => {
                parts.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    parts.join("/")
}

/// The state of one link-target walk.
pub(super) struct LinkWalk {
    root: PathBuf,
    root_fd: OwnedFd,
    root_is_absolute: bool,
    frames: Vec<LinkFrame>,
    pending: VecDeque<LinkPart>,
    expansions: usize,
}

impl LinkWalk {
    /// The path the remaining components name, before any link is followed.
    pub(super) fn lexical_target(&self) -> Result<PathBuf> {
        lexical_link_path(&self.root, &self.pending, self.root_is_absolute)
    }
}

pub(super) fn resolve_target_root(
    target_root: &Path,
    target_path: &Path,
    live_path: &str,
) -> Result<LinkWalk> {
    let target_root = std::fs::canonicalize(target_root)
        .with_context(|| format!("resolving {}", target_root.display()))?;
    let absolute = target_path.is_absolute();
    let under_target_root = absolute && target_path.starts_with(&target_root);
    let (root, root_fd) = if absolute && !under_target_root {
        (PathBuf::from("/"), open_directory(Path::new("/"))?)
    } else {
        let fd = open_directory(&target_root)?;
        (target_root.clone(), fd)
    };
    let root_is_absolute = root == Path::new("/");
    let root_meta = stat_fd(root_fd.as_raw_fd())?;
    trusted_directory(&root_meta, &root)?;

    let mut pending = VecDeque::new();
    if absolute {
        let parts_path = if under_target_root {
            target_path
                .strip_prefix(&target_root)
                .unwrap_or(target_path)
        } else {
            target_path
        };
        pending.extend(link_parts(parts_path)?);
    } else {
        let live = if Path::new(live_path).is_absolute() {
            PathBuf::from(live_path)
        } else {
            target_root.join(live_path)
        };
        let live_parent = live.parent().unwrap_or(Path::new("/"));
        for component in live_parent.components() {
            match component {
                Component::Normal(name) => pending.push_back(LinkPart::Normal(name.to_os_string())),
                Component::CurDir | Component::RootDir => {}
                Component::ParentDir => bail!("live path climbs out of its root: {live_path}"),
                Component::Prefix(_) => {
                    bail!("live path has an unsupported component: {live_path}")
                }
            }
        }
        pending.extend(link_parts(target_path)?);
    }

    Ok(LinkWalk {
        root,
        root_fd,
        root_is_absolute,
        frames: Vec::new(),
        pending,
        expansions: 0,
    })
}

pub(super) fn walk_target_components(walk: &mut LinkWalk) -> Result<()> {
    while let Some(part) = walk.pending.pop_front() {
        match part {
            LinkPart::Parent => {
                if walk.frames.pop().is_none() && !walk.root_is_absolute {
                    bail!("link target climbs out of {}", walk.root.display());
                }
            }
            LinkPart::Normal(name) => {
                let name_c = CString::new(name.as_bytes())?;
                let Some(dir) = current_fd(walk.root_fd.as_raw_fd(), &walk.frames) else {
                    walk.frames.push(LinkFrame { name, dir: None });
                    continue;
                };
                let stat = match stat_at(dir, &name_c) {
                    Ok(stat) => stat,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        walk.frames.push(LinkFrame { name, dir: None });
                        continue;
                    }
                    Err(error) => return Err(error).with_context(|| "reading a link component"),
                };
                let path = frame_path(&walk.root, &walk.frames, &name);
                if is_symlink(&stat) {
                    check_component_trust(ComponentTrust::Link, &stat, &path)?;
                    expand_symlink_frames(walk, dir, &name_c, &path)?;
                } else if is_directory(&stat) {
                    check_component_trust(ComponentTrust::Directory, &stat, &path)?;
                    let next_dir = open_directory_at(dir, &name_c)?;
                    walk.frames.push(LinkFrame {
                        name,
                        dir: Some(next_dir),
                    });
                } else {
                    if !walk.pending.is_empty() {
                        bail!(
                            "link target passes through a non-directory: {}",
                            path.display()
                        );
                    }
                    check_component_trust(ComponentTrust::Final, &stat, &path)?;
                    walk.frames.push(LinkFrame { name, dir: None });
                }
            }
        }
    }
    Ok(())
}

fn expand_symlink_frames(
    walk: &mut LinkWalk,
    dir: RawFd,
    name_c: &CString,
    path: &Path,
) -> Result<()> {
    walk.expansions += 1;
    if walk.expansions > 40 {
        bail!("link target expands through more than 40 links");
    }
    let next = read_link_at(dir, name_c)?;
    if next.as_os_str().is_empty() {
        bail!("link target contains an empty link: {}", path.display());
    }
    let next_absolute = next.is_absolute();
    let next_parts = link_parts(&next)?;
    if next_absolute {
        walk.root = PathBuf::from("/");
        walk.root_fd = open_directory(&walk.root)?;
        let meta = stat_fd(walk.root_fd.as_raw_fd())?;
        trusted_directory(&meta, &walk.root)?;
        walk.frames.clear();
        walk.root_is_absolute = true;
    }
    for next in next_parts.into_iter().rev() {
        walk.pending.push_front(next);
    }
    Ok(())
}

pub(super) fn finish_target_validation(
    walk: &LinkWalk,
    target_root: &Path,
    store: Option<&Path>,
    store_root: Option<&Path>,
    require_own_store: bool,
) -> Result<()> {
    let resolved = resolved_path(&walk.root, &walk.frames);
    if resolved == Path::new("/") {
        bail!("link target points at the live root");
    }
    if !allow_protected_paths()
        && is_protected_link_target(&resolved.to_string_lossy(), store, target_root)
    {
        bail!(
            "link target points at a protected host path: {}",
            resolved.display()
        );
    }
    check_store_boundary(&resolved, store, store_root, require_own_store)?;
    Ok(())
}
