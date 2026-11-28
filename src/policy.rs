//! Static checks applied to a built package before it is activated.
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use crate::build::BuildOutcome;
use crate::recipe::Recipe;

const SENSITIVE_TARGETS: [&str; 23] = [
    "/dev",
    "/etc/fstab",
    "/etc/gshadow",
    "/etc/group",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/machine-id",
    "/etc/nsswitch.conf",
    "/etc/os-release",
    "/etc/resolv.conf",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/ld.so.preload",
    "/etc/ssh",
    "/etc/ssl/private",
    "/etc/sysctl.conf",
    "/etc/timezone",
    "/home",
    "/proc",
    "/root",
    "/run",
    "/sys",
];

const LINK_PROTECTED_TARGETS: [&str; 13] = [
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/tmp",
    "/var",
    "/usr/lib/portalis",
    "/usr/lib/systemd",
    "/lib/systemd",
];

const RESERVED_TARGETS: [&str; 25] = [
    "/usr/bin/bwrap",
    "/bin/bwrap",
    "/usr/bin/ldconfig",
    "/usr/sbin/ldconfig",
    "/sbin/ldconfig",
    "/usr/bin/tar",
    "/bin/tar",
    "/usr/bin/patch",
    "/usr/bin/make",
    "/usr/bin/gzip",
    "/usr/bin/xz",
    "/usr/bin/zstd",
    "/usr/bin/bzip2",
    "/usr/bin/uname",
    "/usr/bin/ldd",
    "/usr/bin/cc",
    "/usr/bin/c++",
    "/usr/bin/rustc",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/chroot",
    "/usr/bin/systemctl",
    "/usr/bin/gtk-update-icon-cache",
    "/usr/sbin/mount",
    "/usr/sbin/umount",
];

const PROTECTED_TARGETS: [&str; 33] = [
    "/etc/portalis",
    "/etc/sudoers.d",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/crontab",
    "/etc/udev",
    "/etc/logrotate.d",
    "/etc/modprobe.d",
    "/etc/polkit-1",
    "/etc/bashrc",
    "/etc/profile.d",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/systemd/system",
    "/etc/pam.d",
    "/etc/security",
    "/etc/init.d",
    "/etc/rc.local",
    "/var/lib/portalis",
    "/var/db/portalis",
    "/var/log/portalis",
    "/usr/portalis",
    "/usr/lib/portalis",
    "/usr/lib/systemd",
    "/lib/systemd",
    "/usr/bin/moirse",
    "/usr/bin/portalis",
];

/// Validates a manifest against the root it will be installed into.
#[cfg(test)]
pub fn validate(recipe: &Recipe, outcome: &BuildOutcome) -> Result<()> {
    validate_at(recipe, outcome, Path::new("/"))
}

/// Validates a manifest against the live root it will be installed into.
pub fn validate_at(recipe: &Recipe, outcome: &BuildOutcome, target_root: &Path) -> Result<()> {
    for file in &outcome.manifest.files {
        validate_path(&file.path)?;
        validate_sensitive_path(&file.path)?;
        validate_privileged(recipe, file)?;
        if let Some(target) = &file.link {
            validate_link(&file.path, target, target_root, &outcome.store_path)?;
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if path.chars().any(char::is_control) {
        bail!("manifest path holds a control character: {path:?}");
    }
    let parsed = Path::new(path);
    if !parsed.is_absolute() {
        bail!("manifest path is not absolute: {path}");
    }
    for component in parsed.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                if name.is_empty() {
                    bail!("manifest path has an empty component: {path}");
                }
            }
            _ => bail!("manifest path has an invalid component: {path}"),
        }
    }
    Ok(())
}

/// True when a live path is reserved for the manager or a root helper.
pub(crate) fn is_protected_path(path: &str) -> bool {
    let path = normalise(path);
    SENSITIVE_TARGETS
        .iter()
        .chain(PROTECTED_TARGETS.iter())
        .chain(RESERVED_TARGETS.iter())
        .any(|sensitive| {
            let sensitive = sensitive.trim_start_matches('/');
            path == sensitive || path.starts_with(&format!("{sensitive}/"))
        })
}

/// True when a live link target names a protected host location.
fn is_protected_link_target(path: &str, store_path: Option<&Path>, target_root: &Path) -> bool {
    if target_root != Path::new("/") && Path::new(path).starts_with(target_root) {
        return false;
    }
    if let Some(store_path) = store_path {
        if Path::new(path).starts_with(store_path) {
            return false;
        }
    }
    let path = normalise(path);
    LINK_PROTECTED_TARGETS.iter().any(|target| {
        let target = target.trim_start_matches('/');
        path == target || path.starts_with(&format!("{target}/"))
    })
}

/// Rejects manifest paths that land on host-sensitive locations.
fn validate_sensitive_path(path: &str) -> Result<()> {
    let normalized = normalise(path);
    if RESERVED_TARGETS.iter().any(|reserved| {
        let reserved = reserved.trim_start_matches('/');
        normalized == reserved
    }) {
        bail!("manifest path is reserved for a host helper: {path}");
    }
    if is_protected_path(path) {
        bail!("manifest path points at a host-sensitive path: {path}");
    }
    Ok(())
}

fn validate_privileged(recipe: &Recipe, file: &crate::recipe::ManifestFile) -> Result<()> {
    let path = normalise(&file.path);
    if file.mode & 0o4000 != 0
        && !recipe
            .install
            .setuid
            .iter()
            .any(|entry| normalise(entry) == path)
    {
        bail!("manifest keeps setuid on an undeclared path: {path}");
    }
    if file.mode & 0o2000 != 0
        && !recipe
            .install
            .setgid
            .iter()
            .any(|entry| normalise(entry.split(':').next().unwrap_or_default()) == path)
    {
        bail!("manifest keeps setgid on an undeclared path: {path}");
    }
    Ok(())
}

#[derive(Debug)]
enum LinkPart {
    Normal(OsString),
    Parent,
}

struct LinkFrame {
    name: OsString,
    dir: Option<OwnedFd>,
}

fn link_parts(path: &Path) -> Result<VecDeque<LinkPart>> {
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

fn trusted_directory(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        bail!(
            "link target passes through a directory writable by another account: {}",
            path.display()
        );
    }
    Ok(())
}

fn trusted_final(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        bail!(
            "link target is writable by another account: {}",
            path.display()
        );
    }
    Ok(())
}

/// Checks a link target against the live root and the package store.
pub(crate) fn validate_link_target(
    target_root: &Path,
    live_path: &str,
    target: &str,
    store_path: Option<&Path>,
) -> Result<()> {
    if target.is_empty() || target.chars().any(char::is_control) {
        bail!("link target is empty or holds a control character: {target:?}");
    }
    let target_path = Path::new(target);
    let target_root = std::fs::canonicalize(target_root)
        .with_context(|| format!("resolving {}", target_root.display()))?;
    let absolute = target_path.is_absolute();
    let under_target_root = absolute && target_path.starts_with(&target_root);
    let (mut root, mut root_fd) = if absolute && !under_target_root {
        (PathBuf::from("/"), open_directory(Path::new("/"))?)
    } else {
        let fd = open_directory(&target_root)?;
        (target_root.clone(), fd)
    };
    let mut root_is_absolute = root == Path::new("/");
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

    let store =
        store_path.map(|path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
    let store_root = store
        .as_ref()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let initial = lexical_link_path(&root, &pending, root_is_absolute)?;
    let mut require_own_store = false;
    if let (Some(store), Some(store_root)) = (&store, &store_root) {
        if initial.starts_with(store_root) && !initial.starts_with(store) {
            bail!(
                "link target points into another package's store: {}",
                initial.display()
            );
        }
        require_own_store = initial.starts_with(store);
    }

    let mut frames: Vec<LinkFrame> = Vec::new();
    let mut expansions = 0usize;
    while let Some(part) = pending.pop_front() {
        match part {
            LinkPart::Parent => {
                if frames.pop().is_none() && !root_is_absolute {
                    bail!("link target climbs out of {}", root.display());
                }
            }
            LinkPart::Normal(name) => {
                let name_c = CString::new(name.as_bytes())?;
                let Some(dir) = current_fd(root_fd.as_raw_fd(), &frames) else {
                    frames.push(LinkFrame { name, dir: None });
                    continue;
                };
                let stat = match stat_at(dir, &name_c) {
                    Ok(stat) => stat,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        frames.push(LinkFrame { name, dir: None });
                        continue;
                    }
                    Err(error) => return Err(error).with_context(|| "reading a link component"),
                };
                let path = frame_path(&root, &frames, &name);
                if is_symlink(&stat) {
                    if stat.st_uid != 0 {
                        bail!(
                            "link target passes through a link not owned by root: {}",
                            path.display()
                        );
                    }
                    expansions += 1;
                    if expansions > 40 {
                        bail!("link target expands through more than 40 links");
                    }
                    let next = read_link_at(dir, &name_c)?;
                    if next.as_os_str().is_empty() {
                        bail!("link target contains an empty link: {}", path.display());
                    }
                    let next_absolute = next.is_absolute();
                    let next_parts = link_parts(&next)?;
                    if next_absolute {
                        root = PathBuf::from("/");
                        root_fd = open_directory(&root)?;
                        let meta = stat_fd(root_fd.as_raw_fd())?;
                        trusted_directory(&meta, &root)?;
                        frames.clear();
                        root_is_absolute = true;
                    }
                    for next in next_parts.into_iter().rev() {
                        pending.push_front(next);
                    }
                } else if is_directory(&stat) {
                    trusted_directory(&stat, &path)?;
                    let next_dir = open_directory_at(dir, &name_c)?;
                    frames.push(LinkFrame {
                        name,
                        dir: Some(next_dir),
                    });
                } else {
                    if !pending.is_empty() {
                        bail!(
                            "link target passes through a non-directory: {}",
                            path.display()
                        );
                    }
                    trusted_final(&stat, &path)?;
                    frames.push(LinkFrame { name, dir: None });
                }
            }
        }
    }

    let resolved = resolved_path(&root, &frames);
    if resolved == Path::new("/") {
        bail!("link target points at the live root");
    }
    if is_protected_link_target(&resolved.to_string_lossy(), store.as_deref(), &target_root) {
        bail!(
            "link target points at a protected host path: {}",
            resolved.display()
        );
    }
    if let (Some(store), Some(store_root)) = (&store, &store_root) {
        if resolved.starts_with(store_root) && !resolved.starts_with(store) {
            bail!(
                "link target points into another package's store: {}",
                resolved.display()
            );
        }
        if require_own_store && !resolved.starts_with(store) {
            bail!(
                "link target leaves its package store: {}",
                resolved.display()
            );
        }
    }
    Ok(())
}

fn validate_link(path: &str, target: &str, target_root: &Path, store_path: &Path) -> Result<()> {
    let raw_target = target;
    if target.is_empty() || target.chars().any(char::is_control) {
        bail!("manifest link has an invalid target: {path} -> {target:?}");
    }
    let parsed = Path::new(target);
    let resolved = if parsed.is_absolute() {
        absolute_target(target)
    } else {
        let parent = Path::new(path).parent().unwrap_or(Path::new("/"));
        absolute_target(&format!("{}/{}", parent.display(), target))
    };
    let Some(target) = resolved else {
        bail!("manifest link climbs out of the live root: {path} -> {target}");
    };
    if target == "/" {
        bail!("manifest link points at the live root: {path}");
    }
    if is_protected_path(&target)
        && !store_path
            .parent()
            .map(|root| Path::new(&target).starts_with(root))
            .unwrap_or(false)
    {
        bail!("manifest link points at a host-sensitive path: {path} -> {target}");
    }
    if is_protected_link_target(&target, Some(store_path), target_root) {
        bail!("manifest link points at a protected host path: {path} -> {target}");
    }
    validate_link_target(target_root, path, raw_target, Some(store_path))?;
    Ok(())
}

fn absolute_target(target: &str) -> Option<String> {
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

fn normalise(path: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{BuildManifest, ManifestFile};

    fn recipe(extra: &str) -> Recipe {
        let text = format!(
            "package.name = p\npackage.version = 1\nsource.file = p.tar\nsource.sha256 = {}\nbuild.system = custom\ninstall.prefix = /usr\n{extra}",
            "0".repeat(64)
        );
        Recipe::parse(&text).expect("recipe")
    }

    fn outcome(file: ManifestFile) -> BuildOutcome {
        BuildOutcome {
            store_path: "/usr/portalis/packages/p-1-deadbeef".into(),
            manifest: BuildManifest {
                patches: Vec::new(),
                name: "p".into(),
                version: "1".into(),
                recipe_sha256: "0".repeat(64),
                source_sha256: "0".repeat(64),
                cflags: String::new(),
                rustflags: String::new(),
                rpath: Vec::new(),
                network: false,
                writable: Vec::new(),
                read: Vec::new(),
                confinement: "bubblewrap".into(),
                check_command: None,
                check_timeout: None,
                check_required: None,
                files: vec![file],
                dirs: Vec::new(),
            },
            log_path: "/tmp/build.log".into(),
        }
    }

    fn file(path: &str) -> ManifestFile {
        ManifestFile {
            path: path.into(),
            sha256: "0".repeat(64),
            mode: 0o644,
            link: None,
        }
    }

    #[test]
    fn a_regular_manifest_passes() {
        validate(&recipe(""), &outcome(file("/usr/share/p/file"))).expect("valid");
    }

    #[test]
    fn a_sensitive_regular_path_is_refused() {
        let error = validate(&recipe(""), &outcome(file("/etc/ld.so.preload")))
            .expect_err("sensitive path accepted");
        assert!(format!("{error}").contains("host-sensitive"));
    }

    #[test]
    fn a_manager_owned_path_is_refused() {
        let error = validate(
            &recipe(""),
            &outcome(file("/etc/portalis/trusted-keys/attacker")),
        )
        .expect_err("manager path accepted");
        assert!(format!("{error}").contains("host-sensitive"));
    }

    #[test]
    fn a_reserved_helper_path_is_refused() {
        let error = validate(&recipe(""), &outcome(file("/usr/bin/bwrap")))
            .expect_err("reserved path accepted");
        assert!(format!("{error}").contains("reserved"));
    }

    #[test]
    fn a_relative_link_that_stays_inside_passes() {
        let mut entry = file("/usr/bin/tool");
        entry.link = Some("../lib/p/tool".into());
        validate(&recipe(""), &outcome(entry)).expect("relative link");
    }

    #[test]
    fn an_undeclared_setuid_file_is_refused() {
        let mut entry = file("/usr/bin/p");
        entry.mode = 0o4755;
        let error = validate(&recipe(""), &outcome(entry)).expect_err("setuid accepted");
        assert!(format!("{error}").contains("setuid"));
    }

    #[test]
    fn a_declared_setgid_file_passes() {
        let mut entry = file("/usr/bin/p");
        entry.mode = 0o2755;
        validate(&recipe("install.setgid = usr/bin/p:5\n"), &outcome(entry))
            .expect("declared setgid");
    }

    #[test]
    fn a_link_to_a_host_sensitive_path_is_refused() {
        let mut entry = file("/usr/share/p/link");
        entry.link = Some("/etc/shadow".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("sensitive link accepted");
        assert!(format!("{error}").contains("host-sensitive"));
    }

    #[test]
    fn a_link_to_a_host_configuration_path_is_refused() {
        let mut entry = file("/usr/share/p/link");
        entry.link = Some("/etc/hosts".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("host config link accepted");
        assert!(
            format!("{error}").contains("protected host path")
                || format!("{error}").contains("host-sensitive"),
            "{error:#}"
        );
    }

    #[test]
    fn the_package_store_is_not_a_protected_link_target() {
        let store = Path::new("/usr/portalis/packages/p-1-deadbeef");
        assert!(!is_protected_link_target(
            "/usr/portalis/packages/p-1-deadbeef/usr/lib/p",
            Some(store),
            Path::new("/"),
        ));
        assert!(is_protected_link_target("/etc/hosts", None, Path::new("/")));
        assert!(!is_protected_link_target(
            "/usr/lib/libc.so.6",
            None,
            Path::new("/")
        ));
    }

    #[test]
    fn a_link_with_a_dot_prefix_is_still_refused() {
        let mut entry = file("/usr/share/p/link");
        entry.link = Some("/./etc/shadow".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("sensitive link accepted");
        assert!(format!("{error}").contains("host-sensitive"));
    }

    #[test]
    fn a_link_to_the_live_root_is_refused() {
        let mut entry = file("/usr/share/p/link");
        entry.link = Some("/".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("root link accepted");
        assert!(format!("{error}").contains("live root"));
    }

    #[test]
    fn a_normal_absolute_link_passes() {
        let mut entry = file("/usr/bin/p");
        entry.link = Some("/usr/lib/p/p".into());
        validate(&recipe(""), &outcome(entry)).expect("normal link");
    }

    #[test]
    fn a_link_to_a_shared_temporary_directory_is_refused() {
        let mut entry = file("/usr/bin/p");
        entry.link = Some("/tmp/evil".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("temporary link accepted");
        assert!(
            format!("{error}").contains("protected host path")
                || format!("{error}").contains("writable")
                || format!("{error}").contains("link target"),
            "{error:#}"
        );
    }

    #[test]
    fn a_relative_link_into_a_shared_directory_is_refused() {
        let mut entry = file("/usr/bin/p");
        entry.link = Some("../../tmp/evil".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("temporary link accepted");
        assert!(
            format!("{error}").contains("protected host path")
                || format!("{error}").contains("writable")
                || format!("{error}").contains("link target"),
            "{error:#}"
        );
    }

    #[test]
    fn a_link_to_another_store_is_refused() {
        let mut entry = file("/usr/bin/p");
        entry.link = Some("/usr/portalis/packages/other-1.0/usr/lib/p".into());
        let error = validate(&recipe(""), &outcome(entry)).expect_err("other store accepted");
        assert!(format!("{error}").contains("store"), "{error:#}");
    }

    #[test]
    fn a_link_inside_this_store_is_allowed() {
        let mut entry = file("/usr/bin/p");
        entry.link = Some("/usr/portalis/packages/p-1-deadbeef/usr/lib/p".into());
        validate(&recipe(""), &outcome(entry)).expect("own store link");
    }

    #[test]
    fn a_climbing_manifest_path_is_refused() {
        let error = validate(&recipe(""), &outcome(file("/usr/../etc/shadow")))
            .expect_err("climbing path accepted");
        assert!(format!("{error}").contains("invalid component"));
    }
}
