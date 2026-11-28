//! Build sandbox arguments and the child setup that applies them.
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::util::env_flag;
use crate::util::limits::apply_limits;
use crate::util::sandbox::{read_only_view, sandbox_enabled, SandboxPolicy};

use super::trusted_program;

/// True when bwrap can be started as the build account on this host and write
/// to a directory owned by it, with the mounts a build needs.
pub(super) fn sandbox_can_drop_uid(uid: u32, gid: u32) -> bool {
    use std::os::unix::process::CommandExt;
    use std::sync::OnceLock;
    static CAN: OnceLock<bool> = OnceLock::new();
    *CAN.get_or_init(|| {
        let probe = match crate::archive::private_dir() {
            Ok(probe) => probe,
            Err(_) => return false,
        };
        if std::os::unix::fs::chown(&probe, Some(uid), Some(gid)).is_err() {
            let _ = std::fs::remove_dir_all(&probe);
            return false;
        }
        let mut args: Vec<String> = vec![
            "--unshare-user".into(),
            "--unshare-pid".into(),
            "--unshare-ipc".into(),
            "--unshare-net".into(),
            "--unshare-uts".into(),
            "--unshare-cgroup-try".into(),
            "--ro-bind".into(),
            "/usr".into(),
            "/usr".into(),
            "--ro-bind".into(),
            "/bin".into(),
            "/bin".into(),
            "--ro-bind".into(),
            "/lib".into(),
            "/lib".into(),
        ];
        if Path::new("/lib64").exists() {
            args.extend(
                ["--ro-bind", "/lib64", "/lib64"]
                    .iter()
                    .map(|v| v.to_string()),
            );
        }
        args.extend(
            ["--proc", "/proc", "--dev", "/dev"]
                .iter()
                .map(|v| v.to_string()),
        );
        for dir in ["root", "home"] {
            let dir = format!("/{dir}");
            if Path::new(&dir).exists() {
                args.push("--tmpfs".into());
                args.push(dir);
            }
        }
        if Path::new("/etc/shadow").exists() {
            args.extend(
                ["--ro-bind", "/dev/null", "/etc/shadow"]
                    .iter()
                    .map(|v| v.to_string()),
            );
        }
        args.push("--bind".into());
        args.push(probe.to_string_lossy().to_string());
        args.push("/probe".into());
        args.push("--chdir".into());
        args.push("/probe".into());
        args.push("--".into());
        args.push("/bin/sh".into());
        args.push("-c".into());
        args.push("touch ok".into());
        let Some(bwrap) = trusted_program("bwrap") else {
            return false;
        };
        let ok = Command::new(bwrap)
            .env_clear()
            .args(&args)
            .uid(uid)
            .gid(gid)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success() && probe.join("ok").exists())
            .unwrap_or(false);
        let _ = std::fs::remove_dir_all(&probe);
        ok
    })
}

/// Creates a workspace directory owned by the build account.
pub(super) fn prepare_workspace_dir(path: &Path, credentials: Option<(u32, u32)>) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("creating {}", path.display()));
        }
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("closing {}", path.display()))?;
    if let Some((uid, gid)) = credentials {
        // Safety: fchown only changes the owner of the opened directory.
        if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("handing {} to the build account", path.display()));
        }
    }
    Ok(())
}

/// Builds the seccomp filter for one offline step. Called before the fork.
pub(super) fn socket_filter() -> std::io::Result<Vec<libc::sock_filter>> {
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc00000b7;
    #[cfg(target_arch = "arm")]
    const AUDIT_ARCH: u32 = 0x40000028;
    #[cfg(target_arch = "x86")]
    const AUDIT_ARCH: u32 = 0x40000003;
    #[cfg(target_arch = "riscv64")]
    const AUDIT_ARCH: u32 = 0xc00000f3;
    #[cfg(target_arch = "loongarch64")]
    const AUDIT_ARCH: u32 = 0xc0000102;
    #[cfg(target_arch = "powerpc64")]
    const AUDIT_ARCH: u32 = 0xc0000015;
    #[cfg(target_arch = "s390x")]
    const AUDIT_ARCH: u32 = 0x80000016;
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )))]
    const AUDIT_ARCH: u32 = 0;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    #[cfg(target_arch = "x86")]
    const SYS_SOCKETCALL: u32 = 102;
    const AF_INET: u32 = libc::AF_INET as u32;
    const AF_INET6: u32 = libc::AF_INET6 as u32;
    const AF_NETLINK: u32 = libc::AF_NETLINK as u32;
    const AF_PACKET: u32 = libc::AF_PACKET as u32;
    const AF_VSOCK: u32 = libc::AF_VSOCK as u32;
    if AUDIT_ARCH == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "socket filtering is not implemented for this architecture",
        ));
    }

    fn ins(code: u32, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        }
    }

    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let jeq = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    let jset = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
    let ret = libc::BPF_RET | libc::BPF_K;

    let mut filter = vec![
        ins(load, 4),
        jump(jeq, 1, 0, AUDIT_ARCH),
        ins(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        ins(load, 0),
        jump(jset, 0, 1, X32_SYSCALL_BIT),
        ins(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ];
    // syscalls that can create a socket without entering SYS_socket
    #[cfg(target_arch = "x86")]
    let denied = vec![
        libc::SYS_io_uring_setup as u32,
        libc::SYS_io_uring_enter as u32,
        libc::SYS_io_uring_register as u32,
        SYS_SOCKETCALL,
    ];
    #[cfg(not(target_arch = "x86"))]
    let denied = vec![
        libc::SYS_io_uring_setup as u32,
        libc::SYS_io_uring_enter as u32,
        libc::SYS_io_uring_register as u32,
    ];
    for syscall in denied {
        filter.push(jump(jeq, 0, 1, syscall));
        filter.push(ins(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    let socket_jump = filter.len();
    filter.push(jump(jeq, 0, 0, libc::SYS_socket as u32));
    filter.push(ins(load, 16));
    for family in [AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_VSOCK] {
        filter.push(jump(jeq, 0, 1, family));
        filter.push(ins(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filter.push(ins(ret, libc::SECCOMP_RET_ALLOW));
    let allow = filter.len() - 1;
    filter[socket_jump].jf = (allow - socket_jump - 1) as u8;
    Ok(filter)
}

/// Blocks IPv4, IPv6, netlink, packet and vsock sockets in the calling process.
///
/// # Safety
///
/// Must run between fork and exec. `filter` was built before the fork and stays
/// alive in the child. The filter is installed for this process and its children
/// and cannot be removed afterwards.
fn install_socket_filter(filter: &mut [libc::sock_filter]) -> std::io::Result<()> {
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // Safety: both prctl calls configure this process only.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// True when every directory from `/` to `path` is readable and executable by
/// another account, and the final file is executable.
fn world_accessible(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.ancestors().all(|part| {
        std::fs::metadata(part)
            .map(|meta| {
                let mode = meta.permissions().mode();
                if meta.is_dir() {
                    mode & 0o005 == 0o005
                } else {
                    mode & 0o001 != 0
                }
            })
            .unwrap_or(false)
    })
}

/// Paths a Landlock-confined step may read: the toolchain view, selected host
/// files, the workspace, dependency stores and recipe-declared inputs.
fn readable_paths(
    policy: Option<&SandboxPolicy>,
    cwd: &Path,
    program: &str,
) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = read_only_view()
        .into_iter()
        .map(|(host, _)| std::path::PathBuf::from(host))
        .collect();
    for path in [
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
        "/dev/full",
        "/dev/tty",
        "/dev/fd",
        "/dev/shm",
        "/proc",
    ] {
        if std::path::Path::new(path).exists() {
            paths.push(std::path::PathBuf::from(path));
        }
    }
    paths.push(cwd.to_path_buf());
    // The build workspace and its source tree.
    for ancestor in cwd.ancestors() {
        if ancestor
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("build-"))
            .unwrap_or(false)
        {
            paths.push(ancestor.to_path_buf());
            break;
        }
    }
    // A toolchain resolved from PATH.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if program.contains('/') {
        candidates.push(std::path::PathBuf::from(program));
    } else {
        let search = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .unwrap_or_default();
        for directory in search {
            let candidate = directory.join(program);
            if candidate.exists() {
                candidates.push(candidate);
                break;
            }
        }
        if candidates.is_empty() {
            for directory in [
                "/usr/local/sbin",
                "/usr/local/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin",
            ] {
                let candidate = std::path::Path::new(directory).join(program);
                if candidate.exists() {
                    candidates.push(candidate);
                    break;
                }
            }
        }
    }
    for candidate in candidates {
        let Ok(canonical) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if !world_accessible(&canonical) {
            continue;
        }
        let Some(parent) = canonical.parent() else {
            continue;
        };
        paths.push(parent.to_path_buf());
        if let Some(root) = parent.parent() {
            paths.push(root.to_path_buf());
        }
    }
    if let Some(policy) = policy {
        for path in &policy.read {
            if std::path::Path::new(path).exists() {
                paths.push(std::path::PathBuf::from(path));
            }
        }
        if let Some(root) = &policy.root {
            if root.exists() {
                paths.push(root.clone());
            }
        }
        for (_, store) in &policy.deps {
            if store.exists() {
                paths.push(store.clone());
            }
        }
    }
    let store = crate::paths::Paths::new().store();
    if store.exists() {
        paths.push(store);
    }
    paths
}

/// Builds the Landlock ruleset for this step, if that is the active mechanism.
pub(super) fn landlock_ruleset(
    sandbox_required: bool,
    policy: Option<&SandboxPolicy>,
    confine_writes: Option<&[&Path]>,
    program: &str,
    cwd: &Path,
    log: &mut std::fs::File,
) -> Result<Option<crate::landlock::Ruleset>> {
    if sandbox_required && !sandbox_enabled() {
        if !crate::landlock::available() {
            bail!("neither bubblewrap nor landlock is available for build steps");
        }
        let writable: Vec<std::path::PathBuf> = match policy {
            Some(policy) if !policy.writable.is_empty() => policy
                .writable
                .iter()
                .map(std::path::PathBuf::from)
                .collect(),
            _ => vec![cwd.to_path_buf()],
        };
        let readable = readable_paths(policy, cwd, program);
        return Ok(Some(crate::landlock::Ruleset::for_build(
            &writable,
            &readable,
            policy.map(|p| p.network).unwrap_or(false),
        )?));
    }
    if let Some(roots) = confine_writes {
        if crate::landlock::available() {
            let owned: Vec<std::path::PathBuf> =
                roots.iter().map(|path| path.to_path_buf()).collect();
            let readable = readable_paths(policy, cwd, program);
            return Ok(Some(crate::landlock::Ruleset::for_build(
                &owned, &readable, false,
            )?));
        }
        writeln!(
            log,
            "sandbox  none: landlock is unavailable, writes are not confined"
        )?;
    }
    Ok(None)
}

/// bwrap arguments for one build step.
pub(super) fn sandbox_arguments(
    policy: Option<&SandboxPolicy>,
    cwd: &Path,
    effective_uid: Option<(u32, u32)>,
    log: &mut std::fs::File,
) -> Result<Vec<String>> {
    if env_flag("PORTALIS_WIDE_READ") {
        writeln!(
            log,
            "reads    limited: PORTALIS_WIDE_READ is ignored for build steps"
        )?;
    }
    let mut sandbox = namespace_arguments(policy);
    sandbox.extend(mount_arguments(policy));
    sandbox.extend(workspace_arguments(cwd, policy, effective_uid)?);
    Ok(sandbox)
}

fn namespace_arguments(policy: Option<&SandboxPolicy>) -> Vec<String> {
    let mut sandbox: Vec<String> = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup-try".into(),
    ];
    if !policy.map(|p| p.network).unwrap_or(false) {
        sandbox.push("--unshare-net".into());
    }
    sandbox
}

fn mount_arguments(policy: Option<&SandboxPolicy>) -> Vec<String> {
    let mut bind: Vec<String> = Vec::new();
    let build_root = policy.and_then(|policy| policy.root.as_deref());
    let store_path = crate::paths::Paths::new().store();
    let store = store_path.to_string_lossy().to_string();

    if let Some(root) = build_root {
        bind.push("--ro-bind".into());
        bind.push(root.to_string_lossy().to_string());
        bind.push("/".into());
        // Host files are mounted over a temporary etc.
        bind.push("--tmpfs".into());
        bind.push("/etc".into());
        bind.push("--tmpfs".into());
        bind.push("/usr/portalis".into());
        bind.push("--tmpfs".into());
        bind.push("/var".into());
    }
    for (host, inside) in read_only_view() {
        // Mounts /bin, /sbin and /usr from the host.
        if build_root.is_some() && matches!(host.as_str(), "/bin" | "/sbin" | "/usr") {
            continue;
        }
        bind.push("--ro-bind".into());
        bind.push(host);
        bind.push(inside);
    }
    if build_root.is_some() {
        for path in [
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib32",
            "/usr/lib64",
            "/usr/libexec",
            "/usr/include",
            "/usr/share",
            "/usr/local",
        ] {
            if std::path::Path::new(path).exists() {
                bind.push("--ro-bind".into());
                bind.push(path.into());
                bind.push(path.into());
            }
        }
    }
    if let Some(policy) = policy {
        if !policy.deps.is_empty() {
            bind.push("--tmpfs".into());
            bind.push("/deps".into());
            for (name, store) in &policy.deps {
                bind.push("--ro-bind".into());
                bind.push(store.to_string_lossy().into_owned());
                bind.push(format!("/deps/{name}"));
            }
        }
        for path in &policy.read {
            if std::path::Path::new(path).exists() {
                bind.push("--ro-bind".into());
                bind.push(path.clone());
                bind.push(path.clone());
            }
        }
    }

    for value in [
        "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/dev/shm",
    ] {
        bind.push(value.into());
    }
    if build_root.is_some() && std::path::Path::new(&store).exists() {
        bind.push("--ro-bind".into());
        bind.push(store.clone());
        bind.push(crate::paths::STORE_PATH.into());
        if store != crate::paths::STORE_PATH {
            bind.push("--ro-bind".into());
            bind.push(store.clone());
            bind.push(store.clone());
        }
    }
    if build_root.is_none() && std::path::Path::new(&store).exists() {
        bind.push("--ro-bind".into());
        bind.push(store.clone());
        bind.push(store.clone());
    }
    if std::path::Path::new(crate::paths::ETC_DIR).exists() {
        bind.push("--tmpfs".into());
        bind.push(crate::paths::ETC_DIR.into());
    }
    if build_root.is_none() {
        for hidden in ["root", "home", "var/lib/portalis"] {
            let hidden = format!("/{hidden}");
            if std::path::Path::new(&hidden).exists() {
                bind.push("--tmpfs".into());
                bind.push(hidden);
            }
        }
    }
    for secret in ["/etc/shadow", "/etc/gshadow"] {
        if std::path::Path::new(secret).exists() {
            bind.push("--ro-bind".into());
            bind.push("/dev/null".into());
            bind.push(secret.into());
        }
    }
    bind
}

fn workspace_arguments(
    cwd: &Path,
    policy: Option<&SandboxPolicy>,
    effective_uid: Option<(u32, u32)>,
) -> Result<Vec<String>> {
    let cwd_text = cwd.to_string_lossy().to_string();
    let mut sandbox = vec![
        "--bind".to_string(),
        cwd_text.clone(),
        cwd_text.clone(),
        "--chdir".to_string(),
        cwd_text,
    ];
    if let Some(policy) = policy {
        for path in &policy.writable {
            sandbox.push("--bind".into());
            sandbox.push(path.clone());
            sandbox.push(path.clone());
        }
    }
    let tmp = cwd.join(".tmp");
    prepare_workspace_dir(&tmp, effective_uid)?;
    sandbox.push("--setenv".into());
    sandbox.push("TMPDIR".into());
    sandbox.push(tmp.to_string_lossy().to_string());
    let home = cwd.join(".home");
    prepare_workspace_dir(&home, effective_uid)?;
    sandbox.push("--setenv".into());
    sandbox.push("HOME".into());
    sandbox.push(home.to_string_lossy().to_string());
    sandbox.push("--".into());
    Ok(sandbox)
}

/// The work a child does between fork and exec: limits, credentials, Landlock,
/// and the socket filter for offline steps.
pub(super) fn sandbox_child_setup(
    credentials: Option<(u32, u32)>,
    landlock_fd: Option<i32>,
    socket_filter: Option<Vec<libc::sock_filter>>,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    let mut socket_filter = socket_filter;
    move || {
        // Safety: called between fork and exec; the calls only touch this child.
        // The socket filter was built before the fork and is only read here.
        unsafe {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            apply_limits()?;
            if let Some((uid, gid)) = credentials {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(fd) = landlock_fd {
                crate::landlock::restrict(fd)?;
            }
            if let Some(filter) = socket_filter.as_mut() {
                install_socket_filter(filter)?;
            }
            Ok(())
        }
    }
}
