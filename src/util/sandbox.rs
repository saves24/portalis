//! What a build step may touch, and which kernel mechanism enforces it.
use std::process::{Command, Stdio};

use super::env_flag;

/// Sandbox relaxations declared by the recipe for the current build.
#[derive(Clone, Default)]
pub struct SandboxPolicy {
    pub network: bool,
    pub writable: Vec<String>,
    /// Extra host paths a build may read on top of the fixed toolchain view.
    pub read: Vec<String>,
    /// Static root the build starts from, when one is embedded.
    pub root: Option<std::path::PathBuf>,
    /// Dependency stores mounted read-only at /deps/<name>.
    pub deps: Vec<(String, std::path::PathBuf)>,
}

/// Read-only view a build gets: toolchain and loader files. Missing paths skip.
pub(super) fn read_only_view() -> Vec<(String, String)> {
    const TREES: [&str; 7] = [
        "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
    ];
    const ETC: [&str; 14] = [
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/ssl/certs",
        "/etc/ssl/openssl.cnf",
        "/etc/ssl/cert.pem",
        "/etc/ca-certificates",
        "/etc/alternatives",
        "/etc/localtime",
    ];
    let mut view: Vec<(String, String)> = Vec::new();
    for path in TREES.iter().chain(ETC.iter()) {
        if std::path::Path::new(path).exists() {
            view.push((path.to_string(), path.to_string()));
        }
    }
    view
}

/// True when a step that must stay offline can still reach the network.
///
/// Landlock handles the file system; this path also installs a socket filter
/// that blocks INET and INET6 sockets.
pub(super) fn network_left_open(network_allowed: bool, confinement: &str) -> bool {
    if network_allowed {
        return false;
    }
    !matches!(confinement, "bubblewrap" | "landlock")
}

/// The confinement build steps run under on this host.
pub fn build_confinement() -> &'static str {
    if sandbox_enabled() {
        "bubblewrap"
    } else if crate::landlock::available() {
        "landlock"
    } else {
        "none"
    }
}

/// True when build steps are expected to run under bubblewrap.
pub fn sandbox_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        if env_flag("PORTALIS_NO_BWRAP") {
            return false;
        }
        // Runs a trivial sandbox to verify bwrap works.
        let Some(bwrap) = crate::util::trusted_program("bwrap") else {
            return false;
        };
        Command::new(bwrap)
            .env_clear()
            .args([
                "--unshare-user",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-net",
                "--unshare-uts",
                "--unshare-cgroup-try",
                "--ro-bind",
                "/",
                "/",
                "--",
                "/bin/true",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    })
}
