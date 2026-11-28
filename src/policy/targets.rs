//! Host paths the manager keeps out of manifests.

use super::walk::normalise;
use anyhow::{bail, Result};
use std::path::Path;

const SENSITIVE_TARGETS: [&str; 26] = [
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
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssl/private",
    "/etc/sysctl.conf",
    "/etc/timezone",
    "/home",
    "/proc",
    "/root",
    "/run",
    "/sys",
];

const LINK_PROTECTED_TARGETS: [&str; 12] = [
    "/boot",
    "/dev",
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

const PROTECTED_TARGETS: [&str; 32] = [
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

/// True when the operator accepts protected host paths for this import.
pub(crate) fn allow_protected_paths() -> bool {
    crate::util::env_flag("PORTALIS_ALLOW_PROTECTED_PATHS")
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
pub(super) fn is_protected_link_target(
    path: &str,
    store_path: Option<&Path>,
    target_root: &Path,
) -> bool {
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
pub(super) fn validate_sensitive_path(path: &str) -> Result<()> {
    let normalized = normalise(path);
    if RESERVED_TARGETS.iter().any(|reserved| {
        let reserved = reserved.trim_start_matches('/');
        normalized == reserved
    }) {
        bail!("manifest path is reserved for a host helper: {path}");
    }
    if !allow_protected_paths() && is_protected_path(path) {
        bail!("manifest path points at a host-sensitive path: {path}");
    }
    Ok(())
}
