//! Restricting a build with Landlock, for machines that have no bubblewrap.
//!
//! A ruleset grants read access beneath the toolchain view and write access
//! beneath the workspace. It carries no mount namespace.

use anyhow::{bail, Result};
use std::os::fd::RawFd;
use std::path::Path;

const LANDLOCK_CREATE_RULESET_VERSION: i32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

const PR_SET_NO_NEW_PRIVS: i32 = 38;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct RulesetAttrBeforeScoped {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The Landlock ABI version, or `None` when the kernel does not offer it.
pub fn abi_version() -> Option<i32> {
    // Safety: the call only reads the request flags.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version < 0 {
        None
    } else {
        Some(version as i32)
    }
}

/// A ruleset that grants write access below `writable` and nothing else. It is
/// created before the fork; the child only has to apply it.
pub struct Ruleset {
    fd: RawFd,
}

impl Ruleset {
    /// Builds a ruleset with write access beneath `writable` and read access
    /// beneath `readable`. `allow_network` leaves network access unrestricted.
    pub fn for_build(
        writable: &[std::path::PathBuf],
        readable: &[std::path::PathBuf],
        allow_network: bool,
    ) -> Result<Self> {
        let abi = abi_version().ok_or_else(|| anyhow::anyhow!("landlock is not available"))?;

        let mut handled_access_fs = ACCESS_FS_EXECUTE
            | ACCESS_FS_WRITE_FILE
            | ACCESS_FS_READ_FILE
            | ACCESS_FS_READ_DIR
            | ACCESS_FS_REMOVE_DIR
            | ACCESS_FS_REMOVE_FILE
            | ACCESS_FS_MAKE_DIR
            | ACCESS_FS_MAKE_REG
            | ACCESS_FS_MAKE_FIFO
            | ACCESS_FS_MAKE_SOCK
            | ACCESS_FS_MAKE_SYM
            | ACCESS_FS_MAKE_CHAR
            | ACCESS_FS_MAKE_BLOCK;
        let mut handled_access_net = 0u64;
        if abi >= 2 {
            handled_access_fs |= ACCESS_FS_REFER;
        }
        if abi >= 3 {
            handled_access_fs |= ACCESS_FS_TRUNCATE;
        }
        if abi >= 4 && !allow_network {
            handled_access_net = ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP;
        }

        let scoped = if abi >= 6 {
            SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
        } else {
            0
        };
        let attr = RulesetAttr {
            handled_access_fs,
            handled_access_net,
            scoped,
        };
        let before_scoped = RulesetAttrBeforeScoped {
            handled_access_fs,
            handled_access_net,
        };
        // Safety: the call only reads the attribute structure.
        let fd = unsafe {
            if abi >= 6 {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    &attr as *const RulesetAttr,
                    std::mem::size_of::<RulesetAttr>(),
                    0u32,
                )
            } else {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    &before_scoped as *const RulesetAttrBeforeScoped,
                    std::mem::size_of::<RulesetAttrBeforeScoped>(),
                    0u32,
                )
            }
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let ruleset = Ruleset { fd: fd as RawFd };
        // every directory the build may write: the source tree, the staging
        // directory and anything a recipe asked to have writable
        for path in writable {
            let metadata = std::fs::metadata(path)?;
            let access = if metadata.is_dir() {
                handled_access_fs
            } else {
                ACCESS_FS_READ_FILE
                    | ACCESS_FS_WRITE_FILE
                    | ACCESS_FS_EXECUTE
                    | (handled_access_fs & ACCESS_FS_TRUNCATE)
            };
            // on the error path the ruleset is dropped, which closes it once
            ruleset.allow_path(path, access)?;
        }
        // toolchain, headers and selected configuration files stay readable
        for path in readable {
            ruleset.allow_read_path(path)?;
        }
        // nearly every configure script writes to /dev/null, which sits outside
        // every writable directory and needs a rule of its own
        let dev_null = Path::new("/dev/null");
        if dev_null.exists() {
            ruleset.allow_path(dev_null, ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE)?;
        }
        Ok(ruleset)
    }

    fn allow_read_path(&self, path: &Path) -> Result<()> {
        let metadata = std::fs::metadata(path)?;
        let access = if metadata.is_dir() {
            ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE
        } else {
            ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE
        };
        self.allow_path(path, access)
    }

    fn allow_path(&self, path: &Path, access: u64) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(path)?;
        use std::os::fd::AsRawFd;
        let attr = PathBeneathAttr {
            allowed_access: access,
            parent_fd: directory.as_raw_fd(),
        };
        // Safety: the call only reads the attribute structure and the descriptor.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Ruleset {
    fn drop(&mut self) {
        // Safety: the descriptor belongs to this value and is closed once.
        unsafe { libc::close(self.fd) };
    }
}

/// Applies a ruleset in the child. Only syscalls; safe inside `pre_exec`.
///
/// # Safety
///
/// Must be called in the child between fork and exec, with a ruleset built by
/// this process; `fd` must still be open and is read here. From then on the
/// calling thread is restricted, irreversibly.
pub unsafe fn restrict(fd: RawFd) -> std::io::Result<()> {
    if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// True when a build step can be confined this way.
pub fn available() -> bool {
    abi_version().is_some()
}

/// Reports the ABI in a sentence, for the build log.
pub fn describe() -> Result<String> {
    let abi = abi_version().ok_or_else(|| anyhow::anyhow!("landlock is not available"))?;
    if abi < 1 {
        bail!("landlock reports an unusable ABI version {abi}");
    }
    Ok(format!("landlock abi {abi}"))
}
