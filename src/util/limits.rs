//! Resource ceilings for build steps: half of what the host offers.
use anyhow::Result;
use std::path::Path;

/// Resource ceilings applied to every build step. Zero means "no ceiling".
#[derive(Debug, Clone, Copy, Default)]
pub struct Limits {
    pub cpu_seconds: u64,
    pub address_space: u64,
    pub file_size: u64,
    pub open_files: u64,
}

static LIMIT_CPU: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LIMIT_AS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LIMIT_FSIZE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LIMIT_NOFILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn set_limits(limits: Limits) {
    use std::sync::atomic::Ordering::Relaxed;
    LIMIT_CPU.store(limits.cpu_seconds, Relaxed);
    LIMIT_AS.store(limits.address_space, Relaxed);
    LIMIT_FSIZE.store(limits.file_size, Relaxed);
    LIMIT_NOFILE.store(limits.open_files, Relaxed);
}

/// Divisor applied to host limits.
const LIMIT_DIVISOR: u64 = 2;

/// Floor for the open-file ceiling.
const MIN_OPEN_FILES: u64 = 64;

/// The ceilings a build gets when the configuration says nothing: half of what
/// this machine offers.
pub fn default_limits(work: &Path) -> Limits {
    // CPU time is not capped.
    let cpu_seconds = 0;
    let mut limits = Limits {
        cpu_seconds,
        ..Limits::default()
    };
    if let Some(total) = mem_total_bytes() {
        limits.address_space = total / LIMIT_DIVISOR;
    }
    if let Some(free) = free_bytes(work) {
        limits.file_size = free / LIMIT_DIVISOR;
    }
    if let Ok(hard) = open_file_hard_limit() {
        limits.open_files = hard.max(MIN_OPEN_FILES) / LIMIT_DIVISOR;
    }
    limits
}

fn mem_total_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let mut name = Vec::with_capacity(path.as_os_str().len() + 1);
    name.extend_from_slice(path.as_os_str().as_bytes());
    name.push(0);
    // Safety: statvfs writes into the provided structure and reads a NUL-terminated path.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(name.as_ptr() as *const libc::c_char, &mut stats) };
    if rc != 0 {
        return None;
    }
    Some(stats.f_bavail as u64 * stats.f_frsize as u64)
}

fn open_file_hard_limit() -> Result<u64> {
    // Safety: getrlimit writes into the provided structure.
    let mut current: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(current.rlim_max as u64)
}

/// Applies the ceilings in the child, just before it execs.
pub(crate) fn apply_limits() -> std::io::Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    // Safety: setrlimit only reads the structure passed to it.
    unsafe {
        let pairs = [
            (libc::RLIMIT_CPU, LIMIT_CPU.load(Relaxed)),
            (libc::RLIMIT_AS, LIMIT_AS.load(Relaxed)),
            (libc::RLIMIT_FSIZE, LIMIT_FSIZE.load(Relaxed)),
            (libc::RLIMIT_NOFILE, LIMIT_NOFILE.load(Relaxed)),
        ];
        for (resource, value) in pairs {
            if value == 0 {
                continue;
            }
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(resource, &mut inherited) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let ceiling = ceiling_within(value, inherited.rlim_cur, inherited.rlim_max);
            let limit = libc::rlimit {
                rlim_cur: ceiling as libc::rlim_t,
                rlim_max: ceiling as libc::rlim_t,
            };
            if libc::setrlimit(resource, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// A requested ceiling, lowered to whatever the process already inherited.
///
/// The answer is the smallest of the request, the inherited hard limit and any
/// tighter limit already in force.
pub(crate) fn ceiling_within(requested: u64, inherited_soft: u64, inherited_hard: u64) -> u64 {
    let mut ceiling = requested;
    for inherited in [inherited_hard, inherited_soft] {
        if inherited != u64::MAX {
            ceiling = ceiling.min(inherited);
        }
    }
    ceiling
}

/// How long a single build step may run when the configuration says nothing.
const DEFAULT_BUILD_TIMEOUT_SECONDS: u64 = 3600;

/// How long a single build step may run before it is stopped.
pub fn build_timeout_seconds() -> u64 {
    std::env::var("PORTALIS_BUILD_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_BUILD_TIMEOUT_SECONDS)
}
