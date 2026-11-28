//! Chores around a build: the ceilings a step runs under, and pruning old logs.
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::paths::Paths;
use crate::util;

/// Applies the build ceilings: half of this machine by default, a configured
/// value, or no ceiling when that value is zero.
pub(super) fn apply_resource_limits(paths: &Paths, work: &Path) -> Result<util::Limits> {
    let mut limits = util::default_limits(work);
    let conf = util::load_conf(&paths.config_file())?;
    // A value that cannot be read stops the build.
    let number = |key: &str| -> Result<Option<u64>> {
        match conf.get(key) {
            None => Ok(None),
            Some(raw) => raw
                .trim()
                .parse::<u64>()
                .map(Some)
                .with_context(|| format!("{key} must be a number, found {raw}")),
        }
    };
    if let Some(mb) = number("build.limit_memory_mb")? {
        limits.address_space = mb * 1024 * 1024;
    }
    if let Some(mb) = number("build.limit_file_mb")? {
        limits.file_size = mb * 1024 * 1024;
    }
    if let Some(seconds) = number("build.limit_cpu_seconds")? {
        limits.cpu_seconds = seconds;
    }
    if let Some(count) = number("build.limit_open_files")? {
        limits.open_files = count;
    }
    if let Some(jobs) = number("build.jobs")? {
        util::set_jobs(jobs as usize);
    }
    util::set_limits(limits);
    Ok(limits)
}

pub(crate) fn prune_logs(paths: &Paths, name: &str, version: &str, keep: usize) {
    let prefix = format!("{name}-{version}-");
    let Ok(entries) = fs::read_dir(paths.logs()) else {
        return;
    };
    let mut logs: Vec<_> = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .collect();
    if logs.len() <= keep {
        return;
    }
    logs.sort_by_key(|entry| entry.metadata().and_then(|m| m.modified()).ok());
    for entry in logs.iter().take(logs.len() - keep) {
        let _ = fs::remove_file(entry.path());
    }
}
