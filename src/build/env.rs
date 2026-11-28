//! Environment, resource limits and staging helpers for a build.
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::housekeeping::apply_resource_limits;
use super::source::flag_mappings;
use super::LocalFlags;
use crate::paths::Paths;
use crate::recipe::Recipe;
use crate::scrub::{scrub_mappings, scrub_paths_enabled, scrub_stage_allowing, LogScrub};
use crate::stage::chown_tree;
use crate::util;

fn merge_env<'a>(envs: &mut Vec<(&'a str, String)>, key: &'a str, value: String) {
    merge_env_with(envs, key, value, " ");
}

fn merge_env_with<'a>(
    envs: &mut Vec<(&'a str, String)>,
    key: &'a str,
    value: String,
    separator: &str,
) {
    match envs.iter_mut().find(|(name, _)| *name == key) {
        Some((_, existing)) => *existing = format!("{existing}{separator}{value}"),
        None => envs.push((key, value)),
    }
}

pub(super) fn dependency_mounts(
    recipe: &Recipe,
    dep_stores: &[PathBuf],
) -> Result<Vec<(String, PathBuf)>> {
    if recipe.package.depends.len() != dep_stores.len() {
        bail!("one or more build dependencies are not installed");
    }
    Ok(recipe
        .package
        .depends
        .iter()
        .cloned()
        .zip(dep_stores.iter().cloned())
        .collect())
}

/// Environment shared by every build system.
pub(super) fn base_envs<'a>(
    recipe: &'a Recipe,
    stage: &Path,
    srcdir: &Path,
    rpath: &[String],
    store: &Path,
    dep_stores: &[PathBuf],
    deps: &[(String, PathBuf)],
) -> Vec<(&'a str, String)> {
    let mut envs: Vec<(&str, String)> = recipe
        .build
        .env
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    envs.push(("DESTDIR", stage.to_string_lossy().to_string()));
    envs.push(("PREFIX", recipe.install.prefix.clone()));
    envs.push(("SRCDIR", srcdir.to_string_lossy().to_string()));
    if !rpath.is_empty() {
        let mut flags = rpath
            .iter()
            .map(|p| format!("-Wl,-rpath,{p}"))
            .collect::<Vec<_>>()
            .join(" ");
        flags.push_str(" -Wl,--enable-new-dtags");
        merge_env(&mut envs, "LDFLAGS", flags);
        let prefix = recipe.install.prefix.trim_matches('/');
        let libdir = if prefix.is_empty() {
            "lib".to_string()
        } else {
            format!("{prefix}/lib")
        };
        let libs = std::iter::once(store.join(libdir))
            .chain(
                dep_stores
                    .iter()
                    .flat_map(|d| crate::stage::dep_lib_dirs(d)),
            )
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(":");
        merge_env_with(&mut envs, "LIBRARY_PATH", libs, ":");
    }
    if !deps.is_empty() {
        let mut include_flags = Vec::with_capacity(deps.len());
        let mut link_flags = Vec::with_capacity(deps.len());
        let mut pkg_config = Vec::with_capacity(deps.len());
        let mut library_path = Vec::with_capacity(deps.len());
        let mut cmake_prefix = Vec::with_capacity(deps.len());
        for (name, path) in deps {
            let prefix = if util::sandbox_enabled() {
                format!("/deps/{name}")
            } else {
                path.to_string_lossy().to_string()
            };
            include_flags.push(format!("-I{prefix}/usr/include"));
            link_flags.push(format!("-L{prefix}/usr/lib"));
            link_flags.push(format!("-L{prefix}/usr/lib64"));
            pkg_config.push(format!("{prefix}/usr/lib/pkgconfig"));
            pkg_config.push(format!("{prefix}/usr/share/pkgconfig"));
            library_path.push(format!("{prefix}/usr/lib"));
            library_path.push(format!("{prefix}/usr/lib64"));
            cmake_prefix.push(prefix);
        }
        merge_env(&mut envs, "CPPFLAGS", include_flags.join(" "));
        merge_env(&mut envs, "CFLAGS", include_flags.join(" "));
        merge_env(&mut envs, "LDFLAGS", link_flags.join(" "));
        merge_env_with(&mut envs, "PKG_CONFIG_PATH", pkg_config.join(":"), ":");
        merge_env_with(&mut envs, "PKG_CONFIG_LIBDIR", pkg_config.join(":"), ":");
        merge_env_with(&mut envs, "LIBRARY_PATH", library_path.join(":"), ":");
        merge_env_with(&mut envs, "CMAKE_PREFIX_PATH", cmake_prefix.join(":"), ":");
    }
    envs
}

/// Compiler flags from the recipe and the local overrides; returns the
/// effective C and Rust flags for the manifest.
pub(super) fn compiler_envs<'a>(
    recipe: &'a Recipe,
    local: Option<&LocalFlags>,
    envs: &mut Vec<(&'a str, String)>,
    scrub_paths: bool,
    work: &Path,
) -> (Option<String>, Option<String>) {
    let eff_cflags = local
        .and_then(|l| l.cflags.clone())
        .or_else(|| recipe.build.cflags.clone());
    let eff_cxxflags = local
        .and_then(|l| l.cxxflags.clone())
        .or_else(|| recipe.build.cxxflags.clone());
    let eff_rustflags = local
        .and_then(|l| l.rustflags.clone())
        .or_else(|| recipe.build.rustflags.clone());
    let join_flags = |base: &Option<String>, extra: &str| match base {
        Some(value) => format!("{value} {extra}"),
        None => extra.to_string(),
    };
    if scrub_paths {
        let flags_map = flag_mappings(work);
        let file_maps = flags_map
            .iter()
            .map(|(from, to)| format!("-ffile-prefix-map={from}={to}"))
            .collect::<Vec<_>>()
            .join(" ");
        let rust_maps = flags_map
            .iter()
            .map(|(from, to)| format!("--remap-path-prefix={from}={to}"))
            .collect::<Vec<_>>()
            .join(" ");
        merge_env(envs, "CPPFLAGS", file_maps.clone());
        merge_env(envs, "CFLAGS", join_flags(&eff_cflags, &file_maps));
        merge_env(envs, "CXXFLAGS", join_flags(&eff_cxxflags, &file_maps));
        merge_env(envs, "RUSTFLAGS", join_flags(&eff_rustflags, &rust_maps));
    } else {
        if let Some(v) = &eff_cflags {
            merge_env(envs, "CFLAGS", v.clone());
        }
        if let Some(v) = &eff_cxxflags {
            merge_env(envs, "CXXFLAGS", v.clone());
        }
        if let Some(v) = &eff_rustflags {
            merge_env(envs, "RUSTFLAGS", v.clone());
        }
    }
    if scrub_paths {
        merge_env(envs, "GOFLAGS", "-trimpath".to_string());
    }
    if let Some(v) = local.and_then(|l| l.ldflags.clone()) {
        match envs.iter_mut().find(|(k, _)| *k == "LDFLAGS") {
            Some((_, existing)) => *existing = format!("{v} {existing}"),
            None => envs.push(("LDFLAGS", v)),
        }
    }
    (eff_cflags, eff_rustflags)
}

pub(super) fn refresh_makeflags(envs: &mut Vec<(&str, String)>, recipe: &Recipe) {
    let Some((_, ldflags)) = envs.iter().find(|(name, _)| *name == "LDFLAGS") else {
        return;
    };
    let jobs = recipe
        .build
        .jobs
        .parse::<usize>()
        .ok()
        .filter(|count| *count > 0)
        .unwrap_or_else(util::jobs);
    let escaped = ldflags.replace(' ', "\\ ");
    let job_flag = if envs
        .iter()
        .find(|(name, _)| *name == "MAKEFLAGS")
        .is_some_and(|(_, value)| {
            value
                .split_whitespace()
                .any(|word| word.starts_with("-j") || word.starts_with("--jobs"))
        }) {
        String::new()
    } else {
        format!("-j{jobs}")
    };
    let value = format!("{job_flag} LDFLAGS={escaped}").trim().to_string();
    match envs.iter_mut().find(|(name, _)| *name == "MAKEFLAGS") {
        Some((_, existing)) if existing.is_empty() => *existing = value,
        Some((_, existing)) => *existing = format!("{existing} {value}"),
        None => envs.push(("MAKEFLAGS", value)),
    }
}

pub(super) fn scrub_logger(
    paths: &Paths,
    work: &Path,
    log_path: &Path,
) -> (bool, Vec<(String, String)>, LogScrub) {
    let enabled = scrub_paths_enabled(paths);
    let map = scrub_mappings(work, paths);
    let scrub = LogScrub {
        path: log_path.to_path_buf(),
        mappings: map.clone(),
        enabled,
    };
    (enabled, map, scrub)
}

pub(super) fn sandbox_policy(
    recipe: &Recipe,
    work: &Path,
    build_root: Option<&Path>,
    deps: &[(String, PathBuf)],
) -> util::SandboxPolicy {
    let mut writable = recipe.build.writable.clone();
    writable.push(work.to_string_lossy().to_string());
    util::SandboxPolicy {
        network: recipe.build.network,
        writable,
        read: recipe.build.read.clone(),
        root: build_root.map(Path::to_path_buf),
        deps: deps.to_vec(),
    }
}

pub(super) fn log_limits(paths: &Paths, work: &Path, log: &mut fs::File) -> Result<()> {
    let limits = apply_resource_limits(paths, work)?;
    writeln!(
        log,
        "limits   memory {} bytes, file {} bytes, open files {}",
        limits.address_space, limits.file_size, limits.open_files
    )?;
    Ok(())
}

/// Hands the unpacked tree and the stage to the build account.
pub(super) fn prepare_stage(work: &Path, creds: Option<(u32, u32)>) -> Result<PathBuf> {
    if let Some((uid, gid)) = creds {
        chown_tree(&work.join("src"), uid, gid).context("chowning the unpacked tree")?;
    }
    let stage = work.join("stage");
    fs::create_dir_all(&stage)?;
    if let Some((uid, gid)) = creds {
        chown_tree(&stage, uid, gid)?;
    }
    Ok(stage)
}

pub(super) fn check_scrubbed(
    stage: &Path,
    enabled: bool,
    map: &[(String, String)],
    allowed: &[PathBuf],
    allow_path_leak: bool,
) -> Result<()> {
    if enabled {
        let report = scrub_stage_allowing(stage, map, allowed)?;
        crate::scrub::check_leaks(&report, allow_path_leak)?;
    }
    Ok(())
}
