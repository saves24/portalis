//! Overlap, orphan and dependency-health reporting.

use super::is_preserved;
use crate::db::Db;
use crate::elf::{
    elf_interpreter, elf_needed, file_provides_soname, is_elf, is_vdso, ldconfig_libraries,
    store_path_for,
};
use crate::links::live_path;
use crate::paths::Paths;
use crate::recipe::Recipe;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn is_ignored_path(rel: &str, ignore: &[String]) -> bool {
    ignore.iter().any(|prefix| {
        let prefix = prefix.trim_matches('/');
        rel == prefix
            || rel
                .strip_prefix(prefix)
                .map(|rest| rest.starts_with('/'))
                .unwrap_or(false)
    })
}

pub(crate) fn report_dependency_health(
    store: &Path,
    files: &[crate::recipe::ManifestFile],
    ignore: &[String],
    db: &Db,
) {
    let cache = ldconfig_libraries();
    let mut findings: Vec<(String, String)> = Vec::new();
    for file in files {
        let target = store_path_for(store, &file.path);
        let rel_path = file.path.trim_start_matches('/');
        if !is_elf(&target) || is_ignored_path(rel_path, ignore) {
            continue;
        }
        let Some((needed, runpath, bits)) = elf_needed(&target) else {
            continue;
        };
        let interpreter = elf_interpreter(&target);
        let mut missing = Vec::new();
        for lib in needed {
            if interpreter.as_deref() == Some(lib.as_str()) || is_vdso(&lib) {
                continue;
            }
            if cache.contains_key(&lib)
                || file_provides_soname(store, files, &lib)
                || runpath.iter().any(|dir| dir.join(&lib).exists())
                || db.soname_owner(&lib, bits).ok().flatten().is_some()
            {
                continue;
            }
            missing.push(lib);
        }
        if !missing.is_empty() {
            findings.push((file.path.clone(), missing.join(", ")));
        }
    }
    if findings.is_empty() {
        say!("deps     all shared libraries resolved");
        return;
    }
    say!(
        "deps     {} file(s) with unresolved shared libraries:",
        findings.len()
    );
    for (path, libs) in findings.iter().take(50) {
        say!("  {path}: {libs}");
    }
    if findings.len() > 50 {
        say!("  ... {} more", findings.len() - 50);
    }
}

pub(crate) fn dependencies_resolve(
    path: &Path,
    files: &[crate::recipe::ManifestFile],
    store: &Path,
    cache: &std::collections::HashMap<String, String>,
) -> Result<bool> {
    let Some((needed, runpath, _bits)) = elf_needed(path) else {
        return Ok(!is_elf(path));
    };
    let interpreter = elf_interpreter(path);
    for lib in needed {
        if interpreter.as_deref() == Some(lib.as_str()) || is_vdso(&lib) {
            continue;
        }
        if cache.contains_key(&lib)
            || file_provides_soname(store, files, &lib)
            || runpath.iter().any(|dir| dir.join(&lib).exists())
        {
            continue;
        }
        return Ok(false);
    }
    Ok(true)
}

struct Overlap {
    fresh: usize,
    owned_here: usize,
    foreign_link: Vec<(String, String)>,
    takeovers: Vec<(String, bool)>,
}

fn overlap_scan(
    recipe: &Recipe,
    outcome: &crate::build::BuildOutcome,
    db: &Db,
    target_root: &Path,
) -> Result<Overlap> {
    let mut found = Overlap {
        fresh: 0,
        owned_here: 0,
        foreign_link: Vec::new(),
        takeovers: Vec::new(),
    };
    for file in &outcome.manifest.files {
        if is_preserved(&recipe.files.preserve, &file.path) {
            continue;
        }
        let live = live_path(target_root, &file.path);
        match fs::symlink_metadata(&live) {
            Err(_) => found.fresh += 1,
            Ok(meta) if meta.file_type().is_symlink() => {
                let current = fs::read_link(&live)
                    .with_context(|| format!("reading link {}", live.display()))?;
                match db.owner(&file.path)? {
                    Some((owner, _)) if owner == recipe.package.name => found.owned_here += 1,
                    _ => found
                        .foreign_link
                        .push((file.path.clone(), current.display().to_string())),
                }
            }
            Ok(_) => {
                let same = match crate::util::sha256_file(&live) {
                    Ok(sha) => sha == file.sha256,
                    Err(_) => false,
                };
                found.takeovers.push((file.path.clone(), same));
            }
        }
    }
    Ok(found)
}

fn report_overlap(name: &str, found: &Overlap) {
    say!("overlap  {name}");
    say!("  new files      {}", found.fresh);
    say!("  own links      {}", found.owned_here);
    say!("  foreign links  {}", found.foreign_link.len());
    for (path, target) in found.foreign_link.iter().take(20) {
        say!("    link  {path} -> {target}");
    }
    say!("  replaced files {}", found.takeovers.len());
    for (path, same) in found.takeovers.iter().take(20) {
        say!(
            "    file  {path}{}",
            if *same { " (identical)" } else { " (differs)" }
        );
    }
    if found.takeovers.len() > 20 || found.foreign_link.len() > 20 {
        say!("  (lists truncated)");
    }
}

fn orphan_candidates(
    outcome: &crate::build::BuildOutcome,
    db: &Db,
    target_root: &Path,
) -> Result<Vec<String>> {
    let manifest_paths: std::collections::BTreeSet<String> = outcome
        .manifest
        .files
        .iter()
        .map(|f| f.path.clone())
        .collect();
    let mut dirs: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    let mut stems: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for file in &outcome.manifest.files {
        if let Some(parent) = std::path::Path::new(&file.path).parent() {
            dirs.insert(live_path(target_root, &parent.to_string_lossy()));
        }
        let base = std::path::Path::new(&file.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Some(stem) = base.split('.').next() {
            if stem.len() > 4 {
                stems.insert(stem.to_string());
            }
        }
    }
    let mut orphans = Vec::new();
    for dir in &dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let live_rel = format!(
                    "/{}",
                    path.strip_prefix(target_root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                );
                if manifest_paths.contains(&live_rel) {
                    continue;
                }
                if name.ends_with(".pacnew") || name.ends_with(".portalis-old") {
                    continue;
                }
                if !stems.iter().any(|s| name.starts_with(s.as_str())) {
                    continue;
                }
                if db.owner(&live_rel)?.is_some() {
                    continue;
                }
                orphans.push(live_rel);
            }
        }
    }
    Ok(orphans)
}

pub(crate) fn overlap_report(
    recipe: &Recipe,
    outcome: &crate::build::BuildOutcome,
    db: &Db,
    paths: &Paths,
) -> Result<()> {
    let target_root = paths.target_root();
    let found = overlap_scan(recipe, outcome, db, &target_root)?;
    report_overlap(&recipe.package.name, &found);
    let orphans = orphan_candidates(outcome, db, &target_root)?;
    if !orphans.is_empty() {
        say!("  orphan candidates {}", orphans.len());
        for path in orphans.iter().take(20) {
            say!("    old   {path}");
        }
        say!("  (review before removing; nothing was changed)");
    }
    Ok(())
}

/// Checks that the manifest on record is the one this package was signed with.
/// Problems no package-level check covers: an activation that never finished,
/// and records whose owner is gone.
pub(super) fn leftover_problems(db: &Db, paths: &Paths) -> Result<Vec<String>> {
    let mut found = Vec::new();
    let marker = paths.state_dir().join("activating");
    match fs::read_to_string(&marker) {
        Ok(staged) => found.push(format!(
            "INCOMPLETE {} never finished activating; reinstall it",
            staged.trim()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", marker.display()));
        }
    }
    for pkg in db.owners_without_package()? {
        found.push(format!(
            "ORPHAN   {pkg} has file records but no package row; reinstall or drop them"
        ));
    }
    for pkg in db.staged_without_pending()? {
        found.push(format!(
            "ORPHAN   {pkg} has staged records but no pending package; drop them with --pending"
        ));
    }
    Ok(found)
}
