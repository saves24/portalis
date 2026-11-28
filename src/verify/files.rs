//! File, directory and runpath checks against the manifest and the live tree.

use super::is_preserved;
use super::manifest::SignedFile;
use crate::db::Db;
use crate::elf::{elf_info, is_elf, runpath_is_isolated};
use crate::links::live_path;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn file_problems(
    db: &Db,
    pkg: &crate::db::PackageRow,
    target_root: &Path,
    signed: Option<&std::collections::HashMap<String, SignedFile>>,
    preserve: &[String],
) -> Result<usize> {
    let (rows, mut problems) = collect_problems(db, pkg, signed, preserve)?;
    for (path, sha, link_target, mode) in rows {
        let live = live_path(target_root, &path);
        let target = PathBuf::from(&link_target);
        if sha.is_empty() {
            problems += link_problems(
                target_root,
                &pkg.store_path,
                &path,
                &link_target,
                &live,
                &target,
            );
            continue;
        }
        problems += hash_problems(&path, &sha, &target);
        problems += mode_problems(&path, mode, &target);
        problems += live_link_problems(&path, &live, &target);
    }
    Ok(problems)
}

/// One manifest row: path, digest, link target, mode.
type FileRow = (String, String, String, u32);

/// The rows to check, plus the manifest cross-checks that need no live tree.
fn collect_problems(
    db: &Db,
    pkg: &crate::db::PackageRow,
    signed: Option<&std::collections::HashMap<String, SignedFile>>,
    preserve: &[String],
) -> Result<(Vec<FileRow>, usize)> {
    let mut problems = 0usize;
    let rows = db.files_of(&pkg.name)?;
    if let Some(signed) = signed {
        let present: std::collections::HashSet<&str> =
            rows.iter().map(|(path, ..)| path.as_str()).collect();
        for path in signed.keys() {
            if !present.contains(path.as_str()) && !is_preserved(preserve, path) {
                say!("MANIFEST {} is missing {path}", pkg.name);
                problems += 1;
            }
        }
    }
    let mut kept = Vec::with_capacity(rows.len());
    for (path, sha, link_target, mode) in rows {
        if is_preserved(preserve, &path) {
            continue;
        }
        if let Some(signed) = signed {
            if !signed.contains_key(&path) {
                say!(
                    "MANIFEST {} has {path}, which is not in its signed manifest",
                    pkg.name
                );
                problems += 1;
            }
        }
        if let Some(expected) = signed.and_then(|map| map.get(&path)) {
            if expected.sha256 != sha {
                say!(
                    "MANIFEST {} records {sha} for {path}, the signed manifest says {}",
                    pkg.name,
                    expected.sha256
                );
                problems += 1;
            }
            if expected.mode != 0 && expected.mode != mode {
                say!(
                    "MANIFEST {} records mode {mode:o} for {path}, the signed manifest says {:o}",
                    pkg.name,
                    expected.mode
                );
                problems += 1;
            }
            if let Some(link) = &expected.link {
                if link != &link_target {
                    say!(
                        "MANIFEST {} records {path} -> {link_target}, the signed manifest says {link}",
                        pkg.name
                    );
                    problems += 1;
                }
            }
        }
        // a running interpreter rewrites its bytecode cache in place, which
        // is the cache working, not the package changing
        if path.contains("__pycache__") {
            continue;
        }
        kept.push((path, sha, link_target, mode));
    }
    Ok((kept, problems))
}

/// One store file's hash against the manifest row.
fn hash_problems(path: &str, sha: &str, target: &Path) -> usize {
    if !target.exists() {
        say!("MISSING  {path} -> {}", target.display());
        return 1;
    }
    match util_sha(target, sha) {
        Ok(true) => 0,
        Ok(false) => {
            say!("CHANGED  {path} (store file modified)");
            1
        }
        Err(e) => {
            say!("ERROR    {path}: {e}");
            1
        }
    }
}

/// One store file's mode bits against the manifest row.
fn mode_problems(path: &str, mode: u32, target: &Path) -> usize {
    if mode == 0 {
        return 0;
    }
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(target) {
        let actual = meta.permissions().mode() & 0o7777;
        if actual != mode {
            say!("MODE     {path} expected {mode:o} found {actual:o}");
            return 1;
        }
    }
    0
}

/// A manifest row that records a link.
fn link_problems(
    target_root: &Path,
    store: &str,
    path: &str,
    link_target: &str,
    live: &Path,
    target: &Path,
) -> usize {
    let mut problems = 0usize;
    if let Err(error) =
        crate::policy::validate_link_target(target_root, path, link_target, Some(Path::new(store)))
    {
        say!("UNSAFE   {path} -> {link_target}: {error:#}");
        problems += 1;
    }
    match fs::read_link(live) {
        Ok(current) if current == target => {}
        Ok(current) => {
            say!(
                "RELINKED {path} -> {} (expected {})",
                current.display(),
                target.display()
            );
            problems += 1;
        }
        Err(_) => {
            say!("MISSING  {path} (symlink absent)");
            problems += 1;
        }
    }
    problems
}

/// The live entry of a file row that should be a link into the store.
fn live_link_problems(path: &str, live: &Path, target: &Path) -> usize {
    match fs::symlink_metadata(live) {
        Ok(meta) if meta.file_type().is_symlink() => match fs::read_link(live) {
            Ok(current) if current == target => 0,
            Ok(current) => {
                say!("RELINKED {path} -> {}", current.display());
                1
            }
            Err(error) => {
                say!("ERROR    {path}: {error}");
                1
            }
        },
        Ok(_) => {
            say!("REPLACED {path} is no longer a symlink");
            1
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            say!("UNLINKED {path} is missing from the live tree");
            1
        }
        Err(error) => {
            say!("ERROR    {path}: {error}");
            1
        }
    }
}

pub(super) fn directory_problems(
    db: &Db,
    pkg: &crate::db::PackageRow,
    target_root: &Path,
) -> Result<usize> {
    let Some(canonical) = db.manifest_of(&pkg.name)? else {
        return Ok(0);
    };
    let manifest = match serde_json::from_str::<crate::recipe::BuildManifest>(&canonical) {
        Ok(manifest) => manifest,
        Err(error) => {
            say!("MANIFEST {} is not readable: {error}", pkg.name);
            return Ok(1);
        }
    };
    let mut problems = 0usize;
    for directory in manifest.dirs {
        use std::os::unix::fs::PermissionsExt;
        let live = live_path(target_root, &directory.path);
        match fs::symlink_metadata(&live) {
            Ok(meta) if meta.file_type().is_symlink() => {
                say!("DIR      {} is a symlink", directory.path);
                problems += 1;
            }
            Ok(meta) if !meta.is_dir() => {
                say!("DIR      {} is not a directory", directory.path);
                problems += 1;
            }
            Ok(meta) => {
                let actual = meta.permissions().mode() & 0o777;
                if actual != directory.mode {
                    say!(
                        "DIR      {} expected {:o} found {:o}",
                        directory.path,
                        directory.mode,
                        actual
                    );
                    problems += 1;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                say!("DIR      {} is missing", directory.path);
                problems += 1;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", live.display()));
            }
        }
    }
    Ok(problems)
}

pub(super) fn runpath_problems(db: &Db, store: &Path, host_dirs: &[PathBuf]) -> Result<usize> {
    let mut problems = 0usize;
    for pkg in db.packages()? {
        if pkg.rpath.is_empty() {
            continue;
        }
        for (path, _sha, link_target, _mode) in db.files_of(&pkg.name)? {
            let target = PathBuf::from(&link_target);
            if !is_elf(&target) {
                continue;
            }
            let Some(info) = elf_info(&target) else {
                say!("RUNPATH  {path} could not be read as an ELF object");
                problems += 1;
                continue;
            };
            if info.needed.is_empty() {
                continue;
            }
            match info.runpath {
                Some(paths) => {
                    for expected in &pkg.rpath {
                        if !paths.iter().any(|p| p == expected) {
                            say!("RUNPATH  {path} missing {expected}");
                            problems += 1;
                        }
                    }
                    if let Some(outside) = paths
                        .iter()
                        .find(|entry| !runpath_is_isolated(store, entry, host_dirs))
                    {
                        say!(
                            "RUNPATH  {path} points at {outside} outside the store (breaks isolation)"
                        );
                        problems += 1;
                    }
                }
                None => {
                    say!("RUNPATH  {path} expected rpath isolation but has none");
                    problems += 1;
                }
            }
        }
    }
    Ok(problems)
}

pub(crate) fn util_sha(path: &Path, expected: &str) -> Result<bool> {
    if expected.is_empty() {
        return Ok(true);
    }
    Ok(crate::util::sha256_file(path)? == expected)
}
