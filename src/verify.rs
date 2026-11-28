//! Verification: comparing the live tree with the manifest and reporting overlaps.

use crate::db::Db;
use crate::elf::{
    elf_info, elf_interpreter, elf_needed, file_provides_soname, host_library_dirs, is_elf,
    is_vdso, ldconfig_libraries, runpath_is_isolated, store_path_for,
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

/// Checks a store's own tree, symlink targets included, against the digest its
/// completion marker names.
fn store_content_problems(pkg: &crate::db::PackageRow) -> Result<usize> {
    let store = Path::new(&pkg.store_path);
    match std::fs::symlink_metadata(store) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            say!("CONTENT {} store is not a directory", pkg.name);
            return Ok(1);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            say!("CONTENT {} store is missing", pkg.name);
            return Ok(1);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", store.display()));
        }
    }
    let marker_path = store.join(crate::archive::STORE_MARKER);
    let marker = match std::fs::read_to_string(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            say!("CONTENT {} store has no completion marker", pkg.name);
            return Ok(1);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", marker_path.display()));
        }
    };
    let Some(recorded_files) = crate::archive::marker_digest(&marker) else {
        say!("CONTENT {} store marker has no usable digest", pkg.name);
        return Ok(1);
    };
    let recorded_tree = crate::archive::marker_tree(&marker);
    if crate::archive::marker_recipe(&marker) != Some(pkg.recipe_sha256.as_str()) {
        say!("CONTENT {} store marker names a different recipe", pkg.name);
        return Ok(1);
    }
    let files = crate::archive::collect_files(store)?;
    let content = if recorded_tree.is_some() {
        crate::archive::tree_digest(&files, &crate::archive::collect_dirs(store)?)?
    } else {
        crate::archive::digest_of(&files)?
    };
    let recorded = recorded_tree.unwrap_or(recorded_files);
    if content.trim() == recorded.trim() {
        return Ok(0);
    }
    say!(
        "CONTENT {} store does not match its completion marker",
        pkg.name
    );
    Ok(1)
}

fn legacy_manifests(db: &Db, packages: &[crate::db::PackageRow]) -> Result<bool> {
    let mut recorded = 0usize;
    for pkg in packages {
        if db.manifest_of(&pkg.name)?.is_some() {
            recorded += 1;
        }
    }
    Ok(recorded == 0 && !packages.is_empty())
}

fn signed_from_db(
    db: &Db,
    pkg: &crate::db::PackageRow,
) -> Result<Option<std::collections::HashMap<String, SignedFile>>> {
    let digest_ok = match db.manifest_of(&pkg.name)? {
        Some(canonical) => crate::util::sha256_bytes(canonical.as_bytes()) == pkg.manifest_digest,
        None => false,
    };
    if digest_ok {
        signed_files(db, &pkg.name)
    } else {
        Ok(None)
    }
}

fn file_problems(
    db: &Db,
    pkg: &crate::db::PackageRow,
    target_root: &Path,
    signed: Option<&std::collections::HashMap<String, SignedFile>>,
    preserve: &[String],
) -> Result<usize> {
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
        let live = live_path(target_root, &path);
        let target = PathBuf::from(&link_target);
        if sha.is_empty() {
            if let Err(error) = crate::policy::validate_link_target(
                target_root,
                &path,
                &link_target,
                Some(Path::new(&pkg.store_path)),
            ) {
                say!("UNSAFE   {path} -> {link_target}: {error:#}");
                problems += 1;
            }
            match fs::read_link(&live) {
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
            continue;
        }
        if !target.exists() {
            say!("MISSING  {path} -> {}", target.display());
            problems += 1;
            continue;
        }
        match util_sha(&target, sha.as_str()) {
            Ok(true) => {}
            Ok(false) => {
                say!("CHANGED  {path} (store file modified)");
                problems += 1;
            }
            Err(e) => {
                say!("ERROR    {path}: {e}");
                problems += 1;
            }
        }
        if mode != 0 {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&target) {
                let actual = meta.permissions().mode() & 0o7777;
                if actual != mode {
                    say!("MODE     {path} expected {mode:o} found {actual:o}");
                    problems += 1;
                }
            }
        }
        match fs::symlink_metadata(&live) {
            Ok(meta) if meta.file_type().is_symlink() => match fs::read_link(&live) {
                Ok(current) if current == target => {}
                Ok(current) => {
                    say!("RELINKED {path} -> {}", current.display());
                    problems += 1;
                }
                Err(error) => {
                    say!("ERROR    {path}: {error}");
                    problems += 1;
                }
            },
            Ok(_) => {
                say!("REPLACED {path} is no longer a symlink");
                problems += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                say!("UNLINKED {path} is missing from the live tree");
                problems += 1;
            }
            Err(error) => {
                say!("ERROR    {path}: {error}");
                problems += 1;
            }
        }
    }
    Ok(problems)
}

fn package_problems(
    db: &Db,
    paths: &Paths,
    pkg: &crate::db::PackageRow,
    legacy: bool,
    target_root: &Path,
) -> Result<usize> {
    let preserve = preserved_paths(paths, pkg);
    let mut problems = store_content_problems(pkg)?;
    problems += manifest_problems(db, paths, pkg, legacy)?;
    let signed = signed_from_db(db, pkg)?;
    problems += file_problems(db, pkg, target_root, signed.as_ref(), &preserve)?;
    problems += directory_problems(db, pkg, target_root)?;
    Ok(problems)
}

fn preserved_paths(paths: &Paths, pkg: &crate::db::PackageRow) -> Vec<String> {
    let recipe = paths.recipe_file(&pkg.name);
    if !recipe.is_file() {
        return Vec::new();
    }
    match Recipe::load(&recipe) {
        Ok(recipe) => recipe.files.preserve,
        Err(error) => {
            eprintln!(
                "warning: preserved paths for {} were not read: {error:#}",
                pkg.name
            );
            Vec::new()
        }
    }
}

fn directory_problems(db: &Db, pkg: &crate::db::PackageRow, target_root: &Path) -> Result<usize> {
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

fn runpath_problems(db: &Db, store: &Path, host_dirs: &[PathBuf]) -> Result<usize> {
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

pub(crate) fn verify(db: &Db, paths: &Paths) -> Result<()> {
    let target_root = paths.target_root();
    let store = paths.store();
    let host_dirs = host_library_dirs();
    let mut problems = 0usize;
    for line in leftover_problems(db, paths)? {
        say!("{line}");
        problems += 1;
    }
    // a database written before manifests were stored has no rows for anything:
    // that is missing history, not tampering, and it is reported once
    let packages = db.packages()?;
    let legacy = legacy_manifests(db, &packages)?;
    if legacy {
        say!(
            "note     no package has a recorded manifest yet; packages that carry a signature are reported as unverified"
        );
    }
    for pkg in &packages {
        problems += package_problems(db, paths, pkg, legacy, &target_root)?;
        for (path, backup) in db.adopted_of(&pkg.name)? {
            if !Path::new(&backup).exists() {
                say!("ADOPTED  {} has no backup at {backup}", path);
                problems += 1;
            }
        }
    }
    for pending in db.pending_packages()? {
        if !Path::new(&pending.store_path).exists() {
            say!(
                "STAGED   {} has no store at {}",
                pending.name,
                pending.store_path
            );
            problems += 1;
            continue;
        }
        for (path, sha, target, _mode, kind) in db.pending_of(&pending.name)? {
            if kind == "symlink" {
                continue;
            }
            let target = Path::new(&target);
            if !target.exists() {
                say!(
                    "STAGED   {} records {path}, but {} is missing",
                    pending.name,
                    target.display()
                );
                problems += 1;
                continue;
            }
            match util_sha(target, &sha) {
                Ok(true) => {}
                Ok(false) => {
                    say!(
                        "STAGED   {} records a changed file for {path}",
                        pending.name
                    );
                    problems += 1;
                }
                Err(error) => {
                    say!("STAGED   {} could not read {path}: {error}", pending.name);
                    problems += 1;
                }
            }
        }
    }
    problems += runpath_problems(db, &store, &host_dirs)?;
    if problems == 0 {
        say!("verified {} packages: clean", db.packages()?.len());
        return Ok(());
    }
    anyhow::bail!("{problems} problems found")
}

/// Checks that the manifest on record is the one this package was signed with.
/// Problems no package-level check covers: an activation that never finished,
/// and records whose owner is gone.
fn leftover_problems(db: &Db, paths: &Paths) -> Result<Vec<String>> {
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

/// The signed fields of one manifest entry.
struct SignedFile {
    sha256: String,
    mode: u32,
    link: Option<String>,
}

/// File hashes from the stored manifest, or None when there is none to read.
fn signed_files(
    db: &Db,
    pkg: &str,
) -> Result<Option<std::collections::HashMap<String, SignedFile>>> {
    let Some(canonical) = db.manifest_of(pkg)? else {
        return Ok(None);
    };
    let Ok(manifest) = serde_json::from_str::<crate::recipe::BuildManifest>(&canonical) else {
        return Ok(None);
    };
    Ok(Some(
        manifest
            .files
            .into_iter()
            .map(|file| {
                (
                    file.path,
                    SignedFile {
                        sha256: file.sha256,
                        mode: file.mode,
                        link: file.link,
                    },
                )
            })
            .collect(),
    ))
}

fn manifest_problems(
    db: &Db,
    paths: &Paths,
    pkg: &crate::db::PackageRow,
    _legacy: bool,
) -> Result<usize> {
    let mut problems = 0usize;
    let signature = pkg.signature.as_deref().filter(|sig| !sig.is_empty());
    if signature.is_none() && crate::resolve::require_signature(paths)? {
        say!(
            "UNSIGNED {} is unsigned and security.require_signature is true",
            pkg.name
        );
        return Ok(1);
    }
    let Some(canonical) = db.manifest_of(&pkg.name)? else {
        // The digest column is older than the stored manifests; a missing row
        // means there is nothing to check the signature against.
        if signature.is_some() {
            if crate::util::env_flag("PORTALIS_ALLOW_UNVERIFIED") {
                say!(
                    "note     {} has no recorded manifest, so its signature was not checked \
                     (PORTALIS_ALLOW_UNVERIFIED=1)",
                    pkg.name
                );
            } else {
                say!(
                    "UNVERIFIED {} is signed but no manifest is recorded, so the signature \
                     cannot be checked; reinstall it, or set PORTALIS_ALLOW_UNVERIFIED=1",
                    pkg.name
                );
                problems += 1;
            }
        }
        return Ok(problems);
    };
    let manifest = match serde_json::from_str::<crate::recipe::BuildManifest>(&canonical) {
        Ok(manifest) => manifest,
        Err(error) => {
            say!("MANIFEST {} is not readable: {error}", pkg.name);
            return Ok(problems + 1);
        }
    };
    if manifest.name != pkg.name
        || manifest.version != pkg.version
        || manifest.recipe_sha256 != pkg.recipe_sha256
    {
        say!("MANIFEST {} does not name this package", pkg.name);
        problems += 1;
    }
    let digest = crate::util::sha256_bytes(canonical.as_bytes());
    if digest != pkg.manifest_digest {
        say!(
            "MANIFEST {} records {} but the stored manifest hashes to {}",
            pkg.name,
            pkg.manifest_digest,
            digest
        );
        problems += 1;
    }
    let Some(signature) = signature else {
        return Ok(problems);
    };
    let trusted = paths.trusted_keys();
    if !crate::sign::has_trusted_keys(&trusted)? {
        if crate::util::env_flag("PORTALIS_ALLOW_UNVERIFIED") {
            say!(
                "note     {} is signed, but no trusted keys are configured \
                 (PORTALIS_ALLOW_UNVERIFIED=1)",
                pkg.name
            );
        } else {
            say!(
                "UNVERIFIED {} is signed, but no trusted keys are configured, so the signature \
                 was not checked; add a key to {}, or set PORTALIS_ALLOW_UNVERIFIED=1",
                pkg.name,
                trusted.display()
            );
            problems += 1;
        }
        return Ok(problems);
    }
    if !crate::sign::verify_bytes(canonical.as_bytes(), signature, &trusted)? {
        say!(
            "SIGNATURE {} is not accepted by any key in {}",
            pkg.name,
            trusted.display()
        );
        problems += 1;
    }
    Ok(problems)
}

pub(crate) fn util_sha(path: &Path, expected: &str) -> Result<bool> {
    if expected.is_empty() {
        return Ok(true);
    }
    Ok(crate::util::sha256_file(path)? == expected)
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
pub(crate) fn is_preserved(list: &[String], path: &str) -> bool {
    list.iter().any(|p| path == p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Access, Db};
    use std::fs;

    fn scratch(tag: &str) -> (std::path::PathBuf, Paths, Db) {
        let root =
            std::env::temp_dir().join(format!("portalis-verify-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/db/portalis")).unwrap();
        let paths = Paths::at(root.clone());
        fs::create_dir_all(paths.state_dir()).unwrap();
        let db = Db::open(&paths, Access::Write).unwrap();
        (root, paths, db)
    }

    #[test]
    fn leftovers_without_an_owner_are_reported() {
        let (root, paths, db) = scratch("leftover");
        db.conn()
            .execute(
                "INSERT INTO files (pkg, path, sha256, link_target, mode) \
                 VALUES ('gone', '/usr/share/gone/a', 'aa', '/x/a', 420)",
                [],
            )
            .unwrap();
        fs::write(paths.state_dir().join("activating"), "gone 1.0\n").unwrap();

        let found = leftover_problems(&db, &paths).unwrap();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("never finished"), "{found:?}");
        assert!(found[1].contains("no package row"), "{found:?}");

        fs::remove_file(paths.state_dir().join("activating")).unwrap();
        assert!(leftover_problems(&db, &paths).unwrap().len() == 1);
        let _ = fs::remove_dir_all(root);
    }
}
