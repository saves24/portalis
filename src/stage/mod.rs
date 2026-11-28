//! Turning a built staging tree into a store entry, plus the binary path.

use crate::archive::{
    close_absolute_links_at, collect_dirs, collect_files, unpack_archive, validate_tree_links,
};
use crate::build::{prune_logs, recipe_hash, BuildOutcome, LocalFlags};
use crate::paths::Paths;
use crate::recipe::{BuildManifest, Recipe};
use crate::scrub::scrub_stage;
use crate::util;
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Everything decided before a build starts: hashes, log, store path and reuse.
pub(crate) struct Plan {
    pub(crate) source: fs::File,
    pub(crate) source_sha: String,
    pub(crate) recipe_sha: String,
    pub(crate) log: fs::File,
    pub(crate) log_path: PathBuf,
    pub(crate) store_path: PathBuf,
    pub(crate) rpath: Vec<String>,
}

pub(crate) enum Identified {
    Reuse(Box<BuildOutcome>),
    Fresh(Plan),
}

mod store;

fn source_handle(recipe: &Recipe, source_path: &Path) -> Result<(fs::File, String)> {
    use std::io::{Seek, SeekFrom};
    let mut input = std::fs::File::open(source_path)
        .with_context(|| format!("opening {}", source_path.display()))?;
    // Hash and unpack one private copy of the source.
    let mut source = tempfile::tempfile().with_context(|| "creating a private source copy")?;
    std::io::copy(&mut input, &mut source)
        .with_context(|| format!("copying {}", source_path.display()))?;
    source.seek(SeekFrom::Start(0))?;
    let source_sha = util::sha256_file_handle(&mut source)?;
    if source_sha != recipe.source.sha256 {
        bail!(
            "source hash mismatch for {}\n  expected {}\n  actual   {}",
            recipe.source.file,
            recipe.source.sha256,
            source_sha
        );
    }
    source.seek(SeekFrom::Start(0))?;
    Ok((source, source_sha))
}

#[allow(clippy::too_many_arguments)]
fn open_log(
    recipe: &Recipe,
    recipe_path: &Path,
    paths: &Paths,
    source_path: &Path,
    source_sha: &str,
    recipe_sha: &str,
    local: Option<&LocalFlags>,
) -> Result<(fs::File, PathBuf)> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let log_path = paths.logs().join(format!(
        "{}-{}-{}.log",
        recipe.package.name, recipe.package.version, stamp
    ));
    let log_dir = log_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("log path has no parent: {}", log_path.display()))?;
    if let Ok(meta) = fs::symlink_metadata(paths.logs()) {
        if !meta.file_type().is_dir() {
            bail!(
                "build log directory is not a directory: {}",
                paths.logs().display()
            );
        }
    }
    fs::create_dir_all(log_dir)?;
    if !fs::symlink_metadata(log_dir)
        .with_context(|| format!("reading {}", log_dir.display()))?
        .file_type()
        .is_dir()
    {
        bail!(
            "build log directory is not a directory: {}",
            log_dir.display()
        );
    }
    let mut log = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&log_path)
        .with_context(|| format!("creating {}", log_path.display()))?;
    prune_logs(
        paths,
        &recipe.package.name,
        &recipe.package.version,
        util::BUILD_LOGS_PER_PACKAGE,
    );
    writeln!(
        log,
        "portalis build {} {}\nrecipe {} ({})\nsource {} ({})",
        recipe.package.name,
        recipe.package.version,
        recipe_path.display(),
        recipe_sha,
        source_path.display(),
        source_sha
    )?;
    writeln!(
        log,
        "flags {}",
        if local.is_some() {
            "local (appconfig)"
        } else {
            "recipe"
        }
    )?;
    for tool in ["tar", "patch", "ldconfig"] {
        let version = crate::util::trusted_program(tool)
            .and_then(|program| {
                Command::new(program)
                    .env_clear()
                    .arg("--version")
                    .output()
                    .ok()
                    .and_then(|out| String::from_utf8(out.stdout).ok())
                    .and_then(|text| text.lines().next().map(|line| line.trim().to_string()))
            })
            .unwrap_or_else(|| "not available".to_string());
        writeln!(log, "tool     {tool}: {version}")?;
    }
    Ok((log, log_path))
}

fn planned_rpath(recipe: &Recipe, planned_store: &Path, dep_stores: &[PathBuf]) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    if recipe.build.isolation.as_deref() == Some("rpath") || !dep_stores.is_empty() {
        let prefix = recipe.install.prefix.trim_matches('/');
        let libdir = if prefix.is_empty() {
            "lib".to_string()
        } else {
            format!("{prefix}/lib")
        };
        entries.push(planned_store.join(&libdir).to_string_lossy().to_string());
        for dep in dep_stores {
            for lib in dep_lib_dirs(dep) {
                entries.push(lib.to_string_lossy().to_string());
            }
        }
    }
    entries
}

pub(crate) fn identify(
    recipe: &Recipe,
    recipe_path: &Path,
    paths: &Paths,
    source_path: &Path,
    dep_stores: &[PathBuf],
    local: Option<&LocalFlags>,
    db: &crate::db::Db,
) -> Result<Identified> {
    let (source, source_sha) = source_handle(recipe, source_path)?;
    let recipe_sha = recipe_hash(
        recipe,
        local,
        dep_stores,
        crate::scrub::scrub_paths_enabled(paths),
    )?;
    let (mut log, log_path) = open_log(
        recipe,
        recipe_path,
        paths,
        source_path,
        &source_sha,
        &recipe_sha,
        local,
    )?;
    let planned_store =
        paths.package_store_path(&recipe.package.name, &recipe.package.version, &recipe_sha);
    let rpath_entries = planned_rpath(recipe, &planned_store, dep_stores);
    let recorded = store::inspect_store(&planned_store, &recipe_sha, &mut log, db)?;
    let reuse = planned_store.exists()
        && recorded.is_some()
        && recipe.build.patches.iter().all(|patch| !patch.optional)
        && std::fs::read_dir(&planned_store)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
    if reuse {
        let files = collect_files(&planned_store)?;
        let dirs = collect_dirs(&planned_store)?;
        if !files.is_empty() || !dirs.is_empty() {
            let cflags = local
                .and_then(|flags| flags.cflags.clone())
                .or_else(|| recipe.build.cflags.clone());
            let rustflags = local
                .and_then(|flags| flags.rustflags.clone())
                .or_else(|| recipe.build.rustflags.clone());
            let manifest = BuildManifest::from_recipe(recipe, &recipe_sha, &source_sha, files)
                .with_dirs(dirs)
                .with_rpath(rpath_entries.clone())
                .with_flags(cflags.as_deref(), rustflags.as_deref());
            writeln!(
                log,
                "\nreused existing store {}\nfiles {}\nmanifest {}\n",
                planned_store.display(),
                manifest.files.len(),
                manifest.digest()?
            )?;
            return Ok(Identified::Reuse(Box::new(BuildOutcome {
                store_path: planned_store,
                manifest,
                log_path,
            })));
        }
    }
    Ok(Identified::Fresh(Plan {
        source,
        source_sha,
        recipe_sha,
        log,
        log_path,
        store_path: planned_store,
        rpath: rpath_entries,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install_binary(
    recipe: &Recipe,
    source_path: &Path,
    source: &mut fs::File,
    source_sha: &str,
    recipe_sha: &str,
    paths: &Paths,
    log_path: &Path,
    work: &Path,
    scrub_paths: bool,
    scrub_map: &[(String, String)],
    local: Option<&LocalFlags>,
    allow_path_leak: bool,
    log: &mut fs::File,
) -> Result<BuildOutcome> {
    if local.is_some() {
        bail!(
            "{} is a binary package; --local compiler flags do not apply",
            recipe.package.name
        );
    }
    if !recipe.build.patches.is_empty() {
        bail!(
            "{} is a binary package; patches can only be applied to source builds",
            recipe.package.name
        );
    }
    let stage = work.join("stage");
    fs::create_dir_all(&stage)?;
    if fs::symlink_metadata(&stage)?.file_type().is_symlink() {
        bail!("binary stage is a symlink; refusing to unpack into it");
    }
    // the unpack runs as the unprivileged account that owns the workspace
    let creds = unpack_user();
    if let Some((uid, gid)) = creds {
        chown_tree(work, uid, gid)?;
    }
    unpack_archive(source, &stage, work, creds, log)?;
    // rewrite absolute link targets into the tree, keep the rest
    close_absolute_links_at(&stage, &paths.target_root())?;
    validate_tree_links(&stage, true)?;
    if let Some(name) = store::wrapper_directory(&stage)? {
        bail!(
            "the archive is wrapped in a single directory ({name}); \
             repack it so the archive root is the filesystem root"
        );
    }
    if scrub_paths {
        let report = scrub_stage(&stage, scrub_map)?;
        crate::scrub::check_leaks(&report, allow_path_leak)?;
    }
    if collect_files(&stage)?.is_empty() && collect_dirs(&stage)?.is_empty() {
        bail!("binary package contains no files or directories");
    }
    let store_path =
        paths.package_store_path(&recipe.package.name, &recipe.package.version, recipe_sha);
    let files = store::place_store(
        &stage,
        &store_path,
        recipe_sha,
        &recipe.install.setuid,
        &recipe.install.setgid,
        paths,
    )?;
    let dirs = collect_dirs(&store_path)?;
    let manifest = BuildManifest::prebuilt(recipe, recipe_sha, source_sha, files).with_dirs(dirs);
    writeln!(
        log,
        "binary {}\nstore {}\nfiles {}\nmanifest {}\n",
        source_path.display(),
        store_path.display(),
        manifest.files.len(),
        manifest.digest()?
    )?;
    Ok(BuildOutcome {
        store_path,
        manifest,
        log_path: log_path.to_path_buf(),
    })
}

/// Everything the staging area needs to become a store entry.
pub(crate) struct SealInputs<'a> {
    pub(crate) recipe: &'a Recipe,
    pub(crate) stage: &'a Path,
    pub(crate) store_path: &'a Path,
    pub(crate) source_sha: &'a str,
    pub(crate) recipe_sha: &'a str,
    pub(crate) rpath: &'a [String],
    pub(crate) patches: &'a [String],
    pub(crate) cflags: &'a Option<String>,
    pub(crate) rustflags: &'a Option<String>,
    pub(crate) log_path: &'a Path,
    pub(crate) paths: &'a Paths,
}

pub(crate) fn seal(inputs: SealInputs<'_>, log: &mut fs::File) -> Result<BuildOutcome> {
    // nothing the build started may still be running while the stage is handled
    // as root, and a step that left a daemon behind is stopped here
    if let Some((uid, _gid)) = build_user() {
        util::stop_build_descendants(uid)?;
    }
    // build steps are untrusted code too: a link they plant is held to the same
    // rule as one that arrives inside an archive
    close_absolute_links_at(inputs.stage, &inputs.paths.target_root())?;
    validate_tree_links(inputs.stage, true)?;
    if collect_files(inputs.stage)?.is_empty() && collect_dirs(inputs.stage)?.is_empty() {
        bail!("build produced no files or directories in stage");
    }
    let files = store::place_store(
        inputs.stage,
        inputs.store_path,
        inputs.recipe_sha,
        &inputs.recipe.install.setuid,
        &inputs.recipe.install.setgid,
        inputs.paths,
    )?;

    let manifest =
        BuildManifest::from_recipe(inputs.recipe, inputs.recipe_sha, inputs.source_sha, files)
            .with_dirs(collect_dirs(inputs.store_path)?)
            .with_rpath(inputs.rpath.to_vec())
            .with_patches(inputs.patches.to_vec())
            .with_flags(inputs.cflags.as_deref(), inputs.rustflags.as_deref());

    writeln!(
        log,
        "store {}\nfiles {}\nmanifest {}\n",
        inputs.store_path.display(),
        manifest.files.len(),
        manifest.digest()?
    )?;

    Ok(BuildOutcome {
        store_path: inputs.store_path.to_path_buf(),
        manifest,
        log_path: inputs.log_path.to_path_buf(),
    })
}

pub(crate) fn single_directory(root: &Path) -> Result<PathBuf> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry.path());
        }
    }
    match dirs.len() {
        1 => Ok(dirs.remove(0)),
        0 => bail!("archive has no top-level directory"),
        _ => bail!("archive has multiple top-level directories; set source.dir"),
    }
}

pub(crate) fn expose_etc(store_path: &Path, name: &str, paths: &Paths) -> Result<()> {
    let Some(store_name) = store_path.file_name() else {
        bail!("the store path has no name: {}", store_path.display());
    };
    let link = paths.store_etc().join(name);
    if !store_path.join("etc").is_dir() {
        match std::fs::remove_file(&link) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("removing the previous /etc link"),
        }
        return Ok(());
    }
    match std::fs::remove_file(&link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing the previous /etc link"),
    }
    let target = format!("../packages/{}/etc", store_name.to_string_lossy());
    std::os::unix::fs::symlink(&target, &link)
        .with_context(|| format!("linking {} to {}", link.display(), target))?;
    Ok(())
}

/// The account that unpacks archives and applies patches. This is never root:
/// the sandbox covers the build steps, not the writes that come before them.
///
/// `PORTALIS_ROOT_BUILD` removes the drop entirely, for the case where the
/// caller already runs unprivileged and cannot switch accounts. Setting it on a
/// root invocation means untrusted archives are written as root.
pub(crate) fn unpack_user() -> Option<(u32, u32)> {
    if crate::util::env_flag("PORTALIS_ROOT_BUILD") {
        return None;
    }
    Some((util::BUILD_UID, util::BUILD_GID))
}

pub(crate) fn build_user() -> Option<(u32, u32)> {
    if crate::util::env_flag("PORTALIS_ROOT_BUILD") {
        return None;
    }
    // root is the account inside the bubblewrap namespaces. Every other
    // confinement runs in the host namespaces with the lowered account.
    if crate::util::sandbox_enabled() {
        Some((0, 0))
    } else {
        Some((util::BUILD_UID, util::BUILD_GID))
    }
}

pub(crate) fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    if fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!("refusing to chown symlink {}", path.display());
    }
    if let Err(error) = std::os::unix::fs::lchown(path, Some(uid), Some(gid)) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error).with_context(|| format!("chown {}", path.display()));
        }
    }
    for entry in walkdir::WalkDir::new(path) {
        let entry = entry?;
        let meta = entry.path().symlink_metadata()?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.uid() != uid || meta.gid() != gid {
            if let Err(error) = std::os::unix::fs::lchown(entry.path(), Some(uid), Some(gid)) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error).with_context(|| format!("chown {}", entry.path().display()));
                }
            }
        }
        if entry.file_type().is_dir() {
            let mode = meta.permissions().mode() | 0o700;
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))
                .with_context(|| format!("setting the mode of {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// A path as the recipe names it, with any `./` or `/` prefixes removed.
fn normalise_relative(path: &str) -> String {
    let mut rest = path.trim_start_matches('/');
    while let Some(stripped) = rest.strip_prefix("./") {
        rest = stripped.trim_start_matches('/');
    }
    rest.to_string()
}

/// The setgid paths of a recipe, mapped to the group each one asks for.
fn declared_groups(
    paths: &Paths,
    allowed_setgid: &[String],
) -> Result<std::collections::HashMap<String, u32>> {
    let mut groups = std::collections::HashMap::new();
    for entry in allowed_setgid {
        let (path, group) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("install.setgid entry {entry} names no group"))?;
        let gid = if group.chars().all(|c| c.is_ascii_digit()) {
            group
                .parse::<u32>()
                .with_context(|| format!("install.setgid gid {group} does not fit in 32 bits"))?
        } else {
            resolve_group(paths, group)?
        };
        groups.insert(normalise_relative(path), gid);
    }
    Ok(groups)
}

/// Looks a group name up in the group file of the tree being installed into.
fn resolve_group(paths: &Paths, name: &str) -> Result<u32> {
    let file = paths.target_root().join("etc/group");
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "the system has no group named {name} ({} is missing)",
                file.display()
            )
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", file.display())),
    };
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        let _password = fields.next();
        let gid = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("{} has a short line for {name}", file.display()))?;
        return gid
            .trim()
            .parse::<u32>()
            .with_context(|| format!("gid for {name} in {}", file.display()));
    }
    bail!("the system has no group named {name} in {}", file.display())
}

/// Resolves every declared group before any work starts.
pub(crate) fn check_setgid_groups(paths: &Paths, allowed_setgid: &[String]) -> Result<()> {
    declared_groups(paths, allowed_setgid)?;
    Ok(())
}

fn normalise_owner(
    path: &Path,
    allowed_setuid: &[String],
    groups: &std::collections::HashMap<String, u32>,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(path)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        let group = groups.get(&relative).copied().unwrap_or(0);
        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(entry.path())
            .with_context(|| format!("opening {}", entry.path().display()))?;

        let meta = handle
            .metadata()
            .with_context(|| format!("reading {}", entry.path().display()))?;
        if meta.is_file() && meta.nlink() > 1 {
            bail!(
                "refusing to normalise the hard-linked entry {}",
                entry.path().display()
            );
        }
        let fd = handle.as_raw_fd();
        // Safety: fd is an open descriptor for the entry and stays alive
        // through both calls.
        if unsafe { libc::fchown(fd, 0, group) } != 0 {
            bail!(
                "setting the owner of {}: {}",
                entry.path().display(),
                std::io::Error::last_os_error()
            );
        }
        let declared_suid = allowed_setuid
            .iter()
            .any(|p| normalise_relative(p) == relative);
        let declared_sgid = groups.contains_key(&relative);
        if meta.file_type().is_file() {
            // privileged bits apply only where the recipe declares them
            let had_bits = meta.mode() & 0o6000 != 0;
            let mut mode = meta.mode() & 0o7777 & !0o6000 & !0o022;
            if declared_suid {
                mode |= 0o4000;
            }
            if declared_sgid {
                mode |= 0o2000;
            }
            if had_bits && !declared_suid && !declared_sgid {
                say!("drop privileged bits on {}", entry.path().display());
            }
            if meta.mode() & 0o022 != 0 {
                say!("drop shared-write bits on {}", entry.path().display());
            }
            // Safety: fd is the descriptor opened above.
            if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
                bail!(
                    "setting the set-user-id bit on {}: {}",
                    entry.path().display(),
                    std::io::Error::last_os_error()
                );
            }
        } else if meta.file_type().is_dir() {
            let mut mode = meta.mode() & 0o7777 & !0o6000 & !0o022;
            if declared_sgid {
                mode |= 0o2000;
            }
            if mode != meta.mode() {
                // Safety: fd is the descriptor opened above.
                if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
                    bail!(
                        "setting the mode of {}: {}",
                        entry.path().display(),
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Library directories a dependency actually installed into.
pub(crate) fn dep_lib_dirs(dep: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(dep).follow_links(false) {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !matches!(name.as_ref(), "lib" | "lib32" | "lib64" | "libx32") {
            continue;
        }
        if has_library(entry.path()) {
            out.push(entry.path().to_path_buf());
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        out.push(dep.join("usr/lib"));
    }
    out
}

fn has_library(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().contains(".so"))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod marker_tests {
    use super::store::{marker_digest_for, marker_tree_for, store_exists};

    #[test]
    fn a_store_path_symlink_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).expect("outside");
        let link = dir.path().join("store");
        std::os::unix::fs::symlink(&outside, &link).expect("link");
        let error = store_exists(&link).expect_err("a symlink store was accepted");
        assert!(
            error.to_string().contains("symlink"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_marker_decides_reuse_only_with_a_well_formed_digest_for_this_recipe() {
        let sha = "a".repeat(64);
        let digest = "b".repeat(64);
        let full = crate::archive::marker_text(&sha, &digest, &digest);
        assert_eq!(marker_digest_for(&full, &sha), Some(digest.clone()));
        assert_eq!(marker_tree_for(&full, &sha), Some(digest.clone()));

        let no_digest = format!("recipe {sha}\n");
        assert!(
            marker_digest_for(&no_digest, &sha).is_none(),
            "a marker without a digest was accepted"
        );
        let short = crate::archive::marker_text(&sha, "abc", &digest);
        assert!(
            marker_digest_for(&short, &sha).is_none(),
            "a digest that is not 64 characters was accepted"
        );
        let not_hex = crate::archive::marker_text(&sha, &"z".repeat(64), &digest);
        assert!(
            marker_digest_for(&not_hex, &sha).is_none(),
            "a digest that is not hexadecimal was accepted"
        );
        assert!(
            marker_digest_for(&full, &"c".repeat(64)).is_none(),
            "a marker written for another recipe was accepted"
        );
    }
}

#[cfg(test)]
mod dependency_layout_tests {
    use super::dep_lib_dirs;

    #[test]
    fn a_dependency_reports_every_library_directory_it_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("usr/lib64")).expect("lib64");
        std::fs::write(dir.path().join("usr/lib64/libexample.so"), b"").expect("library");
        let found = dep_lib_dirs(dir.path());
        assert_eq!(found, vec![dir.path().join("usr/lib64")]);
    }

    #[test]
    fn a_dependency_library_directory_is_found_below_any_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("opt/thing/lib")).expect("lib");
        std::fs::write(dir.path().join("opt/thing/lib/libthing.so"), b"").expect("library");
        let found = dep_lib_dirs(dir.path());
        assert_eq!(found, vec![dir.path().join("opt/thing/lib")]);
    }

    #[test]
    fn a_dependency_library_directory_is_found_below_a_deep_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("opt/vendor/product/lib")).expect("lib");
        std::fs::write(dir.path().join("opt/vendor/product/lib/libproduct.so"), b"")
            .expect("library");
        let found = dep_lib_dirs(dir.path());
        assert_eq!(found, vec![dir.path().join("opt/vendor/product/lib")]);
    }

    #[test]
    fn a_dependency_without_a_library_directory_falls_back_to_usr_lib() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(dep_lib_dirs(dir.path()), vec![dir.path().join("usr/lib")]);
    }
}
