//! Store identity, reuse and placement.
use crate::archive::{
    collect_dirs, collect_files, copy_tree, digest_of, normalised_dir_mode, tree_digest,
};
use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(super) fn marker_digest_for(marker: &str, recipe_sha: &str) -> Option<String> {
    if crate::archive::marker_recipe(marker).map(str::trim) != Some(recipe_sha) {
        return None;
    }
    let digest = crate::archive::marker_digest(marker)?.trim();
    if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(digest.to_string())
    } else {
        None
    }
}

pub(super) fn marker_tree_for(marker: &str, recipe_sha: &str) -> Option<String> {
    if crate::archive::marker_recipe(marker).map(str::trim) != Some(recipe_sha) {
        return None;
    }
    let digest = crate::archive::marker_tree(marker)?.trim();
    if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(digest.to_string())
    } else {
        None
    }
}

/// Returns the recorded digest, discarding an unfinished store on the way.
pub(super) fn inspect_store(
    planned_store: &Path,
    recipe_sha: &str,
    log: &mut fs::File,
    db: &crate::db::Db,
) -> Result<Option<String>> {
    let mut exists = store_exists(planned_store)?;
    let marker_path = planned_store.join(crate::archive::STORE_MARKER);
    let marker = match fs::read_to_string(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", marker_path.display()))
        }
    };
    let recorded_files = marker_digest_for(&marker, recipe_sha);
    let recorded_tree = marker_tree_for(&marker, recipe_sha);
    let recorded = recorded_tree.clone().or(recorded_files.clone());
    // A store with no valid marker was never finished; it is discarded unless
    // the ledger still names it.
    if exists && recorded.is_none() {
        if store_referenced(db, planned_store)? {
            bail!(
                "store {} has no valid completion marker but is still referenced; \
                 repair or remove that reference before rebuilding",
                planned_store.display()
            );
        }
        std::fs::remove_dir_all(planned_store).with_context(|| {
            format!("removing the unfinished store {}", planned_store.display())
        })?;
        exists = false;
        writeln!(
            log,
            "note     {} was never finished; building it again",
            planned_store.display()
        )?;
    }
    // An explicit rebuild only discards a store nothing should depend on yet.
    if exists && crate::util::env_flag("PORTALIS_REBUILD") {
        bail!(
            "refusing to rebuild over a complete store: {}\n\
             remove it only when nothing links into it",
            planned_store.display()
        );
    }
    if exists {
        let Some(recorded) = recorded.clone() else {
            bail!(
                "store {} has no completion record; remove it only when nothing links into it",
                planned_store.display()
            );
        };
        let files = collect_files(planned_store)?;
        let content = if recorded_tree.is_some() {
            tree_digest(&files, &collect_dirs(planned_store)?)?
        } else {
            digest_of(&files)?
        };
        if content != recorded {
            bail!(
                "store content does not match its completion marker: {}\n\
                 remove it only when nothing links into it",
                planned_store.display()
            );
        }
    }
    Ok(recorded)
}

/// True when a store path is a directory, after refusing a symlink or other path type.
pub(super) fn store_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("store path is a symlink: {}", path.display())
        }
        Ok(meta) if !meta.is_dir() => {
            bail!("store path is not a directory: {}", path.display())
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn store_referenced(db: &crate::db::Db, store: &Path) -> Result<bool> {
    let matches = |candidate: &str| Path::new(candidate) == store;
    if db.packages()?.iter().any(|pkg| matches(&pkg.store_path))
        || db
            .pending_packages()?
            .iter()
            .any(|pkg| matches(&pkg.store_path))
    {
        return Ok(true);
    }
    let (generations, unreadable) = db.generation_entries()?;
    if unreadable > 0 {
        return Ok(true);
    }
    Ok(generations.iter().any(|(candidate, _)| matches(candidate)))
}

/// Top-level directories that may hold package content.
pub(super) fn wrapper_directory(stage: &Path) -> Result<Option<String>> {
    const ROOT_DIRS: [&str; 15] = [
        "bin", "boot", "etc", "home", "lib", "lib32", "lib64", "libexec", "media", "mnt", "opt",
        "root", "run", "sbin", "srv",
    ];
    let mut entries = fs::read_dir(stage)?;
    let Some(first) = entries.next() else {
        return Ok(None);
    };
    let first = first?;
    if entries.next().is_some() {
        return Ok(None);
    }
    if !first.file_type()?.is_dir() {
        return Ok(None);
    }
    let name = first.file_name().to_string_lossy().to_string();
    let known = ROOT_DIRS.contains(&name.as_str()) || name == "usr" || name == "var";
    Ok(if known { None } else { Some(name) })
}

/// Moves a staged tree into its store entry, or confirms the entry that is
/// already there. Both the source and the binary path end here.
pub(super) fn place_store(
    stage: &Path,
    store_path: &Path,
    recipe_sha: &str,
    setuid: &[String],
    setgid: &[String],
    paths: &Paths,
) -> Result<Vec<crate::recipe::ManifestFile>> {
    // The groups are resolved before the store check on purpose: a recipe
    // naming a group this system lacks is invalid even when a matching store
    // is already present.
    let groups = super::declared_groups(paths, setgid)?;
    if store_exists(store_path)? {
        let marker_path = store_path.join(crate::archive::STORE_MARKER);
        let marker = match fs::read_to_string(&marker_path) {
            Ok(marker) => marker,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "store {} has no completion marker; remove it only when nothing links into it",
                    store_path.display()
                )
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", marker_path.display()))
            }
        };
        let existing_files = collect_files(store_path)?;
        let rebuilt_files = collect_files(stage)?;
        let has_tree = marker_tree_for(&marker, recipe_sha).is_some();
        let (existing, rebuilt) = if has_tree {
            let existing_dirs = collect_dirs(store_path)?;
            let mut rebuilt_dirs = collect_dirs(stage)?;
            for dir in &mut rebuilt_dirs {
                dir.mode = normalised_dir_mode(dir.mode);
            }
            (
                tree_digest(&existing_files, &existing_dirs)?,
                tree_digest(&rebuilt_files, &rebuilt_dirs)?,
            )
        } else {
            (digest_of(&existing_files)?, digest_of(&rebuilt_files)?)
        };
        if existing != rebuilt {
            bail!(
                "store already exists with different content: {}\n                 bump the recipe (version or patch); remove the store only when nothing links into it",
                store_path.display()
            );
        }
        fs::remove_dir_all(stage)?;
        let files = collect_files(store_path)?;
        let dirs = collect_dirs(store_path)?;
        let content = tree_digest(&files, &dirs)?;
        write_marker(store_path, recipe_sha, &digest_of(&files)?, &content)?;
        return Ok(files);
    }

    let store_dir = store_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("store path has no parent: {}", store_path.display()))?;
    fs::create_dir_all(store_dir)?;
    if let Err(error) = fs::rename(stage, store_path) {
        eprintln!("note: cannot rename the stage into the store ({error}); copying instead");
        if let Err(copy_error) = copy_tree(stage, store_path) {
            let _ = fs::remove_dir_all(store_path);
            return Err(copy_error);
        }
    }
    crate::util::sync_dir(store_dir)?;
    if fs::symlink_metadata(store_path)?.file_type().is_symlink() {
        let _ = fs::remove_file(store_path);
        bail!("store path became a symlink; refusing to continue");
    }
    super::normalise_owner(store_path, setuid, &groups)?;
    let files = collect_files(store_path)?;
    let dirs = collect_dirs(store_path)?;
    let content = tree_digest(&files, &dirs)?;
    if let Err(error) = write_marker(store_path, recipe_sha, &digest_of(&files)?, &content) {
        let _ = fs::remove_dir_all(store_path);
        return Err(error).context("writing the store marker");
    }
    Ok(files)
}

/// Writes the completion marker, replacing whatever holds that name and never
/// following it.
fn write_marker(store: &Path, recipe_sha: &str, content: &str, tree: &str) -> Result<()> {
    use std::io::Write;
    let path = store.join(crate::archive::STORE_MARKER);
    match fs::symlink_metadata(&path) {
        Ok(_) => match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("clearing {}", path.display()))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(crate::archive::marker_text(recipe_sha, content, tree).as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", path.display()))?;
    crate::util::sync_dir(store)?;
    Ok(())
}
