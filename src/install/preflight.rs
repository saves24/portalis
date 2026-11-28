//! What has to hold before anything is written: dependencies present, no
//! unmanaged file in the way, and no parent directory another account can swap.
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

use super::InstallOptions;
use crate::db::Db;
use crate::elf::store_path_for;
use crate::links::live_path;
use crate::paths::Paths;
use crate::recipe::Recipe;
use crate::verify::is_preserved;

pub(super) fn check(
    recipe: &Recipe,
    outcome: &crate::build::BuildOutcome,
    db: &Db,
    paths: &Paths,
    opts: &InstallOptions,
) -> Result<()> {
    check_dependencies(recipe, db)?;
    let target_root = paths.target_root();
    check_writable_parents(outcome, &target_root)?;
    check_live_conflicts(recipe, outcome, db, paths, opts, &target_root)
}

/// Every declared dependency is installed or staged, and warns about rpath.
fn check_dependencies(recipe: &Recipe, db: &Db) -> Result<()> {
    let mut missing = Vec::new();
    for dep in &recipe.package.depends {
        if db.package(dep)?.is_none() && db.pending_packages()?.iter().all(|p| p.name != *dep) {
            missing.push(dep.clone());
        }
    }
    if !missing.is_empty() {
        bail!(
            "missing dependencies: {} (install them first)",
            missing.join(", ")
        );
    }

    if recipe.build.isolation.as_deref() == Some("rpath") {
        for dep in &recipe.package.depends {
            if let Some(row) = db.package(dep)? {
                if row.rpath.is_empty() {
                    say!(
                        "warn     dependency {dep} is not rpath isolated; it will still load from /usr/lib"
                    );
                }
            }
        }
    }
    Ok(())
}

/// No live parent directory another account can replace.
fn check_writable_parents(outcome: &crate::build::BuildOutcome, target_root: &Path) -> Result<()> {
    if crate::util::env_flag("PORTALIS_ALLOW_WRITABLE_PARENT") {
        return Ok(());
    }
    let mut shared: Vec<String> = Vec::new();
    for file in &outcome.manifest.files {
        shared.extend(crate::links::writable_parents(target_root, &file.path));
    }
    for dir in &outcome.manifest.dirs {
        shared.extend(crate::links::writable_parents(target_root, &dir.path));
    }
    shared.sort();
    shared.dedup();
    if !shared.is_empty() {
        bail!(
            "refusing to install through directories a non-root account can replace: {}\n\
             root would write there and another account could swap the entry first; install \
             elsewhere, fix the permissions, or set PORTALIS_ALLOW_WRITABLE_PARENT=1 to accept it",
            shared.join(", ")
        );
    }
    Ok(())
}

/// No live path belongs to another package or to the user.
fn check_live_conflicts(
    recipe: &Recipe,
    outcome: &crate::build::BuildOutcome,
    db: &Db,
    paths: &Paths,
    opts: &InstallOptions,
    target_root: &Path,
) -> Result<()> {
    for file in &outcome.manifest.files {
        if is_preserved(&recipe.files.preserve, &file.path) {
            continue;
        }
        let live = live_path(target_root, &file.path);
        let resolved = crate::links::resolved_live_target(target_root, &file.path)
            .with_context(|| format!("resolving the parent of {}", file.path))?;
        let root_canonical = fs::canonicalize(target_root)
            .with_context(|| format!("resolving {}", target_root.display()))?;
        let relative = resolved.strip_prefix(&root_canonical).unwrap_or(&resolved);
        let protected = format!("/{}", relative.display()).replace("//", "/");
        if !crate::policy::allow_protected_paths() && crate::policy::is_protected_path(&protected) {
            bail!(
                "refusing to install {}: it resolves to protected path {}",
                file.path,
                resolved.display()
            );
        }
        let desired = store_path_for(&outcome.store_path, &file.path);

        if let Some((pkg, target)) = db.pending_owner(&file.path)? {
            if pkg != recipe.package.name {
                bail!("file is already staged by {pkg}: {} -> {target}", file.path);
            }
        }
        match fs::symlink_metadata(&live) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some((owner, _)) = db.owner(&file.path)? {
                    if owner != recipe.package.name && !opts.force {
                        bail!(
                            "missing file is still owned by another package ({owner}): {}",
                            live.display()
                        );
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", live.display()));
            }
            Ok(meta) if meta.file_type().is_symlink() => {
                let current = fs::read_link(&live)?;
                if current != desired {
                    match db.owner(&file.path)? {
                        Some((owner, _)) if owner == recipe.package.name => {}
                        Some((owner, _)) => bail!(
                            "file belongs to another package ({owner}): {} -> {}",
                            live.display(),
                            current.display()
                        ),
                        None => {
                            if current.starts_with(paths.store()) {
                                return Err(crate::error::Coded::new(
                                    crate::error::Code::ConflictUnmanaged,
                                    format!(
                                        "file is linked into the store but unowned: {} -> {}",
                                        live.display(),
                                        current.display()
                                    ),
                                )
                                .into());
                            }
                            if !opts.force {
                                return Err(crate::error::Coded::new(
                                    crate::error::Code::ConflictUnmanaged,
                                    format!(
                                        "unmanaged symlink exists: {} -> {} (set PORTALIS_FORCE=1)",
                                        live.display(),
                                        current.display()
                                    ),
                                )
                                .into());
                            }
                        }
                    }
                }
            }
            Ok(_) => {
                if !opts.force {
                    return Err(crate::error::Coded::new(
                        crate::error::Code::ConflictUnmanaged,
                        format!(
                            "unmanaged file exists: {} (set PORTALIS_FORCE=1)",
                            live.display()
                        ),
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}
