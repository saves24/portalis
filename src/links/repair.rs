//! Repairing the links a transaction missed.

use super::live::live_path;
use super::safe::safe_symlink;
use crate::db::Db;
use crate::paths::Paths;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// True when `target`, resolved next to `live`, lands inside `store_path`.
fn resolves_inside(live: &std::path::Path, target: &str, store_path: &str) -> bool {
    let Some(base) = live.parent() else {
        return false;
    };
    let joined = base.join(target);
    let Ok(resolved) = joined.canonicalize() else {
        return false;
    };
    let Ok(store) = std::path::Path::new(store_path).canonicalize() else {
        return false;
    };
    resolved.starts_with(&store)
}

pub(crate) fn repair_links(db: &Db, paths: &Paths) -> Result<()> {
    let target_root = paths.target_root();
    let mut fixed = 0usize;
    let mut missing = 0usize;
    for pkg in db.packages()? {
        let recipe_path = paths.recipes().join(format!("{}.port", pkg.name));
        let preserve = if recipe_path.is_file() {
            match crate::recipe::Recipe::load(&recipe_path) {
                Ok(recipe) => recipe.files.preserve,
                Err(error) => {
                    eprintln!(
                        "warning: links for {} were not repaired: {error:#}",
                        pkg.name
                    );
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        for (path, _sha, link_target, _mode) in db.files_of(&pkg.name)? {
            if preserve.iter().any(|p| p == &path) {
                continue;
            }
            if crate::policy::is_protected_path(&path)
                || (link_target.starts_with('/') && crate::policy::is_protected_path(&link_target))
            {
                continue;
            }
            let desired = format!("{}{}", pkg.store_path, path);
            if fs::symlink_metadata(&desired).is_err() {
                continue;
            }
            let store_root = paths.store().to_string_lossy().to_string();
            let live = live_path(&target_root, &path);
            let mut rewrote = false;
            match fs::symlink_metadata(&live) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    let current = match fs::read_link(&live) {
                        Ok(target) => target.to_string_lossy().to_string(),
                        Err(error) => {
                            eprintln!(
                                "warning: {} could not be read ({error}); it is pointed at its store path",
                                live.display()
                            );
                            String::new()
                        }
                    };
                    // A package-owned link keeps its own target; a link into the
                    // package store follows the store that owns the row.
                    if current != desired
                        && current.starts_with(&store_root)
                        && !resolves_inside(&live, &current, &pkg.store_path)
                    {
                        crate::policy::validate_link_target(
                            &target_root,
                            &path,
                            &desired,
                            Some(Path::new(&pkg.store_path)),
                        )?;
                        safe_symlink(&target_root, &path, &desired)?;
                        rewrote = true;
                        fixed += 1;
                    }
                }
                Err(_) => {
                    if !link_target.is_empty() {
                        crate::policy::validate_link_target(
                            &target_root,
                            &path,
                            &link_target,
                            Some(Path::new(&pkg.store_path)),
                        )?;
                        safe_symlink(&target_root, &path, &link_target)?;
                        rewrote = true;
                        fixed += 1;
                    }
                }
                Ok(_) => {
                    missing += 1;
                }
            }
            if rewrote && link_target.starts_with(&store_root) && link_target != desired {
                db.set_file_target(&pkg.name, &path, &desired)?;
            }
        }
    }
    say!("repaired {fixed} links, {missing} paths left as regular files");
    Ok(())
}
