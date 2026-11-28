//! Verification: comparing the live tree with the manifest and reporting overlaps.

use crate::db::Db;
use crate::elf::host_library_dirs;
use crate::paths::Paths;
use crate::recipe::Recipe;
use anyhow::Result;
use std::path::Path;

mod files;
mod manifest;
mod overlap;

#[cfg(test)]
mod tests;

use files::{directory_problems, file_problems, runpath_problems};
use manifest::{legacy_manifests, manifest_problems, signed_from_db, store_content_problems};
use overlap::leftover_problems;

pub(crate) use files::util_sha;
pub(crate) use overlap::{dependencies_resolve, overlap_report, report_dependency_health};

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

pub(crate) fn is_preserved(list: &[String], path: &str) -> bool {
    list.iter().any(|p| path == p)
}
