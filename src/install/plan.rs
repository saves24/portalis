//! The install plan: preflight, staging and the ledger rows.

use crate::db::Db;
use crate::elf::{is_elf, ldconfig_libraries, store_path_for};
use crate::paths::Paths;
use crate::proc::{is_critical_path, live_paths_in_use};
use crate::recipe::Recipe;
use crate::verify::{dependencies_resolve, is_preserved, report_dependency_health};
use anyhow::{bail, Result};

use super::generations::{generations_to_keep, protected_generations, write_anchor};

pub struct InstallOptions {
    pub force: bool,
}

fn in_use_paths(
    paths: &Paths,
    outcome: &crate::build::BuildOutcome,
    opts: &InstallOptions,
) -> Result<std::collections::HashSet<String>> {
    match live_paths_in_use(paths) {
        Ok(set) => Ok(set),
        // Without a readable /proc every replaced file is treated as held.
        Err(error) if opts.force => {
            eprintln!("warning: {error:#}");
            eprintln!("         every replaced file is staged for shutdown instead");
            Ok(outcome
                .manifest
                .files
                .iter()
                .map(|file| file.path.clone())
                .collect())
        }
        Err(error) => bail!(
            "{error:#}\n  \
             set PORTALIS_FORCE=1 to stage the transaction for shutdown instead"
        ),
    }
}

fn check_runtime_deps(
    outcome: &crate::build::BuildOutcome,
    in_use: &std::collections::HashSet<String>,
    ld_cache: &std::collections::HashMap<String, String>,
    force: bool,
) -> Result<()> {
    for file in &outcome.manifest.files {
        if !is_critical_path(&file.path, in_use) {
            continue;
        }
        let target = store_path_for(&outcome.store_path, &file.path);
        if is_elf(&target)
            && !dependencies_resolve(
                &target,
                &outcome.manifest.files,
                &outcome.store_path,
                ld_cache,
            )?
            && !force
        {
            bail!(
                "preflight failed for {}: shared libraries missing (set PORTALIS_FORCE=1 to override)",
                file.path
            );
        }
    }
    Ok(())
}

fn stage_manifest(
    recipe: &Recipe,
    outcome: &crate::build::BuildOutcome,
    db: &Db,
) -> Result<(usize, usize)> {
    let mut links = 0usize;
    let mut configs = 0usize;
    for file in &outcome.manifest.files {
        let target = store_path_for(&outcome.store_path, &file.path);
        if is_preserved(&recipe.files.preserve, &file.path) {
            db.stage_file(
                &recipe.package.name,
                file,
                &target.to_string_lossy(),
                "config",
            )?;
            configs += 1;
        } else if let Some(rel) = &file.link {
            db.stage_file(&recipe.package.name, file, rel, "symlink")?;
            links += 1;
        } else {
            db.stage_file(
                &recipe.package.name,
                file,
                &target.to_string_lossy(),
                "link",
            )?;
            links += 1;
        }
    }
    Ok((links, configs))
}

pub fn install(
    recipe: &Recipe,
    outcome: &crate::build::BuildOutcome,
    db: &Db,
    paths: &Paths,
    opts: &InstallOptions,
    signature: Option<&str>,
) -> Result<()> {
    crate::install::preflight::check(recipe, outcome, db, paths, opts)?;
    let in_use = in_use_paths(paths, outcome, opts)?;
    let ld_cache = ldconfig_libraries();
    check_runtime_deps(outcome, &in_use, &ld_cache, opts.force)?;
    let pre_id = db.snapshot(&format!(
        "stage {} {}",
        recipe.package.name, recipe.package.version
    ))?;
    write_anchor(paths, pre_id, &recipe.package.name, &outcome.manifest.files)?;
    db.begin()?;
    let staged = (|| -> Result<(usize, usize)> {
        db.stage_package(
            &outcome.manifest,
            &outcome.store_path.to_string_lossy(),
            &outcome.log_path.to_string_lossy(),
            signature,
            &recipe.hooks,
            opts.force,
        )?;
        db.clear_pending(&recipe.package.name)?;
        stage_manifest(recipe, outcome, db)
    })();
    let (links, configs) = match staged {
        Ok(staged) => staged,
        Err(error) => {
            db.abort();
            return Err(error);
        }
    };
    db.commit()?;
    let keep = generations_to_keep(paths);
    if let Ok(removed) = db.prune_generations(keep, &protected_generations(paths)) {
        if removed > 0 {
            say!("pruned   {removed} old generation(s), keeping {keep}");
        }
    }
    say!(
        "staged   {} {} ({} links, {} configs)",
        recipe.package.name,
        recipe.package.version,
        links,
        configs
    );
    say!("store    {}", outcome.store_path.display());
    report_dependency_health(
        &outcome.store_path,
        &outcome.manifest.files,
        &recipe.install.deps_ignore,
        db,
    );
    Ok(())
}
