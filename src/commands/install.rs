//! The install command: resolving the target, building it and applying it.

use crate::build;
use crate::check;
use crate::cli::{install_flags, InstallFlags};
use crate::commands::{housekeeping, referenced_stores, report_reclaimable_stores, store_in_use};
use crate::db;
use crate::elf;
use crate::install;
use crate::json;
use crate::paths::Paths;
use crate::policy;
use crate::resolve::{
    backup_recipe, dependency_graph, find_cycle, load_recipe, require_signature, resolve_target,
    short_hash, update_recipe_source, PendingRecipe,
};
use crate::sign;
use crate::util;
use anyhow::{bail, Context, Result};

fn apply_pending_pin(
    recipe: &mut crate::recipe::Recipe,
    pending: &PendingRecipe,
    update_pin: bool,
) -> Result<()> {
    if recipe.source.sha256 != pending.sha && !update_pin {
        let version_note = match &pending.version {
            Some(version) if *version != recipe.package.version => format!(
                "\n  the recipe pins version {}, this archive is {}",
                recipe.package.version, version
            ),
            _ => String::new(),
        };
        return Err(crate::error::Coded::new(
            crate::error::Code::ShaMismatch,
            format!(
                "the archive does not match the hash pinned in {}\n  pinned {}\n  actual   {}{}\n\
                 run the install again with PORTALIS_UPDATE_PIN=1 to pin this archive instead",
                pending.path.display(),
                recipe.source.sha256,
                pending.sha,
                version_note
            ),
        )
        .into());
    }
    if let Some(version) = &pending.version {
        recipe.package.version = version.clone();
    }
    recipe.source.file = pending.file.clone();
    recipe.source.sha256 = pending.sha.clone();
    Ok(())
}

#[allow(clippy::type_complexity)]
fn resolve_install(
    paths: &Paths,
    target: &str,
    flags: &InstallFlags,
) -> Result<(
    String,
    crate::recipe::Recipe,
    std::path::PathBuf,
    std::path::PathBuf,
    TempPayload,
    Option<build::LocalFlags>,
    Option<PendingRecipe>,
)> {
    let (name, derived, pending_recipe) = resolve_target(paths, target, flags.keep_privileged)?;
    // the payload is already unpacked; register it before the checks below
    let mut payload = TempPayload::default();
    if let Some(derived) = &derived {
        payload.path = derived.temporary.then(|| derived.payload.clone());
        payload.work = Some(derived.work.clone());
    }
    let archive_path =
        std::fs::canonicalize(target).with_context(|| format!("resolving {target}"))?;
    if derived.is_some() && flags.local {
        bail!("{name} is a prebuilt package; --local compiler flags do not apply");
    }
    let (recipe, recipe_path, source_path) = match derived {
        Some(derived) => {
            let path =
                std::fs::canonicalize(&derived.payload).unwrap_or_else(|_| derived.payload.clone());
            (derived.recipe, archive_path.clone(), path)
        }
        None => {
            if flags.keep_privileged {
                eprintln!(
                    "note: PORTALIS_KEEP_PRIVILEGED applies to imported archives; {name} installs from a recipe, \
                     which declares its own install.setuid and install.setgid"
                );
            }
            let (recipe, path) = load_recipe(paths, &name)?;
            (recipe, path, archive_path.clone())
        }
    };
    let mut recipe = recipe;
    if let Some(pending) = &pending_recipe {
        apply_pending_pin(&mut recipe, pending, flags.update_pin)?;
    }
    let local_flags = if flags.local {
        match build::load_local_flags(paths, &name)? {
            Some(flags) => Some(flags),
            None => bail!(
                "{} requested --local but {} does not exist",
                name,
                build::local_config_path(paths, &name).display()
            ),
        }
    } else {
        None
    };
    Ok((
        name,
        recipe,
        recipe_path,
        source_path,
        payload,
        local_flags,
        pending_recipe,
    ))
}

fn dependency_stores(
    recipe: &crate::recipe::Recipe,
    paths: &Paths,
    db: &mut db::Db,
) -> Result<Vec<std::path::PathBuf>> {
    housekeeping(paths, db);
    install::ensure_index(db, paths)?;
    let graph = dependency_graph(paths, db)?;
    let unreadable: Vec<&str> = recipe
        .package
        .depends
        .iter()
        .map(|depend| depend.as_str())
        .filter(|depend| {
            graph
                .unreadable
                .iter()
                .any(|file| file.trim_end_matches(".port") == *depend)
        })
        .collect();
    if !unreadable.is_empty() {
        bail!(
            "cannot check {} for dependency cycles: the recipe for {} does not load",
            recipe.package.name,
            unreadable.join(", ")
        );
    }
    if let Some(cycle) = find_cycle(&graph.edges, &recipe.package.name) {
        bail!("dependency cycle: {}", cycle.join(" -> "));
    }
    let mut dep_stores = Vec::new();
    for dep in &recipe.package.depends {
        match db.package(dep)? {
            Some(row) => dep_stores.push(std::path::PathBuf::from(row.store_path)),
            None => match db
                .pending_packages()?
                .into_iter()
                .find(|pending| pending.name == *dep)
            {
                Some(row) => dep_stores.push(std::path::PathBuf::from(row.store_path)),
                None => bail!("missing build dependency: {dep}; install it first"),
            },
        }
    }
    Ok(dep_stores)
}

fn transitive_dependency_stores(
    recipe: &crate::recipe::Recipe,
    paths: &Paths,
    db: &db::Db,
) -> Result<Vec<std::path::PathBuf>> {
    let mut queue: std::collections::VecDeque<String> =
        recipe.package.depends.iter().cloned().collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut stores = Vec::new();
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let row = match db.package(&name)? {
            Some(row) => row,
            None => match db
                .pending_packages()?
                .into_iter()
                .find(|pending| pending.name == name)
            {
                Some(row) => row,
                None => bail!("missing build dependency: {name}; install it first"),
            },
        };
        stores.push(std::path::PathBuf::from(row.store_path));
        let depends = match crate::recipe::Recipe::load(&paths.recipe_file(&name)) {
            Ok(recipe) => recipe.package.depends,
            Err(_) => db.depends_of(&name)?,
        };
        queue.extend(depends);
    }
    stores.sort();
    stores.dedup();
    Ok(stores)
}

fn sign_manifest(
    recipe: &crate::recipe::Recipe,
    outcome: &build::BuildOutcome,
    paths: &Paths,
    allow_unsigned: bool,
) -> Result<Option<String>> {
    let canonical = outcome.manifest.canonical_bytes()?;
    let signature = sign::sign_bytes(&canonical, paths)?;
    let trusted = sign::has_trusted_keys(&paths.trusted_keys())?;
    if !trusted {
        eprintln!(
            "warning: no trusted keys in {}; accepting an unsigned package",
            paths.trusted_keys().display()
        );
    }
    if trusted || require_signature(paths)? {
        match signature.as_deref() {
            Some(sig) => {
                if !sign::verify_bytes(&canonical, sig, &paths.trusted_keys())? {
                    return Err(crate::error::Coded::new(
                        crate::error::Code::SignatureRequired,
                        format!("signature verification failed for {}", recipe.package.name),
                    )
                    .into());
                }
                say!("signed   verified");
            }
            None => {
                if !allow_unsigned {
                    return Err(crate::error::Coded::new(
                        crate::error::Code::SignatureRequired,
                        "trusted keys are configured but this build is unsigned \
                         (set PORTALIS_ALLOW_UNSIGNED=1 to override)",
                    )
                    .into());
                }
                say!("signed   unsigned build accepted by override");
            }
        }
    }
    Ok(signature)
}

fn report_activation(
    recipe: &crate::recipe::Recipe,
    outcome: &build::BuildOutcome,
    paths: &Paths,
    db: &mut db::Db,
) -> Result<()> {
    let active = db.package(&recipe.package.name)?.is_some();
    if active {
        match elf::record_elf_links(db, &recipe.package.name) {
            Ok(()) => {
                if let Err(error) = db.mark_indexed() {
                    eprintln!("warning: index state not recorded: {error}");
                }
            }
            Err(error) => eprintln!("warning: library edges not recorded: {error}"),
        }
    }
    report_reclaimable_stores(paths, db);
    if install::activation_blocked(paths, &outcome.manifest.files)? {
        let unit = paths.shutdown_unit();
        if !unit.exists() {
            eprintln!(
                "warning: files are in use and {} is absent; \
                     this transaction will not be applied until the shutdown unit is enabled",
                unit.display()
            );
        }
        say!(
            "staged   {} {} from {} (files in use; applied at shutdown)",
            recipe.package.name,
            recipe.package.version,
            outcome.store_path.display()
        );
        json::done(serde_json::json!({
            "package": recipe.package.name,
            "version": recipe.package.version,
            "store": outcome.store_path.display().to_string(),
            "applied": false,
        }));
    } else if install::activate_pending_named(db, paths, &recipe.package.name)? > 0 {
        say!(
            "applied  {} {} from {}",
            recipe.package.name,
            recipe.package.version,
            outcome.store_path.display()
        );
        json::done(serde_json::json!({
            "package": recipe.package.name,
            "version": recipe.package.version,
            "store": outcome.store_path.display().to_string(),
            "files": outcome.manifest.files.len(),
            "applied": true,
        }));
    } else {
        // the activation kept the package staged and said why
        json::done(serde_json::json!({
            "package": recipe.package.name,
            "version": recipe.package.version,
            "store": outcome.store_path.display().to_string(),
            "applied": false,
        }));
    }
    Ok(())
}

fn finish_pending_recipe(pending: Option<&PendingRecipe>) {
    if let Some(pending) = pending {
        // the package is installed; a recipe that cannot be rewritten is a warning
        let written = backup_recipe(&pending.path).and_then(|_| {
            update_recipe_source(
                &pending.path,
                pending.version.as_deref(),
                &pending.file,
                &pending.sha,
            )
        });
        match written {
            Ok(()) => say!(
                "recipe   updated {} (version {}, file {}, sha {})",
                pending.path.display(),
                pending.version.as_deref().unwrap_or("unchanged"),
                pending.file,
                short_hash(&pending.sha)
            ),
            Err(error) => eprintln!("warning: the recipe was not updated: {error:#}"),
        }
    }
}

pub(crate) fn install_cmd(paths: &Paths, db: &mut db::Db, target: String) -> Result<()> {
    // the command line only names the archive; every mode that changes what an
    // install accepts is set where the other internal switches live
    let flags = install_flags();
    let (_name, recipe, recipe_path, source_path, _payload, local_flags, pending_recipe) =
        resolve_install(paths, &target, &flags)?;
    let dep_stores = dependency_stores(&recipe, paths, db)?;
    let check_stores = transitive_dependency_stores(&recipe, paths, db)?;
    json::phase(
        if recipe.source.kind == "binary" {
            "unpack"
        } else {
            "build"
        },
        &recipe.package.name,
        &recipe.package.version,
    );
    // A prebuilt package is only unpacked.
    util::note(&match recipe.source.kind.as_str() {
        "binary" => format!(
            "unpacking {} {} (prebuilt package)",
            recipe.package.name, recipe.package.version
        ),
        _ => format!(
            "building {} {} with {} (the log is written while this runs)",
            recipe.package.name, recipe.package.version, recipe.build.system
        ),
    });
    let outcome = build::build(
        &recipe,
        &recipe_path,
        paths,
        &source_path,
        &dep_stores,
        local_flags.as_ref(),
        flags.allow_path_leak,
        db,
    )?;
    let result = (|| -> Result<()> {
        policy::validate_at(&recipe, &outcome, &paths.target_root())?;
        check::run(&recipe, &outcome, paths, &check_stores)?;
        if flags.dry_run {
            // The build already produced the store entry; a later install reuses it.
            say!(
                "store    {} (built now; an install reuses it)",
                outcome.store_path.display()
            );
            crate::verify::overlap_report(&recipe, &outcome, db, paths)?;
            return Ok(());
        }
        let signature = sign_manifest(&recipe, &outcome, paths, flags.allow_unsigned)?;
        json::phase("activate", &recipe.package.name, &recipe.package.version);
        util::note(&format!(
            "applying {} {} ({} file(s))",
            recipe.package.name,
            recipe.package.version,
            outcome.manifest.files.len()
        ));
        install::install(
            &recipe,
            &outcome,
            db,
            paths,
            &install::InstallOptions { force: flags.force },
            signature.as_deref(),
        )?;
        if let Err(error) =
            db.in_transaction(|db| db.set_depends(&recipe.package.name, &recipe.package.depends))
        {
            eprintln!("warning: declared dependencies not recorded: {error}");
        }
        report_activation(&recipe, &outcome, paths, db)?;
        finish_pending_recipe(pending_recipe.as_ref());
        Ok(())
    })();
    if result.is_err() {
        discard_unreferenced_store(db, paths, &outcome.store_path);
    }
    result
}

/// Drops a store this command wrote when nothing names it.
fn discard_unreferenced_store(db: &db::Db, paths: &Paths, store: &std::path::Path) {
    let Ok((used, unreadable)) = referenced_stores(paths, db) else {
        return;
    };
    if unreadable > 0 {
        return;
    }
    let Some(name) = store
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
    else {
        return;
    };
    if used.contains(&name) {
        return;
    }
    if !matches!(store_in_use(store), Ok(false)) {
        return;
    }
    let _ = std::fs::remove_dir_all(store);
}

/// Package name for a target argument.
/// Removes an extracted payload when the command returns, however it returns.
#[derive(Default)]
struct TempPayload {
    path: Option<std::path::PathBuf>,
    work: Option<std::path::PathBuf>,
}

impl Drop for TempPayload {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(work) = self.work.take() {
            let _ = std::fs::remove_dir_all(work);
        }
    }
}
