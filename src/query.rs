//! Read-only views: package list, details, history, logs, orphans and checks.

use crate::commands::{dir_size, referenced_stores};
use crate::db;
use crate::paths::{self, Paths};
use crate::recipe;
use crate::util;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub(crate) struct QueryArgs {
    pub(crate) show: Option<String>,
    pub(crate) file: Option<String>,
    pub(crate) history: bool,
    pub(crate) orphans: bool,
    pub(crate) verify: bool,
    pub(crate) check: bool,
    pub(crate) logs: Option<String>,
    pub(crate) tail: Option<usize>,
}

fn show_package(paths: &Paths, db: &db::Db, name: &str) -> Result<()> {
    let pkg = match db.package(name)? {
        Some(p) => p,
        None => bail!("not installed: {name}"),
    };
    db::line("package", &pkg.name);
    db::line("version", &pkg.version);
    db::line("store", &pkg.store_path);
    db::line("installed", &pkg.installed_at);
    db::line("recipe", &pkg.recipe_sha256);
    db::line("manifest", &pkg.manifest_digest);
    db::line("log", &pkg.build_log);
    db::line("signature", pkg.signature.unwrap_or_else(|| "-".into()));
    if let Ok(recipe) = recipe::Recipe::load(&paths.recipe_file(name)) {
        if !recipe.package.description.is_empty() {
            db::line("description", &recipe.package.description);
        }
    }
    db::line(
        "size",
        util::human_size(dir_size(std::path::Path::new(&pkg.store_path))),
    );
    let deps = dependencies_of(paths, db, name)?;
    db::line(
        "depends",
        if deps.is_empty() {
            "-".to_string()
        } else {
            deps.join(", ")
        }
        .as_str(),
    );
    let needs = db.needs_of(name)?;
    if !needs.is_empty() {
        let libs: Vec<String> = needs
            .iter()
            .map(|(dep, soname, bits)| format!("{dep} ({soname}, {bits}-bit)"))
            .collect();
        db::line("needs", libs.join(", ").as_str());
    }
    if !db.edges_indexed() {
        say!(
            "note     library edges are not indexed; the next install, remove or rollback rebuilds them"
        );
    }
    let dependents = db.users_of(name)?;
    db::line(
        "used by",
        if dependents.is_empty() {
            "-".to_string()
        } else {
            dependents.join(", ")
        }
        .as_str(),
    );
    for (path, sha, target, mode) in db.files_of(name)? {
        say!("  {path}  {sha}  {mode:o}  -> {target}");
    }
    Ok(())
}

fn list_packages(db: &db::Db) -> Result<()> {
    let packages = db.packages()?;
    if packages.is_empty() {
        say!("no packages installed");
    }
    for pkg in packages {
        let state = match pkg.signature.is_some() {
            // a signature with no manifest is listed as signed (unverified)
            true if db.manifest_of(&pkg.name)?.is_none() => "signed (unverified)",
            true => "signed",
            false => "-",
        };
        say!(
            "{:<28} {:<12} {:<44} {}",
            pkg.name,
            pkg.version,
            pkg.store_path,
            state
        );
    }
    let pending = db.pending_packages()?;
    if !pending.is_empty() {
        say!(
            "pending {} package(s); applied at next shutdown",
            pending.len()
        );
    }
    Ok(())
}

pub(crate) fn query_cmd(paths: &Paths, db: &db::Db, args: QueryArgs) -> Result<()> {
    let QueryArgs {
        show: package,
        file: owns,
        history: generations,
        orphans,
        verify,
        check,
        logs,
        tail,
    } = args;
    let modes = [
        package.is_some(),
        owns.is_some(),
        logs.is_some() || tail.is_some(),
        generations,
        orphans,
        verify,
        check,
    ]
    .into_iter()
    .filter(|chosen| *chosen)
    .count();
    if tail.is_some() && logs.is_none() {
        bail!("--tail needs --logs <package>");
    }
    if modes > 1 {
        bail!("choose one of: --show, --file, --logs, --history, --orphans, --verify, --check");
    }
    if let Some(name) = package {
        show_package(paths, db, &name)?;
    } else if orphans {
        orphan_report(paths, db)?;
    } else if let Some(path) = owns {
        match db.owner(&path)? {
            Some((pkg, _)) => say!("{pkg}"),
            None => say!("no package owns {path}"),
        }
    } else if generations {
        for (id, created, note) in db.generations()? {
            say!("{id:>4}  {created}  {note}");
        }
    } else if verify {
        crate::verify::verify(db, paths)?;
    } else if check {
        check_recipes(paths)?;
        // the index follows the recipes, and every command that writes brings it
        // in step; a read-only report only says so
        if !db.is_writable() {
            eprintln!(
                "note: edits to package.depends are picked up by the next command that writes"
            );
        }
    } else if let Some(name) = logs {
        print_logs(paths, &name, tail)?;
    } else {
        list_packages(db)?;
    }
    Ok(())
}

/// Findings of an orphan audit.
pub(crate) struct Orphans {
    pub(crate) stores: Vec<PathBuf>,
    pub(crate) missing: Vec<String>,
    pub(crate) dangling: Vec<(String, String, String)>,
}

pub(crate) fn find_orphans(paths: &Paths, db: &db::Db) -> Result<Orphans> {
    let (used, unreadable) = referenced_stores(paths, db)?;
    if unreadable > 0 {
        anyhow::bail!(
            "cannot audit orphans: {unreadable} generation manifest(s) could not be read"
        );
    }
    let mut stores: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(paths.store()) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !used.contains(&name) {
                stores.push(entry.path());
            }
        }
    }
    let mut broken = Vec::new();
    for pkg in db.packages()? {
        if !Path::new(&pkg.store_path).exists() {
            broken.push(pkg.name);
        }
    }
    let mut dangling = Vec::new();
    for (pkg, path, target) in db.all_files()? {
        let resolved = if Path::new(&target).is_relative() {
            match Path::new(&path).parent() {
                Some(parent) => paths.under_path(&parent.join(&target)),
                None => PathBuf::from(&target),
            }
        } else {
            PathBuf::from(&target)
        };
        if !resolved.exists() {
            dangling.push((pkg, path, target));
        }
    }
    stores.sort();
    Ok(Orphans {
        stores,
        missing: broken,
        dangling,
    })
}

pub(crate) fn orphan_report(paths: &Paths, db: &db::Db) -> Result<()> {
    let orphaned = find_orphans(paths, db)?;
    for store in &orphaned.stores {
        say!("store    {}", store.display());
    }
    for name in &orphaned.missing {
        say!("missing  {name} (store directory is gone)");
    }
    for (pkg, path, target) in &orphaned.dangling {
        say!("dangling {path} -> {target} ({pkg})");
    }
    say!(
        "orphans  {} unreferenced store(s), {} missing store(s), {} dangling link(s)",
        orphaned.stores.len(),
        orphaned.missing.len(),
        orphaned.dangling.len()
    );
    Ok(())
}

pub(crate) fn dependencies_of(paths: &Paths, db: &db::Db, name: &str) -> Result<Vec<String>> {
    let deps = db.depends_of(name)?;
    if !deps.is_empty() {
        return Ok(deps);
    }
    let path = paths.recipe_file(name);
    if path.exists() {
        return Ok(recipe::Recipe::load(&path)?.package.depends);
    }
    Ok(deps)
}

pub(crate) fn check_recipes(paths: &Paths) -> Result<()> {
    let mut ok = 0usize;
    let mut bad = 0usize;
    for entry in std::fs::read_dir(paths.recipes())? {
        let entry = entry?;
        if !paths::is_recipe(&entry.path()) {
            continue;
        }
        match recipe::Recipe::load(&entry.path()) {
            Ok(_) => ok += 1,
            Err(error) => {
                bad += 1;
                say!("invalid  {}: {error:#}", entry.path().display());
            }
        }
    }
    say!("{ok} recipe(s) valid, {bad} invalid");
    if bad > 0 {
        bail!("{bad} recipe(s) failed to parse");
    }
    Ok(())
}

pub(crate) fn print_logs(paths: &Paths, name: &str, tail: Option<usize>) -> Result<()> {
    let entries = match std::fs::read_dir(paths.logs()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            say!("no build logs for {name}");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let mut logs: Vec<_> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{name}-"))
                && crate::util::log_is_for(&entry.path(), name)
        })
        .collect();
    logs.sort_by_key(|entry| entry.metadata().and_then(|m| m.modified()).ok());
    match (tail, logs.last()) {
        (Some(lines), Some(newest)) => {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = std::fs::File::open(newest.path())?;
            let len = file.metadata()?.len();
            let window = 64 * 1024u64;
            let start = len.saturating_sub(window);
            file.seek(SeekFrom::Start(start))?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let text = String::from_utf8_lossy(&buffer);
            let mut all: Vec<&str> = text.lines().collect();
            if start > 0 && !all.is_empty() {
                all.remove(0);
            }
            let begin = all.len().saturating_sub(lines);
            for line in &all[begin..] {
                say!("{line}");
            }
        }
        (None, _) => {
            for entry in &logs {
                say!("{}", entry.path().display());
            }
            if logs.is_empty() {
                say!("no build logs for {name}");
            }
        }
        (Some(_), None) => say!("no build logs for {name}"),
    }
    Ok(())
}
