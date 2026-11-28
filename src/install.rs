use crate::db::Db;
use crate::elf::{is_elf, ldconfig_libraries, record_needs, record_sonames, store_path_for};
use crate::links::{live_path, safe_symlink};
use crate::paths::Paths;
use std::io::Write;

mod activate;
mod hooks;
mod journal;
mod operations;
mod preflight;
mod remove;
mod rollback;
use crate::proc::{is_critical_path, live_paths_in_use};
use crate::recipe::Recipe;
use crate::verify::{dependencies_resolve, is_preserved, report_dependency_health};
pub use activate::{activate_pending, activate_pending_named};
pub use operations::recover_operations;
pub(crate) use operations::OperationMarker;

/// Undoes activations a crash left half-applied; write commands call this.
pub fn recover_interrupted(paths: &Paths, db: &crate::db::Db) -> Result<usize> {
    journal::replay(paths, &paths.target_root(), Some(db))
}
use anyhow::{bail, Context, Result};
pub use remove::remove;
pub use rollback::rollback;

use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

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

/// Generation ids referenced by the boot and recovery anchors.
fn protected_generations(paths: &Paths) -> Vec<i64> {
    [paths.last_good()]
        .iter()
        .filter_map(|path| {
            let raw = std::fs::read_to_string(path).ok()?;
            let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
            doc.get("generation")?.as_i64()
        })
        .collect()
}

/// `[maintenance] retain_generations`, default five.
const DEFAULT_RETAIN_GENERATIONS: usize = 5;

fn generations_to_keep(paths: &Paths) -> usize {
    let file = paths.config_file();
    match std::fs::read_to_string(&file) {
        Ok(text) => match crate::util::Conf::parse(&text) {
            Ok(conf) => conf
                .get("maintenance.retain_generations")
                .and_then(|value| value.parse::<usize>().ok())
                .map(|value| value.clamp(1, 1000))
                .unwrap_or(DEFAULT_RETAIN_GENERATIONS),
            Err(error) => {
                eprintln!(
                    "warning: cannot parse {}: {error}; keeping {DEFAULT_RETAIN_GENERATIONS} generations",
                    file.display()
                );
                DEFAULT_RETAIN_GENERATIONS
            }
        },
        Err(_) => DEFAULT_RETAIN_GENERATIONS,
    }
}

/// What stood at a live path before this attempt replaced it.
pub(crate) use journal::Previous;

/// Records that an activation is in progress, and clears that record when it
/// ends, including when it ends by returning early.
struct ActivationMarker {
    path: Option<PathBuf>,
}

impl ActivationMarker {
    fn start(paths: &Paths, name: &str, version: &str) -> Result<Self> {
        let path = paths.state_dir().join("activating");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.write_all(format!("{name} {version}\n").as_bytes())?;
        file.sync_all()?;
        crate::util::sync_dir(&paths.state_dir())?;
        Ok(Self { path: Some(path) })
    }

    /// Drops the record once the activation has committed.
    fn finish(mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for ActivationMarker {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

/// Drops the activation records and the operation marker that a write command
/// refuses to run past, naming each one it removes.
pub fn discard_recovery(paths: &Paths) -> Result<usize> {
    let mut dropped = 0usize;
    let dir = paths.state_dir();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            let journal = (name.starts_with("activation-journal-")
                || name.starts_with("operation-journal-"))
                && name.ends_with(".jsonl");
            if !journal {
                continue;
            }
            if fs::remove_file(entry.path()).is_ok() {
                say!("dropped  {}", entry.path().display());
                dropped += 1;
            }
        }
    }
    for name in ["operation", "activating"] {
        let marker = dir.join(name);
        if fs::remove_file(&marker).is_ok() {
            say!("dropped  {}", marker.display());
            dropped += 1;
        }
    }
    if dropped == 0 {
        say!("nothing  to discard");
    } else {
        say!("note     the paths the dropped records named are no longer rolled back;");
        say!("         reinstall the affected packages if the tree looks wrong");
    }
    Ok(dropped)
}

/// Rebuilds the derived edge tables that the query views read.
pub fn reindex(db: &Db, paths: &Paths) -> Result<()> {
    db.in_transaction(|db| {
        sync_depends_locked(db, paths)?;
        let packages = db.packages()?;
        for pkg in &packages {
            record_sonames(db, &pkg.name)?;
        }
        for pkg in &packages {
            record_needs(db, &pkg.name)?;
        }
        db.mark_indexed()?;
        Ok(())
    })
}

/// Rebuilds the derived edge tables when they are missing.
pub fn ensure_index(db: &Db, paths: &Paths) -> Result<()> {
    if db.edges_indexed() {
        return Ok(());
    }
    reindex(db, paths)
}

/// Rewrites the declared edges of every installed package from its recipe.
pub fn sync_depends(db: &Db, paths: &Paths) -> Result<()> {
    db.in_transaction(|db| sync_depends_locked(db, paths))
}

fn sync_depends_locked(db: &Db, paths: &Paths) -> Result<()> {
    let packages = db.packages()?;
    let mut kept = Vec::new();
    for pkg in &packages {
        let path = paths.recipe_file(&pkg.name);
        let recipe = if path.exists() {
            crate::recipe::Recipe::load(&path).ok()
        } else {
            None
        };
        match recipe {
            Some(recipe) => db.set_depends(&pkg.name, &recipe.package.depends)?,
            None => kept.push(pkg.name.clone()),
        }
    }
    let installed: std::collections::HashSet<String> =
        packages.iter().map(|pkg| pkg.name.clone()).collect();
    let stale = db.package_names_with_edges()?;
    for pkg in stale.iter().filter(|name| !installed.contains(*name)) {
        db.clear_depends(pkg)?;
    }
    if !kept.is_empty() {
        eprintln!(
            "warning: kept declared edges for {} package(s) without a readable recipe: {}",
            kept.len(),
            kept.join(", ")
        );
    }
    Ok(())
}

fn warn_missing_backup(path: &str, backup: &Path) {
    eprintln!(
        "warning: {path} was taken over but its backup {} is missing; the path stays empty",
        backup.display()
    );
}

/// Moves a file, falling back to copy-and-remove when the two paths sit on
/// different filesystems (the state directory is often its own mount).
fn move_file(from: &Path, to: &Path) -> Result<()> {
    let sync_parents = || -> Result<()> {
        let from_parent = from
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent", from.display()))?;
        crate::util::sync_dir(from_parent)?;
        let to_parent = to
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent", to.display()))?;
        if to_parent != from_parent {
            crate::util::sync_dir(to_parent)?;
        }
        Ok(())
    };
    if fs::rename(from, to).is_ok() {
        sync_parents()?;
        return Ok(());
    }
    let meta = fs::symlink_metadata(from).with_context(|| format!("reading {}", from.display()))?;
    let sequence = MOVE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = to.with_file_name(format!(".portalis-move-{}-{sequence}", std::process::id()));
    let result = (|| -> Result<()> {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(from)?;
            std::os::unix::fs::symlink(&target, &temporary)?;
        } else if meta.is_dir() {
            crate::archive::copy_tree(from, &temporary)?;
        } else {
            fs::copy(from, &temporary)?;
            std::fs::set_permissions(&temporary, meta.permissions())?;
            std::os::unix::fs::chown(&temporary, Some(meta.uid()), Some(meta.gid()))?;
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temporary)?
                .sync_all()?;
        }
        fs::rename(&temporary, to)?;
        if meta.is_dir() {
            fs::remove_dir_all(from)?;
        } else {
            fs::remove_file(from)?;
        }
        Ok(())
    })();
    if result.is_err() {
        if meta.is_dir() {
            let _ = fs::remove_dir_all(&temporary);
        } else {
            let _ = fs::remove_file(&temporary);
        }
    }
    result?;
    sync_parents()?;
    Ok(())
}

static MOVE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Drops the staged copy of a package and leaves the installed version alone.
pub fn drop_staged(name: &str, db: &Db) -> Result<()> {
    if !db.pending_packages()?.iter().any(|pkg| pkg.name == name) {
        bail!("nothing is staged for {name}");
    }
    db.drop_pending(name)?;
    match db.package(name)? {
        Some(_) => say!("dropped  {name} (staged copy; the installed version stays)"),
        None => say!("dropped  {name} (was staged, never activated)"),
    }
    Ok(())
}

/// Recreates the links an interrupted remove already deleted. Paths that now hold
/// a restored original or a user file are left untouched.
fn relink_after_failed_remove(
    target_root: &Path,
    files: &[(String, String, String, u32)],
) -> (usize, usize) {
    let mut relinked = 0usize;
    let mut skipped = 0usize;
    for (path, _sha, link_target, _mode) in files {
        let live = live_path(target_root, path);
        if fs::symlink_metadata(&live).is_ok() {
            skipped += 1;
            continue;
        }
        if let Some(parent) = live.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                eprintln!("warning: cannot recreate {}: {error}", parent.display());
                skipped += 1;
                continue;
            }
        }
        match crate::policy::validate_link_target(target_root, path, link_target, None)
            .and_then(|()| safe_symlink(target_root, path, link_target))
        {
            Ok(()) => relinked += 1,
            Err(error) => {
                eprintln!("warning: cannot relink {path}: {error:#}");
                skipped += 1;
            }
        }
    }
    (relinked, skipped)
}

/// True when no replaced file is mapped or executed.
pub fn activation_blocked(paths: &Paths, files: &[crate::recipe::ManifestFile]) -> Result<bool> {
    if files.iter().any(|file| {
        file.path.starts_with("/boot/")
            || file.path.starts_with("/lib/modules/")
            || file.path.starts_with("/usr/lib/modules/")
    }) {
        return Ok(true);
    }
    let in_use = match live_paths_in_use(paths) {
        Ok(set) => set,
        // a failed scan counts as "in use"
        Err(error) => {
            eprintln!("warning: {error:#}");
            eprintln!("         the transaction is staged for shutdown");
            return Ok(true);
        }
    };
    Ok(files.iter().any(|file| in_use.contains(&file.path)))
}

fn write_anchor(
    paths: &Paths,
    generation: i64,
    package: &str,
    files: &[crate::recipe::ManifestFile],
) -> Result<()> {
    let doc = serde_json::json!({
        "generation": generation,
        "package": package,
        "created": crate::now(),
        "files": files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(),
        "rollback": format!("moirse rollback {generation}"),
    });
    let bytes = serde_json::to_vec_pretty(&doc)?;
    let path = paths.last_good();
    let sequence = ANCHOR_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = path.with_file_name(format!(".last-good-{}-{sequence}", std::process::id()));
    let result = (|| -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("writing {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing {}", temporary.display()))?;
        drop(file);
        std::fs::rename(&temporary, &path).with_context(|| format!("moving {}", path.display()))?;
        crate::util::sync_dir(&paths.state_dir())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

static ANCHOR_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::activate::{apply_pending_file, restore_created};
    use crate::install::hooks::hook_line;

    #[test]
    fn a_path_whose_backup_is_missing_is_left_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        let live = root.join("usr/bin/tool");
        std::fs::write(&live, b"user data").expect("user file");

        let created = vec![(
            "usr/bin/tool".to_string(),
            Previous::Displaced {
                backup: root.join("backup/usr/bin/tool").display().to_string(),
            },
        )];
        restore_created(root, &created);

        assert_eq!(
            std::fs::read(&live).expect("the user file was removed"),
            b"user data"
        );
    }

    #[test]
    fn a_link_and_a_new_path_are_restored() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        std::fs::write(root.join("usr/bin/new"), b"x").expect("file");

        let created = vec![
            ("usr/bin/new".to_string(), Previous::Missing),
            (
                "usr/bin/old".to_string(),
                Previous::Symlink {
                    target: "/store/x".to_string(),
                },
            ),
        ];
        restore_created(root, &created);

        assert!(
            !root.join("usr/bin/new").exists(),
            "a new path was left behind"
        );
        let target = std::fs::read_link(root.join("usr/bin/old")).expect("link");
        assert_eq!(target, PathBuf::from("/store/x"));
    }

    #[test]
    fn a_failed_link_puts_the_adopted_file_back() {
        use crate::db::{Access, PackageRow, PackageState};
        use crate::recipe::{Hooks, ManifestFile};

        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        let paths = Paths::at(root);
        paths.ensure_layout().expect("layout");
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        let live = root.join("usr/bin/tool");
        std::fs::write(&live, b"user data").expect("user file");
        let store = root.join("store/pkg/tool");
        std::fs::create_dir_all(store.parent().expect("store dir")).expect("store dir");
        std::fs::write(&store, b"binary").expect("store file");

        let db = Db::open(&paths, Access::Write).expect("db");
        let file = ManifestFile {
            path: "/usr/bin/tool".into(),
            sha256: crate::util::sha256_file(&store).expect("sha"),
            mode: 0,
            link: None,
        };
        db.stage_file("pkg", &file, store.to_str().expect("utf8"), "file")
            .expect("stage");

        let pkg = PackageRow {
            name: "pkg".into(),
            version: "1.0".into(),
            store_path: "store/pkg".into(),
            recipe_sha256: String::new(),
            manifest_digest: String::new(),
            installed_at: String::new(),
            build_log: String::new(),
            signature: None,
            rpath: Vec::new(),
            hooks: Hooks::default(),
            state: PackageState::StagedForced,
        };

        crate::links::FAIL_NEXT_LINK.with(|flag| flag.set(true));
        let mut kept = 0usize;
        let entry = (
            "/usr/bin/tool".to_string(),
            file.sha256.clone(),
            store.to_str().expect("utf8").to_string(),
            0u32,
            "file".to_string(),
        );
        let result = apply_pending_file(&db, &pkg, &paths, root, entry, &mut kept);
        assert!(result.is_err(), "the injected link failure was swallowed");
        assert_eq!(
            std::fs::read(&live).expect("the user file is gone"),
            b"user data"
        );
        assert!(
            !paths.state_dir().join("backup/usr/bin/tool").exists(),
            "the backup was left behind"
        );
    }

    #[test]
    fn an_old_pending_link_to_a_shared_directory_is_refused() {
        use crate::db::{Access, PackageRow, PackageState};
        use crate::recipe::Hooks;

        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        let paths = Paths::at(root);
        paths.ensure_layout().expect("layout");
        let db = Db::open(&paths, Access::Write).expect("db");
        let pkg = PackageRow {
            name: "pkg".into(),
            version: "1.0".into(),
            store_path: root.join("store/pkg").to_string_lossy().into_owned(),
            recipe_sha256: String::new(),
            manifest_digest: String::new(),
            installed_at: String::new(),
            build_log: String::new(),
            signature: None,
            rpath: Vec::new(),
            hooks: Hooks::default(),
            state: PackageState::Staged,
        };
        let mut kept = 0usize;
        let entry = (
            "/usr/bin/old".to_string(),
            String::new(),
            "/tmp/evil".to_string(),
            0u32,
            "symlink".to_string(),
        );
        let error = apply_pending_file(&db, &pkg, &paths, root, entry, &mut kept)
            .expect_err("the old pending link was accepted");
        assert!(
            format!("{error}").contains("link target") || format!("{error}").contains("writable"),
            "{error:#}"
        );
        assert!(!root.join("usr/bin/old").exists());
    }

    #[test]
    fn a_staged_package_does_not_replace_an_unowned_symlink() {
        use crate::db::{Access, PackageRow, PackageState};
        use crate::recipe::Hooks;

        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        let paths = Paths::at(root);
        paths.ensure_layout().expect("layout");
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        let live = root.join("usr/bin/tool");
        std::os::unix::fs::symlink("/tmp/elsewhere", &live).expect("existing link");
        let store = root.join("store/pkg/tool");
        std::fs::create_dir_all(store.parent().expect("store dir")).expect("store dir");
        std::fs::write(&store, b"binary").expect("store file");

        let db = Db::open(&paths, Access::Write).expect("db");
        let pkg = PackageRow {
            name: "pkg".into(),
            version: "1.0".into(),
            store_path: root.join("store/pkg").to_string_lossy().into_owned(),
            recipe_sha256: String::new(),
            manifest_digest: String::new(),
            installed_at: String::new(),
            build_log: String::new(),
            signature: None,
            rpath: Vec::new(),
            hooks: Hooks::default(),
            state: PackageState::Staged,
        };
        let mut kept = 0usize;
        let entry = (
            "/usr/bin/tool".to_string(),
            crate::util::sha256_file(&store).expect("sha"),
            store.to_string_lossy().into_owned(),
            0u32,
            "file".to_string(),
        );
        let error = apply_pending_file(&db, &pkg, &paths, root, entry, &mut kept)
            .expect_err("the unowned link was replaced");
        assert!(format!("{error}").contains("unowned"), "{error:#}");
        assert_eq!(
            std::fs::read_link(&live).expect("the existing link was removed"),
            PathBuf::from("/tmp/elsewhere")
        );
    }

    #[test]
    fn a_hook_that_succeeds_reports_nothing() {
        let result = std::process::Command::new("true").status();
        assert!(hook_line("true", result).is_none());
    }

    #[test]
    fn a_hook_that_fails_is_reported_with_its_status() {
        let result = std::process::Command::new("false").status();
        let line = hook_line("ldconfig in /tmp/x", result).expect("the failure was swallowed");
        assert!(
            line.contains("ldconfig in /tmp/x"),
            "unexpected text: {line}"
        );
        assert!(line.contains("exited"), "no exit status: {line}");
    }

    #[test]
    fn a_hook_that_cannot_start_is_reported() {
        let result = std::process::Command::new("definitely-not-a-command").status();
        let line = hook_line("icon cache", result).expect("the failure was swallowed");
        assert!(line.contains("could not run"), "unexpected text: {line}");
    }

    #[test]
    fn a_backup_path_never_escapes_the_backup_directory() {
        let state = Path::new("/var/lib/portalis");
        for path in ["/etc/rpc", "etc/rpc", "/usr/lib/libc.so.6"] {
            let backup = state.join("backup").join(path.trim_start_matches('/'));
            assert!(
                backup.starts_with("/var/lib/portalis/backup/"),
                "{path} produced {backup:?}"
            );
        }
    }

    #[test]
    fn elf_info_reads_the_running_binary() {
        let exe = std::env::current_exe().expect("current executable");
        let info = crate::elf::elf_info(&exe).expect("parses as ELF");
        assert!(!info.needed.is_empty(), "no NEEDED entries");
        assert!(info.interpreter.is_some(), "no program interpreter");
    }

    #[test]
    fn runpath_entries_reaching_host_library_dirs_are_not_isolated() {
        let store = PathBuf::from("/usr/portalis/packages/pkg-1.0-abcdef123456");
        let host = vec![PathBuf::from("/usr/lib"), PathBuf::from("/usr/lib64")];
        assert!(crate::elf::runpath_is_isolated(
            &store,
            "/usr/portalis/packages/pkg-1.0-abcdef123456/usr/lib",
            &host
        ));
        assert!(!crate::elf::runpath_is_isolated(
            &store,
            "$ORIGIN/../lib",
            &host
        ));
        assert!(crate::elf::runpath_is_isolated(
            &store,
            "/opt/vendor/lib",
            &host
        ));
        assert!(!crate::elf::runpath_is_isolated(&store, "/usr/lib", &host));
        assert!(!crate::elf::runpath_is_isolated(
            &store,
            "/usr/lib64",
            &host
        ));
        assert!(!crate::elf::runpath_is_isolated(&store, "lib", &host));
        assert!(!crate::elf::runpath_is_isolated(
            &store,
            "/opt/vendor/lib",
            &[]
        ));
    }

    #[test]
    fn live_paths_are_derived_from_store_locations() {
        let paths = Paths::new();
        assert_eq!(
            crate::proc::live_from_store(
                &paths,
                "/usr/portalis/packages/systemd-261.2-abc/usr/lib/systemd/systemd"
            ),
            Some("/usr/lib/systemd/systemd".into())
        );
        assert_eq!(
            crate::proc::live_from_store(&paths, "/usr/bin/firefox"),
            None
        );
    }

    #[test]
    fn criticality_follows_actual_use_plus_boot_artifacts() {
        let mut used = std::collections::HashSet::new();
        used.insert("/usr/lib/libc.so.6".to_string());
        assert!(is_critical_path("/usr/lib/libc.so.6", &used));
        assert!(is_critical_path("/boot/vmlinuz", &used));
        assert!(!is_critical_path("/usr/bin/firefox", &used));
    }

    #[test]
    fn safe_symlink_rejects_parent_components() {
        let root = std::env::temp_dir().join(format!("portalis-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let error = safe_symlink(&root, "../escape", "target").unwrap_err();
        assert!(
            format!("{error:#}").contains("parent component"),
            "unexpected error: {error:#}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_remove_recreates_the_links_it_deleted() {
        let root = std::env::temp_dir().join(format!("portalis-relink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let files = vec![(
            "usr/bin/x".to_string(),
            "0".repeat(64),
            "store/x/bin".to_string(),
            0o755u32,
        )];
        let (relinked, skipped) = relink_after_failed_remove(&root, &files);
        assert_eq!(
            (relinked, skipped),
            (1, 0),
            "the missing link was not recreated"
        );
        assert_eq!(
            fs::read_link(root.join("usr/bin/x")).unwrap(),
            PathBuf::from("store/x/bin")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_restored_original_survives_a_failed_remove() {
        let root = std::env::temp_dir().join(format!("portalis-relink-own-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/conf"), "original\n").unwrap();
        let files = vec![(
            "etc/conf".to_string(),
            "0".repeat(64),
            "store/conf".to_string(),
            0o644u32,
        )];
        let (relinked, skipped) = relink_after_failed_remove(&root, &files);
        assert_eq!(
            (relinked, skipped),
            (0, 1),
            "a restored file was overwritten"
        );
        assert_eq!(
            fs::read_to_string(root.join("etc/conf")).unwrap(),
            "original\n"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_symlink_creates_nested_link() {
        let root = std::env::temp_dir().join(format!("portalis-link-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        safe_symlink(&root, "usr/lib/libx.so.1", "store/libx.so.1").unwrap();
        let link = root.join("usr/lib/libx.so.1");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("store/libx.so.1")
        );
        let _ = fs::remove_dir_all(&root);
    }
    #[test]
    fn boot_artifacts_always_defer_activation() {
        let files = vec![crate::recipe::ManifestFile {
            path: "/boot/vmlinuz".into(),
            sha256: String::new(),
            mode: 0o644,
            link: None,
        }];
        assert!(activation_blocked(&Paths::at("/"), &files).unwrap());
    }
}

#[cfg(test)]
mod icon_hook_tests {
    use crate::install::hooks::is_icon_theme_dir;

    #[test]
    fn only_theme_directories_under_share_are_accepted() {
        assert!(is_icon_theme_dir("/usr/share/icons/hicolor"));
        assert!(is_icon_theme_dir("/usr/share/pixmaps"));
        assert!(!is_icon_theme_dir("/etc"));
        assert!(!is_icon_theme_dir("/usr/share/icons/../../etc"));
        assert!(!is_icon_theme_dir("usr/share/icons/hicolor"));
        assert!(!is_icon_theme_dir("/usr/share/pixmaps-evil"));
    }
}
