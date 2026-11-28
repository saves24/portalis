#[macro_use]
mod json;
mod archive;
mod build;
mod build_container;
mod check;
mod commands;
mod db;
mod db_edges;
mod derive;
mod elf;
mod error;
mod host_abi;
mod install;
mod landlock;
mod links;
mod paths;
mod policy;
mod proc;
mod query;
mod recipe;
mod resolve;
mod rootfs;
mod scrub;
mod sign;
mod stage;
mod steps;
mod tar;
mod util;
mod verify;

use crate::commands::{clean_cmd, housekeeping, report_reclaimable_stores};
use crate::query::{query_cmd, QueryArgs};
use crate::resolve::{
    backup_recipe, dependency_graph, find_cycle, load_recipe, require_signature, resolve_target,
    short_hash, update_recipe_source, PendingRecipe,
};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

pub use paths::Paths;
pub(crate) use resolve::ARCH_SEGMENTS;

const BACKUP_RETENTION_DAYS: u64 = 30;

pub fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// The name the command installs under; release artifacts keep `portalis`.
pub const COMMAND_NAME: &str = "moirse";

#[derive(Parser)]
#[command(
    name = COMMAND_NAME,
    version,
    long_version = crate::rootfs::LONG_VERSION,
    about = "Portalis package manager (offline, hash-locked)"
)]
struct Cli {
    /// Show one package in detail
    #[arg(long, value_name = "PACKAGE")]
    show: Option<String>,
    /// Find the package that owns a path
    #[arg(long, value_name = "PATH")]
    file: Option<String>,
    /// List installation generations
    #[arg(long)]
    history: bool,
    /// Report stores, rows and links that nothing references
    #[arg(long)]
    orphans: bool,
    /// Check every activated file against its hash
    #[arg(long)]
    verify: bool,
    /// Check that every recipe parses
    #[arg(long)]
    check: bool,
    /// List build logs for a package, or print the tail with --tail
    #[arg(long, value_name = "PACKAGE")]
    logs: Option<String>,
    /// Print the last N lines of the build log
    #[arg(long, value_name = "LINES")]
    tail: Option<usize>,
    /// Silence the progress lines a long command prints while it works
    #[arg(long)]
    quiet: bool,
    /// Drop the record that blocks write commands, after printing what it names
    #[arg(long)]
    discard_recovery: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and apply a package from an archive
    Install {
        /// Path to a source or binary archive
        target: String,
    },
    /// Unlink a package, optionally deleting its store directory
    Remove {
        name: String,
        #[arg(long)]
        purge: bool,
        /// Drop a staged copy only; the installed version stays
        #[arg(long = "pending")]
        pending_only: bool,
        /// Remove even when a file is in use, the store is busy, or another package depends on it
        #[arg(long)]
        force: bool,
    },
    /// Restore the package set recorded in a generation
    Rollback { id: i64 },
    /// Remove old logs, unused stores and stale build trees
    Clean {
        #[arg(long)]
        logs: bool,
        #[arg(long)]
        store: bool,
        #[arg(long)]
        backups: bool,
        #[arg(long)]
        yes: bool,
    },
}

fn main() {
    // a build step that detaches must leave its children below this process
    util::become_subreaper();
    if let Err(err) = run() {
        json::fail(&err);
        eprintln!("{COMMAND_NAME}: {err:#}");
        std::process::exit(1);
    }
}

fn check_listing(cli: &Cli) -> Result<()> {
    let listing = cli.show.is_some()
        || cli.file.is_some()
        || cli.history
        || cli.orphans
        || cli.verify
        || cli.check
        || cli.logs.is_some();
    if cli.command.is_some() && listing {
        bail!(
            "the listing flags (--show, --file, --history, --orphans, --verify, --check, --logs) \
             describe the package list; they do not combine with a command"
        );
    }
    Ok(())
}

fn open_database(paths: &Paths, reading: bool) -> Result<db::Db> {
    match db::Db::open(
        paths,
        if reading {
            db::Access::Read
        } else {
            db::Access::Write
        },
    ) {
        Ok(db) => Ok(db),
        // a database that exists but cannot be opened is a permission problem;
        // one that is missing is simply a fresh system
        Err(error) if reading && paths.db_file().exists() => {
            bail!("{error}\nthe package database is not readable by this account; run this as root")
        }
        Err(error) => Err(error),
    }
}

fn recover_before_write(db: &mut db::Db, paths: &Paths, discard: bool) -> Result<()> {
    if discard {
        install::discard_recovery(paths)?;
    }
    // The activation record is read with the database open. A state that
    // cannot be repaired stops every write command.
    match install::recover_interrupted(paths, db) {
        Ok(0) => {}
        Ok(restored) => say!("recovered {restored} path(s) from an activation that did not finish"),
        Err(error) => {
            return Err(crate::error::Coded::new(
                crate::error::Code::RecoveryBlocked,
                format!(
                    "an interrupted activation could not be repaired; no write command runs until it is.\n{error:#}"
                ),
            )
            .into())
        }
    }
    install::recover_operations(db, paths).map_err(|error| {
        anyhow::Error::from(crate::error::Coded::new(
            crate::error::Code::RecoveryBlocked,
            format!(
                "an interrupted operation could not be repaired; no write command runs until it is.\n{error:#}"
            ),
        ))
    })?;
    Ok(())
}

fn run_query(args: QueryArgs, paths: &Paths, db: &mut db::Db) -> Result<()> {
    if util::env_flag("PORTALIS_APPLY_PENDING") {
        let _ = install::activate_pending(db, paths)?;
        return Ok(());
    }
    query_cmd(paths, db, args)
}

fn dispatch(command: Commands, paths: &Paths, db: &mut db::Db) -> Result<()> {
    match command {
        Commands::Install { target } => {
            install_cmd(paths, db, target)?;
        }
        Commands::Remove {
            name,
            purge,
            pending_only,
            force,
        } => {
            if pending_only {
                install::drop_staged(&name, db)?;
            } else {
                install::ensure_index(db, paths)?;
                install::sync_depends(db, paths)?;
                install::remove(&name, db, paths, purge, force)?;
            }
        }
        Commands::Rollback { id } => {
            install::ensure_index(db, paths)?;
            install::rollback(id, db, paths)?;
        }
        Commands::Clean {
            logs,
            store,
            backups,
            yes,
        } => {
            clean_cmd(paths, db, logs, store, backups, yes)?;
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    util::set_quiet(cli.quiet);
    json::enable(util::env_flag("PORTALIS_JSON"));
    check_listing(&cli)?;
    let paths = Paths::new();
    let clean_preview = matches!(&cli.command, Some(Commands::Clean { yes: false, .. }));
    let reading = (cli.command.is_none() || clean_preview)
        && !util::env_flag("PORTALIS_APPLY_PENDING")
        && !cli.discard_recovery;
    if reading && !paths.db_file().exists() {
        if cli.check {
            return query::check_recipes(&paths);
        }
        if let Some(name) = cli.logs.as_deref() {
            return query::print_logs(&paths, name, cli.tail);
        }
    }
    if !reading {
        paths.ensure_layout()?;
    }
    // The write connection migrates the schema; the lock is taken first.
    let _lock = if reading {
        None
    } else {
        Some(util::lock_state(&paths.state_dir())?)
    };
    let mut db = open_database(&paths, reading)?;
    if !reading {
        recover_before_write(&mut db, &paths, cli.discard_recovery)?;
    }
    match cli.command {
        Some(command) => dispatch(command, &paths, &mut db),
        None => run_query(
            QueryArgs {
                show: cli.show.clone(),
                file: cli.file.clone(),
                history: cli.history,
                orphans: cli.orphans,
                verify: cli.verify,
                check: cli.check,
                logs: cli.logs.clone(),
                tail: cli.tail,
            },
            &paths,
            &mut db,
        ),
    }
}

/// Builds, verifies and activates one archive.
#[derive(Clone, Copy)]
struct InstallFlags {
    force: bool,
    allow_unsigned: bool,
    local: bool,
    dry_run: bool,
    keep_privileged: bool,
    update_pin: bool,
    allow_path_leak: bool,
}

fn install_flags() -> InstallFlags {
    InstallFlags {
        force: util::env_flag("PORTALIS_FORCE"),
        allow_unsigned: util::env_flag("PORTALIS_ALLOW_UNSIGNED"),
        local: util::env_flag("PORTALIS_LOCAL"),
        dry_run: util::env_flag("PORTALIS_DRY_RUN"),
        keep_privileged: util::env_flag("PORTALIS_KEEP_PRIVILEGED"),
        update_pin: util::env_flag("PORTALIS_UPDATE_PIN"),
        allow_path_leak: util::env_flag("PORTALIS_ALLOW_PATH_LEAK"),
    }
}

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

fn install_cmd(paths: &Paths, db: &mut db::Db, target: String) -> Result<()> {
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

#[cfg(test)]
mod target_tests {
    use super::*;
    use crate::resolve::version_from_file;

    #[test]
    fn versions_are_parsed_from_archive_names() {
        assert_eq!(
            version_from_file("ffmpeg-9.0.3.tar.xz", "ffmpeg"),
            Some("9.0.3".into())
        );
        assert_eq!(
            version_from_file("gtk3-3.24.52.tar.bz2", "gtk3"),
            Some("3.24.52".into())
        );
        assert_eq!(
            version_from_file("okpkg-1.0-x86_64.tar", "okpkg"),
            Some("1.0".into())
        );
        assert_eq!(
            version_from_file("noarch-tool-2.0-any.tar.gz", "noarch-tool"),
            Some("2.0".into())
        );
        assert_eq!(version_from_file("ffmpeg.tar.xz", "ffmpeg"), None);
        assert_eq!(version_from_file("other-1.0.tar.gz", "ffmpeg"), None);
    }

    #[test]
    fn orphans_are_reported_by_category() {
        let root = std::env::temp_dir().join(format!("portalis-orphans-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("var/db/portalis")).unwrap();
        let paths = Paths::at(root.clone());
        let db = db::Db::open(&paths, db::Access::Write).unwrap();

        let keep = paths.store().join("keep-1.0-aaaa");
        let orphan = paths.store().join("z-orphan-1.0-bbbb");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::create_dir_all(paths.store().join("a-orphan-1.0-cccc")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO packages (name, version, store_path, recipe_sha256, \
                 manifest_digest, installed_at, build_log) VALUES \
                 ('keep', '1.0', ?1, 'x', 'y', 'now', 'log'), \
                 ('gone', '1.0', '/nonexistent/gone-1.0-cccc', 'x', 'y', 'now', 'log')",
                rusqlite::params![keep.to_string_lossy().to_string()],
            )
            .unwrap();
        db.insert_file(
            "keep",
            &recipe::ManifestFile {
                path: "/usr/bin/keep".to_string(),
                sha256: "0".repeat(64),
                mode: 0o644,
                link: None,
            },
            "/nonexistent/store/file",
        )
        .unwrap();

        let orphaned = query::find_orphans(&paths, &db).unwrap();
        assert_eq!(
            orphaned.stores,
            vec![paths.store().join("a-orphan-1.0-cccc"), orphan],
            "orphans are sorted and referenced stores are not listed"
        );
        assert_eq!(orphaned.missing, vec!["gone".to_string()]);
        assert_eq!(orphaned.dangling.len(), 1);
        assert_eq!(orphaned.dangling[0].1, "/usr/bin/keep");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn finds_dependency_cycles() {
        let mut graph = std::collections::BTreeMap::new();
        graph.insert("a".to_string(), vec!["b".to_string()]);
        graph.insert("b".to_string(), vec!["a".to_string()]);
        graph.insert("c".to_string(), vec!["a".to_string()]);
        graph.insert("d".to_string(), Vec::new());
        assert_eq!(
            find_cycle(&graph, "a"),
            Some(vec!["a".to_string(), "b".to_string(), "a".to_string()])
        );
        assert!(find_cycle(&graph, "d").is_none());
        assert!(find_cycle(&graph, "c").is_some());
    }

    #[test]
    fn stale_build_dirs_skips_state_files_and_other_directories() {
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::at(root.path());
        std::fs::create_dir_all(paths.state_dir().join("build-AB12CD")).unwrap();
        std::fs::create_dir_all(paths.state_dir().join("backup")).unwrap();
        std::fs::write(paths.state_dir().join("build-not-a-dir"), b"x").unwrap();

        let stale = crate::commands::stale_build_dirs(&paths).unwrap();

        assert_eq!(stale.len(), 1);
        assert!(stale[0].ends_with("build-AB12CD"));
    }

    #[test]
    fn stale_build_logs_keep_the_retention_count_per_package() {
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::at(root.path());
        paths.ensure_layout().unwrap();
        let db = db::Db::open(&paths, db::Access::Write).unwrap();
        std::fs::write(
            paths.recipes().join("alpha.port"),
            format!(
                "package.name = alpha\npackage.version = 1.0\n\
                 source.file = alpha-1.0.tar.xz\nsource.sha256 = {}\n\
                 build.system = custom\ninstall.prefix = /usr\n",
                "0".repeat(64)
            ),
        )
        .unwrap();
        let total = util::BUILD_LOGS_PER_PACKAGE + 5;
        let now = std::time::SystemTime::now();
        for index in 0..total {
            let path = paths.logs().join(format!("alpha-1.0-{index:04}.log"));
            std::fs::write(&path, b"portalis build alpha 1.0\n").unwrap();
            let stamp = now - std::time::Duration::from_secs((total - index) as u64);
            let times = std::fs::FileTimes::new().set_modified(stamp);
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(times)
                .unwrap();
        }
        std::fs::write(paths.logs().join("unrelated.log"), b"x").unwrap();
        // a package whose name extends this one keeps its own logs
        std::fs::write(
            paths.logs().join("alpha-tools-2.0-0001.log"),
            b"portalis build alpha-tools 2.0\n",
        )
        .unwrap();

        let stale = crate::commands::stale_build_logs(&paths, &db).unwrap();

        assert_eq!(stale.len(), 5);
        for index in 0..5 {
            assert!(
                stale
                    .iter()
                    .any(|path| path.ends_with(format!("alpha-1.0-{index:04}.log"))),
                "expected alpha-1.0-{index:04}.log to be pruned"
            );
        }
        assert!(!stale.iter().any(|path| path.ends_with("unrelated.log")));
        assert!(!stale
            .iter()
            .any(|path| path.ends_with("alpha-tools-2.0-0001.log")));
    }
}
