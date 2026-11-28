#[macro_use]
mod json;
mod archive;
mod build;
mod build_container;
mod check;
mod cli;
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

use crate::cli::{Cli, Commands};
use crate::commands::clean_cmd;
use crate::commands::install::install_cmd;
use crate::query::{query_cmd, QueryArgs};
use anyhow::{bail, Result};
use clap::Parser;

pub use paths::Paths;
pub(crate) use resolve::ARCH_SEGMENTS;

const BACKUP_RETENTION_DAYS: u64 = 30;

pub fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// The name the command installs under; release artifacts keep `portalis`.
pub const COMMAND_NAME: &str = "moirse";

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
            crate::resolve::find_cycle(&graph, "a"),
            Some(vec!["a".to_string(), "b".to_string(), "a".to_string()])
        );
        assert!(crate::resolve::find_cycle(&graph, "d").is_none());
        assert!(crate::resolve::find_cycle(&graph, "c").is_some());
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
