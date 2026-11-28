//! The command line surface.

use crate::util;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = crate::COMMAND_NAME,
    version,
    long_version = crate::rootfs::LONG_VERSION,
    about = "Portalis package manager (offline, hash-locked)"
)]
pub(crate) struct Cli {
    /// Show one package in detail
    #[arg(long, value_name = "PACKAGE")]
    pub(crate) show: Option<String>,
    /// Find the package that owns a path
    #[arg(long, value_name = "PATH")]
    pub(crate) file: Option<String>,
    /// List installation generations
    #[arg(long)]
    pub(crate) history: bool,
    /// Report stores, rows and links that nothing references
    #[arg(long)]
    pub(crate) orphans: bool,
    /// Check every activated file against its hash
    #[arg(long)]
    pub(crate) verify: bool,
    /// Check that every recipe parses
    #[arg(long)]
    pub(crate) check: bool,
    /// List build logs for a package, or print the tail with --tail
    #[arg(long, value_name = "PACKAGE")]
    pub(crate) logs: Option<String>,
    /// Print the last N lines of the build log
    #[arg(long, value_name = "LINES")]
    pub(crate) tail: Option<usize>,
    /// Silence the progress lines a long command prints while it works
    #[arg(long)]
    pub(crate) quiet: bool,
    /// Drop the record that blocks write commands, after printing what it names
    #[arg(long)]
    pub(crate) discard_recovery: bool,
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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

/// Builds, verifies and activates one archive.
#[derive(Clone, Copy)]
pub(crate) struct InstallFlags {
    pub(crate) force: bool,
    pub(crate) allow_unsigned: bool,
    pub(crate) local: bool,
    pub(crate) dry_run: bool,
    pub(crate) keep_privileged: bool,
    pub(crate) update_pin: bool,
    pub(crate) allow_path_leak: bool,
}

pub(crate) fn install_flags() -> InstallFlags {
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
