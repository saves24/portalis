//! The marker a command that rewrites the live tree leaves behind, and the
//! repair a later write command runs from it.
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::db::Db;
use crate::paths::Paths;

/// Marks a command that rewrites the live tree, for the repair a later write
/// command runs.
pub(crate) struct OperationMarker {
    path: Option<PathBuf>,
    keep: bool,
}

impl OperationMarker {
    pub(crate) fn start(paths: &Paths, label: &str) -> Result<Self> {
        let path = paths.state_dir().join("operation");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        file.write_all(format!("{label}\n").as_bytes())?;
        file.sync_all()?;
        crate::util::sync_dir(&paths.state_dir())?;
        Ok(Self {
            path: Some(path),
            keep: false,
        })
    }

    /// Removes the marker: the tree and the records are in step.
    pub(crate) fn finish(mut self) {
        self.clear();
    }

    /// Leaves the marker for the next write command to repair from.
    pub(crate) fn keep(mut self) {
        self.keep = true;
    }

    fn clear(&mut self) {
        if let Some(path) = self.path.take() {
            if fs::remove_file(&path).is_ok() {
                if let Some(dir) = path.parent() {
                    let _ = crate::util::sync_dir(dir);
                }
            }
        }
    }
}

impl Drop for OperationMarker {
    fn drop(&mut self) {
        if !self.keep {
            self.clear();
        }
    }
}

/// The moves a command that rewrites the tree is about to make, written before
/// they happen. A crash leaves it behind for the next write command.
pub(super) struct OperationJournal {
    file: fs::File,
    path: PathBuf,
    left: bool,
}

impl OperationJournal {
    pub(super) fn begin(paths: &Paths, label: &str) -> Result<Self> {
        let name: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let path = paths
            .state_dir()
            .join(format!("operation-journal-{name}.jsonl"));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        file.write_all(format!("# operation {label}\n").as_bytes())?;
        file.sync_all()?;
        crate::util::sync_dir(&paths.state_dir())?;
        Ok(Self {
            file,
            path,
            left: false,
        })
    }

    /// Records the database state a rollback is moving to, before the tree is
    /// rewritten.
    pub(super) fn target(&mut self, digest: &str) -> Result<()> {
        writeln!(self.file, "# target {digest}")?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Records one path and what it held, then makes the record durable.
    pub(super) fn record(&mut self, entry: &super::journal::Entry) -> Result<()> {
        serde_json::to_writer(&mut self.file, entry)?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Marks the operation as finished; the record goes.
    pub(super) fn commit(mut self) -> Result<()> {
        if let Err(error) = self.file.write_all(b"commit\n") {
            self.left = true;
            return Err(error.into());
        }
        if let Err(error) = self.file.sync_all() {
            self.left = true;
            return Err(error.into());
        }
        Ok(())
    }

    /// Leaves the record for the next write command to replay.
    pub(super) fn keep(mut self) {
        self.left = true;
    }
}

impl Drop for OperationJournal {
    fn drop(&mut self) {
        if self.left {
            return;
        }
        if fs::remove_file(&self.path).is_ok() {
            if let Some(dir) = self.path.parent() {
                let _ = crate::util::sync_dir(dir);
            }
        }
    }
}

/// Rebuilds the live links after a command that rewrites the tree was killed.
pub fn recover_operations(db: &Db, paths: &Paths) -> Result<bool> {
    let marker = paths.state_dir().join("operation");
    if let Ok(meta) = fs::symlink_metadata(&marker) {
        use std::os::unix::fs::MetadataExt;
        if !meta.file_type().is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            anyhow::bail!(
                "operation marker is not a root-owned regular file: {}",
                marker.display()
            );
        }
    }
    let label = match fs::read_to_string(&marker) {
        Ok(label) => label,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", marker.display()));
        }
    };
    let label = label.trim().to_string();
    match fs::read_dir(paths.state_dir()) {
        Ok(entries) => {
            for entry in entries {
                let entry =
                    entry.with_context(|| format!("reading {}", paths.state_dir().display()))?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with("operation-journal-") || !name.ends_with(".jsonl") {
                    continue;
                }
                crate::install::journal::replay_record(&entry.path(), &paths.target_root())?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", paths.state_dir().display()));
        }
    }
    super::rollback::recover_adopted(db, paths)?;
    crate::links::repair_links(db, paths)?;
    if let Err(error) = fs::remove_file(&marker) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "warning: the operation marker {} was not removed: {error}",
                marker.display()
            );
        }
    } else if let Some(dir) = marker.parent() {
        let _ = crate::util::sync_dir(dir);
    }
    say!("repaired  the tree after an interrupted {label}");
    Ok(true)
}
