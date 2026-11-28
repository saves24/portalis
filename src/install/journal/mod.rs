//! The file moves one activation is about to make, written down before they
//! happen. The next write command undoes what an interrupted activation left.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::paths::Paths;

/// What a live path held before the activation touched it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Previous {
    /// Nothing was there; the activation creates the path.
    Missing,
    /// A link was there, and this is where it pointed.
    Symlink { target: String },
    /// A regular file was moved here.
    Displaced { backup: String },
    /// The file a backup held now sits at the live path.
    Restored { backup: String },
}

/// One live path the activation will touch.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Entry {
    pub path: String,
    pub previous: Previous,
}

pub(super) struct Journal {
    file: fs::File,
    path: PathBuf,
}

const PREFIX: &str = "activation-journal-";
/// A line saying the activation reached the database.
const COMMIT: &str = "commit";
/// A line recording the database digest before the activation changed it.
const START: &str = "# start ";

/// Removes a journal and makes the removal durable.
fn drop_journal(path: &Path) {
    if fs::remove_file(path).is_ok() {
        if let Some(dir) = path.parent() {
            let _ = crate::util::sync_dir(dir);
        }
    }
}

impl Journal {
    /// Opens a fresh journal for `pkg`, replacing any record left behind.
    pub(super) fn begin(
        paths: &Paths,
        pkg: &str,
        version: &str,
        store: &str,
        db: Option<&crate::db::Db>,
    ) -> Result<Self> {
        let path = paths.state_dir().join(format!("{PREFIX}{pkg}.jsonl"));
        // a record left by an earlier attempt is undone before this one starts;
        // one that cannot be undone is not overwritten
        if path.exists() {
            replay_file(&path, &paths.target_root(), db, false).with_context(|| {
                format!(
                    "an earlier activation record for {pkg} could not be undone: {}",
                    path.display()
                )
            })?;
        }
        // Writes the digest of the state before the first move.
        let start_digest = db.map(|db| db.state_digest()).transpose()?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut journal = Self { file, path };
        writeln!(journal.file, "# {pkg} {version} {store}")?;
        if let Some(start) = start_digest {
            writeln!(journal.file, "{START}{start}")?;
        }
        journal.file.flush()?;
        Ok(journal)
    }

    /// Records that the activation reached the database.
    pub(super) fn commit(&mut self) -> Result<()> {
        writeln!(self.file, "{COMMIT}")?;
        self.file.flush()?;
        self.file.sync_all()?;
        if let Some(dir) = self.path.parent() {
            crate::util::sync_dir(dir).with_context(|| format!("flushing {}", dir.display()))?;
        }
        Ok(())
    }

    /// Writes the whole plan and puts it on disk before anything moves.
    pub(super) fn write_plan(&mut self, entries: &[Entry]) -> Result<()> {
        for entry in entries {
            serde_json::to_writer(&mut self.file, entry)
                .with_context(|| format!("recording {}", entry.path))?;
            writeln!(self.file)?;
        }
        self.file.flush()?;
        self.file.sync_all()?;
        // the record itself has to reach the directory, not just the file
        if let Some(dir) = self.path.parent() {
            let handle =
                fs::File::open(dir).with_context(|| format!("opening {}", dir.display()))?;
            handle
                .sync_all()
                .with_context(|| format!("flushing {}", dir.display()))?;
        }
        Ok(())
    }

    /// Drops the record once the activation that wrote it has committed.
    pub(super) fn finish(self) {
        let path = self.path.clone();
        drop(self.file);
        drop_journal(&path);
    }
}

mod replay;
use replay::replay_file;
pub(crate) use replay::{replay, replay_record};

#[cfg(test)]
mod tests {
    use super::replay::{committed, header_of, landed};
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("portalis-journal-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/lib/portalis")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        root
    }

    /// Opens a record for `tool` 1.0 installing into `store`, with no ledger to
    /// consult — the state a run without a live database sees.
    fn journal_for(paths: &Paths, store: &str) -> Journal {
        Journal::begin(paths, "tool", "1.0", store, None).unwrap()
    }

    #[test]
    fn a_recorded_move_is_put_back() {
        let root = scratch("displaced");
        let paths = Paths::at(&root);
        fs::write(root.join("usr/bin/tool"), "original\n").unwrap();
        let backup = root.join("var/lib/portalis/backup/usr/bin/tool");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::rename(root.join("usr/bin/tool"), &backup).unwrap();
        // the activation got as far as placing its own file
        fs::write(root.join("usr/bin/tool"), "installed\n").unwrap();

        let mut journal = journal_for(&paths, "/usr/portalis/packages/tool-1.0-aaa");
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Displaced {
                    backup: backup.display().to_string(),
                },
            }])
            .unwrap();

        let restored = replay(&paths, &root, None).unwrap();
        assert_eq!(restored, 1, "the recorded move was not undone");
        assert_eq!(
            fs::read_to_string(root.join("usr/bin/tool")).unwrap(),
            "original\n",
            "the original did not come back"
        );
        assert!(!root
            .join("var/lib/portalis/activation-journal-tool.jsonl")
            .exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_link_that_was_there_points_where_it_did() {
        let root = scratch("relink");
        let paths = Paths::at(&root);
        let store = root.join("usr/portalis/packages/tool-1.0/usr/bin/tool");
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        fs::write(&store, "payload\n").unwrap();
        // the activation replaced an older link with its own
        std::os::unix::fs::symlink(&store, root.join("usr/bin/tool")).unwrap();

        let mut journal = journal_for(&paths, "/usr/portalis/packages/tool-1.0-aaa");
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Symlink {
                    target: "/usr/bin/tool-v0".to_string(),
                },
            }])
            .unwrap();

        assert_eq!(replay(&paths, &root, None).unwrap(), 1);
        let now = fs::read_link(root.join("usr/bin/tool")).unwrap();
        assert_eq!(
            now,
            PathBuf::from("/usr/bin/tool-v0"),
            "the previous link target did not come back"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_journal_that_reached_the_database_is_not_replayed() {
        let root = scratch("committed");
        let paths = Paths::at(&root);
        let store = root.join("usr/portalis/packages/tool-1.0");
        fs::create_dir_all(store.join("usr/bin")).unwrap();
        fs::write(store.join("usr/bin/tool"), "payload\n").unwrap();
        std::os::unix::fs::symlink(store.join("usr/bin/tool"), root.join("usr/bin/tool")).unwrap();

        let mut journal = journal_for(&paths, "/usr/portalis/packages/tool-1.0-aaa");
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Missing,
            }])
            .unwrap();
        journal.commit().unwrap();
        drop(journal);

        assert_eq!(
            replay(&paths, &root, None).unwrap(),
            0,
            "a committed activation was undone"
        );
        assert!(
            root.join("usr/bin/tool").exists(),
            "the link a committed activation made was removed"
        );
        assert!(
            !paths
                .state_dir()
                .join(format!("{PREFIX}tool.jsonl"))
                .exists(),
            "the committed record was left behind"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_record_is_committed_when_the_database_holds_that_store() {
        let header =
            "# tool 1.0 /usr/portalis/packages/tool-1.0-aaa\n{\"path\":\"/usr/bin/tool\",\"previous\":{\"kind\":\"missing\"}}\n";
        assert!(
            committed(header, true),
            "an installed store was not treated as committed"
        );
        assert!(
            !committed(header, false),
            "a store the database does not hold was treated as committed"
        );
        assert!(
            committed(&format!("{header}{COMMIT}\n"), false),
            "the commit line did not count"
        );
        assert!(!committed(header, false));
    }

    #[test]
    fn a_journal_header_names_the_package_and_its_store() {
        let header = header_of("# tool 1.0 /usr/portalis/packages/tool-1.0-aaa\n").unwrap();
        assert_eq!(header.package, "tool");
        assert_eq!(header.store, "/usr/portalis/packages/tool-1.0-aaa");
        assert!(
            header_of("# tool 1.0\n").is_none(),
            "a header without a store was read as naming one"
        );
        assert!(header_of("{}\n").is_none());
    }

    #[test]
    fn a_lost_backup_without_the_restored_file_blocks_the_next_write() {
        let root = scratch("lost");
        let paths = Paths::at(&root);
        let backup = paths.state_dir().join("backup/usr/bin/tool");
        let mut journal = journal_for(&paths, "/usr/portalis/packages/tool-1.0-aaa");
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Displaced {
                    backup: backup.display().to_string(),
                },
            }])
            .unwrap();
        drop(journal);

        let failure = replay(&paths, &root, None)
            .expect_err("a lost backup and a lost file were taken as restored");
        assert_eq!(
            crate::error::code_of(&failure),
            crate::error::Code::RecoveryBlocked
        );
        assert!(
            paths
                .state_dir()
                .join(format!("{PREFIX}tool.jsonl"))
                .exists(),
            "the record of a lost backup was dropped"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_lost_backup_with_the_restored_file_in_place_is_finished() {
        let root = scratch("done");
        let paths = Paths::at(&root);
        fs::write(root.join("usr/bin/tool"), "original\n").unwrap();
        let backup = paths.state_dir().join("backup/usr/bin/tool");
        let mut journal = journal_for(&paths, "/usr/portalis/packages/tool-1.0-aaa");
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Displaced {
                    backup: backup.display().to_string(),
                },
            }])
            .unwrap();
        drop(journal);

        assert_eq!(replay(&paths, &root, None).unwrap(), 0);
        assert!(
            !paths
                .state_dir()
                .join(format!("{PREFIX}tool.jsonl"))
                .exists(),
            "the finished record was kept"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_header_naming_another_store_is_not_committed_against_the_ledger() {
        let root = scratch("landed");
        let paths = Paths::at(&root);
        fs::create_dir_all(root.join("var/db/portalis")).unwrap();
        let db = crate::db::Db::open(&paths, crate::db::Access::Write).unwrap();
        db.conn
            .execute(
                "INSERT INTO packages (name, version, store_path, recipe_sha256, \
                 manifest_digest, installed_at, build_log) \
                 VALUES ('tool', '1.0', '/store/tool-1.0-old', 'x', 'y', 'now', 'log')",
                [],
            )
            .unwrap();

        let same = "# tool 1.0 /store/tool-1.0-old\n";
        assert!(
            landed(Some(&db), same).unwrap(),
            "a record for the installed store was not treated as committed"
        );
        let other = "# tool 1.0 /store/tool-1.0-new\n";
        assert!(
            !landed(Some(&db), other).unwrap(),
            "a record for another store was treated as committed"
        );
        assert!(
            !landed(None, same).unwrap(),
            "a record was treated as committed with no ledger to read"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_header_keeps_a_store_path_that_holds_spaces() {
        let header = header_of("# tool 1.0 /store/tool 1.0-aaa\n").unwrap();
        assert_eq!(header.package, "tool");
        assert_eq!(header.store, "/store/tool 1.0-aaa");
    }

    #[test]
    fn a_same_version_rebuild_in_another_store_is_undone() {
        // the ledger names the first store while the activation installs the second
        let root = scratch("rebuild");
        let paths = Paths::at(&root);
        fs::create_dir_all(root.join("var/db/portalis")).unwrap();
        let old = root.join("usr/portalis/packages/tool-1.0-old");
        let new = root.join("usr/portalis/packages/tool-1.0-new");
        for store in [&old, &new] {
            fs::create_dir_all(store.join("usr/bin")).unwrap();
            fs::write(store.join("usr/bin/tool"), "payload\n").unwrap();
        }
        // the activation replaced the old store's link with the new one
        std::os::unix::fs::symlink(new.join("usr/bin/tool"), root.join("usr/bin/tool")).unwrap();

        let db = crate::db::Db::open(&paths, crate::db::Access::Write).unwrap();
        db.conn
            .execute(
                "INSERT INTO packages (name, version, store_path, recipe_sha256, \
                 manifest_digest, installed_at, build_log) \
                 VALUES ('tool', '1.0', ?1, 'x', 'y', 'now', 'log')",
                rusqlite::params![old.to_str().unwrap()],
            )
            .unwrap();

        let mut journal =
            Journal::begin(&paths, "tool", "1.0", new.to_str().unwrap(), Some(&db)).unwrap();
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Symlink {
                    target: old.join("usr/bin/tool").to_str().unwrap().to_string(),
                },
            }])
            .unwrap();
        drop(journal);

        assert_eq!(
            replay(&paths, &root, Some(&db)).unwrap(),
            1,
            "a same-version rebuild in another store was taken for a committed activation"
        );
        assert_eq!(
            fs::read_link(root.join("usr/bin/tool")).unwrap(),
            old.join("usr/bin/tool"),
            "the link the interrupted rebuild replaced did not come back"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_damaged_record_keeps_the_journal_and_blocks_the_next_write() {
        let root = scratch("torn");
        let paths = Paths::at(&root);
        let store = root.join("usr/portalis/packages/tool-1.0");
        fs::create_dir_all(store.join("usr/bin")).unwrap();
        fs::write(store.join("usr/bin/tool"), "payload\n").unwrap();
        std::os::unix::fs::symlink(store.join("usr/bin/tool"), root.join("usr/bin/tool")).unwrap();
        std::os::unix::fs::symlink(store.join("usr/bin/tool"), root.join("usr/bin/other")).unwrap();

        let journal_path = paths.state_dir().join(format!("{PREFIX}tool.jsonl"));
        let good = serde_json::to_string(&Entry {
            path: "/usr/bin/tool".to_string(),
            previous: Previous::Missing,
        })
        .unwrap();
        // a record broken in the middle of the file, with a readable one after it
        fs::write(
            &journal_path,
            format!("{good}\n{{\"path\":\"/usr/bin/oth\n{good}\n"),
        )
        .unwrap();

        let failure = replay(&paths, &root, None).expect_err("a damaged record was accepted");
        assert_eq!(
            crate::error::code_of(&failure),
            crate::error::Code::RecoveryBlocked,
            "a damaged record did not block the next write"
        );
        assert!(
            !root.join("usr/bin/tool").exists(),
            "the readable record was not replayed"
        );
        assert!(
            root.join("usr/bin/other").exists(),
            "the path under the torn record was changed even though its record is unreadable"
        );
        assert!(
            journal_path.exists(),
            "the damaged record was dropped instead of kept"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_restored_file_goes_back_to_its_backup_last_first() {
        let root = scratch("restored");
        let paths = Paths::at(&root);
        let backup = paths.state_dir().join("backup/usr/bin/tool");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::write(&backup, "original\n").unwrap();
        let store = root.join("usr/portalis/packages/tool-1.0/usr/bin/tool");
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        fs::write(&store, "payload\n").unwrap();

        // the remove dropped the link, then put the original back at the live path
        fs::remove_file(&backup).unwrap();
        fs::write(root.join("usr/bin/tool"), "original\n").unwrap();
        let journal_path = paths
            .state_dir()
            .join("operation-journal-remove-of-tool.jsonl");
        let link = serde_json::to_string(&Entry {
            path: "/usr/bin/tool".to_string(),
            previous: Previous::Symlink {
                target: store.display().to_string(),
            },
        })
        .unwrap();
        let restored = serde_json::to_string(&Entry {
            path: "/usr/bin/tool".to_string(),
            previous: Previous::Restored {
                backup: backup.display().to_string(),
            },
        })
        .unwrap();
        fs::write(
            &journal_path,
            format!("# operation remove of tool\n{link}\n{restored}\n"),
        )
        .unwrap();

        assert_eq!(replay_record(&journal_path, &root).unwrap(), 2);
        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            "original\n",
            "the original did not go back to its backup"
        );
        assert_eq!(
            fs::read_link(root.join("usr/bin/tool")).unwrap(),
            store,
            "the link the remove dropped did not come back"
        );
        assert!(!journal_path.exists(), "the replayed record was kept");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_torn_last_record_is_discarded_and_the_journal_dropped() {
        let root = scratch("torn-tail");
        let paths = Paths::at(&root);
        let store = root.join("usr/portalis/packages/tool-1.0");
        fs::create_dir_all(store.join("usr/bin")).unwrap();
        fs::write(store.join("usr/bin/tool"), "payload\n").unwrap();
        std::os::unix::fs::symlink(store.join("usr/bin/tool"), root.join("usr/bin/tool")).unwrap();

        let journal_path = paths.state_dir().join(format!("{PREFIX}tool.jsonl"));
        let good = serde_json::to_string(&Entry {
            path: "/usr/bin/tool".to_string(),
            previous: Previous::Missing,
        })
        .unwrap();
        // a crash in the middle of the plan write leaves no trailing newline
        fs::write(&journal_path, format!("{good}\n{{\"path\":\"/usr/bin/oth")).unwrap();

        assert_eq!(replay(&paths, &root, None).unwrap(), 1);
        assert!(
            !journal_path.exists(),
            "the record of a plan that never finished was kept"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_recorded_new_link_is_removed() {
        let root = scratch("created");
        let paths = Paths::at(&root);
        let store = root.join("usr/portalis/packages/tool-1.0");
        fs::create_dir_all(&store).unwrap();
        let target = store.join("usr/bin/tool");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "payload\n").unwrap();
        std::os::unix::fs::symlink(&target, root.join("usr/bin/tool")).unwrap();

        let mut journal = journal_for(&paths, "/usr/portalis/packages/tool-1.0-aaa");
        journal
            .write_plan(&[Entry {
                path: "/usr/bin/tool".to_string(),
                previous: Previous::Missing,
            }])
            .unwrap();

        assert_eq!(replay(&paths, &root, None).unwrap(), 1);
        assert!(
            fs::symlink_metadata(root.join("usr/bin/tool")).is_err(),
            "the link an interrupted activation made is still there"
        );
        let _ = fs::remove_dir_all(&root);
    }
    #[test]
    fn a_truncated_last_record_does_not_block_a_reverse_replay() {
        let root = scratch("truncated");
        let paths = Paths::at(&root);
        let journal = paths.state_dir().join("activation-journal-tool.jsonl");
        fs::write(
            &journal,
            "# tool 1.0 /store\n{\"path\":\"/usr/bin/missing\",\"previous\":{\"kind\":\"missing\"}}\n{\"path\":\"/usr/bin/cut\",\"previous\":{\"kind\":",
        )
        .unwrap();

        replay_record(&journal, &root).expect("a cut last record is not damage");
        assert!(!journal.exists(), "the clean journal was kept");
        let _ = fs::remove_dir_all(&root);
    }
}
