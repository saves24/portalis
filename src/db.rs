use crate::paths::Paths;
use crate::recipe::{BuildManifest, ManifestFile};
use anyhow::{bail, Context, Result};
use std::collections::HashSet;

/// Row in `meta` that records when the derived index was last rebuilt.
pub(crate) const INDEX_META_KEY: &str = "edges_indexed_at";

/// Reads a JSON column. A row that does not parse is reported as an error.
fn json_column<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row,
    index: usize,
) -> rusqlite::Result<T> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, error.into())
    })
}

/// Version of the derived library-edge tables.
const LINK_SCHEMA_VERSION: i64 = 2;

/// Tables that hold derived library edges.
const LINK_TABLES_SQL: &str = "CREATE TABLE IF NOT EXISTS sonames (
                 soname TEXT NOT NULL,
                 bits INTEGER NOT NULL,
                 pkg TEXT NOT NULL,
                 PRIMARY KEY (soname, bits, pkg)
             );
             CREATE TABLE IF NOT EXISTS needs (
                 pkg TEXT NOT NULL,
                 dep TEXT NOT NULL,
                 soname TEXT NOT NULL,
                 bits INTEGER NOT NULL,
                 PRIMARY KEY (pkg, soname, bits)
             );";

/// path, sha256, link target, mode, kind
type PendingFile = (String, String, String, u32, String);
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};

mod generations;
mod open;
mod records;

/// Whether an open database may be written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// How long a second command waits for the lock of a first one.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct Db {
    pub(crate) conn: Connection,
    writable: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageRow {
    pub name: String,
    pub version: String,
    pub store_path: String,
    pub recipe_sha256: String,
    pub manifest_digest: String,
    pub installed_at: String,
    pub build_log: String,
    pub signature: Option<String>,
    #[serde(default)]
    pub rpath: Vec<String>,
    #[serde(default)]
    pub state: PackageState,
    #[serde(default)]
    pub hooks: crate::recipe::Hooks,
}

/// What a package row represents: the live version or one waiting for a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum PackageState {
    #[default]
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "staged")]
    Staged,
    #[serde(rename = "staged-force")]
    StagedForced,
}

impl rusqlite::ToSql for PackageState {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'static>> {
        Ok(rusqlite::types::ToSqlOutput::from(self.as_str()))
    }
}

impl PackageState {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "active" => Ok(Self::Active),
            "staged" => Ok(Self::Staged),
            "staged-force" => Ok(Self::StagedForced),
            other => bail!("unknown package state: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Staged => "staged",
            Self::StagedForced => "staged-force",
        }
    }
}

/// Tables a readable database has to carry. A database written by an older
/// version is migrated by the first command that opens it for writing.
const REQUIRED_TABLES: [&str; 11] = [
    "packages",
    "files",
    "manifests",
    "generations",
    "pending_packages",
    "pending_files",
    "meta",
    "depends",
    "adopted",
    "sonames",
    "needs",
];

const REQUIRED_COLUMNS: [(&str, &str); 7] = [
    ("packages", "rpath"),
    ("packages", "hooks"),
    ("files", "mode"),
    ("pending_packages", "manifest"),
    ("pending_files", "kind"),
    ("sonames", "bits"),
    ("needs", "bits"),
];

impl Db {
    pub fn delete_file(&self, pkg: &str, path: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM files WHERE pkg = ?1 AND path = ?2",
            params![pkg, path],
        )?;
        Ok(())
    }

    pub fn insert_file(&self, pkg: &str, file: &ManifestFile, link_target: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO files (pkg, path, sha256, link_target, mode)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![pkg, file.path, file.sha256, link_target, file.mode],
        )?;
        Ok(())
    }

    pub fn package(&self, name: &str) -> Result<Option<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, state, hooks
             FROM packages WHERE name = ?1",
        )?;
        let mut rows = stmt.query(params![name])?;
        if let Some(row) = rows.next()? {
            Ok(Some(PackageRow {
                name: row.get(0)?,
                version: row.get(1)?,
                store_path: row.get(2)?,
                recipe_sha256: row.get(3)?,
                manifest_digest: row.get(4)?,
                installed_at: row.get(5)?,
                build_log: row.get(6)?,
                signature: row.get(7)?,
                rpath: json_column(row, 8)?,
                state: PackageState::parse(&row.get::<_, String>(9)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        9,
                        rusqlite::types::Type::Text,
                        error.into(),
                    )
                })?,
                hooks: json_column(row, 10)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn packages(&self) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, state, hooks
             FROM packages ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PackageRow {
                name: row.get(0)?,
                version: row.get(1)?,
                store_path: row.get(2)?,
                recipe_sha256: row.get(3)?,
                manifest_digest: row.get(4)?,
                installed_at: row.get(5)?,
                build_log: row.get(6)?,
                signature: row.get(7)?,
                rpath: json_column(row, 8)?,
                state: PackageState::parse(&row.get::<_, String>(9)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        9,
                        rusqlite::types::Type::Text,
                        error.into(),
                    )
                })?,
                hooks: json_column(row, 10)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn all_files(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkg, path, link_target FROM files ORDER BY pkg, path")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn files_of(&self, pkg: &str) -> Result<Vec<(String, String, String, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, link_target, mode FROM files WHERE pkg = ?1 ORDER BY path",
        )?;
        let rows = stmt.query_map(params![pkg], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn stage_package(
        &self,
        manifest: &BuildManifest,
        store_path: &str,
        log: &str,
        sig: Option<&str>,
        hooks: &crate::recipe::Hooks,
        force: bool,
    ) -> Result<()> {
        let canonical = String::from_utf8(manifest.canonical_bytes()?)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_packages
             (name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, hooks, force, manifest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                manifest.name,
                manifest.version,
                store_path,
                manifest.recipe_sha256,
                manifest.digest()?,
                crate::now(),
                log,
                sig,
                serde_json::to_string(&manifest.rpath)?,
                serde_json::to_string(hooks)?,
                force as i32,
                canonical
            ],
        )?;
        Ok(())
    }

    pub fn pending_packages(&self) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, hooks, force
             FROM pending_packages ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PackageRow {
                name: row.get(0)?,
                version: row.get(1)?,
                store_path: row.get(2)?,
                recipe_sha256: row.get(3)?,
                manifest_digest: row.get(4)?,
                installed_at: row.get(5)?,
                build_log: row.get(6)?,
                signature: row.get(7)?,
                rpath: json_column(row, 8)?,
                hooks: json_column(row, 9)?,
                state: if row.get::<_, i32>(10)? != 0 {
                    PackageState::StagedForced
                } else {
                    PackageState::Staged
                },
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn promote_pending(&self, pkg: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO packages
             (name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, state, hooks)
             SELECT name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, 'active', hooks
             FROM pending_packages WHERE name = ?1",
            params![pkg],
        )?;
        // the manifest is recorded when the package is activated
        self.conn.execute(
            "INSERT OR REPLACE INTO manifests (pkg, canonical)
             SELECT name, manifest FROM pending_packages WHERE name = ?1 AND manifest <> ''",
            params![pkg],
        )?;
        self.conn
            .execute("DELETE FROM pending_packages WHERE name = ?1", params![pkg])?;
        Ok(())
    }

    pub fn drop_pending(&self, pkg: &str) -> Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM pending_packages WHERE name = ?1", params![pkg])?;
        tx.execute("DELETE FROM pending_files WHERE pkg = ?1", params![pkg])?;
        tx.commit()?;
        Ok(())
    }

    pub fn stage_file(
        &self,
        pkg: &str,
        file: &ManifestFile,
        link_target: &str,
        kind: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_files (pkg, path, sha256, link_target, mode, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![pkg, file.path, file.sha256, link_target, file.mode, kind],
        )?;
        Ok(())
    }

    pub fn set_file_target(&self, pkg: &str, path: &str, target: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE files SET link_target = ?3 WHERE pkg = ?1 AND path = ?2",
            params![pkg, path, target],
        )?;
        Ok(())
    }

    pub fn pending_of(&self, pkg: &str) -> Result<Vec<PendingFile>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, link_target, mode, kind FROM pending_files WHERE pkg = ?1 ORDER BY path",
        )?;
        let rows = stmt.query_map(params![pkg], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// The manifest a staged package will carry when it is activated.
    pub fn pending_manifest(&self, pkg: &str) -> Result<Option<crate::recipe::BuildManifest>> {
        let mut stmt = self
            .conn
            .prepare("SELECT manifest FROM pending_packages WHERE name = ?1")?;
        let mut rows = stmt.query(params![pkg])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let text: String = row.get(0)?;
        if text.is_empty() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&text)?))
    }

    pub fn pending_owner(&self, path: &str) -> Result<Option<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkg, link_target FROM pending_files WHERE path = ?1")?;
        let mut rows = stmt.query(params![path])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    pub fn clear_pending(&self, pkg: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_files WHERE pkg = ?1", params![pkg])?;
        Ok(())
    }

    pub fn owner(&self, path: &str) -> Result<Option<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkg, sha256 FROM files WHERE path = ?1")?;
        let mut rows = stmt.query(params![path])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    pub fn delete_package(&self, pkg: &str) -> Result<()> {
        // one transaction; the package row is deleted last
        let tx = rusqlite::Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM files WHERE pkg = ?1", params![pkg])?;
        tx.execute("DELETE FROM pending_files WHERE pkg = ?1", params![pkg])?;
        tx.execute("DELETE FROM pending_packages WHERE name = ?1", params![pkg])?;
        tx.execute(
            "DELETE FROM depends WHERE pkg = ?1 OR dep = ?1",
            params![pkg],
        )?;
        tx.execute("DELETE FROM sonames WHERE pkg = ?1", params![pkg])?;
        tx.execute("DELETE FROM needs WHERE pkg = ?1 OR dep = ?1", params![pkg])?;
        tx.execute("DELETE FROM manifests WHERE pkg = ?1", params![pkg])?;
        tx.execute("DELETE FROM adopted WHERE pkg = ?1", params![pkg])?;
        tx.execute("DELETE FROM packages WHERE name = ?1", params![pkg])?;
        tx.commit()?;
        Ok(())
    }

    pub fn current_files(&self) -> Result<Vec<FileRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, pkg, sha256, link_target, mode FROM files ORDER BY path")?;
        let rows = stmt.query_map([], |row| {
            Ok(FileRow {
                path: row.get(0)?,
                pkg: row.get(1)?,
                sha256: row.get(2)?,
                link_target: row.get(3)?,
                mode: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

pub fn line(label: &str, value: impl std::fmt::Display) {
    say!("{label:<10} {value}");
}

/// Runs one legacy `ADD COLUMN` statement; a column that is already there is
/// not an error, everything else is.
fn add_column(conn: &Connection, sql: &str) -> Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(error) => {
            if error.to_string().contains("duplicate column name") {
                Ok(())
            } else {
                Err(error).with_context(|| format!("running {sql}"))
            }
        }
    }
}

/// Store path and RUNPATH pairs recorded across the retained generations, with a
/// count of manifests that could not be read.
pub type GenerationEntries = (Vec<(String, Vec<String>)>, usize);

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct State {
    pub packages: Vec<PackageRow>,
    pub files: Vec<FileRow>,
    // Signed manifests recorded with the generation.
    #[serde(default)]
    pub manifests: Vec<(String, String)>,
    /// Host files this generation took over, as `path -> backup` pairs.
    #[serde(default)]
    pub adopted: Vec<(String, String, String)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRow {
    pub path: String,
    pub pkg: String,
    pub sha256: String,
    pub link_target: String,
    #[serde(default)]
    pub mode: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch_db(tag: &str) -> (std::path::PathBuf, Paths, Db) {
        let root = std::env::temp_dir().join(format!("portalis-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/db/portalis")).unwrap();
        let paths = Paths::at(root.clone());
        let db = Db::open(&paths, Access::Write).unwrap();
        (root, paths, db)
    }

    fn insert_package(db: &Db, name: &str, store: &str) {
        db.conn
            .execute(
                "INSERT INTO packages (name, version, store_path, recipe_sha256, \
                 manifest_digest, installed_at, build_log) \
                 VALUES (?1, '1.0', ?2, 'x', 'y', 'now', 'log')",
                params![name, store],
            )
            .unwrap();
    }

    #[test]
    fn a_generation_carries_the_adoptions_it_took_over() {
        let (root, _paths, mut db) = scratch_db("adopted");
        insert_package(&db, "foo", "/usr/portalis/packages/foo-1.0-aaa");
        db.set_adopted(
            "foo",
            "/usr/bin/tool",
            "/var/lib/portalis/backup/usr/bin/tool",
        )
        .unwrap();
        let id = db.snapshot("adopt foo").unwrap();
        db.clear_adopted_path("foo", "/usr/bin/tool").unwrap();
        assert!(db.adopted_of("foo").unwrap().is_empty(), "adoption stayed");

        let state = db.state_of(id).unwrap().expect("the generation exists");
        db.replace_state(&state).unwrap();
        let restored = db.adopted_of("foo").unwrap();
        assert_eq!(
            restored,
            vec![(
                "/usr/bin/tool".to_string(),
                "/var/lib/portalis/backup/usr/bin/tool".to_string()
            )],
            "the adoption did not come back with the generation"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_rolled_back_state_drops_the_staged_copy() {
        let (root, _paths, mut db) = scratch_db("pendingrollback");
        insert_package(&db, "foo", "/usr/portalis/packages/foo-1.0-aaa");
        let id = db.snapshot("before staging").unwrap();
        db.conn
            .execute(
                "INSERT INTO pending_packages (name, version, store_path, recipe_sha256, \
                 manifest_digest, installed_at, build_log, force) \
                 VALUES ('next', '2.0', '/usr/portalis/packages/next-2.0-bbb', 'x', 'y', 'now', 'log', 0)",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO pending_files (pkg, path, sha256, link_target, kind, mode) \
                 VALUES ('next', '/usr/bin/next', 'abc', '', 'file', 493)",
                [],
            )
            .unwrap();
        assert_eq!(
            db.pending_packages().unwrap().len(),
            1,
            "staging did not take"
        );

        let state = db.state_of(id).unwrap().expect("the generation exists");
        db.replace_state(&state).unwrap();
        assert!(
            db.pending_packages().unwrap().is_empty(),
            "a staged copy survived the rollback and would be applied at the next shutdown"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_store_refuses_when_a_generation_cannot_be_read() {
        let (root, paths, db) = scratch_db("corruptgen");
        db.conn
            .execute(
                "INSERT INTO generations (created_at, note, manifest) VALUES ('now', 'x', 'not json')",
                [],
            )
            .unwrap();

        let error = crate::commands::clean_cmd(&paths, &db, false, true, false, true)
            .expect_err("an unreadable generation must stop store reclamation");

        assert!(
            format!("{error}").contains("could not be read"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_runpath_reference_keeps_its_store_out_of_reclaim() {
        let (root, paths, db) = scratch_db("runpath");
        insert_package(
            &db,
            "appa",
            &paths.store().join("appa-1.0-aaa").to_string_lossy(),
        );
        let dep_entry = paths
            .store()
            .join("zlib-1.0-bbb/usr/lib")
            .to_string_lossy()
            .to_string();
        db.conn
            .execute(
                "UPDATE packages SET rpath = ?1 WHERE name = 'appa'",
                params![serde_json::to_string(&vec![dep_entry]).unwrap()],
            )
            .unwrap();

        let (used, unreadable) = crate::commands::referenced_stores(&paths, &db).unwrap();
        assert_eq!(
            unreadable, 0,
            "a readable database has no unreadable manifest"
        );

        assert!(
            used.contains("zlib-1.0-bbb"),
            "a store named only by a RUNPATH was reported as reclaimable: {used:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sync_depends_keeps_edges_whose_recipe_is_gone() {
        let (root, paths, db) = scratch_db("sync");
        insert_package(&db, "app", "/usr/portalis/packages/app-1.0-abc");
        db.set_depends("app", &["lib".to_string()]).unwrap();

        crate::install::sync_depends(&db, &paths).unwrap();

        assert_eq!(
            db.depends_of("app").unwrap(),
            vec!["lib".to_string()],
            "an unreadable recipe must not drop the recorded edges"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn records_whose_owner_is_gone_are_found() {
        let (root, _paths, db) = scratch_db("orphanrows");
        insert_package(&db, "app", "/usr/portalis/packages/app-1.0-abc");
        db.conn
            .execute(
                "INSERT INTO files (pkg, path, sha256, link_target, mode) \
                 VALUES ('app', '/usr/share/app/a', 'aa', '/x/a', 420)",
                [],
            )
            .unwrap();
        assert!(db.owners_without_package().unwrap().is_empty());

        db.conn
            .execute("DELETE FROM packages WHERE name = 'app'", [])
            .unwrap();
        assert_eq!(
            db.owners_without_package().unwrap(),
            vec!["app".to_string()]
        );

        db.conn
            .execute(
                "INSERT INTO pending_files (pkg, path, sha256, link_target, mode, kind) \
                 VALUES ('app', '/usr/share/app/b', 'bb', '/x/b', 420, 'link')",
                [],
            )
            .unwrap();
        assert_eq!(
            db.staged_without_pending().unwrap(),
            vec!["app".to_string()]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn index_state_follows_the_marker() {
        let (root, _paths, db) = scratch_db("marker");
        assert!(!db.edges_indexed(), "a fresh database is not indexed");
        db.mark_indexed().unwrap();
        assert!(db.edges_indexed());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn removing_a_package_drops_its_edges() {
        let (root, _paths, db) = scratch_db("edges");
        insert_package(&db, "app", "/usr/portalis/packages/app-1.0-abc");
        insert_package(&db, "lib", "/usr/portalis/packages/lib-1.0-def");
        db.set_depends("app", &["lib".to_string()]).unwrap();
        db.set_sonames("lib", &[("libfoo.so.1".to_string(), 64)])
            .unwrap();
        db.set_needs("app", &[("lib".to_string(), "libfoo.so.1".to_string(), 64)])
            .unwrap();

        db.delete_package("lib").unwrap();

        assert!(
            db.depends_of("app").unwrap().is_empty(),
            "declared edge survived"
        );
        assert!(db.soname_owner("libfoo.so.1", 64).unwrap().is_none());
        assert!(db.needs_of("app").unwrap().is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn two_providers_of_one_soname_stay_separate() {
        let (root, _paths, db) = scratch_db("sonames");
        db.set_sonames("lib-1", &[("libfoo.so.1".to_string(), 64)])
            .unwrap();
        db.set_sonames("lib-2", &[("libfoo.so.1".to_string(), 64)])
            .unwrap();
        let owners: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sonames WHERE soname = 'libfoo.so.1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owners, 2, "the second provider overwrote the first");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reading_an_old_database_asks_for_a_root_run() {
        let (root, paths, db) = scratch_db("read-old");
        db.conn.execute_batch("DROP TABLE manifests;").unwrap();
        drop(db);

        let text = match Db::open(&paths, Access::Read) {
            Ok(_) => panic!("an old database was opened for reading"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            text.contains("run a command as root once"),
            "the refusal did not explain how to migrate: {text}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_link_tables_are_rebuilt() {
        let (root, paths, db) = scratch_db("migrate");
        db.conn
            .execute_batch(
                "PRAGMA user_version = 1;
                 DROP TABLE IF EXISTS sonames;
                 CREATE TABLE sonames (soname TEXT PRIMARY KEY, pkg TEXT NOT NULL);",
            )
            .unwrap();
        drop(db);

        let db = Db::open(&paths, Access::Write).unwrap();
        let columns: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('sonames') WHERE name = 'bits'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(columns, 1, "the old table survived the upgrade");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prune_keeps_boot_and_recovery_anchors() {
        let root = std::env::temp_dir().join(format!("portalis-prune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/db/portalis")).unwrap();
        let paths = Paths::at(root.clone());
        let db = Db::open(&paths, Access::Write).unwrap();
        for _ in 0..8 {
            db.snapshot("test").unwrap();
        }
        let ids: Vec<i64> = db
            .generations()
            .unwrap()
            .into_iter()
            .map(|row| row.0)
            .collect();
        let protected = vec![ids[0], ids[1]];
        let removed = db.prune_generations(2, &protected).unwrap();
        let left: Vec<i64> = db
            .generations()
            .unwrap()
            .into_iter()
            .map(|row| row.0)
            .collect();
        assert!(left.contains(&ids[0]), "oldest anchor was pruned");
        assert!(left.contains(&ids[1]), "second anchor was pruned");
        assert_eq!(left.len(), 4);
        assert_eq!(removed, ids.len() - left.len());
        let _ = fs::remove_dir_all(&root);
    }
}
