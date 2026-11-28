//! Opening the database, migrating it, and running a transaction.
use anyhow::Result;
use rusqlite::Connection;

use super::*;

fn create_pending_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_packages (
             name TEXT PRIMARY KEY,
             version TEXT NOT NULL,
             store_path TEXT NOT NULL,
             recipe_sha256 TEXT NOT NULL,
             manifest_digest TEXT NOT NULL,
             installed_at TEXT NOT NULL,
             build_log TEXT NOT NULL,
             signature TEXT,
             rpath TEXT NOT NULL DEFAULT '[]',
             hooks TEXT NOT NULL DEFAULT '{}',
             force INTEGER NOT NULL DEFAULT 0,
             manifest TEXT NOT NULL DEFAULT ''
         );",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_files (
             pkg TEXT NOT NULL,
             path TEXT NOT NULL,
             sha256 TEXT NOT NULL,
             link_target TEXT NOT NULL,
             mode INTEGER NOT NULL DEFAULT 0,
             kind TEXT NOT NULL DEFAULT 'link',
             PRIMARY KEY (pkg, path)
         );",
    )?;
    Ok(())
}

impl Db {
    /// True when this connection may write.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    pub fn open(paths: &Paths, access: Access) -> Result<Self> {
        match access {
            Access::Read => Self::open_read(paths),
            Access::Write => Self::open_write(paths),
        }
    }

    /// A reading connection creates nothing: no file, no journal, no schema, so
    /// an account with read access can list what is installed.
    fn open_read(paths: &Paths) -> Result<Self> {
        let file = paths.db_file();
        // a reading connection cannot create the file, and a missing database is
        // not a permission problem: say which one it is
        if !file.exists() {
            bail!(
                "there is no package database yet ({}); install something first",
                file.display()
            );
        }
        let conn = Connection::open_with_flags(&file, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("opening database {} for reading", file.display()))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        for table in REQUIRED_TABLES {
            let mut stmt =
                conn.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1")?;
            let mut rows = stmt.query([table])?;
            if rows.next()?.is_none() {
                bail!(
                    "the package database predates this version (no {table} table); \
                     run a command as root once to migrate it"
                );
            }
        }
        for (table, column) in REQUIRED_COLUMNS {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let mut rows = stmt.query([])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == column {
                    found = true;
                    break;
                }
            }
            if !found {
                bail!(
                    "the package database predates this version (no {table}.{column}); \
                     run a command as root once to migrate it"
                );
            }
        }
        Ok(Self {
            conn,
            writable: false,
        })
    }

    fn open_write(paths: &Paths) -> Result<Self> {
        let file = paths.db_file();
        let conn = Connection::open(&file)
            .with_context(|| format!("opening database {}", file.display()))?;
        // A second install may hold the write lock while it finishes a large
        // package; waiting longer turns a spurious failure into a short pause
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // rollback journal: no shared-memory file next to the database
        if let Err(error) = conn.pragma_update(None, "journal_mode", "DELETE") {
            eprintln!(
                "warning: the package database keeps its current journal mode ({error}); \
                 other accounts may be unable to read it"
            );
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS packages (
                 name TEXT PRIMARY KEY,
                 version TEXT NOT NULL,
                 store_path TEXT NOT NULL,
                 recipe_sha256 TEXT NOT NULL,
                 manifest_digest TEXT NOT NULL,
                 installed_at TEXT NOT NULL,
                 build_log TEXT NOT NULL,
                 signature TEXT,
                 rpath TEXT NOT NULL DEFAULT '[]',
                 state TEXT NOT NULL DEFAULT 'active',
                 hooks TEXT NOT NULL DEFAULT '{}'
             );
             CREATE TABLE IF NOT EXISTS manifests (
                 pkg TEXT PRIMARY KEY,
                 canonical TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS adopted (
                 pkg TEXT NOT NULL,
                 path TEXT NOT NULL,
                 backup TEXT NOT NULL,
                 PRIMARY KEY (pkg, path)
             );
             CREATE TABLE IF NOT EXISTS files (
                 pkg TEXT NOT NULL,
                 path TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 link_target TEXT NOT NULL,
                 mode INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (pkg, path)
             );
             CREATE TABLE IF NOT EXISTS generations (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 created_at TEXT NOT NULL,
                 note TEXT NOT NULL,
                 manifest TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS depends (
                 pkg TEXT NOT NULL,
                 dep TEXT NOT NULL,
                 PRIMARY KEY (pkg, dep)
             );
",
        )?;
        conn.execute_batch(LINK_TABLES_SQL)?;
        create_pending_tables(&conn)?;
        let tx =
            rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
        for sql in [
            "ALTER TABLE packages ADD COLUMN rpath TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE packages ADD COLUMN state TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE packages ADD COLUMN hooks TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE pending_packages ADD COLUMN force INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE pending_packages ADD COLUMN rpath TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE pending_packages ADD COLUMN hooks TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE files ADD COLUMN mode INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE pending_files ADD COLUMN mode INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE pending_files ADD COLUMN kind TEXT NOT NULL DEFAULT 'link'",
        ] {
            add_column(&tx, sql)?;
        }
        tx.commit()?;
        let db = Self {
            conn,
            writable: true,
        };
        db.migrate_pending_manifest()?;
        db.migrate_link_tables()?;
        Ok(db)
    }

    /// Adds the staged manifest column to databases that predate it.
    fn migrate_pending_manifest(&self) -> Result<()> {
        let has_column = self
            .conn
            .prepare("PRAGMA table_info(pending_packages)")
            .and_then(|mut stmt| {
                let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
                let mut found = false;
                for name in names.flatten() {
                    if name == "manifest" {
                        found = true;
                    }
                }
                Ok(found)
            })
            .unwrap_or(false);
        if !has_column {
            self.conn.execute(
                "ALTER TABLE pending_packages ADD COLUMN manifest TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        Ok(())
    }

    /// Rebuilds the derived tables when they predate the current schema.
    fn migrate_link_tables(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version >= LINK_SCHEMA_VERSION {
            return Ok(());
        }
        // one transaction; the version moves only after every step succeeded
        let tx = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        tx.execute_batch("DROP TABLE IF EXISTS sonames; DROP TABLE IF EXISTS needs;")?;
        tx.execute_batch(LINK_TABLES_SQL)?;
        tx.execute("DELETE FROM meta WHERE key = ?1", params![INDEX_META_KEY])?;
        tx.execute_batch(&format!("PRAGMA user_version = {LINK_SCHEMA_VERSION}"))?;
        tx.commit()?;
        Ok(())
    }

    /// Runs `body` inside a transaction, rolling back when it fails.
    pub(crate) fn in_transaction<T>(&self, body: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match body(self) {
            Ok(value) => {
                if let Err(error) = self.conn.execute_batch("COMMIT") {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(error).context("committing the transaction");
                }
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    pub fn abort(&self) {
        let _ = self.conn.execute_batch("ROLLBACK");
    }

    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }
}
