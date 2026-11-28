//! Rows describing what each package owns.
use anyhow::Result;

use super::*;

impl Db {
    /// Packages with activated file records but no package row. A crash or a
    /// hand edit can leave these behind, and no other check looks at them.
    pub fn owners_without_package(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT pkg FROM files \
             WHERE pkg NOT IN (SELECT name FROM packages) ORDER BY pkg",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    }

    /// Packages with staged file records but no pending package row.
    pub fn staged_without_pending(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT pkg FROM pending_files \
             WHERE pkg NOT IN (SELECT name FROM pending_packages) ORDER BY pkg",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    }

    /// Records where the file this package took over was moved to.
    pub fn set_adopted(&self, pkg: &str, path: &str, backup: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO adopted (pkg, path, backup) VALUES (?1, ?2, ?3)",
            params![pkg, path, backup],
        )?;
        Ok(())
    }

    /// Removes one adopted path from a package.
    pub fn clear_adopted_path(&self, pkg: &str, path: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM adopted WHERE pkg = ?1 AND path = ?2",
            params![pkg, path],
        )?;
        Ok(())
    }

    /// Every backup path recorded in the adopted table.
    pub fn adopted_backups(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT backup FROM adopted")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Store paths and RUNPATHs recorded in the retained generations, with a
    /// count of the manifests that could not be read.
    pub fn generation_entries(&self) -> Result<GenerationEntries> {
        let mut stmt = self.conn.prepare("SELECT manifest FROM generations")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        let mut unreadable = 0usize;
        for row in rows {
            match serde_json::from_str::<State>(&row?) {
                Ok(state) => {
                    for pkg in state.packages {
                        out.push((pkg.store_path, pkg.rpath));
                    }
                }
                Err(_) => unreadable += 1,
            }
        }
        Ok((out, unreadable))
    }

    pub fn adopted_of(&self, pkg: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, backup FROM adopted WHERE pkg = ?1")?;
        let rows = stmt.query_map(params![pkg], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn manifest_of(&self, pkg: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT canonical FROM manifests WHERE pkg = ?1")?;
        let mut rows = stmt.query(params![pkg])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }
}
