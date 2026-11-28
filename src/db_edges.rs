//! Derived edges: declared dependencies, library owners and index freshness.

use crate::db::{Db, INDEX_META_KEY};
use anyhow::Result;
use rusqlite::params;

impl Db {
    pub(crate) fn mark_indexed(&self) -> Result<()> {
        self.set_meta(INDEX_META_KEY, &crate::now())
    }

    pub(crate) fn clear_index(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE key = ?1", params![INDEX_META_KEY])?;
        Ok(())
    }

    pub(crate) fn edges_indexed(&self) -> bool {
        self.meta_value(INDEX_META_KEY).ok().flatten().is_some()
    }

    pub(crate) fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub(crate) fn meta_value(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    pub(crate) fn set_depends(&self, pkg: &str, deps: &[String]) -> Result<()> {
        self.conn
            .execute("DELETE FROM depends WHERE pkg = ?1", params![pkg])?;
        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO depends (pkg, dep) VALUES (?1, ?2)")?;
        for dep in deps {
            stmt.execute(params![pkg, dep])?;
        }
        Ok(())
    }

    pub(crate) fn package_names_with_edges(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT pkg FROM depends")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn clear_depends(&self, pkg: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM depends WHERE pkg = ?1", rusqlite::params![pkg])?;
        Ok(())
    }

    pub(crate) fn depends_of(&self, pkg: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT dep FROM depends WHERE pkg = ?1 ORDER BY dep")?;
        let rows = stmt.query_map(params![pkg], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn dependents_of(&self, dep: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkg FROM depends WHERE dep = ?1 ORDER BY pkg")?;
        let rows = stmt.query_map(params![dep], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn set_sonames(&self, pkg: &str, sonames: &[(String, u8)]) -> Result<()> {
        self.conn
            .execute("DELETE FROM sonames WHERE pkg = ?1", params![pkg])?;
        let mut stmt = self
            .conn
            .prepare("INSERT OR REPLACE INTO sonames (soname, bits, pkg) VALUES (?1, ?2, ?3)")?;
        for (soname, bits) in sonames {
            stmt.execute(params![soname, bits, pkg])?;
        }
        Ok(())
    }

    pub(crate) fn soname_owner(&self, soname: &str, bits: u8) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT pkg FROM sonames WHERE soname = ?1 AND bits = ?2 ORDER BY pkg LIMIT 1",
        )?;
        let mut rows = stmt.query(params![soname, bits])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    pub(crate) fn set_needs(&self, pkg: &str, needs: &[(String, String, u8)]) -> Result<()> {
        self.conn
            .execute("DELETE FROM needs WHERE pkg = ?1", params![pkg])?;
        let mut stmt = self.conn.prepare(
            "INSERT OR REPLACE INTO needs (pkg, dep, soname, bits) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (dep, soname, bits) in needs {
            stmt.execute(params![pkg, dep, soname, bits])?;
        }
        Ok(())
    }

    pub(crate) fn needs_of(&self, pkg: &str) -> Result<Vec<(String, String, u8)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT dep, soname, bits FROM needs WHERE pkg = ?1 ORDER BY soname")?;
        let rows = stmt.query_map(params![pkg], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u8>(2)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn users_of(&self, pkg: &str) -> Result<Vec<String>> {
        let mut users: Vec<String> = self.dependents_of(pkg)?;
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT pkg FROM needs WHERE dep = ?1")?;
        for name in stmt.query_map(params![pkg], |row| row.get::<_, String>(0))? {
            users.push(name?);
        }
        users.sort();
        users.dedup();
        Ok(users)
    }
}
