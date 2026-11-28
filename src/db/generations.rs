//! Recording and restoring whole-tree generations.
use anyhow::Result;

use super::*;

impl Db {
    /// The state a generation records, read from the live tables.
    pub fn current_state(&self) -> Result<State> {
        let mut state = State::default();
        for pkg in self.packages()? {
            state.packages.push(pkg);
        }
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
        for row in rows {
            state.files.push(row?);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT pkg, canonical FROM manifests ORDER BY pkg")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        for row in rows {
            state.manifests.push(row?);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT pkg, path, backup FROM adopted ORDER BY pkg, path")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        for row in rows {
            state.adopted.push(row?);
        }
        Ok(state)
    }

    /// A digest of the current state, used by recovery to decide whether an
    /// operation that rewrites the tree already reached the database.
    pub fn state_digest(&self) -> Result<String> {
        let state = self.current_state()?;
        Ok(crate::util::sha256_bytes(&serde_json::to_vec(&state)?))
    }

    pub fn snapshot(&self, note: &str) -> Result<i64> {
        let state = self.current_state()?;
        let json = serde_json::to_string(&state)?;
        self.conn.execute(
            "INSERT INTO generations (created_at, note, manifest) VALUES (?1, ?2, ?3)",
            params![crate::now(), note, json],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn state_of(&self, id: i64) -> Result<Option<State>> {
        let mut stmt = self
            .conn
            .prepare("SELECT manifest FROM generations WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let state: State = serde_json::from_str(&json)
                .context("generation uses an older format and cannot be restored")?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub fn replace_state(&mut self, state: &State) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM packages", [])?;
        tx.execute("DELETE FROM files", [])?;
        tx.execute("DELETE FROM depends", [])?;
        tx.execute("DELETE FROM sonames", [])?;
        tx.execute("DELETE FROM needs", [])?;
        tx.execute("DELETE FROM manifests", [])?;
        // a staged copy belongs to the state being replaced, not to the one restored
        tx.execute("DELETE FROM pending_packages", [])?;
        tx.execute("DELETE FROM pending_files", [])?;
        // the index marker is cleared with the tables it describes
        tx.execute("DELETE FROM meta WHERE key = ?1", params![INDEX_META_KEY])?;
        for (pkg, canonical) in &state.manifests {
            tx.execute(
                "INSERT OR REPLACE INTO manifests (pkg, canonical) VALUES (?1, ?2)",
                params![pkg, canonical],
            )?;
        }
        for pkg in &state.packages {
            tx.execute(
                "INSERT OR REPLACE INTO packages
                 (name, version, store_path, recipe_sha256, manifest_digest, installed_at, build_log, signature, rpath, state, hooks)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    pkg.name,
                    pkg.version,
                    pkg.store_path,
                    pkg.recipe_sha256,
                    pkg.manifest_digest,
                    pkg.installed_at,
                    pkg.build_log,
                    pkg.signature,
                    serde_json::to_string(&pkg.rpath)?,
                    pkg.state,
                    serde_json::to_string(&pkg.hooks)?
                ],
            )?;
        }
        // adoptions travel with the generation; rows the restored state does
        // not name are dropped with it
        tx.execute("DELETE FROM adopted", [])?;
        for (pkg, path, backup) in &state.adopted {
            tx.execute(
                "INSERT OR REPLACE INTO adopted (pkg, path, backup) VALUES (?1, ?2, ?3)",
                params![pkg, path, backup],
            )?;
        }
        for file in &state.files {
            tx.execute(
                "INSERT OR REPLACE INTO files (pkg, path, sha256, link_target, mode)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    file.pkg,
                    file.path,
                    file.sha256,
                    file.link_target,
                    file.mode
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn generations(&self) -> Result<Vec<(i64, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, created_at, note FROM generations ORDER BY id")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Drops all but the newest `keep` generation snapshots.
    pub fn prune_generations(&self, keep: usize, protected: &[i64]) -> Result<usize> {
        let keep = keep.max(1);
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM generations ORDER BY id DESC")?;
        let ids: Vec<i64> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        let mut retained: HashSet<i64> = ids.iter().take(keep).copied().collect();
        retained.extend(protected.iter().copied());
        let mut removed = 0usize;
        for id in ids {
            if retained.contains(&id) {
                continue;
            }
            removed += self
                .conn
                .execute("DELETE FROM generations WHERE id = ?1", [id])?;
        }
        Ok(removed)
    }
}
