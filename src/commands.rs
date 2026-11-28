//! Maintenance commands: cleanup planning, housekeeping and store accounting.

use crate::db;
use crate::paths::{self, Paths};
use crate::recipe;
use crate::util;
use crate::BACKUP_RETENTION_DAYS;
use anyhow::Result;
use std::path::{Path, PathBuf};

pub(crate) fn dir_size(path: &std::path::Path) -> u64 {
    let Ok(root) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if root.file_type().is_symlink() {
        return 0;
    }
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(link_meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if link_meta.file_type().is_symlink() {
                total += link_meta.len();
            } else if meta.is_dir() {
                total += dir_size(&entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

/// Store names referenced by symlinks anywhere below the live root.
pub(crate) fn linked_store_names(paths: &Paths) -> Result<std::collections::HashSet<String>> {
    fn lexical(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir => out.push("/"),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::Normal(name) => out.push(name),
                std::path::Component::Prefix(_) => {}
            }
        }
        out
    }

    fn skip_tree(entry: &walkdir::DirEntry) -> bool {
        if entry.depth() != 1 {
            return true;
        }
        !matches!(
            entry.file_name().to_str(),
            Some("proc") | Some("sys") | Some("dev")
        )
    }

    let root = paths.target_root();
    let store = paths.store();
    let store = std::fs::canonicalize(&store).unwrap_or(store);
    let mut names = std::collections::HashSet::new();
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(skip_tree)
    {
        let entry = entry?;
        if !entry.file_type().is_symlink() {
            continue;
        }
        let target = std::fs::read_link(entry.path())?;
        let target = if target.is_absolute() {
            target
        } else {
            entry.path().parent().unwrap_or(Path::new("")).join(target)
        };
        let target = std::fs::canonicalize(&target).unwrap_or_else(|_| lexical(&target));
        let Ok(rest) = target.strip_prefix(&store) else {
            continue;
        };
        let Some(name) = rest.components().next() else {
            continue;
        };
        let name = name.as_os_str();
        if !name.is_empty() {
            names.insert(name.to_string_lossy().to_string());
        }
    }
    Ok(names)
}

/// Whether any running process holds a file from `store`, read from `/proc`.
///
/// Returns an error when the answer cannot be established: a caller that is
/// about to delete a store has to treat "unknown" as "in use".
pub(crate) fn store_in_use(store: &std::path::Path) -> Result<bool> {
    crate::proc::store_in_use_in(std::path::Path::new("/proc"), store)
}

pub(crate) fn stale_build_logs(paths: &Paths, db: &db::Db) -> Result<Vec<PathBuf>> {
    let mut known: Vec<String> = db.packages()?.into_iter().map(|pkg| pkg.name).collect();
    for entry in std::fs::read_dir(paths.recipes())? {
        let entry = entry?;
        if paths::is_recipe(&entry.path()) {
            if let Ok(recipe) = recipe::Recipe::load(&entry.path()) {
                known.push(recipe.package.name);
            }
        }
    }
    known.sort();
    known.dedup();
    let mut entries: Vec<(PathBuf, std::time::SystemTime)> = std::fs::read_dir(paths.logs())?
        .flatten()
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect();
    entries.sort_by_key(|(_, modified)| *modified);
    let mut stale = Vec::new();
    for package in &known {
        let prefix = format!("{package}-");
        let mut matching: Vec<_> = entries
            .iter()
            .filter(|(path, _)| {
                path.file_name()
                    .map(|n| n.to_string_lossy().starts_with(&prefix))
                    .unwrap_or(false)
                    && util::log_is_for(path, package)
            })
            .map(|(path, _)| path.clone())
            .collect();
        if matching.len() > util::BUILD_LOGS_PER_PACKAGE {
            let excess = matching.len() - util::BUILD_LOGS_PER_PACKAGE;
            stale.extend(matching.drain(..excess));
        }
    }
    Ok(stale)
}

/// Logs whose package is neither installed nor described by a recipe.
pub(crate) fn stale_orphan_logs(paths: &Paths, db: &db::Db) -> Result<Vec<PathBuf>> {
    let mut known: std::collections::HashSet<String> =
        db.packages()?.into_iter().map(|pkg| pkg.name).collect();
    for entry in std::fs::read_dir(paths.recipes())? {
        let entry = entry?;
        if paths::is_recipe(&entry.path()) {
            if let Ok(recipe) = recipe::Recipe::load(&entry.path()) {
                known.insert(recipe.package.name);
            }
        }
    }
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(paths.logs())?.flatten() {
        if let Some(package) = util::log_package(&entry.path()) {
            if !known.contains(&package) {
                stale.push(entry.path());
            }
        }
    }
    Ok(stale)
}

pub(crate) fn housekeeping(paths: &Paths, db: &db::Db) {
    if let Ok(dirs) = stale_build_dirs(paths) {
        let now = std::time::SystemTime::now();
        for dir in dirs {
            let oldest = std::fs::metadata(&dir)
                .and_then(|meta| meta.modified())
                .map(|modified| now.duration_since(modified).unwrap_or_default() >= STALE_BUILD_AGE)
                .unwrap_or(false);
            if oldest {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    if let Ok(files) = stale_build_logs(paths, db) {
        for file in files {
            let _ = std::fs::remove_file(file);
        }
    }
    // The recipes decide the dependency index; a write command brings it in step.
    if let Err(error) = crate::install::sync_depends(db, paths) {
        eprintln!("note: dependency index not refreshed: {error}");
    }
}

pub(crate) fn stale_build_dirs(paths: &Paths) -> Result<Vec<PathBuf>> {
    let mut stale = Vec::new();
    let Ok(entries) = std::fs::read_dir(paths.state_dir()) else {
        return Ok(stale);
    };
    for entry in entries.flatten() {
        let is_build = entry.file_name().to_string_lossy().starts_with("build-");
        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
        if is_build && is_dir {
            stale.push(entry.path());
        }
    }
    Ok(stale)
}

/// True when a build directory is older than the retention age.
fn build_dir_is_stale(dir: &std::path::Path) -> bool {
    std::fs::metadata(dir)
        .and_then(|meta| meta.modified())
        .map(|modified| {
            std::time::SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default()
                >= STALE_BUILD_AGE
        })
        .unwrap_or(false)
}

pub(crate) fn backup_retention_days(paths: &Paths) -> u64 {
    match util::load_conf(&paths.config_file()) {
        Ok(conf) => conf
            .get("maintenance.backup_retention_days")
            .and_then(|value| value.parse::<u64>().ok())
            .map(|days| days.clamp(1, 3650))
            .unwrap_or(BACKUP_RETENTION_DAYS),
        Err(error) => {
            eprintln!("warning: {error}; keeping the default retention");
            BACKUP_RETENTION_DAYS
        }
    }
}

fn unused_stores(paths: &Paths, db: &db::Db) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let (used, unreadable) = referenced_stores(paths, db)?;
    if unreadable > 0 {
        anyhow::bail!(
            "cannot decide which stores are unreferenced: {unreadable} generation manifest(s) could not be read"
        );
    }
    for entry in std::fs::read_dir(paths.store())? {
        let entry = entry?;
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if used.contains(&name) {
            continue;
        }
        match store_in_use(&entry.path()) {
            Ok(true) => {
                say!("in use   {} (skipped)", entry.path().display());
                continue;
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("warning: skipping {}: {error:#}", entry.path().display());
                continue;
            }
        }
        dirs.push(entry.path());
    }
    Ok(dirs)
}

fn stale_backups(paths: &Paths, db: &db::Db) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut by_recipe: std::collections::BTreeMap<String, Vec<PathBuf>> = Default::default();
    for entry in std::fs::read_dir(paths.recipes())? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some((base, _)) = name.split_once(".bak-") {
            by_recipe
                .entry(base.to_string())
                .or_default()
                .push(entry.path());
        }
    }
    for (_base, mut group) in by_recipe {
        group.sort_by_key(|path| path.metadata().and_then(|m| m.modified()).ok());
        if group.len() > 1 {
            let excess = group.len() - 1;
            files.extend(group.into_iter().take(excess));
        }
    }
    let retained_days = backup_retention_days(paths);
    let cutoff =
        std::time::SystemTime::now() - std::time::Duration::from_secs(retained_days * 86400);
    // backups named by the adopted table, relative to the backup root
    let backup_root = paths.state_dir().join("backup");
    match std::fs::symlink_metadata(&backup_root) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            eprintln!(
                "warning: {} is not a directory; backups were not scanned",
                backup_root.display()
            );
            return Ok(files);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(files),
        Err(error) => return Err(error.into()),
    }
    let mut adopted: std::collections::HashSet<PathBuf> = Default::default();
    for recorded in db.adopted_backups()? {
        match Path::new(&recorded).strip_prefix(&backup_root) {
            Ok(rel) => {
                adopted.insert(rel.to_path_buf());
            }
            Err(_) => say!(
                "warning: adopted backup outside {}: {recorded}",
                backup_root.display()
            ),
        }
    }
    let mut stack = vec![backup_root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.modified().map(|m| m < cutoff).unwrap_or(false)
                && !adopted.contains(path.strip_prefix(&backup_root).unwrap_or(path.as_path()))
            {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn remove_files(files: &[PathBuf], yes: bool) -> Result<u64> {
    let mut bytes = 0u64;
    for file in files {
        bytes += file.metadata().map(|m| m.len()).unwrap_or(0);
        if yes {
            match std::fs::remove_file(file) {
                Ok(()) => say!("removed  {}", file.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            say!("stale    {}", file.display());
        }
    }
    Ok(bytes)
}

fn remove_dirs(paths: &Paths, dirs: &[PathBuf], yes: bool) -> Result<u64> {
    let mut bytes = 0u64;
    for dir in dirs {
        bytes += dir_size(dir);
        if yes {
            // ask again right before deleting
            if dir.starts_with(paths.store()) {
                match store_in_use(dir) {
                    Ok(true) => {
                        say!("in use   {} (skipped)", dir.display());
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        eprintln!("warning: skipping {}: {error:#}", dir.display());
                        continue;
                    }
                }
            }
            match std::fs::remove_dir_all(dir) {
                Ok(()) => say!("removed  {}", dir.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            say!("unused   {}", dir.display());
        }
    }
    Ok(bytes)
}

pub(crate) fn clean_cmd(
    paths: &Paths,
    db: &db::Db,
    logs: bool,
    store: bool,
    backups: bool,
    yes: bool,
) -> Result<()> {
    let all = !logs && !store && !backups;
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    if logs || all {
        files.extend(stale_build_logs(paths, db)?);
        files.extend(stale_orphan_logs(paths, db)?);
    }
    if store || all {
        dirs.extend(
            stale_build_dirs(paths)?
                .into_iter()
                .filter(|dir| build_dir_is_stale(dir)),
        );
        dirs.extend(unused_stores(paths, db)?);
    }
    if backups || all {
        files.extend(stale_backups(paths, db)?);
    }
    let mut bytes = remove_files(&files, yes)?;
    bytes += remove_dirs(paths, &dirs, yes)?;
    say!(
        "{} {} file(s), {} store dir(s), {}",
        if yes { "deleted" } else { "would delete" },
        files.len(),
        dirs.len(),
        crate::util::human_size(bytes)
    );
    if !yes {
        say!("re-run with --yes to delete");
    }
    crate::json::done(serde_json::json!({
        "files": files.len(),
        "stores": dirs.len(),
        "bytes": bytes,
        "deleted": yes,
    }));
    Ok(())
}

/// The first path component of [entry] below [store_root].
fn store_name_under(store_root: &std::path::Path, entry: &str) -> Option<String> {
    let rest = std::path::Path::new(entry).strip_prefix(store_root).ok()?;
    rest.components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
}

fn push_store_name(used: &mut std::collections::HashSet<String>, store_path: &str) {
    if let Some(name) = Path::new(store_path).file_name() {
        used.insert(name.to_string_lossy().to_string());
    }
}

fn push_runpath_stores(
    used: &mut std::collections::HashSet<String>,
    store_root: &std::path::Path,
    rpath: &[String],
) {
    for entry in rpath {
        if let Some(name) = store_name_under(store_root, entry) {
            used.insert(name);
        }
    }
}

/// Store directories that something still refers to, plus the number of
/// generation manifests that could not be read.
pub(crate) fn referenced_stores(
    paths: &Paths,
    db: &db::Db,
) -> Result<(std::collections::HashSet<String>, usize)> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let store_root = paths.store();
    for pkg in db.packages()?.into_iter().chain(db.pending_packages()?) {
        push_store_name(&mut used, &pkg.store_path);
        push_runpath_stores(&mut used, &store_root, &pkg.rpath);
    }
    used.extend(linked_store_names(paths)?);
    let (generations, unreadable) = db.generation_entries()?;
    for (store_path, rpath) in generations {
        push_store_name(&mut used, &store_path);
        push_runpath_stores(&mut used, &store_root, &rpath);
    }
    Ok((used, unreadable))
}

pub(crate) fn report_reclaimable_stores(paths: &Paths, db: &db::Db) {
    let Ok((used, unreadable)) = referenced_stores(paths, db) else {
        return;
    };
    if unreadable > 0 {
        say!(
            "note     {unreadable} generation manifest(s) could not be read; store reclamation stays off"
        );
        return;
    }
    let Ok(entries) = std::fs::read_dir(paths.store()) else {
        return;
    };
    let reclaimable = entries
        .flatten()
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .filter(|entry| !used.contains(&entry.file_name().to_string_lossy().to_string()))
        .count();
    if reclaimable > 0 {
        say!("note     {reclaimable} unreferenced store(s); `moirse clean --store` reclaims them");
    }
}

pub(crate) const STALE_BUILD_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

#[cfg(test)]
mod tests {
    use super::{dir_size, stale_orphan_logs};

    #[test]
    fn a_size_scan_does_not_follow_a_symlink_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, vec![0u8; 4096]).expect("outside file");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&outside, &link).expect("link");
        assert_eq!(
            dir_size(&link),
            0,
            "a symlink root was followed into its target"
        );
        assert_eq!(
            std::fs::metadata(&outside).expect("outside").len(),
            4096,
            "the target changed"
        );
    }

    #[test]
    fn an_orphan_build_log_is_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::Paths::at(dir.path());
        paths.ensure_layout().expect("layout");
        let db = crate::db::Db::open(&paths, crate::db::Access::Write).expect("db");
        let log = paths.logs().join("gone-1.0-0001.log");
        std::fs::write(&log, b"portalis build gone 1.0\n").expect("log");
        let stale = stale_orphan_logs(&paths, &db).expect("orphans");
        assert_eq!(stale, vec![log]);
    }

    #[test]
    fn a_proc_that_cannot_be_read_is_an_error_not_a_free_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-proc");
        let store = dir.path().join("store");
        let answer = crate::proc::store_in_use_in(&missing, &store);
        assert!(
            answer.is_err(),
            "an unreadable /proc was reported as {answer:?}"
        );
    }

    #[test]
    fn a_store_no_process_maps_is_not_in_use() {
        let dir = tempfile::tempdir().expect("tempdir");
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("1")).expect("proc dir");
        std::fs::create_dir_all(proc_root.join("1/fd")).expect("fd dir");
        std::fs::write(
            proc_root.join("1/maps"),
            "7f00-7f01 r-xp 00000000 00:00 0 /usr/lib/libc.so.6\n",
        )
        .expect("maps");
        let store = dir.path().join("store");
        assert!(
            !crate::proc::store_in_use_in(&proc_root, &store).expect("answer"),
            "a store nothing maps was reported as in use"
        );
        std::fs::write(
            proc_root.join("1/maps"),
            format!("7f00-7f01 r-xp 00000000 00:00 0 {}\n", store.display()),
        )
        .expect("maps");
        assert!(
            crate::proc::store_in_use_in(&proc_root, &store).expect("answer"),
            "a mapped store was reported as free"
        );
    }
}

#[cfg(test)]
mod store_reference_tests {
    use super::linked_store_names;
    use super::store_name_under;
    use crate::paths::Paths;
    use std::path::Path;

    #[test]
    fn a_runpath_entry_names_the_store_it_lives_in() {
        let root = Path::new("/usr/portalis/packages");
        assert_eq!(
            store_name_under(root, "/usr/portalis/packages/zlib-1.3-abc123/usr/lib").as_deref(),
            Some("zlib-1.3-abc123")
        );
    }

    #[test]
    fn an_entry_outside_the_store_names_nothing() {
        let root = Path::new("/usr/portalis/packages");
        assert_eq!(store_name_under(root, "/usr/lib"), None);
    }

    #[test]
    fn relative_and_absolute_live_links_name_their_stores() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        let first = paths.store().join("first-1.0-aaaa");
        let second = paths.store().join("second-1.0-bbbb");
        std::fs::create_dir_all(first.join("usr/lib")).expect("first store");
        std::fs::create_dir_all(second.join("usr/lib")).expect("second store");
        let live = paths.target_root().join("usr/bin");
        std::fs::create_dir_all(&live).expect("live");
        std::os::unix::fs::symlink(
            "../../usr/portalis/packages/first-1.0-aaaa/usr/lib/x",
            live.join("relative"),
        )
        .expect("relative link");
        std::os::unix::fs::symlink(second.join("usr/lib/y"), live.join("absolute"))
            .expect("absolute link");

        let names = linked_store_names(&paths).expect("store links");
        assert!(names.contains("first-1.0-aaaa"), "{names:?}");
        assert!(names.contains("second-1.0-bbbb"), "{names:?}");
    }
}
