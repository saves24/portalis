//! Process inspection: who is using a store or a live path.

use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// True when `path` is `root` or lies below it; `/usr/bin` is below `/usr` and
/// `/usrx` is not.
fn under(path: &str, root: &str) -> bool {
    if root == "/" {
        return path.starts_with('/');
    }
    if path == root {
        return true;
    }
    match path.strip_prefix(root) {
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// `/proc/<pid>/maps` escapes spaces and newlines with octal codes.
fn unescape(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = &bytes[index + 1..index + 4];
            if digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                let value = (digits[0] - b'0') as u16 * 64
                    + (digits[1] - b'0') as u16 * 8
                    + (digits[2] - b'0') as u16;
                if value <= u8::MAX as u16 {
                    out.push(value as u8);
                    index += 4;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A mapped or opened file keeps this suffix once it was replaced; the path that
/// matters is the one before it.
fn clean(candidate: &str) -> String {
    unescape(candidate.trim_end_matches(" (deleted)"))
}

/// The file name a maps line points at, if it has one.
fn maps_path(line: &str) -> Option<&str> {
    let mut parts = line.splitn(6, ' ');
    parts.next()?; // address range
    parts.next()?; // permissions
    parts.next()?; // offset
    parts.next()?; // device
    parts.next()?; // inode
    let path = parts.next()?.trim();
    path.starts_with('/').then_some(path)
}

/// Pids that hold the store open: mapped, executed, the working directory, or an
/// open descriptor.
pub(crate) fn processes_using(store: &Path) -> Result<Vec<(u32, String)>> {
    processes_using_in(Path::new("/proc"), store)
}

/// Whether any process holds a file from `store`.
pub(crate) fn store_in_use_in(proc_root: &Path, store: &Path) -> Result<bool> {
    Ok(!processes_using_in(proc_root, store)?.is_empty())
}

/// The same scan over a given proc filesystem. A pid that cannot be inspected
/// for a reason other than having exited makes this an error: "cannot tell" has
/// to reach the caller as "in use".
/// Looks through one process for a path under `needle`; the second value says
/// a source could not be read.
fn process_uses(proc_dir: &Path, needle: &str) -> (bool, bool) {
    let mut hit = false;
    let mut unreadable = false;
    match fs::read_link(proc_dir.join("exe")) {
        Ok(path) => hit = under(&clean(&path.to_string_lossy()), needle),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => unreadable = true,
    }
    if !hit && !unreadable {
        match fs::read_link(proc_dir.join("cwd")) {
            Ok(path) => hit = under(&clean(&path.to_string_lossy()), needle),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable = true,
        }
    }
    if !hit && !unreadable {
        match fs::read_to_string(proc_dir.join("maps")) {
            Ok(maps) => {
                hit = maps
                    .lines()
                    .filter_map(maps_path)
                    .any(|path| under(&clean(path), needle));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable = true,
        }
    }
    if !hit && !unreadable {
        match fs::read_dir(proc_dir.join("fd")) {
            Ok(descriptors) => {
                for descriptor in descriptors {
                    let descriptor = match descriptor {
                        Ok(entry) => entry,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => {
                            unreadable = true;
                            break;
                        }
                    };
                    match fs::read_link(descriptor.path()) {
                        Ok(path) => {
                            if under(&clean(&path.to_string_lossy()), needle) {
                                hit = true;
                                break;
                            }
                        }
                        // the process closed the descriptor under us
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {}
                        Err(_) => {
                            unreadable = true;
                            break;
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable = true,
        }
    }
    (hit, unreadable)
}

fn processes_using_in(proc_root: &Path, store: &Path) -> Result<Vec<(u32, String)>> {
    let store = store.canonicalize().unwrap_or_else(|_| store.to_path_buf());
    let needle = clean(&store.to_string_lossy());
    let mut found = Vec::new();
    let mut blind: Vec<u32> = Vec::new();
    for entry in
        fs::read_dir(proc_root).with_context(|| format!("reading {}", proc_root.display()))?
    {
        let entry =
            entry.with_context(|| format!("reading an entry of {}", proc_root.display()))?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let proc_dir = entry.path();
        let (hit, unreadable) = process_uses(&proc_dir, &needle);
        if unreadable && !hit {
            blind.push(pid);
            continue;
        }
        if hit {
            let command = fs::read_to_string(proc_dir.join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            found.push((pid, command));
        }
    }
    if !blind.is_empty() {
        blind.sort_unstable();
        let shown: Vec<String> = blind.iter().take(5).map(|pid| pid.to_string()).collect();
        bail!(
            "cannot tell whether {} is in use: no access to {} process(es) ({}{})",
            store.display(),
            blind.len(),
            shown.join(", "),
            if blind.len() > shown.len() {
                ", …"
            } else {
                ""
            }
        );
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// True for boot artifacts, which no user process maps.
pub(crate) fn is_critical_path(path: &str, in_use: &std::collections::HashSet<String>) -> bool {
    let canonical = fs::canonicalize(path)
        .ok()
        .map(|resolved| resolved.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    under(path, "/boot")
        || under(path, "/lib/modules")
        || under(path, "/usr/lib/modules")
        || under(&canonical, "/boot")
        || under(&canonical, "/lib/modules")
        || under(&canonical, "/usr/lib/modules")
        || in_use.contains(path)
        || in_use.contains(&canonical)
}

pub(crate) fn live_from_store(paths: &Paths, candidate: &str) -> Option<String> {
    let store = paths
        .store()
        .canonicalize()
        .unwrap_or_else(|_| paths.store());
    let store = store.to_string_lossy().to_string();
    let rest = candidate.strip_prefix(&store)?.trim_start_matches('/');
    let (_package, inner) = rest.split_once('/')?;
    if inner.is_empty() {
        None
    } else {
        Some(format!("/{inner}"))
    }
}

/// Records one path a process holds. A path under the store is reduced to the
/// live path that backs it; any other path is recorded as given.
fn record(path: &str, store: &str, paths: &Paths, used: &mut std::collections::HashSet<String>) {
    if under(path, store) {
        if let Some(live) = live_from_store(paths, path) {
            used.insert(live);
        }
    } else {
        used.insert(path.to_string());
    }
}

/// Collects live paths currently mapped or executed by any process.
///
/// Scope: `/proc/<pid>/maps` and `/proc/<pid>/exe` only. This answers "would
/// replacing this file disturbs something that is running", not "does any process
/// hold this store open" — that question belongs to [`store_in_use_in`], which
/// also looks at `cwd` and open descriptors.
pub(crate) fn live_paths_in_use(paths: &Paths) -> Result<std::collections::HashSet<String>> {
    let store = paths.store().to_string_lossy().to_string();
    let mut used = std::collections::HashSet::new();
    let mut blind: Vec<u32> = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let dir = entry.path();
        let mut unreadable = false;
        match fs::read_to_string(dir.join("maps")) {
            Ok(maps) => {
                for path in maps.lines().filter_map(maps_path) {
                    record(&clean(path), &store, paths, &mut used);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable = true,
        }
        match fs::read_link(dir.join("exe")) {
            Ok(path) => record(&clean(&path.to_string_lossy()), &store, paths, &mut used),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable = true,
        }
        if unreadable {
            blind.push(pid);
        }
    }
    if !blind.is_empty() {
        blind.sort_unstable();
        let shown: Vec<String> = blind.iter().take(5).map(|pid| pid.to_string()).collect();
        bail!(
            "cannot tell which files are in use: no access to {} process(es) ({}{})",
            blind.len(),
            shown.join(", "),
            if blind.len() > shown.len() {
                ", …"
            } else {
                ""
            }
        );
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::{clean, maps_path, under};
    use crate::paths::Paths;

    #[test]
    fn a_file_the_store_has_not_taken_over_counts_as_in_use() {
        use std::collections::HashSet;
        let root = std::env::temp_dir().join(format!("portalis-proc-{}", std::process::id()));
        let paths = Paths::at(root);
        let store = paths.store().to_string_lossy().to_string();
        let mut used = HashSet::new();
        // a base-system library a process mapped: recorded as it is
        super::record("/usr/lib/libc.so.6", &store, &paths, &mut used);
        assert!(used.contains("/usr/lib/libc.so.6"));
        // Records one path a process holds, reduced to its live path under the store.
        let owned = format!("{store}/libfoo-1.0-abc/usr/lib/libfoo.so.1");
        super::record(&owned, &store, &paths, &mut used);
        assert!(used.contains("/usr/lib/libfoo.so.1"), "{used:?}");
    }

    #[test]
    fn a_proc_root_that_cannot_be_read_is_an_error() {
        let base =
            std::env::temp_dir().join(format!("portalis-proc-missing-{}", std::process::id()));
        let paths = Paths::at(&base);
        let missing = base.join("no-such-proc");
        let error = crate::proc::store_in_use_in(&missing, &paths.store())
            .expect_err("a proc root that cannot be read was treated as free");
        assert!(
            format!("{error:#}").contains("reading"),
            "the error does not say what could not be read: {error:#}"
        );
    }

    #[test]
    fn a_prefix_matches_on_a_path_boundary() {
        assert!(under("/usr/lib/x", "/usr/lib"));
        assert!(under("/usr/lib", "/usr/lib"));
        assert!(!under("/usr/lib64/x", "/usr/lib"));
        assert!(!under("/usr/libx", "/usr/lib"));
    }

    #[test]
    fn a_replaced_file_loses_its_suffix() {
        assert_eq!(clean("/usr/bin/foo (deleted)"), "/usr/bin/foo");
    }

    #[test]
    fn an_escaped_space_is_decoded() {
        assert_eq!(clean("/home/a b/lib.so"), "/home/a b/lib.so");
        assert_eq!(clean("/home/a\\040b/lib.so"), "/home/a b/lib.so");
    }

    #[test]
    fn only_named_mappings_have_a_path() {
        assert_eq!(
            maps_path("7f00-7f01 r-xp 00000000 08:01 1234 /usr/lib/libc.so.6"),
            Some("/usr/lib/libc.so.6")
        );
        assert_eq!(maps_path("7f00-7f01 rw-p 00000000 00:00 0"), None);
        assert_eq!(maps_path("7f00-7f01 rw-p 00000000 00:00 0 [heap]"), None);
    }
}
