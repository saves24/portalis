//! Running a build step: dropping privileges, confining writes, logging the
//! output, and killing the process group when a step overruns.
use anyhow::{bail, Context, Result};
use std::path::Path;

mod run;
mod sandbox;

pub(crate) use run::BUILD_PATH;
pub use run::{capture_unprivileged, run_logged_as, run_unprivileged};

/// Resolves a host helper from a system directory with root ownership.
pub(crate) fn trusted_program(name: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    for directory in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let path = std::path::Path::new(directory).join(name);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 {
            return Some(path);
        }
    }
    None
}

/// Marks this process as the reaper of orphaned descendants.
pub(crate) fn become_subreaper() {
    // Safety: the call sets a flag on this process and touches no memory.
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
}

/// Kills every descendant of this process that runs as `uid`, and refuses to go
/// on while one is left. A process of the same account outside that tree is
/// untouched.
pub(crate) fn stop_build_descendants(uid: u32) -> Result<()> {
    let root = std::process::id();
    for _ in 0..40 {
        let found = descendants_running_as(Path::new("/proc"), root, uid)?;
        if found.is_empty() {
            return Ok(());
        }
        for pid in found {
            // Safety: the pid comes from /proc and names a process below this one.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let left = descendants_running_as(Path::new("/proc"), root, uid)?;
    if !left.is_empty() {
        bail!(
            "{} process(es) of the build account are still running; the stage is left alone",
            left.len()
        );
    }
    Ok(())
}

/// Answers which entries of `proc_root` run as `uid` and sit below `root`.
fn descendants_running_as(proc_root: &Path, root: u32, uid: u32) -> Result<Vec<i32>> {
    let mut table: std::collections::HashMap<i32, (i32, u32, bool)> =
        std::collections::HashMap::new();
    for entry in
        std::fs::read_dir(proc_root).with_context(|| format!("reading {}", proc_root.display()))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", proc_root.display()))
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let value = |key: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(str::trim)
                .map(str::to_string)
        };
        let owner =
            value("Uid:").and_then(|rest| rest.split_whitespace().next()?.parse::<u32>().ok());
        let parent = value("PPid:").and_then(|rest| rest.parse::<i32>().ok());
        let zombie = value("State:")
            .map(|state| state.starts_with('Z'))
            .unwrap_or(false);
        if let (Some(owner), Some(parent)) = (owner, parent) {
            table.insert(pid, (parent, owner, zombie));
        }
    }
    let mut out = Vec::new();
    for (&pid, &(_, owner, zombie)) in table.iter() {
        if zombie || owner != uid {
            continue;
        }
        let mut parent = table.get(&pid).map(|entry| entry.0).unwrap_or(0);
        for _ in 0..64 {
            if parent == root as i32 {
                out.push(pid);
                break;
            }
            if parent <= 1 {
                break;
            }
            match table.get(&parent) {
                Some(entry) => parent = entry.0,
                None => break,
            }
        }
    }
    Ok(out)
}

/// Parallel job count, set by the build and passed to the tools as `MAKEFLAGS`.
static JOB_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Pins the worker count for this process; zero means "use every core".
pub fn set_jobs(count: usize) {
    JOB_COUNT.store(count, std::sync::atomic::Ordering::Relaxed);
}

pub fn jobs() -> usize {
    let pinned = JOB_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    if pinned > 0 {
        return pinned;
    }
    // Uses half the available cores by default.
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (cores / 2).max(1)
}

#[cfg(test)]
mod tree_tests {
    use super::descendants_running_as;
    use std::path::Path;

    #[test]
    fn only_descendants_of_the_named_root_are_selected() {
        let dir = std::env::temp_dir().join(format!("portalis-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let entry = |pid: &str, ppid: &str, uid: &str, state: &str| {
            let path = dir.join(pid);
            std::fs::create_dir_all(&path).expect("proc entry");
            std::fs::write(
                path.join("status"),
                format!("Name:\ttool\nState:\t{state}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            )
            .expect("status");
        };
        entry("100", "1", "0", "S");
        entry("200", "100", "65534", "S");
        entry("300", "200", "65534", "S");
        entry("400", "1", "65534", "S");
        entry("500", "100", "65534", "Z");

        let mut named = descendants_running_as(Path::new(&dir), 100, 65534).expect("scan");
        named.sort();
        assert_eq!(named, vec![200, 300], "wrong set: {named:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::run::capture_unprivileged;
    use super::sandbox::prepare_workspace_dir;

    #[test]
    fn a_workspace_link_is_refused_before_permissions_change() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = std::env::temp_dir().join(format!(
            "portalis-workspace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let target = dir.join("target");
        std::fs::create_dir(&target).expect("target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("target mode");
        let link = dir.join(".tmp");
        symlink(&target, &link).expect("link");

        assert!(
            prepare_workspace_dir(&link, None).is_err(),
            "a workspace symlink was accepted"
        );
        let mode = std::fs::symlink_metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "the target permissions changed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_step_that_writes_past_the_pipe_buffer_still_finishes() {
        let dir = std::env::temp_dir().join(format!("portalis-capture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let args = vec![
            "-c".to_string(),
            "i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); done".to_string(),
        ];
        let output = capture_unprivileged("/bin/sh", &args, &dir, None).expect("the step finished");
        assert!(output.status.success(), "the step failed");
        assert!(
            output.stdout.len() > 128 * 1024,
            "output was truncated: {} bytes",
            output.stdout.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
