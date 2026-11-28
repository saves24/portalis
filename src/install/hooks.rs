//! Hooks that run after a package lands: ldconfig, icon caches, daemon reload.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::util::BUILD_PATH;

const LIVE_ROOT: &str = "/";

/// Where a hook has to run, and what to say when it must not run.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plan {
    Run(Vec<String>),
    Skip(String),
}

/// One line per hook that did not run, empty when it succeeded.
pub(super) fn hook_line(
    command: &str,
    result: std::io::Result<std::process::ExitStatus>,
) -> Option<String> {
    match result {
        Ok(status) if status.success() => None,
        Ok(status) => Some(format!("{command} exited with {status}")),
        Err(error) => Some(format!("{command} could not run: {error}")),
    }
}

pub(super) fn run_ld_cache_hooks(target_root: &Path) -> Vec<String> {
    let hooks = crate::recipe::Hooks {
        ldconfig: true,
        icon_cache: Vec::new(),
        daemon_reload: true,
    };
    run_hooks(&hooks, target_root)
}

/// Icon cache hooks may only touch theme directories the system owns.
pub(super) fn is_icon_theme_dir(dir: &str) -> bool {
    const ROOTS: [&str; 3] = [
        "/usr/share/icons",
        "/usr/share/pixmaps",
        "/usr/local/share/icons",
    ];
    if !dir.starts_with('/') || dir.contains("..") || dir.contains('\0') {
        return false;
    }
    ROOTS
        .iter()
        .any(|root| dir == *root || dir.starts_with(&format!("{root}/")))
}

/// Locates `program` inside `root`, answering with the path as it appears there.
/// The search runs against `root`.
fn program_path(root: &Path, program: &str) -> Option<PathBuf> {
    const DIRS: [&str; 4] = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"];
    let base = if root == Path::new(LIVE_ROOT) {
        PathBuf::from("/")
    } else {
        root.to_path_buf()
    };
    DIRS.iter()
        .map(|dir| base.join(dir.trim_start_matches('/')).join(program))
        .find(|path| {
            std::fs::metadata(path)
                .map(|meta| meta.is_file())
                .unwrap_or(false)
        })
}

/// A hook that edits files belongs to the root it serves: the live system gets
/// the command directly, any other root gets it through `chroot`.
pub(super) fn file_hook(root: &Path, program: &str, args: &[&str]) -> Plan {
    let Some(found) = program_path(root, program) else {
        return Plan::Skip(if root == Path::new(LIVE_ROOT) {
            format!("{program} is not installed on this system")
        } else {
            format!("{program} is not present in {}", root.display())
        });
    };
    let mut line = Vec::new();
    if root == Path::new(LIVE_ROOT) {
        line.push(found.display().to_string());
    } else {
        // inside the root the program sits at the same path, without the prefix
        let inside = found
            .strip_prefix(root)
            .map(|path| path.to_path_buf())
            .unwrap_or(found.clone());
        line.push("chroot".to_string());
        line.push(root.display().to_string());
        line.push(format!("/{}", inside.display()));
    }
    line.extend(args.iter().map(|arg| arg.to_string()));
    Plan::Run(line)
}

/// Runs service hooks only against the live root.
pub(super) fn service_hook(root: &Path, program: &str, args: &[&str]) -> Plan {
    if root != Path::new(LIVE_ROOT) {
        return Plan::Skip(format!(
            "{program} belongs to the running system, not to {}",
            root.display()
        ));
    }
    let mut line = vec![program.to_string()];
    line.extend(args.iter().map(|arg| arg.to_string()));
    Plan::Run(line)
}

fn run_plan(label: &str, plan: Plan, warnings: &mut Vec<String>) {
    match plan {
        Plan::Skip(reason) => warnings.push(format!("skipped {label}: {reason}")),
        Plan::Run(line) => {
            let program = Path::new(&line[0]);
            let program = if program.is_absolute() {
                program.to_path_buf()
            } else {
                let Some(found) = program_path(Path::new("/"), &line[0]) else {
                    warnings.push(format!("skipped {label}: {} is not installed", line[0]));
                    return;
                };
                found
            };
            if let Some(text) = hook_line(label, run_hook(&program, &line[1..])) {
                warnings.push(text);
            }
        }
    }
}

/// Runs one hook with a bounded wait.
fn run_hook(program: &Path, args: &[String]) -> std::io::Result<std::process::ExitStatus> {
    const TIMEOUT: Duration = Duration::from_secs(30);
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", BUILD_PATH)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("the hook ran longer than {} seconds", TIMEOUT.as_secs()),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(super) fn run_hooks(hooks: &crate::recipe::Hooks, target_root: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    if hooks.ldconfig {
        run_plan(
            "ldconfig",
            file_hook(target_root, "ldconfig", &[]),
            &mut warnings,
        );
    }
    if hooks.daemon_reload {
        run_plan(
            "systemctl daemon-reload",
            service_hook(target_root, "systemctl", &["daemon-reload"]),
            &mut warnings,
        );
    }
    for dir in &hooks.icon_cache {
        if !is_icon_theme_dir(dir) {
            warnings.push(format!(
                "skipped gtk-update-icon-cache {dir}: not a theme directory under /usr/share"
            ));
            continue;
        }
        run_plan(
            &format!("gtk-update-icon-cache {dir}"),
            file_hook(target_root, "gtk-update-icon-cache", &["-f", dir]),
            &mut warnings,
        );
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_with(dir: &str, program: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "portalis-hooks-{}-{program}-{sequence}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let bin = root.join(dir.trim_start_matches('/'));
        std::fs::create_dir_all(&bin).expect("create bin");
        std::fs::write(bin.join(program), "#!/bin/sh\n").expect("write program");
        root
    }

    #[test]
    fn a_file_hook_runs_inside_the_root_it_serves() {
        let root = root_with("/usr/bin", "gtk-update-icon-cache");
        let plan = file_hook(
            &root,
            "gtk-update-icon-cache",
            &["-f", "/usr/share/icons/hicolor"],
        );
        match plan {
            Plan::Run(line) => {
                assert_eq!(line[0], "chroot");
                assert_eq!(line[1], root.display().to_string());
                assert!(line[2].ends_with("gtk-update-icon-cache"));
                assert_eq!(line[4], "/usr/share/icons/hicolor");
            }
            other => panic!("expected a chroot launch, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_hook_is_skipped_when_the_root_lacks_the_tool() {
        let root = root_with("/usr/bin", "placeholder");
        let plan = file_hook(&root, "ldconfig", &[]);
        match plan {
            Plan::Skip(reason) => assert!(reason.contains("is not present in"), "{reason}"),
            other => panic!("expected a skip, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_service_hook_is_skipped_outside_the_live_root() {
        let root = root_with("/usr/bin", "placeholder");
        match service_hook(&root, "systemctl", &["daemon-reload"]) {
            Plan::Skip(reason) => {
                assert!(reason.contains("belongs to the running system"), "{reason}")
            }
            other => panic!("expected a skip, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_service_hook_runs_on_the_live_root() {
        let plan = service_hook(Path::new(LIVE_ROOT), "systemctl", &["daemon-reload"]);
        assert_eq!(
            plan,
            Plan::Run(vec!["systemctl".to_string(), "daemon-reload".to_string()])
        );
    }
}
