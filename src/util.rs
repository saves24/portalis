use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

mod config;
mod limits;
mod process;
mod sandbox;
pub use config::{load_conf, Conf};
pub(crate) use limits::apply_limits;
pub use limits::{build_timeout_seconds, default_limits, set_limits, Limits};
pub(crate) use process::{become_subreaper, stop_build_descendants, trusted_program, BUILD_PATH};
pub use process::{capture_unprivileged, jobs, run_logged_as, run_unprivileged, set_jobs};
pub use sandbox::{build_confinement, sandbox_enabled, SandboxPolicy};

use std::path::Path;

/// Build logs kept per package; older ones are pruned.
pub const BUILD_LOGS_PER_PACKAGE: usize = 50;

/// Makes a directory entry change durable.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let handle = std::fs::File::open(dir)?;
    handle.sync_all()
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    sha256_file_handle(&mut file).with_context(|| format!("reading {}", path.display()))
}

/// Hashes an already-open file, reading from the start and rewinding the
/// descriptor afterwards.
pub fn sha256_file_handle(file: &mut std::fs::File) -> Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Held for the lifetime of a mutating command; serialises install, remove,
pub struct StateLock {
    _file: std::fs::File,
}

static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Silences the progress lines a long command prints while it works.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, std::sync::atomic::Ordering::Relaxed);
}

/// One line about what a command is doing.
pub fn note(text: &str) {
    if !QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("{text}");
    }
}

/// Reads a switch from the environment: only 1/true/yes/on turn it on.
pub fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

pub fn lock_state(state_dir: &Path) -> Result<StateLock> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    // 300 s when applying pending, 30 s for other commands.
    let default_secs = if env_flag("PORTALIS_APPLY_PENDING") {
        300
    } else {
        30
    };
    let timeout = std::env::var("PORTALIS_LOCK_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(default_secs));
    let started = std::time::Instant::now();
    let mut waiting = false;
    loop {
        // Safety: flock only reads the valid file descriptor; it does not touch
        // memory and the descriptor stays open through the returned guard.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock && !waiting {
            waiting = true;
            note(&format!(
                "waiting  another command holds {}",
                path.display()
            ));
        }
        if error.kind() != std::io::ErrorKind::WouldBlock {
            bail!("cannot lock {}: {error}", path.display());
        }
        if started.elapsed() >= timeout {
            return Err(crate::error::Coded::new(
                crate::error::Code::LockTimeout,
                format!(
                    "cannot lock {}: another command has held it for {}s (set PORTALIS_LOCK_TIMEOUT to wait longer)",
                    path.display(),
                    timeout.as_secs()
                ),
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(StateLock { _file: file })
}

/// True when the log file was written for this package. The first line carries
/// the name.
pub(crate) fn log_is_for(path: &std::path::Path, package: &str) -> bool {
    log_package(path).as_deref() == Some(package)
}

/// The package name on the first line of a build log.
pub(crate) fn log_package(path: &std::path::Path) -> Option<String> {
    use std::io::BufRead;
    let file = std::fs::File::open(path).ok()?;
    let mut head = String::new();
    std::io::BufReader::new(file).read_line(&mut head).ok()?;
    let rest = head.strip_prefix("portalis build ")?;
    rest.split_whitespace().next().map(|name| name.to_string())
}

/// Formats a byte count for human-readable output.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// User id that builds and unpacks run as.
pub const BUILD_UID: u32 = 65534;
/// Group id that builds and unpacks run as.
pub const BUILD_GID: u32 = 65534;

#[cfg(test)]
mod tests {
    use crate::util::limits::ceiling_within;
    use crate::util::sandbox::{network_left_open, read_only_view};

    #[test]
    fn the_build_view_never_mounts_the_whole_root() {
        for (host, inside) in read_only_view() {
            assert_ne!(host, "/", "the host root was mounted: {inside}");
            assert!(host.starts_with('/'), "a relative mount crept in: {host}");
        }
    }

    #[test]
    fn the_build_view_offers_the_toolchain() {
        let view = read_only_view();
        assert!(
            view.iter().any(|(host, _)| host == "/usr"),
            "the toolchain tree is missing from the build view"
        );
    }

    #[test]
    fn an_offline_step_is_refused_without_confinement() {
        assert!(network_left_open(false, "none"));
    }

    #[test]
    fn an_offline_step_is_allowed_with_socket_confinement() {
        assert!(!network_left_open(false, "bubblewrap"));
        assert!(!network_left_open(false, "landlock"));
    }

    #[test]
    fn a_step_that_may_use_the_network_is_never_refused() {
        assert!(!network_left_open(true, "none"));
        assert!(!network_left_open(true, "landlock"));
    }

    #[test]
    fn only_a_truthy_value_turns_a_switch_on() {
        for value in ["0", "", "false", "no", "off", " 0 "] {
            std::env::set_var("PORTALIS_TEST_FLAG", value);
            assert!(
                !super::env_flag("PORTALIS_TEST_FLAG"),
                "{value:?} enabled the switch"
            );
        }
        for value in ["1", "true", "YES", " on "] {
            std::env::set_var("PORTALIS_TEST_FLAG", value);
            assert!(
                super::env_flag("PORTALIS_TEST_FLAG"),
                "{value:?} did not enable it"
            );
        }
        std::env::remove_var("PORTALIS_TEST_FLAG");
        assert!(
            !super::env_flag("PORTALIS_TEST_FLAG"),
            "an unset switch was on"
        );
    }

    use super::*;
    use crate::util::config::{split_list, strip_comment};

    #[test]
    fn a_ceiling_never_exceeds_what_was_inherited() {
        let infinite = u64::MAX;
        assert_eq!(ceiling_within(4096, 1024, infinite), 1024);
        assert_eq!(ceiling_within(4096, infinite, 2048), 2048);
        assert_eq!(ceiling_within(4096, infinite, infinite), 4096);
        assert_eq!(ceiling_within(4096, 512, 2048), 512);
    }

    #[test]
    fn conf_parses_values_lists_and_blocks() {
        let conf = Conf::parse(
            "# comment\n\
             package.name = xkbcomp\n\
             package.version = \"1.4.7\"\n\
             build.args = --disable-static, \"--with-x,really\"\n\
             build.network = false\n\
             hooks.ldconfig = true\n\
             build.patch.0.content = <<DIFF\n\
             --- a/x\n\
             +++ b/x\n\
             DIFF\n",
        )
        .expect("parses");
        assert_eq!(conf.get("package.name").as_deref(), Some("xkbcomp"));
        assert_eq!(conf.get("package.version").as_deref(), Some("1.4.7"));
        assert_eq!(
            conf.list("build.args"),
            vec![
                "--disable-static".to_string(),
                "--with-x,really".to_string()
            ]
        );
        assert!(!conf.flag("build.network", true).expect("flag"));
        assert!(conf.flag("hooks.ldconfig", false).expect("flag"));
        assert_eq!(
            conf.get("build.patch.0.content").as_deref(),
            Some("--- a/x\n+++ b/x\n")
        );
    }

    #[test]
    fn conf_repeats_blocks_and_strips_trailing_comments() {
        let text = "\
build.patch = <<PATCH
file = a.patch
content = <<DIFF
--- a/x
+++ b/x
DIFF
PATCH
build.patch = <<PATCH
file = b.patch
PATCH
name = value # trailing note
quoted = \"keep # inside\"
";
        let conf = Conf::parse_with(text, &["build.patch"]).expect("parses");
        let patches = conf.all("build.patch");
        assert_eq!(patches.len(), 2);
        let first = Conf::parse(&patches[0]).expect("inner patch");
        assert_eq!(first.get("file").as_deref(), Some("a.patch"));
        assert_eq!(first.get("content").as_deref(), Some("--- a/x\n+++ b/x\n"));
        assert_eq!(conf.get("name").as_deref(), Some("value"));
        assert_eq!(conf.get("quoted").as_deref(), Some("keep # inside"));
    }

    #[test]
    fn conf_rejects_malformed_lines_and_unterminated_blocks() {
        assert!(Conf::parse("no separator here\n").is_err());
        assert!(Conf::parse("bad key = value\n").is_err());
        assert!(Conf::parse("key = <<END\nbody\n").is_err());
        assert!(Conf::parse("key = maybe\n")
            .and_then(|conf| conf.flag("key", false))
            .is_err());
        assert!(Conf::parse("key = 1\nkey = 2\n").is_err());
    }

    #[test]
    fn state_lock_creates_the_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = lock_state(dir.path()).unwrap();
        assert!(dir.path().join("lock").exists());
    }

    #[test]
    fn build_sandbox_allows_declared_writable() {
        if !sandbox_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let writable = dir.path().join("rw");
        std::fs::create_dir_all(&writable).unwrap();
        let policy = SandboxPolicy {
            network: false,
            writable: vec![writable.to_string_lossy().into_owned()],
            read: Vec::new(),
            root: None,
            deps: Vec::new(),
        };
        let mut log = std::fs::File::create(dir.path().join("log")).unwrap();
        let target = writable.join("ok");
        let result = run_logged_as(
            "sh",
            &["-c".to_string(), format!("touch {}", target.display())],
            dir.path(),
            &mut log,
            &[],
            Some((0, 0)),
            Some(&policy),
        );
        assert!(result.is_ok(), "writable path was rejected: {result:?}");
        assert!(target.exists());
    }

    #[test]
    fn build_sandbox_defaults_to_no_network() {
        if !sandbox_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut log = std::fs::File::create(dir.path().join("log")).unwrap();
        let probe = "tail -n +3 /proc/net/dev | grep -v 'lo:' | grep -q ':'";
        let blocked = run_logged_as(
            "sh",
            &["-c".to_string(), probe.to_string()],
            dir.path(),
            &mut log,
            &[],
            Some((0, 0)),
            None,
        );
        assert!(blocked.is_err(), "network namespace was not isolated");
        let policy = SandboxPolicy {
            network: true,
            writable: Vec::new(),
            read: Vec::new(),
            root: None,
            deps: Vec::new(),
        };
        let allowed = run_logged_as(
            "sh",
            &["-c".to_string(), probe.to_string()],
            dir.path(),
            &mut log,
            &[],
            Some((0, 0)),
            Some(&policy),
        );
        assert!(
            allowed.is_ok(),
            "network=true did not share the host network"
        );
    }

    #[test]
    fn state_lock_serialises_writers() {
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let held = lock_state(&path).unwrap();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            let _lock = lock_state(&path).unwrap();
            Instant::now()
        });
        std::thread::sleep(Duration::from_millis(200));
        drop(held);
        let acquired = waiter.join().unwrap();
        assert!(
            acquired.duration_since(started) >= Duration::from_millis(150),
            "second lock was not serialised"
        );
    }

    #[test]
    fn build_sandbox_makes_usr_read_only() {
        if !sandbox_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut log = std::fs::File::create(dir.path().join("log")).unwrap();
        let result = run_logged_as(
            "sh",
            &["-c".to_string(), "test ! -w /usr".to_string()],
            dir.path(),
            &mut log,
            &[],
            Some((0, 0)),
            None,
        );
        assert!(
            result.is_ok(),
            "sandbox did not make /usr read-only: {result:?}"
        );
    }

    #[test]
    fn a_hash_inside_quotes_belongs_to_the_value() {
        assert_eq!(strip_comment("a 'b#c' d"), "a 'b#c' d");
        assert_eq!(strip_comment(r#"a "b#c" d"#), r#"a "b#c" d"#);
        assert_eq!(strip_comment("a b # c"), "a b ");
    }

    #[test]
    fn a_quoted_comma_stays_inside_one_item() {
        let items = split_list(r#"/a,"/b,c",'/d,e'"#);
        assert_eq!(items, vec!["/a", "/b,c", "/d,e"]);
    }
}
