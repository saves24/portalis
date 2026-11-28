//! End-to-end checks: the binary is driven the way a user drives it, in a
//! throwaway root, and the assertions only look at what a user can observe.
//!
//! These tests change file ownership; they need root:
//!     sudo -E cargo test --test cli

mod concurrency;
mod inspect;
mod install;
mod recovery;
mod security;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    root: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        for dir in [
            "etc/portalis/packages",
            "var/log/portalis/builds",
            "var/lib/portalis",
        ] {
            fs::create_dir_all(root.join(dir)).expect("sandbox layout");
        }
        // a target root carries its own group database
        fs::write(
            root.join("etc/group"),
            "root:x:0:\ntty:x:5:\nshadow:x:42:\ncrontab:x:105:\n",
        )
        .expect("sandbox group file");
        Self { root, _tmp: tmp }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_portalis"));
        command
            .env("PORTALIS_ROOT", &self.root)
            .env("PORTALIS_NO_BWRAP", "1")
            .env_remove("PORTALIS_APPLY_PENDING")
            .env_remove("PORTALIS_FORCE")
            .env_remove("PORTALIS_ALLOW_UNSIGNED")
            .env_remove("PORTALIS_LOCAL")
            .env_remove("PORTALIS_DRY_RUN")
            .env_remove("PORTALIS_KEEP_PRIVILEGED")
            .env_remove("PORTALIS_UPDATE_PIN")
            .env_remove("PORTALIS_ALLOW_PATH_LEAK")
            .env_remove("PORTALIS_JSON");
        command
    }

    /// The same command with the machine-readable stream switched on.
    fn events(&self, args: &[&str]) -> Output {
        let mut command = self.command();
        command.env("PORTALIS_JSON", "1").args(args);
        command.output().expect("running portalis")
    }

    /// The same command, but with the build sandbox left switched on.
    fn sandboxed(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_portalis"))
            .env("PORTALIS_ROOT", &self.root)
            .env_remove("PORTALIS_NO_BWRAP")
            .env_remove("PORTALIS_APPLY_PENDING")
            .env_remove("PORTALIS_FORCE")
            .env_remove("PORTALIS_ALLOW_UNSIGNED")
            .env_remove("PORTALIS_LOCAL")
            .env_remove("PORTALIS_DRY_RUN")
            .env_remove("PORTALIS_KEEP_PRIVILEGED")
            .env_remove("PORTALIS_UPDATE_PIN")
            .env_remove("PORTALIS_ALLOW_PATH_LEAK")
            .args(args)
            .output()
            .expect("running portalis")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command()
            .args(args)
            .output()
            .expect("running portalis")
    }

    fn ok_env(&self, args: &[&str], env: &[(&str, &str)]) -> String {
        let mut command = self.command();
        for (key, value) in env {
            command.env(key, value);
        }
        let out = command.args(args).output().expect("running portalis");
        assert!(
            out.status.success(),
            "portalis {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = self.command();
        for (key, value) in env {
            command.env(key, value);
        }
        command.args(args).output().expect("running portalis")
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "portalis {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn activate_pending(&self) -> String {
        let out = self
            .command()
            .env("PORTALIS_APPLY_PENDING", "1")
            .output()
            .expect("running portalis to apply pending");
        assert!(
            out.status.success(),
            "activation failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn recipe_dir(&self) -> PathBuf {
        self.root.join("etc/portalis/packages")
    }
}

/// Cases that build take this slot one at a time.
static BUILD_SLOT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn take_build_slot() -> std::sync::MutexGuard<'static, ()> {
    BUILD_SLOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A tmpfs mount that unmounts itself when dropped.
struct Tmpfs(PathBuf);

/// True when the process may mount filesystems.
fn sys_admin_available() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|rest| u64::from_str_radix(rest.trim(), 16).ok())
        .map(|bits| bits & (1 << 21) != 0)
        .unwrap_or(false)
}

impl Tmpfs {
    fn new(path: &std::path::Path, size: &str) -> Option<Self> {
        if !sys_admin_available() {
            allow_skip("CAP_SYS_ADMIN is not available in this environment");
            return None;
        }
        let output = Command::new("mount")
            .args(["-t", "tmpfs", "-o", &format!("size={size}"), "tmpfs"])
            .arg(path)
            .output()
            .expect("mount binary");
        assert!(
            output.status.success(),
            "mounting a tmpfs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(Self(path.to_path_buf()))
    }

    fn remount_read_only(&self) {
        let output = Command::new("mount")
            .args(["-o", "remount,ro"])
            .arg(&self.0)
            .output()
            .expect("mount binary");
        assert!(
            output.status.success(),
            "remounting read-only failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Tmpfs {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

/// Returns true when the check cannot run here and skipping was allowed.
fn allow_skip(hint: &str) -> bool {
    let allowed = std::env::var("PORTALIS_ALLOW_SKIP")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if allowed {
        eprintln!("skipping: {hint}");
        return true;
    }
    panic!("{hint} (set PORTALIS_ALLOW_SKIP=1 to run without it)");
}

/// Asserts a failed install left no store, no ledger rows, no live file and no
/// activation marker behind.
fn assert_failed_install_left_nothing(sb: &Sandbox, live: &[&str]) {
    let stores = match fs::read_dir(sb.root.join("usr/portalis/packages")) {
        Ok(entries) => entries.count(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("reading the store directory: {error}"),
    };
    assert_eq!(stores, 0, "a failed install left {stores} store(s) behind");

    let ledger = sb.root.join("var/db/portalis/db.sqlite");
    if ledger.exists() {
        let conn = rusqlite::Connection::open(&ledger).expect("open the ledger");
        for table in ["packages", "files", "pending_packages", "pending_files"] {
            let rows: i64 = conn
                .query_row(&format!("select count(*) from {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|error| panic!("counting {table}: {error}"));
            assert_eq!(rows, 0, "a failed install left {rows} row(s) in {table}");
        }
    }

    for path in live {
        assert!(
            !sb.root.join(path).exists(),
            "{path} was left behind by a failed install"
        );
    }

    let marker = sb.root.join("var/lib/portalis/activating");
    assert!(
        !marker.exists(),
        "a failed install left an activation marker"
    );
}

fn require_root() -> bool {
    // Safety: geteuid reads this process's effective user id.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let hint = "these checks need root: sudo -E cargo test --test cli";
    allow_skip(hint);
    false
}

fn require_tool(name: &str) -> bool {
    if std::process::Command::new(name)
        .arg("--version")
        .output()
        .is_ok()
    {
        return true;
    }
    allow_skip(&format!("{name} is not installed and this check needs it"));
    false
}

fn sha256_file(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).expect("read archive");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
}

/// Like [`fixture`], but lets a case plant extra entries in the source tree
/// first — the way a hostile archive would.
fn fixture_with_source(
    sb: &Sandbox,
    name: &str,
    version: &str,
    prefix: &str,
    body: &str,
    prepare: impl FnOnce(&Path),
) -> PathBuf {
    let top = format!("{name}-{version}");
    let src = sb.root.join("fixtures").join(&top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), "hello\n").expect("fixture payload");
    prepare(&src);

    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&fixtures)
        .arg(&top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let recipe = format!(
        "package.name = {name}\n\
         package.version = {version}\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = {body}\n\
         install.prefix = {prefix}\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join(format!("{name}.port")), recipe).expect("write recipe");
    archive
}

/// Writes a source archive and the recipe that builds it, returning the archive.
fn fixture(sb: &Sandbox, name: &str, version: &str, prefix: &str, body: &str) -> PathBuf {
    // the archive must carry one top-level directory, as a real tarball does
    let top = format!("{name}-{version}");
    let src = sb.root.join("fixtures").join(&top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), "hello\n").expect("fixture payload");

    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&fixtures)
        .arg(&top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let recipe = format!(
        "package.name = {name}\n\
         package.version = {version}\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = {body}\n\
         install.prefix = {prefix}\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join(format!("{name}.port")), recipe).expect("write recipe");
    archive
}

/// Writes a dependency-free crate plus a recipe that builds it with cargo.
fn cargo_fixture(sb: &Sandbox, name: &str, version: &str) -> PathBuf {
    let top = format!("{name}-{version}");
    let src = sb.root.join("fixtures").join(&top);
    fs::create_dir_all(src.join("src")).expect("crate source");
    fs::write(
        src.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"),
    )
    .expect("manifest");
    fs::write(src.join("src/main.rs"), "fn main() {}\n").expect("main");

    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&fixtures)
        .arg(&top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let recipe = format!(
        "package.name = {name}\n\
         package.version = {version}\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = cargo\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join(format!("{name}.port")), recipe).expect("write recipe");
    archive
}

/// The pids of the build account's processes whose command line carries
/// `marker` — how a test recognizes the process it planted.
fn build_account_processes(marker: &str) -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").expect("proc") {
        let entry = entry.expect("proc entry");
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.parse::<u32>().is_err() {
            continue;
        }
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next()?.parse::<u32>().ok());
        if uid != Some(65534) {
            continue;
        }
        let cmdline = fs::read(entry.path().join("cmdline")).unwrap_or_default();
        let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if text.contains(marker) {
            found.push(name);
        }
    }
    found
}

fn ar_write(out: &mut Vec<u8>, name: &str, body: &[u8]) {
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        name,
        0,
        0,
        0,
        "100644",
        body.len()
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
    if body.len() % 2 == 1 {
        out.push(b'\n');
    }
}

fn raw_deb(sb: &Sandbox, file_name: &str, data_members: &[(&str, &[u8], u64)]) -> PathBuf {
    raw_deb_with_control(sb, file_name, b"Package: x\n", data_members)
}

fn raw_deb_with_control(
    sb: &Sandbox,
    file_name: &str,
    control: &[u8],
    data_members: &[(&str, &[u8], u64)],
) -> PathBuf {
    let mut out = Vec::new();
    out.extend_from_slice(b"!<arch>\n");
    ar_write(&mut out, "debian-binary", b"2.0\n");
    ar_write(&mut out, "control.tar", &raw_tar(&[("control", control)]));
    ar_write(&mut out, "data.tar", &raw_tar_modes(data_members));
    let archive = sb.root.join("fixtures").join(file_name);
    fs::create_dir_all(archive.parent().unwrap()).expect("fixture directory");
    fs::write(&archive, out).expect("write deb");
    archive
}

/// Builds a tar archive with member names exactly as given, header and all.
fn raw_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let with_modes: Vec<(&str, &[u8], u64)> = members
        .iter()
        .map(|(name, body)| (*name, *body, 0o644))
        .collect();
    raw_tar_modes(&with_modes)
}

fn raw_tar_modes(members: &[(&str, &[u8], u64)]) -> Vec<u8> {
    let full: Vec<(&str, &[u8], u64, u64)> = members
        .iter()
        .map(|(name, body, mode)| (*name, *body, *mode, 0))
        .collect();
    raw_tar_full(&full)
}

/// Builds a tar archive whose gid fields use the base-256 encoding.
/// Builds a tar archive whose members name their group.
fn raw_tar_gname(members: &[(&str, &[u8], u64, u32, &str)]) -> Vec<u8> {
    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let digits = format!("{:0width$o}", value, width = width);
        field[..width].copy_from_slice(digits.as_bytes());
        field[width] = 0;
    }

    let mut out = Vec::new();
    for (name, body, mode, gid, gname) in members {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        let copied = name_bytes.len().min(100);
        header[..copied].copy_from_slice(&name_bytes[..copied]);
        octal(&mut header[100..108], *mode);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], u64::from(*gid));
        octal(&mut header[124..136], body.len() as u64);
        octal(&mut header[136..148], 0);
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[265..269].copy_from_slice(b"root");
        let group_bytes = gname.as_bytes();
        let group_len = group_bytes.len().min(31);
        header[297..297 + group_len].copy_from_slice(&group_bytes[..group_len]);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        let padding = (512 - body.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, padding));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

fn raw_tar_base256_gid(members: &[(&str, &[u8], u64, u32)]) -> Vec<u8> {
    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let digits = format!("{:0width$o}", value, width = width);
        field[..width].copy_from_slice(digits.as_bytes());
        field[width] = 0;
    }

    let mut out = Vec::new();
    for (name, body, mode, gid) in members {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        let copied = name_bytes.len().min(100);
        header[..copied].copy_from_slice(&name_bytes[..copied]);
        octal(&mut header[100..108], *mode);
        octal(&mut header[108..116], 0);
        let mut encoded = [0u8; 8];
        encoded[0] = 0x80;
        encoded[1..].copy_from_slice(&u64::from(*gid).to_be_bytes()[1..]);
        header[116..124].copy_from_slice(&encoded);
        octal(&mut header[124..136], body.len() as u64);
        octal(&mut header[136..148], 0);
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        let padding = (512 - body.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, padding));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

fn raw_tar_full(members: &[(&str, &[u8], u64, u64)]) -> Vec<u8> {
    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let digits = format!("{:0width$o}", value, width = width);
        field[..width].copy_from_slice(digits.as_bytes());
        field[width] = 0;
    }

    let mut out = Vec::new();
    for (name, body, mode, gid) in members {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        let copied = name_bytes.len().min(100);
        header[..copied].copy_from_slice(&name_bytes[..copied]);
        octal(&mut header[100..108], *mode);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], *gid);
        octal(&mut header[124..136], body.len() as u64);
        octal(&mut header[136..148], 0);
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
        let field = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(field.as_bytes());

        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        let padding = (512 - body.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, padding));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

/// The same writer with a per-member type flag.
fn raw_tar_typed(members: &[(&str, &[u8], u8)]) -> Vec<u8> {
    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let digits = format!("{:0width$o}", value, width = width);
        field[..width].copy_from_slice(digits.as_bytes());
        field[width] = 0;
    }

    let mut out = Vec::new();
    for (name, body, typeflag) in members {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        let copied = name_bytes.len().min(100);
        header[..copied].copy_from_slice(&name_bytes[..copied]);
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], body.len() as u64);
        octal(&mut header[136..148], 0);
        header[148..156].copy_from_slice(b"        ");
        header[156] = *typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
        let field = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(field.as_bytes());

        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        let padding = (512 - body.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, padding));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

fn raw_archive(sb: &Sandbox, file_name: &str, members: &[(&str, &[u8])]) -> PathBuf {
    let archive = sb.root.join("fixtures").join(file_name);
    fs::create_dir_all(archive.parent().unwrap()).expect("fixture directory");
    fs::write(&archive, raw_tar(members)).expect("write raw tar");
    archive
}

fn fixture_from_raw_tar(sb: &Sandbox, name: &str, members: &[(&str, &[u8])]) -> PathBuf {
    let archive = sb.root.join("fixtures").join(format!("{name}-1.0.tar"));
    fs::create_dir_all(archive.parent().unwrap()).expect("fixture directory");
    fs::write(&archive, raw_tar(members)).expect("write raw tar");

    let recipe = format!(
        "package.name = {name}\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = true\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join(format!("{name}.port")), recipe).expect("write recipe");
    archive
}
