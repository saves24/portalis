//! Runs a recipe's check command inside the embedded rootfs.
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::build::BuildOutcome;
use crate::paths::{Paths, STORE_DIR};
use crate::recipe::Recipe;
use crate::util::{BUILD_GID, BUILD_UID};

const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

struct StoreBind {
    source: PathBuf,
    target: String,
}

struct CheckRoot {
    root: tempfile::TempDir,
    _upper: tempfile::TempDir,
    _work: tempfile::TempDir,
    mounted: bool,
}

impl CheckRoot {
    fn new(image: &Path, paths: &Paths) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("check-root-")
            .tempdir_in(paths.state_dir())
            .context("creating the check root")?;
        let upper = tempfile::Builder::new()
            .prefix("check-upper-")
            .tempdir_in(paths.state_dir())
            .context("creating the check upper layer")?;
        let work = tempfile::Builder::new()
            .prefix("check-work-")
            .tempdir_in(paths.state_dir())
            .context("creating the check work layer")?;
        let mounted = mount_overlay(root.path(), image, upper.path(), work.path());
        if !mounted {
            crate::archive::copy_tree(image, root.path()).context("copying the rootfs")?;
        }
        Ok(Self {
            root,
            _upper: upper,
            _work: work,
            mounted,
        })
    }

    fn path(&self) -> &Path {
        self.root.path()
    }
}

impl Drop for CheckRoot {
    fn drop(&mut self) {
        if self.mounted {
            if let Some(program) = system_program("umount") {
                let _ = Command::new(program)
                    .env_clear()
                    .arg(self.root.path())
                    .status();
            }
        }
    }
}

fn system_program(name: &str) -> Option<std::path::PathBuf> {
    crate::util::trusted_program(name)
}

fn mount_overlay(root: &Path, lower: &Path, upper: &Path, work: &Path) -> bool {
    if [root, lower, upper, work]
        .iter()
        .any(|path| path.to_string_lossy().contains(','))
    {
        return false;
    }
    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let Some(mount) = system_program("mount") else {
        return false;
    };
    Command::new(mount)
        .env_clear()
        .args(["-t", "overlay", "overlay", "-o", &options])
        .arg(root)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// What the recipe and the manifest say about this check.
struct CheckPlan {
    command: String,
    required: bool,
    timeout: u64,
}

fn check_plan(recipe: &Recipe, outcome: &BuildOutcome) -> Result<Option<CheckPlan>> {
    let required = outcome
        .manifest
        .check_required
        .unwrap_or(recipe.check.required);
    let Some(command) = outcome
        .manifest
        .check_command
        .as_deref()
        .or(recipe.check.command.as_deref())
    else {
        if required {
            bail!(
                "check for {} {} is required, but no check command is set",
                recipe.package.name,
                recipe.package.version
            );
        }
        return Ok(None);
    };
    let timeout = outcome
        .manifest
        .check_timeout
        .or(recipe.check.timeout)
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    Ok(Some(CheckPlan {
        command: command.to_string(),
        required,
        timeout,
    }))
}

/// Builds the disposable root the check runs in, and its bwrap arguments.
fn prepare_check_root(
    recipe: &Recipe,
    outcome: &BuildOutcome,
    paths: &Paths,
    dependencies: &[PathBuf],
    command: &str,
    required: bool,
) -> Result<Option<(CheckRoot, Vec<String>)>> {
    let Some(image) = crate::rootfs::prepare(paths)? else {
        if required {
            bail!(
                "check for {} {} is required, but this build has no rootfs image",
                recipe.package.name,
                recipe.package.version
            );
        }
        eprintln!(
            "warning: check skipped for {} {}: this build has no rootfs image",
            recipe.package.name, recipe.package.version
        );
        return Ok(None);
    };

    let root = CheckRoot::new(&image, paths)?;
    for directory in ["dev", "proc", "tmp", "run", STORE_DIR] {
        ensure_directory(root.path(), directory)?;
    }
    let mut stores: Vec<PathBuf> = dependencies
        .iter()
        .filter(|store| *store != &outcome.store_path)
        .cloned()
        .collect();
    stores.sort();
    stores.dedup();
    stores.push(outcome.store_path.clone());
    for store in &stores {
        crate::archive::copy_tree(store, root.path())
            .with_context(|| format!("copying {} into the check root", store.display()))?;
    }
    let binds = store_binds(root.path(), &stores)?;
    let args = arguments(
        root.path(),
        &binds,
        recipe,
        outcome,
        command,
        &recipe.install.prefix,
    );
    Ok(Some((root, args)))
}

fn run_check_command(
    args: &[String],
    paths: &Paths,
    timeout: u64,
) -> Result<(tempfile::NamedTempFile, Option<std::process::ExitStatus>)> {
    let log = tempfile::Builder::new()
        .prefix("check-log-")
        .tempfile_in(paths.state_dir())
        .context("creating the check log")?;
    let status = run_bwrap(args, log.path(), timeout)?;
    Ok((log, status))
}

/// Runs the recipe's check command in a disposable copy of the rootfs.
pub fn run(
    recipe: &Recipe,
    outcome: &BuildOutcome,
    paths: &Paths,
    dependencies: &[PathBuf],
) -> Result<()> {
    let Some(plan) = check_plan(recipe, outcome)? else {
        return Ok(());
    };
    let Some((_root, args)) = prepare_check_root(
        recipe,
        outcome,
        paths,
        dependencies,
        &plan.command,
        plan.required,
    )?
    else {
        return Ok(());
    };
    let (log, status) = match run_check_command(&args, paths, plan.timeout) {
        Ok(result) => result,
        Err(error) if !plan.required => {
            eprintln!(
                "warning: check skipped for {} {}: {error:#}",
                recipe.package.name, recipe.package.version
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let Some(status) = status else {
        if plan.required {
            bail!(
                "check for {} {} did not finish within {}s",
                recipe.package.name,
                recipe.package.version,
                plan.timeout
            );
        }
        eprintln!(
            "warning: check skipped for {} {}: it did not finish within {}s",
            recipe.package.name, recipe.package.version, plan.timeout
        );
        return Ok(());
    };
    let output = read_output(log.path())?;
    if !status.success() {
        let message = format!(
            "check failed for {} {} ({}):\n{}",
            recipe.package.name, recipe.package.version, status, output
        );
        if plan.required {
            bail!("{message}");
        }
        eprintln!("warning: {message}");
        return Ok(());
    }
    crate::say!(
        "check    {} {} passed",
        recipe.package.name,
        recipe.package.version
    );
    Ok(())
}

fn ensure_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            bail!("check path has an invalid component: {relative}");
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("check path crosses a symlink: {}", current.display());
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => bail!("check path is not a directory: {}", current.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .with_context(|| format!("creating {}", current.display()))?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", current.display()));
            }
        }
    }
    Ok(current)
}

fn store_binds(root: &Path, stores: &[PathBuf]) -> Result<Vec<StoreBind>> {
    let mut binds = Vec::with_capacity(stores.len());
    for store in stores {
        let name = store
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("store has no name: {}", store.display()))?;
        let relative = format!("{STORE_DIR}/{}", name.to_string_lossy());
        ensure_directory(root, &relative)?;
        let target = format!("/{relative}");
        binds.push(StoreBind {
            source: store.clone(),
            target,
        });
    }
    Ok(binds)
}

fn arguments(
    root: &Path,
    binds: &[StoreBind],
    recipe: &Recipe,
    outcome: &BuildOutcome,
    command: &str,
    prefix: &str,
) -> Vec<String> {
    let package_store = binds
        .iter()
        .find(|bind| bind.source == outcome.store_path)
        .map(|bind| bind.target.clone())
        .unwrap_or_else(|| format!("/{STORE_DIR}"));
    let mut args = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-net".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup-try".into(),
        "--uid".into(),
        BUILD_UID.to_string(),
        "--gid".into(),
        BUILD_GID.to_string(),
        "--cap-drop".into(),
        "ALL".into(),
        "--ro-bind".into(),
        root.to_string_lossy().into_owned(),
        "/".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "PATH".into(),
        "/usr/bin:/bin:/usr/sbin:/sbin".into(),
        "--setenv".into(),
        "HOME".into(),
        "/tmp".into(),
        "--setenv".into(),
        "TMPDIR".into(),
        "/tmp".into(),
        "--setenv".into(),
        "LANG".into(),
        "C".into(),
        "--setenv".into(),
        "PORTALIS_PACKAGE".into(),
        package_store.clone(),
        "--setenv".into(),
        "PORTALIS_STORE".into(),
        package_store,
        "--setenv".into(),
        "PORTALIS_NAME".into(),
        recipe.package.name.clone(),
        "--setenv".into(),
        "PORTALIS_VERSION".into(),
        recipe.package.version.clone(),
        "--setenv".into(),
        "PORTALIS_PREFIX".into(),
        prefix.to_string(),
        "--chdir".into(),
        "/".into(),
    ];
    for bind in binds {
        args.extend([
            "--ro-bind".into(),
            bind.source.to_string_lossy().into_owned(),
            bind.target.clone(),
        ]);
    }
    args.extend([
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        command.to_string(),
    ]);
    args
}

fn run_bwrap(
    args: &[String],
    log_path: &Path,
    timeout: u64,
) -> Result<Option<std::process::ExitStatus>> {
    let log = fs::File::create(log_path).context("creating the check output")?;
    let out = log.try_clone()?;
    let Some(bwrap) = system_program("bwrap") else {
        bail!("bubblewrap is not available in a system path");
    };
    let mut command = Command::new(bwrap);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(log))
        .process_group(0);
    // Safety: the closure only raises and lowers resource ceilings for this child.
    unsafe {
        command.pre_exec(|| {
            crate::util::apply_limits()?;
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .context("starting the check sandbox (is bubblewrap installed?)")?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() > Duration::from_secs(timeout) {
            stop_group(child.id());
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stop_group(pid: u32) {
    // Safety: the process group was created for this child.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

fn read_output(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = vec![0; MAX_OUTPUT_BYTES];
    let read = file
        .read(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    bytes.truncate(read);
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(all(test, portalis_rootfs))]
mod tests {
    use super::*;
    use crate::recipe::BuildManifest;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn an_embedded_image_runs_a_check_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        fs::create_dir_all(paths.state_dir()).expect("state");
        let store = paths.store().join("checkpkg-1.0-deadbeef");
        fs::create_dir_all(store.join("usr/bin")).expect("store");
        let real = store.join("usr/lib/checkprobe");
        fs::create_dir_all(real.parent().expect("parent")).expect("lib dir");
        fs::write(&real, "#!/bin/sh\nexit 0\n").expect("probe");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("mode");
        let probe = store.join("usr/bin/checkprobe");
        fs::create_dir_all(probe.parent().expect("parent")).expect("bin dir");
        std::os::unix::fs::symlink(
            "/usr/portalis/packages/checkpkg-1.0-deadbeef/usr/lib/checkprobe",
            &probe,
        )
        .expect("symlink");

        let text = "package.name = checkpkg\npackage.version = 1.0\nsource.file = checkpkg.tar\nsource.sha256 = 0000000000000000000000000000000000000000000000000000000000000000\nbuild.system = custom\ninstall.prefix = /usr\ncheck.command = checkprobe\ncheck.required = true\n";
        let recipe = Recipe::parse(text).expect("recipe");
        let outcome = BuildOutcome {
            store_path: store,
            manifest: BuildManifest {
                patches: Vec::new(),
                name: "checkpkg".into(),
                version: "1.0".into(),
                recipe_sha256: "0".repeat(64),
                source_sha256: "0".repeat(64),
                cflags: String::new(),
                rustflags: String::new(),
                rpath: Vec::new(),
                network: false,
                writable: Vec::new(),
                read: Vec::new(),
                confinement: "bubblewrap".into(),
                check_command: None,
                check_timeout: None,
                check_required: None,
                files: Vec::new(),
                dirs: Vec::new(),
            },
            log_path: paths.state_dir().join("build.log"),
        };
        run(&recipe, &outcome, &paths, &[]).expect("check passes");
    }

    #[test]
    fn a_failed_required_check_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        fs::create_dir_all(paths.state_dir()).expect("state");
        let store = paths.store().join("checkpkg-1.0-deadbeef");
        fs::create_dir_all(store.join("usr/bin")).expect("store");
        let probe = store.join("usr/bin/checkprobe");
        fs::write(&probe, "#!/bin/sh\nexit 7\n").expect("probe");
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).expect("mode");
        let text = "package.name = checkpkg\npackage.version = 1.0\nsource.file = checkpkg.tar\nsource.sha256 = 0000000000000000000000000000000000000000000000000000000000000000\nbuild.system = custom\ninstall.prefix = /usr\ncheck.command = checkprobe\ncheck.required = true\n";
        let recipe = Recipe::parse(text).expect("recipe");
        let outcome = BuildOutcome {
            store_path: store,
            manifest: BuildManifest {
                patches: Vec::new(),
                name: "checkpkg".into(),
                version: "1.0".into(),
                recipe_sha256: "0".repeat(64),
                source_sha256: "0".repeat(64),
                cflags: String::new(),
                rustflags: String::new(),
                rpath: Vec::new(),
                network: false,
                writable: Vec::new(),
                read: Vec::new(),
                confinement: "bubblewrap".into(),
                check_command: None,
                check_timeout: None,
                check_required: None,
                files: Vec::new(),
                dirs: Vec::new(),
            },
            log_path: paths.state_dir().join("build.log"),
        };
        let error = run(&recipe, &outcome, &paths, &[]).expect_err("check failure");
        assert!(format!("{error}").contains("check failed"));
    }

    #[test]
    fn a_check_that_outlives_its_timeout_is_stopped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        fs::create_dir_all(paths.state_dir()).expect("state");
        let store = paths.store().join("checkpkg-1.0-deadbeef");
        fs::create_dir_all(&store).expect("store");
        let text = "package.name = checkpkg\npackage.version = 1.0\nsource.file = checkpkg.tar\nsource.sha256 = 0000000000000000000000000000000000000000000000000000000000000000\nbuild.system = custom\ninstall.prefix = /usr\ncheck.command = while :; do :; done\ncheck.timeout = 1\ncheck.required = true\n";
        let recipe = Recipe::parse(text).expect("recipe");
        let outcome = BuildOutcome {
            store_path: store,
            manifest: BuildManifest {
                patches: Vec::new(),
                name: "checkpkg".into(),
                version: "1.0".into(),
                recipe_sha256: "0".repeat(64),
                source_sha256: "0".repeat(64),
                cflags: String::new(),
                rustflags: String::new(),
                rpath: Vec::new(),
                network: false,
                writable: Vec::new(),
                read: Vec::new(),
                confinement: "bubblewrap".into(),
                check_command: None,
                check_timeout: None,
                check_required: None,
                files: Vec::new(),
                dirs: Vec::new(),
            },
            log_path: paths.state_dir().join("build.log"),
        };
        let error = run(&recipe, &outcome, &paths, &[]).expect_err("timeout");
        assert!(format!("{error}").contains("did not finish within 1s"));
    }
}

#[cfg(all(test, not(portalis_rootfs)))]
mod no_image_tests {
    use super::*;
    use crate::recipe::BuildManifest;

    #[test]
    fn a_required_check_without_an_image_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        let store = paths.store().join("checkpkg-1.0-deadbeef");
        let text = "package.name = checkpkg\npackage.version = 1.0\nsource.file = checkpkg.tar\nsource.sha256 = 0000000000000000000000000000000000000000000000000000000000000000\nbuild.system = custom\ninstall.prefix = /usr\ncheck.command = true\ncheck.required = true\n";
        let recipe = Recipe::parse(text).expect("recipe");
        let outcome = BuildOutcome {
            store_path: store,
            manifest: BuildManifest {
                patches: Vec::new(),
                name: "checkpkg".into(),
                version: "1.0".into(),
                recipe_sha256: "0".repeat(64),
                source_sha256: "0".repeat(64),
                cflags: String::new(),
                rustflags: String::new(),
                rpath: Vec::new(),
                network: false,
                writable: Vec::new(),
                read: Vec::new(),
                confinement: "bubblewrap".into(),
                check_command: None,
                check_timeout: None,
                check_required: None,
                files: Vec::new(),
                dirs: Vec::new(),
            },
            log_path: paths.state_dir().join("build.log"),
        };
        let error =
            run(&recipe, &outcome, &paths, &[]).expect_err("a required check ran without an image");
        assert!(format!("{error}").contains("no rootfs image"), "{error}");
    }
}
