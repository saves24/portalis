//! Running a command with output capture, deadlines and process-group cleanup.
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use super::jobs;
use super::sandbox::{
    landlock_ruleset, prepare_workspace_dir, sandbox_arguments, sandbox_can_drop_uid,
    sandbox_child_setup, socket_filter,
};
use super::trusted_program;
use crate::util::limits::build_timeout_seconds;
use crate::util::sandbox::{build_confinement, network_left_open, sandbox_enabled, SandboxPolicy};

/// The search path a build step gets.
pub(crate) const BUILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Runs a program without the build sandbox.
pub fn run_unprivileged(
    program: &str,
    args: &[String],
    cwd: &Path,
    log: &mut std::fs::File,
    extra_env: &[(&str, String)],
    credentials: Option<(u32, u32)>,
    writable: &[&Path],
) -> Result<()> {
    run_logged_with(
        program,
        args,
        cwd,
        log,
        extra_env,
        credentials,
        None,
        false,
        Some(writable),
    )
}

/// Runs a build step, optionally as an unprivileged user.
pub fn run_logged_as(
    program: &str,
    args: &[String],
    cwd: &Path,
    log: &mut std::fs::File,
    extra_env: &[(&str, String)],
    credentials: Option<(u32, u32)>,
    policy: Option<&SandboxPolicy>,
) -> Result<()> {
    run_logged_with(
        program,
        args,
        cwd,
        log,
        extra_env,
        credentials,
        policy,
        true,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_logged_with(
    program: &str,
    args: &[String],
    cwd: &Path,
    log: &mut std::fs::File,
    extra_env: &[(&str, String)],
    credentials: Option<(u32, u32)>,
    policy: Option<&SandboxPolicy>,
    sandbox_required: bool,
    confine_writes: Option<&[&Path]>,
) -> Result<()> {
    let program = resolve_program(program);
    let mut sandbox: Vec<String> = Vec::new();
    let network_allowed = policy.map(|p| p.network).unwrap_or(false);
    let sandboxed = sandbox_required && sandbox_enabled();
    let effective_uid = if sandboxed {
        credentials.filter(|(uid, gid)| sandbox_can_drop_uid(*uid, *gid))
    } else {
        credentials
    };
    if policy.is_some() && network_left_open(network_allowed, build_confinement()) {
        bail!(
            "this step must not reach the network, and {} cannot confine sockets",
            build_confinement()
        );
    }
    let landlock = landlock_ruleset(sandbox_required, policy, confine_writes, &program, cwd, log)?;
    if landlock.is_some() {
        writeln!(
            log,
            "sandbox  {}: writes limited to the workspace (no bubblewrap)",
            crate::landlock::describe()?
        )?;
        writeln!(log, "reads    limited (landlock)")?;
    }
    if sandboxed {
        sandbox = sandbox_arguments(policy, cwd, effective_uid, log)?;
    }
    writeln!(
        log,
        "\n$ {}{} {}",
        if sandbox.is_empty() { "" } else { "[sandbox] " },
        program,
        args.join(" ")
    )?;
    let mut cmd = prepare_command(
        &program,
        args,
        cwd,
        &sandbox,
        log,
        extra_env,
        credentials,
        landlock.is_some(),
    )?;
    if sandboxed && credentials.is_some() && effective_uid.is_none() {
        let (uid, _) = credentials.unwrap_or((0, 0));
        bail!("refusing to run a build as namespace root: bwrap cannot start as uid {uid}");
    }
    let landlock_fd = landlock.as_ref().map(|ruleset| ruleset.raw_fd());
    let socket_filter = if landlock.is_some() && !network_allowed {
        Some(socket_filter()?)
    } else {
        None
    };
    {
        use std::os::unix::process::CommandExt;
        // Safety: the closure only calls async-signal-safe libc functions; the
        // socket filter was built before the fork.
        unsafe {
            cmd.pre_exec(sandbox_child_setup(
                effective_uid,
                landlock_fd,
                socket_filter,
            ));
        }
    }
    let child = cmd.spawn().with_context(|| format!("running {program}"))?;
    wait_for_child(child, &program, args, log)
}

/// Resolves a bare program name against the search path the child receives.
fn resolve_program(program: &str) -> String {
    if program.contains('/') {
        return program.to_string();
    }
    for directory in BUILD_PATH.split(':') {
        let candidate = Path::new(directory).join(program);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    program.to_string()
}

/// Builds the command with its environment and the landlock tmpdir.
#[allow(clippy::too_many_arguments)]
fn prepare_command(
    program: &str,
    args: &[String],
    cwd: &Path,
    sandbox: &[String],
    log: &mut std::fs::File,
    extra_env: &[(&str, String)],
    credentials: Option<(u32, u32)>,
    landlocked: bool,
) -> Result<Command> {
    let mut cmd = if sandbox.is_empty() {
        Command::new(program)
    } else {
        let bwrap = trusted_program("bwrap")
            .ok_or_else(|| anyhow::anyhow!("bubblewrap is not available in a system path"))?;
        let mut command = Command::new(bwrap);
        command.args(sandbox);
        command.arg(program);
        command
    };
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", BUILD_PATH)
        .env("HOME", cwd)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("MAKEFLAGS", format!("-j{}", jobs()))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log.try_clone()?));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if sandbox.is_empty() && landlocked {
        let tmp = cwd.join(".tmp");
        prepare_workspace_dir(&tmp, credentials)?;
        cmd.env("TMPDIR", &tmp).env("TMP", &tmp).env("TEMP", &tmp);
    }
    Ok(cmd)
}

/// Waits for a step, stopping its process group on failure or timeout.
fn wait_for_child(
    mut child: std::process::Child,
    program: &str,
    args: &[String],
    log: &mut std::fs::File,
) -> Result<()> {
    let timeout = build_timeout_seconds();
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                stop_tree(&mut child);
                bail!(
                    "command failed ({}): {} {}",
                    status,
                    program,
                    args.join(" ")
                );
            }
            return Ok(());
        }
        if started.elapsed().as_secs() > timeout {
            stop_tree(&mut child);
            writeln!(
                log,
                "timed out after {timeout}s: {program} {}",
                args.join(" ")
            )?;
            bail!(
                "command timed out after {timeout}s: {} {}",
                program,
                args.join(" ")
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Reads a pipe to the end on its own thread.
fn drain_in_background<R>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    })
}

/// Asks the process group to stop, then kills whatever is still there. The group
/// id is the child's pid, which `pre_exec` sets before exec.
fn stop_tree(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    // Safety: the group id is the child's pid, set up before exec.
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    let grace = std::time::Instant::now();
    while grace.elapsed().as_secs() < 10 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Safety: the group outlives its leader, so this runs even when the leader
    // exited on the TERM above: what is left in the group is stopped here.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs a program as an unprivileged user and captures its output, for steps
/// whose result has to be inspected before the next one runs.
pub fn capture_unprivileged(
    program: &str,
    args: &[String],
    cwd: &Path,
    credentials: Option<(u32, u32)>,
) -> Result<std::process::Output> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", BUILD_PATH)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if credentials.is_some() {
        cmd.env("HOME", cwd);
    }
    let temporary = cwd.join(".tmp");
    prepare_workspace_dir(&temporary, credentials)?;
    cmd.env("TMPDIR", &temporary)
        .env("TMP", &temporary)
        .env("TEMP", &temporary);
    let mut confinement_log = tempfile::tempfile().context("creating the confinement log")?;
    let landlock = landlock_ruleset(
        false,
        None,
        Some(&[cwd]),
        program,
        cwd,
        &mut confinement_log,
    )?;
    let landlock_fd = landlock.as_ref().map(crate::landlock::Ruleset::raw_fd);
    let socket_filter = if landlock.is_some() {
        Some(socket_filter()?)
    } else {
        None
    };
    use std::os::unix::process::CommandExt;
    // Safety: the closure only calls async-signal-safe libc functions; the socket
    // filter was built before the fork.
    unsafe {
        cmd.pre_exec(sandbox_child_setup(credentials, landlock_fd, socket_filter));
    }
    let mut child = cmd
        .spawn()
        .map_err(|error| anyhow::anyhow!("running {program}: {error}"))?;
    // The pipes are drained while the child runs.
    let out_reader = drain_in_background(child.stdout.take());
    let err_reader = drain_in_background(child.stderr.take());
    let timeout = build_timeout_seconds();
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("waiting for {program}"))?
        {
            break status;
        }
        if started.elapsed().as_secs() > timeout {
            stop_tree(&mut child);
            bail!("{program} did not finish within {timeout}s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    Ok(std::process::Output {
        status,
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
    })
}
