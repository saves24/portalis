//! Unpacking an archive in a child process.

use crate::util;
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use super::stream::{decompressor, drain_tail};

/// Bytes allowed after the end-of-archive marker.
const MAX_TAIL_BYTES: u64 = 16 * 1024 * 1024;

/// Unpacks `source` into `dest` by starting this binary again with the builder's
/// credentials.
pub(crate) fn unpack_archive(
    source: &mut std::fs::File,
    dest: &Path,
    _cwd: &Path,
    creds: Option<(u32, u32)>,
    log: &mut std::fs::File,
) -> Result<()> {
    unpack_as(source, dest, creds, log)
}

/// Unpacks in a child that drops to `uid:gid` first. A failure is returned, not
/// retried in this process.
fn unpack_in_child(
    source_fd: std::os::fd::RawFd,
    log_fd: std::os::fd::RawFd,
    dest: &Path,
    creds: Option<(u32, u32)>,
) -> ! {
    // In the child: drop, unpack, report, exit. Nothing unwinds here.
    let outcome = (|| -> Result<()> {
        // Safety: setpgid only touches this process.
        unsafe {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        // Ceilings are set before the account is dropped.
        util::apply_limits()?;
        if let Some((uid, gid)) = creds {
            // Safety: setgroups/setgid/setuid only touch this process.
            unsafe {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
        }
        use std::os::fd::FromRawFd;
        // Safety: dup may fail; from_raw_fd requires a descriptor we own.
        let duplicated = unsafe { libc::dup(source_fd) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Safety: duplicated is a fresh descriptor owned here.
        let mut inherited = unsafe { std::fs::File::from_raw_fd(duplicated) };
        unpack(&mut inherited, dest)
    })();
    let code = match &outcome {
        Ok(()) => 0,
        Err(error) => {
            let text = format!("unpacking failed: {error:#}\n");
            // Safety: write to descriptors this process already holds, so the
            // reason appears both in the build log and in the caller's output.
            unsafe {
                libc::write(log_fd, text.as_ptr() as *const libc::c_void, text.len());
                libc::write(
                    libc::STDERR_FILENO,
                    text.as_ptr() as *const libc::c_void,
                    text.len(),
                );
            }
            1
        }
    };
    // Safety: the child exits immediately; no destructors run.
    unsafe { libc::_exit(code) }
}

fn wait_for_unpack(pid: libc::pid_t, log: &mut std::fs::File) -> Result<()> {
    // The child is waited on with a deadline of `build_timeout_seconds`.
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(util::build_timeout_seconds());
    let mut status: libc::c_int = 0;
    loop {
        // Safety: waitpid only writes into the given status word.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            break;
        }
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if std::time::Instant::now() >= deadline {
            // Safety: the child is ours and still running; a negative pid
            // addresses the group it leads, decompressor included, and the
            // direct pid covers the window before the child set its group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            // reaping is bounded: a child that somehow survives the signals must
            // not turn the timeout into an unbounded wait
            for _ in 0..40 {
                // Safety: waitpid only writes into the status word.
                if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            bail!(
                "unpacking did not finish within {} seconds",
                util::build_timeout_seconds()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        if libc::WIFSIGNALED(status) {
            // a member that grows past RLIMIT_FSIZE kills the child with
            // SIGXFSZ, and a killed child never gets to report why
            let signal = libc::WTERMSIG(status);
            let reason = if signal == libc::SIGXFSZ {
                "a file grew past the size limit (RLIMIT_FSIZE, or the filesystem is full)"
            } else {
                "the unpacking process was killed"
            };
            let _ = writeln!(log, "unpack   stopped by signal {signal}: {reason}");
            bail!("unpacking was stopped by signal {signal}: {reason}");
        }
        bail!("unpacking the archive failed; the reason is in the build log");
    }
    Ok(())
}

fn ensure_single_threaded() -> Result<()> {
    let entries =
        std::fs::read_dir("/proc/self/task").with_context(|| "reading /proc/self/task")?;
    let mut count = 0usize;
    for entry in entries {
        entry?;
        count += 1;
    }
    if count != 1 {
        bail!("unpacking needs a single-threaded process; found {count} threads");
    }
    Ok(())
}

fn unpack_as(
    source: &mut std::fs::File,
    dest: &Path,
    creds: Option<(u32, u32)>,
    log: &mut std::fs::File,
) -> Result<()> {
    use std::os::fd::AsRawFd;

    match creds {
        Some((uid, gid)) => writeln!(log, "unpack   as {uid}:{gid}")?,
        None => writeln!(log, "unpack   as the calling account")?,
    }
    let source_fd = source.as_raw_fd();
    let log_fd = log.as_raw_fd();

    ensure_single_threaded()?;
    // Safety: forked in a single-threaded process; the child never returns here
    // and ends with _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if pid == 0 {
        unpack_in_child(source_fd, log_fd, dest, creds);
    }

    wait_for_unpack(pid, log)
}

pub(crate) fn unpack(source: &mut std::fs::File, dest: &Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    let mut magic = [0u8; 6];
    let read = source.read(&mut magic)?;
    source.seek(SeekFrom::Start(0))?;

    match decompressor(&magic[..read]) {
        None => {
            crate::tar::extract(source, dest)?;
            // the same ceiling the compressed path applies: only padding may
            // follow the end-of-archive marker
            if let Err(error) = drain_tail(source, MAX_TAIL_BYTES) {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    bail!(
                        "archive carries more than {MAX_TAIL_BYTES} bytes after the \
                         end-of-archive marker"
                    );
                }
                return Err(error.into());
            }
        }
        Some(program) => {
            let Some(program) = crate::util::trusted_program(program) else {
                bail!("the decompressor {program} is not available in a system path");
            };
            let mut child = std::process::Command::new(&program)
                .env_clear()
                .arg("-dc")
                .stdin(Stdio::from(source.try_clone()?))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "cannot start {} to decompress the archive: {error}",
                        program.display()
                    )
                })?;
            let mut stream = child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("the decompressor has no output to read"))?;
            // a refused archive is not drained; the decompressor is killed
            if let Err(error) = crate::tar::extract(&mut stream, dest) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            // The tail after the marker is read up to a ceiling of its own.
            if let Err(error) = drain_tail(&mut stream, MAX_TAIL_BYTES) {
                let _ = child.kill();
                let _ = child.wait();
                if error.kind() == std::io::ErrorKind::InvalidData {
                    bail!(
                        "archive carries more than {MAX_TAIL_BYTES} bytes after the \
                         end-of-archive marker"
                    );
                }
                return Err(error.into());
            }
            let status = child.wait()?;
            if !status.success() {
                bail!(
                    "{} failed while decompressing the archive ({status})",
                    program.display()
                );
            }
        }
    }
    Ok(())
}
