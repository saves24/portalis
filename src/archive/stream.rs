//! Feeding the stream through a decompressor, with a deadline and a size
//! ceiling; and copying bounded ranges out of it.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Reads a stream to its end, refusing more than `limit` bytes.
pub(super) fn drain_tail(stream: &mut impl std::io::Read, limit: u64) -> std::io::Result<u64> {
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        total += read as u64;
        if total > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trailing data",
            ));
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "non-zero data after the end-of-archive marker",
            ));
        }
    }
}

/// Detects the compression of an archive by its first bytes.
pub(super) fn decompressor(magic: &[u8]) -> Option<&'static str> {
    if magic.starts_with(&[0x1f, 0x8b]) {
        return Some("gzip");
    }
    if magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some("xz");
    }
    if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("zstd");
    }
    if magic.starts_with(b"BZh") {
        return Some("bzip2");
    }
    None
}

/// Reads one member out of a possibly compressed archive.
pub(crate) fn read_member(
    source: &mut std::fs::File,
    want: &str,
    creds: Option<(u32, u32)>,
) -> Result<Option<Vec<u8>>> {
    through_decompressor(source, creds, |reader| {
        // `&mut dyn Read` is itself a reader, which is what the tar reader wants
        let mut reader = reader;
        crate::tar::read_member(&mut reader, want)
    })
}

/// Starts the decompressor as `creds`, with the build ceilings in place.
fn start_decompressor(
    program: &str,
    source: &std::fs::File,
    out: Stdio,
    creds: Option<(u32, u32)>,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;

    let Some(program) = crate::util::trusted_program(program) else {
        bail!("the decompressor {program} is not available in a system path");
    };
    let mut command = std::process::Command::new(&program);
    command
        .env_clear()
        .arg("-dc")
        .stdin(Stdio::from(source.try_clone()?))
        .stdout(out)
        .stderr(Stdio::null());
    // Safety: the closure runs in the child between fork and exec; the
    // identity and resource calls only touch this process.
    unsafe {
        command.pre_exec(move || {
            if let Some((uid, gid)) = creds {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            crate::util::apply_limits()
        });
    }
    command.spawn().map_err(|error| {
        anyhow::anyhow!(
            "cannot start {} to read the archive: {error}",
            program.display()
        )
    })
}

/// Waits for the decompressor, stopping it once `deadline` passes.
fn wait_for_decompressor(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Result<()> {
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => bail!("the decompressor stopped with {status}"),
            None if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("the decompressor ran past the time it was given");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
}

/// Reads from a pipe and gives up once `deadline` passes.
pub(super) struct DeadlineReader<'a> {
    inner: &'a mut dyn std::io::Read,
    fd: std::os::fd::RawFd,
    deadline: std::time::Instant,
}

impl<'a> DeadlineReader<'a> {
    pub(super) fn new(
        inner: &'a mut dyn std::io::Read,
        fd: std::os::fd::RawFd,
        deadline: std::time::Instant,
    ) -> Self {
        Self {
            inner,
            fd,
            deadline,
        }
    }
}

impl std::io::Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        let millis = (left.as_millis().min(i32::MAX as u128) as i32).max(1);
        let mut descriptor = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // Safety: poll reads the single descriptor structure that lives here.
        let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if ready == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the decompressor went quiet",
            ));
        }
        if ready < 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.inner.read(buf)
    }
}

fn through_decompressor<R>(
    source: &mut std::fs::File,
    creds: Option<(u32, u32)>,
    mut consume: impl FnMut(&mut dyn std::io::Read) -> Result<R>,
) -> Result<R> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut magic = [0u8; 6];
    let read = source.read(&mut magic)?;
    source.seek(SeekFrom::Start(0))?;
    let Some(program) = decompressor(&magic[..read]) else {
        return consume(source);
    };
    let mut child = start_decompressor(program, source, Stdio::piped(), creds)?;
    let mut stream = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("the decompressor has no output to read"))?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(crate::util::build_timeout_seconds());
    let fd = std::os::fd::AsRawFd::as_raw_fd(&stream);
    let produced = {
        let mut reader = DeadlineReader::new(&mut stream, fd, deadline);
        consume(&mut reader)
    };
    drop(stream);
    let mut killed = false;
    let status = match produced {
        Ok(_) => match child.try_wait() {
            Ok(Some(status)) => Some(status),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                killed = true;
                child.wait().ok()
            }
        },
        Err(_) => {
            let _ = child.kill();
            child.wait().ok()
        }
    };
    match produced {
        Ok(value) => {
            if let Some(status) = status {
                if !status.success() && !killed {
                    anyhow::bail!("the decompressor failed ({status})");
                }
            }
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

/// Free bytes on the filesystem holding `path`, or None when it cannot be read.
fn free_bytes(path: &Path) -> Option<u64> {
    let target = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // Safety: a zeroed stat is a valid buffer for the call that fills it in.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // Safety: both pointers refer to live, correctly sized values, and statvfs
    // only writes into the struct it is handed.
    if unsafe { libc::statvfs(target.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// Creates a directory under the temporary directory that only this user can
/// enter.
pub(crate) fn private_dir() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;

    let base = std::env::temp_dir();
    for attempt in 0..64u32 {
        let path = base.join(format!("portalis-{}-{attempt}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", path.display()));
            }
        }
    }
    bail!("no free temporary directory name under {}", base.display())
}

/// Creates a file that did not exist before, readable and writable by its owner
/// only.
pub(crate) fn create_private(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Copies `stream` into `out`, refusing more than `limit` bytes or a run longer
/// than `deadline`.
pub(crate) fn copy_bounded<R: std::io::Read>(
    stream: &mut R,
    out: &mut std::fs::File,
    limit: u64,
    deadline: std::time::Instant,
) -> Result<u64> {
    use std::io::Write as _;

    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Ok(total);
        }
        total += read as u64;
        if total > limit {
            bail!("the archive expands past {limit} bytes");
        }
        if std::time::Instant::now() > deadline {
            bail!("decompressing took longer than the time it was given");
        }
        out.write_all(&buf[..read])?;
    }
}

/// Writes the archive's decompressed bytes to `dest`, returning false when the
/// stream was not compressed. Scanning and unpacking then read one plain tar.
pub(crate) fn decompress_to(
    source: &mut std::fs::File,
    dest: &Path,
    creds: Option<(u32, u32)>,
) -> Result<bool> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut magic = [0u8; 6];
    let read = source.read(&mut magic)?;
    source.seek(SeekFrom::Start(0))?;
    let Some(program) = decompressor(&magic[..read]) else {
        return Ok(false);
    };
    let mut out = create_private(dest)?;
    let mut child = start_decompressor(program, source, Stdio::piped(), creds)?;
    let mut stream = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("the decompressor has no output to read"))?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(crate::util::build_timeout_seconds());
    let fd = std::os::fd::AsRawFd::as_raw_fd(&stream);
    let mut bounded = DeadlineReader::new(&mut stream, fd, deadline);
    let room = dest
        .parent()
        .and_then(free_bytes)
        .map(|free| free / 2)
        .unwrap_or(u64::MAX);
    let copied = copy_bounded(
        &mut bounded,
        &mut out,
        crate::tar::max_unpacked_bytes().min(room),
        deadline,
    );
    let stopped = match copied {
        Ok(_) => wait_for_decompressor(&mut child, deadline),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    };
    if let Err(error) = stopped {
        let _ = std::fs::remove_file(dest);
        return Err(error).with_context(|| format!("decompressing {}", dest.display()));
    }
    Ok(true)
}

/// One member's mode and the group it asks for.
pub(crate) struct MemberMode {
    pub path: String,
    pub mode: u32,
    pub gid: Option<u32>,
    pub gname: Option<String>,
}

/// Member paths and modes, read without unpacking anything. Used to refuse a
/// package whose privileged modes cannot be kept.
pub(crate) fn member_modes(
    source: &mut std::fs::File,
    creds: Option<(u32, u32)>,
) -> Result<Vec<MemberMode>> {
    through_decompressor(source, creds, |reader| {
        let mut reader = reader;
        Ok(crate::tar::members(&mut reader)?
            .into_iter()
            .map(|member| MemberMode {
                path: member.path,
                mode: member.mode,
                gid: member.gid,
                gname: member.gname,
            })
            .collect())
    })
}
