//! Archive and tree handling: reading a package archive, checking symlinks, copying trees.

use crate::recipe::{ManifestDir, ManifestFile};
use crate::util;
use anyhow::{bail, Context, Result};

/// Bytes allowed after the end-of-archive marker.
const MAX_TAIL_BYTES: u64 = 16 * 1024 * 1024;
static COPY_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// Written into a store directory once its content is final.
pub(crate) const STORE_MARKER: &str = ".portalis-complete";

/// The text a store marker carries.
pub(crate) fn marker_text(recipe_sha: &str, content: &str, tree: &str) -> String {
    format!("recipe {recipe_sha}\nfiles {content}\ntree {tree}\n")
}

/// The recipe hash a marker names, when the text reads as one.
pub(crate) fn marker_recipe(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("recipe "))
}

/// The digest of the packed files a marker names, when the text reads as one.
pub(crate) fn marker_digest(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("files "))
}

/// The digest of files and directories a marker names, when the text carries one.
pub(crate) fn marker_tree(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("tree "))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

mod paths;
mod stream;

#[cfg(test)]
pub(crate) use paths::close_absolute_links;
pub(crate) use paths::{close_absolute_links_at, validate_tree_links};
pub(crate) use stream::{create_private, decompress_to, member_modes, private_dir, read_member};
use stream::{decompressor, drain_tail};

#[cfg(test)]
use paths::resolve_within;
#[cfg(test)]
use stream::{copy_bounded, DeadlineReader};

pub(crate) fn collect_files(root: &Path) -> Result<Vec<ManifestFile>> {
    let mut files = Vec::new();
    let mut hashes: std::collections::HashMap<(u64, u64), String> =
        std::collections::HashMap::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(root)?.to_path_buf();
        let base = entry.file_name().to_string_lossy().to_string();
        // Skips archive metadata names at the tree root.
        if rel.components().count() == 1
            && matches!(
                base.as_str(),
                ".BUILDINFO" | ".PKGINFO" | ".MTREE" | ".INSTALL" | ".CHANGELOG"
            )
        {
            continue;
        }
        // the marker belongs to the store: a package that ships this name, as a
        // file or as a link, is refused
        if base == STORE_MARKER {
            let ours = std::fs::symlink_metadata(entry.path())
                .map(|meta| meta.file_type().is_file() && meta.len() <= 64 * 1024)
                .unwrap_or(false)
                && std::fs::read_to_string(entry.path())
                    .map(|text| {
                        marker_recipe(&text)
                            .map(|recipe| !recipe.trim().is_empty())
                            .unwrap_or(false)
                            && marker_digest(&text).is_some_and(is_digest)
                            && marker_tree(&text).is_some_and(is_digest)
                    })
                    .unwrap_or(false);
            if !ours {
                bail!(
                    "a package may not ship {STORE_MARKER}: the name is reserved for the store marker"
                );
            }
            continue;
        }
        // Rejects non-UTF-8 member names.
        let Some(rel_text) = rel.to_str() else {
            bail!(
                "the staged tree carries a name that is not valid UTF-8: {:?}",
                rel
            );
        };
        let path = format!("/{rel_text}");
        // Skips install-info's target index.
        if rel.ends_with("share/info/dir") {
            continue;
        }
        if path.contains("/__pycache__/") || base.ends_with(".pyc") || base.ends_with(".pyo") {
            continue;
        }
        if entry.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            let Some(link_text) = target.to_str().map(|text| text.to_string()) else {
                bail!(
                    "a link in the staged tree points at a name that is not valid UTF-8: {:?}",
                    target
                );
            };
            files.push(ManifestFile {
                path,
                sha256: String::new(),
                mode: 0,
                link: Some(link_text),
            });
        } else if entry.file_type().is_dir() {
            continue;
        } else if entry.file_type().is_file() {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = entry.metadata()?;
            let key = (metadata.dev(), metadata.ino());
            let sha = match hashes.get(&key) {
                Some(sha) => sha.clone(),
                None => {
                    let sha = util::sha256_file(entry.path())?;
                    hashes.insert(key, sha.clone());
                    sha
                }
            };
            let mode = metadata.permissions().mode() & 0o7777;
            files.push(ManifestFile {
                path,
                sha256: sha,
                mode,
                link: None,
            });
        } else {
            bail!(
                "unsupported file type in build tree: {} (only regular files, directories and symlinks are packaged)",
                entry.path().display()
            );
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Records every directory below `root` with its permission bits.
pub(crate) fn collect_dirs(root: &Path) -> Result<Vec<ManifestDir>> {
    let mut dirs = Vec::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_dir() {
            continue;
        }
        let rel = entry.path().strip_prefix(root)?.to_path_buf();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let Some(rel_text) = rel.to_str() else {
            bail!(
                "the staged tree carries a directory name that is not valid UTF-8: {:?}",
                rel
            );
        };
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&entry.metadata()?.permissions()) & 0o777;
        dirs.push(ManifestDir {
            path: format!("/{rel_text}"),
            mode,
        });
    }
    dirs.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(dirs)
}

/// The mode a directory gets after the store owner is normalized.
pub(crate) fn normalised_dir_mode(mode: u32) -> u32 {
    mode & 0o777 & !0o022
}

/// The digest of both the file manifest and the directory metadata.
pub(crate) fn tree_digest(files: &[ManifestFile], dirs: &[ManifestDir]) -> Result<String> {
    let mut bytes = serde_json::to_vec(files)?;
    bytes.push(0);
    bytes.extend(serde_json::to_vec(dirs)?);
    Ok(util::sha256_bytes(&bytes))
}

pub(crate) fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut dirs: Vec<(std::path::PathBuf, u32, u32, u32)> = Vec::new();
    let mut hardlinks: std::collections::HashMap<(u64, u64), std::path::PathBuf> =
        std::collections::HashMap::new();
    ensure_dir_nofollow(to)?;
    for entry in walkdir::WalkDir::new(from).follow_links(false) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(from)?;
        let target = to.join(rel);
        if entry.file_type().is_dir() {
            ensure_dir_nofollow(&target)?;
            let meta = entry.metadata()?;
            dirs.push((target, meta.mode() & 0o7777, meta.uid(), meta.gid()));
        } else if entry.file_type().is_symlink() {
            let source = fs::symlink_metadata(entry.path())?;
            match fs::symlink_metadata(&target) {
                Ok(meta) if meta.is_dir() => {
                    bail!(
                        "refusing to replace directory {} with a symlink",
                        target.display()
                    )
                }
                Ok(_) => fs::remove_file(&target)
                    .with_context(|| format!("removing {}", target.display()))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", target.display()))
                }
            }
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, &target)
                .with_context(|| format!("linking {}", target.display()))?;
            std::os::unix::fs::lchown(&target, Some(source.uid()), Some(source.gid()))
                .with_context(|| format!("setting the owner of {}", target.display()))?;
        } else {
            let meta = entry.metadata()?;
            let key = (meta.dev(), meta.ino());
            if let Some(existing) = hardlinks.get(&key) {
                match fs::symlink_metadata(&target) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        bail!("refusing to write through symlink {}", target.display())
                    }
                    Ok(meta) if meta.is_dir() => {
                        bail!("refusing to replace directory {}", target.display())
                    }
                    Ok(_) => fs::remove_file(&target)
                        .with_context(|| format!("removing {}", target.display()))?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| format!("reading {}", target.display()))
                    }
                }
                fs::hard_link(existing, &target)
                    .with_context(|| format!("linking {}", target.display()))?;
            } else {
                copy_file_nofollow(entry.path(), &target)?;
                hardlinks.insert(key, target);
            }
        }
    }
    // Deepest first.
    dirs.sort_by_key(|(path, _, _, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode, uid, gid) in dirs {
        std::os::unix::fs::chown(&path, Some(uid), Some(gid))
            .with_context(|| format!("setting the owner of {}", path.display()))?;
        fs::set_permissions(
            &path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(mode),
        )
        .with_context(|| format!("setting the mode of {}", path.display()))?;
    }
    Ok(())
}

fn ensure_dir_nofollow(path: &Path) -> Result<()> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("refusing to traverse symlink {}", current.display())
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => bail!("{} is not a directory", current.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .with_context(|| format!("creating {}", current.display()))?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", current.display()));
            }
        }
    }
    Ok(())
}

fn copy_file_nofollow(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if let Some(parent) = target.parent() {
        ensure_dir_nofollow(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(target) {
        if meta.file_type().is_symlink() {
            bail!("refusing to write through symlink {}", target.display());
        }
        if meta.is_dir() {
            bail!(
                "refusing to replace directory {} with a file",
                target.display()
            );
        }
    }
    let sequence = COPY_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary =
        target.with_file_name(format!(".portalis-copy-{}-{sequence}", std::process::id()));
    let mut input =
        fs::File::open(source).with_context(|| format!("opening {}", source.display()))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        let meta = input.metadata()?;
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
        std::os::unix::fs::chown(&temporary, Some(meta.uid()), Some(meta.gid()))?;
        fs::set_permissions(
            &temporary,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(mode),
        )?;
        fs::rename(&temporary, target)
            .with_context(|| format!("moving {}", temporary.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub(crate) fn validate_source_symlinks(root: &Path) -> Result<()> {
    validate_tree_links(root, false)
}

pub(crate) fn digest_of(files: &[ManifestFile]) -> Result<String> {
    serde_json::to_vec(files)
        .map(|bytes| util::sha256_bytes(&bytes))
        .map_err(Into::into)
}

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

#[cfg(test)]
mod tests {
    use super::{collect_files, copy_tree, STORE_MARKER};

    #[test]
    fn a_copy_does_not_write_through_a_destination_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source/bin");
        let destination = dir.path().join("destination/bin");
        std::fs::create_dir_all(&source).expect("source");
        std::fs::create_dir_all(&destination).expect("destination");
        std::fs::write(source.join("sh"), b"package").expect("source file");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"keep").expect("outside");
        std::os::unix::fs::symlink(&outside, destination.join("sh")).expect("destination link");

        let error = copy_tree(
            dir.path().join("source").as_path(),
            dir.path().join("destination").as_path(),
        )
        .expect_err("a symlinked destination was followed");
        assert!(
            format!("{error:#}").contains("symlink"),
            "the refusal does not name the link: {error:#}"
        );
        assert_eq!(
            std::fs::read(&outside).expect("outside"),
            b"keep",
            "the copy wrote through the destination link"
        );
    }

    #[test]
    fn the_marker_text_round_trips() {
        let text = super::marker_text("abc123", "def456", "789abc");
        assert_eq!(super::marker_recipe(&text), Some("abc123"));
        assert_eq!(super::marker_digest(&text), Some("def456"));
        assert_eq!(super::marker_tree(&text), Some("789abc"));
    }

    #[test]
    fn a_package_may_not_ship_the_marker_name() {
        let dir = std::env::temp_dir().join(format!("portalis-marker-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(STORE_MARKER), b"not ours\n").unwrap();
        let error = collect_files(&dir).expect_err("a shipped marker name was accepted");
        assert!(
            format!("{error:#}").contains("reserved"),
            "the refusal does not say why: {error:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shipped_marker_name_that_is_a_link_is_refused() {
        let dir = std::env::temp_dir().join(format!("portalis-marker-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join(STORE_MARKER)).unwrap();
        let error = collect_files(&dir).expect_err("a marker-shaped link was accepted");
        assert!(
            format!("{error:#}").contains("reserved"),
            "the refusal does not say why: {error:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_store_marker_is_not_part_of_the_manifest() {
        let dir =
            std::env::temp_dir().join(format!("portalis-marker-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload"), b"x").unwrap();
        std::fs::write(
            dir.join(STORE_MARKER),
            crate::archive::marker_text("recipe-hash", &"a".repeat(64), &"b".repeat(64)),
        )
        .unwrap();
        let files = collect_files(&dir).expect("collect");
        let names: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            names,
            vec!["/payload"],
            "the marker leaked into the manifest"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn an_absolute_link_inside_the_tree_becomes_relative() {
        let dir = super::private_dir().expect("private dir");
        let root = dir.join("tree");
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        std::fs::create_dir_all(root.join("usr/lib/okpkg")).expect("lib");
        std::fs::write(root.join("usr/lib/okpkg/data"), b"x").expect("data");
        std::os::unix::fs::symlink("/usr/lib/okpkg/data", root.join("usr/bin/abslink"))
            .expect("link");
        super::close_absolute_links(&root).expect("rewrite");
        let target = std::fs::read_link(root.join("usr/bin/abslink")).expect("read link");
        assert_eq!(
            target,
            std::path::PathBuf::from("../lib/okpkg/data"),
            "the absolute target was not rewritten: {}",
            target.display()
        );
        super::validate_tree_links(&root, false).expect("the rewritten tree still validates");
    }

    #[test]
    fn an_absolute_link_to_the_live_root_keeps_its_form() {
        let dir = super::private_dir().expect("private dir");
        let root = dir.join("tree");
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        std::os::unix::fs::symlink("/usr/lib/libfoo.so.1", root.join("usr/bin/other"))
            .expect("link");
        super::close_absolute_links(&root).expect("a cross-package link");
        let target = std::fs::read_link(root.join("usr/bin/other")).expect("read link");
        assert_eq!(
            target,
            std::path::PathBuf::from("/usr/lib/libfoo.so.1"),
            "a link to the live root was rewritten: {}",
            target.display()
        );
    }

    #[test]
    fn an_absolute_link_to_another_package_is_left_alone() {
        let dir = super::private_dir().expect("private dir");
        let root = dir.join("tree");
        std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
        std::os::unix::fs::symlink("/usr/bin/other-package", root.join("usr/bin/alias"))
            .expect("link");
        super::close_absolute_links(&root).expect("a cross-package link");
        let target = std::fs::read_link(root.join("usr/bin/alias")).expect("read link");
        assert_eq!(
            target,
            std::path::PathBuf::from("/usr/bin/other-package"),
            "the cross-package link was rewritten: {}",
            target.display()
        );
    }

    #[test]
    fn a_copy_that_grows_past_the_limit_is_refused() {
        let dir = super::private_dir().expect("private dir");
        let path = dir.join("out");
        let mut out = super::create_private(&path).expect("file");
        let mut source = std::io::Cursor::new(vec![b'x'; 4096]);
        let later = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let error = super::copy_bounded(&mut source, &mut out, 1024, later)
            .expect_err("the limit was not enforced");
        assert!(
            format!("{error}").contains("expands past"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_pipe_that_stays_quiet_times_out() {
        use std::io::Read as _;

        let (mut reader, writer) = std::os::unix::net::UnixStream::pair().expect("pair");
        let fd = std::os::fd::AsRawFd::as_raw_fd(&reader);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(60);
        let mut bounded = super::DeadlineReader::new(&mut reader, fd, deadline);
        let mut buf = [0u8; 8];
        let error = bounded
            .read(&mut buf)
            .expect_err("a quiet pipe was read from");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(writer);
    }

    #[test]
    fn a_private_file_cannot_be_created_twice() {
        let dir = super::private_dir().expect("private dir");
        let path = dir.join("once");
        let first = super::create_private(&path);
        assert!(
            first.is_ok(),
            "the first creation failed: {:?}",
            first.err()
        );
        let second = super::create_private(&path);
        assert!(
            second.is_err(),
            "a second creation over the same path was allowed"
        );
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).expect("metadata").permissions(),
        ) & 0o777;
        assert_eq!(mode, 0o600, "the file is not owner-only: {mode:04o}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_absolute_link_is_resolved_from_the_tree_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/bin")).expect("directories");
        std::os::unix::fs::symlink("/usr/lib/portalis/portalis", root.join("usr/bin/moirse"))
            .expect("link");
        resolve_within(root, &root.join("usr/bin/moirse"), true)
            .expect("a binary package may carry an absolute target");
        assert!(
            resolve_within(root, &root.join("usr/bin/moirse"), false).is_err(),
            "a source archive may not"
        );
    }

    #[test]
    fn a_link_chain_that_climbs_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tree = dir.path().join("pkg");
        std::fs::create_dir_all(tree.join("deep")).expect("directories");
        std::os::unix::fs::symlink("..", tree.join("deep/x")).expect("first link");
        std::os::unix::fs::symlink("x/../etc/passwd", tree.join("deep/a")).expect("second link");
        let error = resolve_within(&tree, &tree.join("deep/a"), false)
            .expect_err("the chained targets were accepted");
        assert!(error.to_string().contains("escapes the tree"), "{error}");
    }

    #[test]
    fn a_tail_beyond_the_ceiling_is_refused() {
        let at_limit = vec![0u8; 8];
        assert_eq!(
            drain_tail(&mut at_limit.as_slice(), 8).expect("at the ceiling"),
            8
        );
        let past_limit = vec![0u8; 9];
        let error = drain_tail(&mut past_limit.as_slice(), 8).expect_err("past the ceiling");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
