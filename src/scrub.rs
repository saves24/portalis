//! Build path scrubbing: keeps builder paths out of staged files and logs.

use crate::paths::Paths;
use crate::util;
use anyhow::{bail, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) fn scrub_paths_enabled(paths: &Paths) -> bool {
    match util::load_conf(&paths.config_file()) {
        Ok(conf) => conf.flag("build.scrub_paths", true).unwrap_or(true),
        Err(error) => {
            eprintln!("warning: {error}; scrubbing build paths");
            true
        }
    }
}

pub(crate) fn scrub_mappings(work: &Path, paths: &Paths) -> Vec<(String, String)> {
    let work = work.to_string_lossy().to_string();
    let mut mappings = vec![(work.clone(), "/build".to_string())];
    if paths.root != Path::new("/") {
        let root = paths.root.to_string_lossy().to_string();
        if !root.is_empty() && !root.starts_with(&work) {
            mappings.push((root, String::new()));
        }
    }
    mappings.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    mappings
}

/// Scrubs the build log when the build ends, whatever the exit path.
pub(crate) struct LogScrub {
    pub(crate) path: PathBuf,
    pub(crate) mappings: Vec<(String, String)>,
    pub(crate) enabled: bool,
}

impl Drop for LogScrub {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        if let Err(error) = scrub_file(&self.path, &self.mappings) {
            eprintln!("warning: cannot scrub {}: {error}", self.path.display());
        }
    }
}

pub(crate) fn apply_mappings(data: Vec<u8>, mappings: &[(String, String)]) -> Vec<u8> {
    let mut data = data;
    for (from, to) in mappings {
        if from.is_empty() {
            continue;
        }
        data = replace_path(&data, from.as_bytes(), to.as_bytes());
    }
    data
}

/// What one scrub pass found: files that still name their builder, and files it
/// could not read at all. A file that could not be read is not a clean file.
pub(crate) struct ScrubReport {
    pub leaked: usize,
    pub unreadable: usize,
}

/// Refuses a package whose files still name their builder; an import may opt in.
pub(crate) fn check_leaks(report: &ScrubReport, allow: bool) -> Result<()> {
    if allow {
        return Ok(());
    }
    if report.leaked > 0 {
        bail!(
            "{} file(s) still carry a build path that the scrub cannot rewrite.\n\
             Prefix maps fix source and debug references; strings the build writes itself\n\
             (compiler commands, build metadata) must be removed or patched in the recipe.\n\
             An import can accept them with PORTALIS_ALLOW_PATH_LEAK=1",
            report.leaked
        );
    }
    if report.unreadable > 0 {
        bail!(
            "{} path(s) could not be read, so they cannot be checked for builder paths;\n\
             an import can accept that with PORTALIS_ALLOW_PATH_LEAK=1",
            report.unreadable
        );
    }
    Ok(())
}

pub(crate) fn scrub_stage(stage: &Path, mappings: &[(String, String)]) -> Result<ScrubReport> {
    scrub_stage_allowing(stage, mappings, &[])
}

pub(crate) fn scrub_stage_allowing(
    stage: &Path,
    mappings: &[(String, String)],
    allowed: &[PathBuf],
) -> Result<ScrubReport> {
    let mut report = ScrubReport {
        leaked: 0,
        unreadable: 0,
    };
    if mappings.is_empty() {
        return Ok(report);
    }
    let mut stack = vec![stage.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                report.unreadable += 1;
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // A link is left alone.
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(_) => {
                    report.unreadable += 1;
                    continue;
                }
            };
            if kind.is_symlink() {
                scrub_link(&entry.path(), mappings, allowed, &mut report);
                continue;
            }
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            scrub_one_file(&path, &entry, mappings, allowed, &mut report)?;
        }
    }
    Ok(report)
}

fn scrub_link(
    path: &Path,
    mappings: &[(String, String)],
    allowed: &[PathBuf],
    report: &mut ScrubReport,
) {
    // The target text travels into the manifest and onto the running system.
    if let Ok(target) = std::fs::read_link(path) {
        let text = target.to_string_lossy();
        if allowed
            .iter()
            .any(|prefix| text.contains(&prefix.to_string_lossy().to_string()))
        {
            return;
        }
        if mappings
            .iter()
            .any(|(from, _)| text.contains(from.as_str()))
        {
            report.leaked += 1;
            say!("leak     {} points at a builder path", path.display());
        }
    }
}

fn binary_hint(data: &[u8]) -> &'static str {
    let has = |needle: &[u8]| data.windows(needle.len()).any(|window| window == needle);
    if has(b"compiler:") || has(b"-ffile-prefix-map") || has(b"-fdebug-prefix-map") {
        "the binary embeds compiler or build metadata; strip that metadata in the recipe"
    } else {
        "the binary embeds the path in code or data; add a prefix map or patch the source"
    }
}

fn has_binary_magic(data: &[u8]) -> bool {
    const MAGICS: [&[u8]; 17] = [
        b"\x7fELF",
        b"%PDF-",
        b"%!PS",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ",
        b"\x28\xb5\x2f\xfd",
        b"PK\x03\x04",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!",
        b"!<arch>\n",
        b"\0asm",
        b"SQLite format 3\0",
        b"\x89PNG\r\n\x1a\n",
        b"GIF8",
        b"\xff\xd8\xff",
        b"MZ",
    ];
    MAGICS.iter().any(|magic| data.starts_with(magic))
}

/// True when a file can be rewritten as text without changing bytes.
fn is_text(data: &[u8]) -> bool {
    if has_binary_magic(data) || std::str::from_utf8(data).is_err() {
        return false;
    }
    !data
        .iter()
        .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\r' | b'\t'))
}

fn scrub_one_file(
    path: &Path,
    entry: &std::fs::DirEntry,
    mappings: &[(String, String)],
    allowed: &[PathBuf],
    report: &mut ScrubReport,
) -> Result<()> {
    let len = match entry.metadata() {
        Ok(meta) => meta.len(),
        Err(_) => {
            report.unreadable += 1;
            return Ok(());
        }
    };
    // A file that cannot be read counts as unchecked, not as clean.
    if len > MAX_SCRUB_BYTES {
        match stream_mentions_any(path, mappings) {
            Ok(true) => {
                report.leaked += 1;
                say!("leak     {} keeps a builder path", path.display());
            }
            Ok(false) => {}
            Err(_) => report.unreadable += 1,
        }
        return Ok(());
    }
    let mut input = match open_no_follow(path, false) {
        Ok(input) => input,
        Err(_) => {
            report.unreadable += 1;
            return Ok(());
        }
    };
    let mut data = Vec::new();
    if input.read_to_end(&mut data).is_err() {
        report.unreadable += 1;
        return Ok(());
    }
    if !mappings.iter().any(|(from, _)| mentions_path(&data, from)) {
        return Ok(());
    }
    let binary = !is_text(&data);
    if binary {
        let mut probe = data;
        for prefix in allowed {
            probe = replace_path(&probe, prefix.to_string_lossy().as_bytes(), b"");
        }
        if !mappings.iter().any(|(from, _)| mentions_path(&probe, from)) {
            return Ok(());
        }
        report.leaked += 1;
        say!(
            "leak     {} keeps a builder path inside binary content; {}",
            path.display(),
            binary_hint(&probe)
        );
        return Ok(());
    }
    let mut output = open_no_follow(path, true)?;
    output.write_all(&apply_mappings(data, mappings))?;
    Ok(())
}

/// True when a file names any mapped path, read in chunks.
fn stream_mentions_any(path: &Path, mappings: &[(String, String)]) -> std::io::Result<bool> {
    let mut needles: Vec<Vec<u8>> = Vec::new();
    for (from, _) in mappings {
        if from.is_empty() {
            continue;
        }
        let mut needle = from.as_bytes().to_vec();
        if !needle.ends_with(b"/") {
            needle.push(b'/');
        }
        needles.push(needle);
    }
    if needles.is_empty() {
        return Ok(false);
    }
    let longest = needles.iter().map(|needle| needle.len()).max().unwrap_or(1);
    let mut file = open_no_follow(path, false)?;
    let mut chunk = vec![0u8; 1 << 20];
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(mappings
                .iter()
                .any(|(from, _)| !from.is_empty() && mentions_path(&tail, from)));
        }
        let mut window = std::mem::take(&mut tail);
        window.extend_from_slice(&chunk[..read]);
        if needles.iter().any(|needle| contains_path(&window, needle)) {
            return Ok(true);
        }
        // Carry the last needle-length bytes into the next read.
        let keep = longest.saturating_sub(1).min(window.len());
        tail = window[window.len() - keep..].to_vec();
    }
}

/// True when `data` contains `path` as a directory prefix.
fn mentions_path(data: &[u8], path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let base = path.as_bytes();
    let mut at = 0;
    while let Some(found) = data[at..]
        .windows(base.len())
        .position(|window| window == base)
    {
        let start = at + found;
        let after = start + base.len();
        // a path is a directory prefix when a separator follows it, or the
        // match reaches the end of the file; a line break or NUL also ends a
        // string that names it
        if after == data.len() || matches!(data[after], b'/' | b'\n' | b'\r' | 0) {
            return true;
        }
        at = start + 1;
    }
    false
}

/// Replaces a mapped path only where a name boundary follows it.
fn replace_path(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut index = 0;
    while index < haystack.len() {
        if haystack[index..].starts_with(needle) {
            let after = index + needle.len();
            let boundary = after == haystack.len() || !is_name_byte(haystack[after]);
            if boundary {
                out.extend_from_slice(with);
                index = after;
                continue;
            }
        }
        out.push(haystack[index]);
        index += 1;
    }
    out
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

pub(crate) fn scrub_file(path: &Path, mappings: &[(String, String)]) -> std::io::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if mappings.is_empty() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() <= MAX_SCRUB_BYTES {
        let data = fs::read(path)?;
        let mut output = open_no_follow(path, true)?;
        output.write_all(&apply_mappings(data, mappings))?;
        return Ok(());
    }
    let mut input = open_no_follow(path, false)?;
    let temporary = path.with_file_name(format!(
        ".portalis-log-{}-{}",
        std::process::id(),
        LOG_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let longest = mappings
        .iter()
        .map(|(from, _)| from.len())
        .max()
        .unwrap_or(1)
        .max(1);
    let carry_len = longest.saturating_sub(1);
    let mut carry: Vec<u8> = Vec::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let result = (|| -> std::io::Result<()> {
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            carry.extend_from_slice(&buffer[..read]);
            if carry.len() <= carry_len {
                continue;
            }
            let split = carry.len() - carry_len;
            let mut ready = carry[..split].to_vec();
            carry = carry[split..].to_vec();
            for (from, to) in mappings {
                ready = replace_path(&ready, from.as_bytes(), to.as_bytes());
            }
            output.write_all(&ready)?;
        }
        for (from, to) in mappings {
            carry = replace_path(&carry, from.as_bytes(), to.as_bytes());
        }
        output.write_all(&carry)?;
        output.sync_all()?;
        let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
        fs::set_permissions(
            &temporary,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(mode),
        )?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

static LOG_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) const MAX_SCRUB_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn contains_path(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && data.windows(needle.len()).any(|window| window == needle)
}

fn open_no_follow(path: &Path, write: bool) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.read(!write);
    if write {
        options.write(true).truncate(true);
    }
    options.custom_flags(libc::O_NOFOLLOW).open(path)
}

#[cfg(test)]
mod tests {
    use super::{apply_mappings, binary_hint, mentions_path, scrub_stage};

    #[test]
    fn a_build_that_still_names_its_builder_is_refused() {
        let clean = super::ScrubReport {
            leaked: 0,
            unreadable: 0,
        };
        super::check_leaks(&clean, false).expect("no leak passes");
        let leaky = super::ScrubReport {
            leaked: 3,
            unreadable: 0,
        };
        super::check_leaks(&leaky, true).expect("an import may opt in");
        let error = super::check_leaks(&leaky, false).expect_err("the leak was accepted");
        assert!(
            format!("{error:#}").contains("PORTALIS_ALLOW_PATH_LEAK"),
            "the refusal does not name the switch: {error:#}"
        );
    }

    #[test]
    fn binary_leaks_point_at_build_metadata() {
        assert!(binary_hint(b"compiler: gcc -ffile-prefix-map=/build=/build").contains("metadata"));
        assert!(binary_hint(b"source /build/src/main.c").contains("prefix map"));
    }

    #[test]
    fn a_non_text_file_is_not_rewritten() {
        let dir = tempfile::Builder::new()
            .prefix("scrub-pdf")
            .tempdir()
            .expect("temp dir");
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(stage.join("usr/share")).expect("stage");
        let path = stage.join("usr/share/chart.pdf");
        let original = format!("%PDF-1.7\n{}\n", dir.path().display());
        std::fs::write(&path, original.as_bytes()).expect("pdf");
        let mappings = vec![(
            dir.path().to_string_lossy().to_string(),
            "/build".to_string(),
        )];

        let report = scrub_stage(&stage, &mappings).expect("scrub");

        assert_eq!(report.leaked, 1, "the binary leak was not reported");
        assert_eq!(
            std::fs::read(&path).expect("pdf"),
            original.as_bytes(),
            "a non-text file was rewritten"
        );
    }

    #[test]
    fn a_file_larger_than_the_read_limit_is_still_checked() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::Builder::new()
            .prefix("scrub-big")
            .tempdir()
            .expect("temp dir");
        let path = dir.path().join("big.bin");
        let mut file = std::fs::File::create(&path).expect("create");
        write!(file, "/build/secret/").expect("write the path");
        file.set_len(super::MAX_SCRUB_BYTES + 4096).expect("grow");
        file.seek(SeekFrom::Start(0)).expect("seek");
        let mappings = vec![("/build".to_string(), "/x".to_string())];
        let report = super::scrub_stage(dir.path(), &mappings).expect("scrub");
        assert_eq!(
            report.leaked, 1,
            "a file past the read limit was reported as clean"
        );
        assert_eq!(report.unreadable, 0);
    }

    #[test]
    fn a_path_word_is_not_a_leaked_builder_path() {
        // the release binary carries these as its own directory names
        assert!(!super::mentions_path(
            b"\x7fELF ... /var/lib/portalis ...",
            "/var/lib/portalis"
        ));
        assert!(!super::mentions_path(
            b"... sbin:/bin/root LC_ALL ...",
            "/root"
        ));
        // a real leak is a prefix of a longer path
        assert!(super::mentions_path(
            b"... /var/lib/portalis/build-abc/src/main.rs ...",
            "/var/lib/portalis/build-abc"
        ));
        let parent = std::env::temp_dir().join(format!("portalis-parent-{}", std::process::id()));
        let nested = parent.join("nested/registry");
        let text = format!("... {} ...", nested.display());
        let parent = parent.to_string_lossy().to_string();
        assert!(super::mentions_path(text.as_bytes(), &parent));
    }

    #[test]
    fn a_link_into_the_stage_is_not_rewritten_through() {
        let root = std::env::temp_dir().join(format!("portalis-scrub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch directory");
        let outside = root.join("outside.txt");
        std::fs::write(&outside, "keeps /build/path in it\n").expect("outside file");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).expect("stage directory");
        std::os::unix::fs::symlink(&outside, stage.join("link.txt")).expect("symlink");

        let mappings = vec![("/build/path".to_string(), "/usr".to_string())];
        scrub_stage(&stage, &mappings).expect("scrubbing the stage");

        assert_eq!(
            std::fs::read_to_string(&outside).expect("outside file is still there"),
            "keeps /build/path in it\n",
            "scrubbing followed a link and rewrote a file outside the stage"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_path_that_ends_the_file_counts_as_a_leak() {
        let data = b"prefix=/var/lib/portalis/build-abc";
        assert!(
            mentions_path(data, "/var/lib/portalis"),
            "a leaked path at the end of the file went unnoticed"
        );
        assert!(mentions_path(
            b"cd /var/lib/portalis/x",
            "/var/lib/portalis"
        ));
        assert!(!mentions_path(b"/var/lib/portalis2/x", "/var/lib/portalis"));
    }

    #[test]
    fn a_short_mapping_does_not_eat_the_neighbouring_name() {
        let data = b"/opt/portalis/data and /opt/p/bin".to_vec();
        let out = apply_mappings(data, &[("/opt/p".to_string(), String::new())]);
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "/opt/portalis/data and /bin",
            "a mapping rewrote a path that merely started with it"
        );
    }
}
