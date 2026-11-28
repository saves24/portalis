//! Build parameters a package may set locally in appconfig/<package>/build.conf.
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::paths::Paths;

/// Build parameters from appconfig/<package>/build.conf.
#[derive(Debug, Default, Clone)]
pub struct LocalFlags {
    pub cflags: Option<String>,
    pub cxxflags: Option<String>,
    pub rustflags: Option<String>,
    pub ldflags: Option<String>,
    pub bytes: Vec<u8>,
}

const LOCAL_KEYS: [&str; 4] = ["cflags", "cxxflags", "rustflags", "ldflags"];

pub fn local_config_path(paths: &Paths, name: &str) -> PathBuf {
    paths.appconfig().join(name).join("build.conf")
}

pub fn load_local_flags(paths: &Paths, name: &str) -> Result<Option<LocalFlags>> {
    let path = local_config_path(paths, name);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if meta.file_type().is_symlink() {
        bail!("{} must not be a symbolic link", path.display());
    }
    if paths.root == Path::new("/") {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 {
            bail!("{} must be owned by root", path.display());
        }
        if meta.mode() & 0o022 != 0 {
            bail!("{} must not be writable by group or others", path.display());
        }
    }
    let bytes = fs::read(&path)?;
    let mut flags = parse_local_bytes(&path, &bytes)?;
    flags.bytes = bytes;
    Ok(Some(flags))
}

pub(super) fn parse_local_bytes(path: &Path, bytes: &[u8]) -> Result<LocalFlags> {
    let text = std::str::from_utf8(bytes).context("build.conf is not valid UTF-8")?;
    let mut flags = LocalFlags::default();
    let mut seen: Vec<&str> = Vec::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("{}:{}: expected key=value", path.display(), line_no + 1);
        };
        let key = key.trim();
        let value = value.trim();
        if !LOCAL_KEYS.contains(&key) {
            bail!("{}:{}: unknown key {key}", path.display(), line_no + 1);
        }
        if seen.contains(&key) {
            bail!("{}:{}: duplicate key {key}", path.display(), line_no + 1);
        }
        if value.chars().any(|c| c.is_control()) {
            bail!(
                "{}:{}: control character in value",
                path.display(),
                line_no + 1
            );
        }
        seen.push(key);
        let slot = match key {
            "cflags" => &mut flags.cflags,
            "cxxflags" => &mut flags.cxxflags,
            "rustflags" => &mut flags.rustflags,
            "ldflags" => &mut flags.ldflags,
            _ => unreachable!(),
        };
        *slot = Some(value.to_string());
    }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<LocalFlags> {
        parse_local_bytes(
            Path::new("/usr/portalis/appconfig/x/build.conf"),
            text.as_bytes(),
        )
    }

    #[test]
    fn parses_known_keys_and_comments() {
        let flags = parse("# comment\ncflags=-O2 -pipe\nldflags=\n").expect("parse");
        assert_eq!(flags.cflags.as_deref(), Some("-O2 -pipe"));
        assert_eq!(flags.ldflags.as_deref(), Some(""));
        assert!(flags.rustflags.is_none());
    }

    #[test]
    fn rejects_unknown_duplicate_and_control_characters() {
        assert!(parse("optimize=-O3\n").is_err());
        assert!(parse("cflags=-O2\ncflags=-O3\n").is_err());
        assert!(parse("cflags=-O2\u{7}\n").is_err());
        assert!(parse("not a key value\n").is_err());
    }
}
