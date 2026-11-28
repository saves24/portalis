//! The optional rootfs image that ships inside the binary.
mod meta {
    include!(concat!(env!("OUT_DIR"), "/rootfs_meta.rs"));
}

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::paths::Paths;

pub const LONG_VERSION: &str = meta::LONG_VERSION;

pub fn embedded() -> bool {
    meta::EMBEDDED
}

/// Digest of the embedded rootfs image, when one is present.
pub fn image_digest() -> Option<&'static str> {
    if meta::EMBEDDED {
        Some(meta::SHA256)
    } else {
        None
    }
}

fn cache_root(paths: &Paths) -> Result<PathBuf> {
    let conf = crate::util::load_conf(&paths.config_file())?;
    let mode = conf
        .get("rootfs.cache")
        .unwrap_or_else(|| "runtime".to_string());
    match mode.as_str() {
        "runtime" | "tmpfs" => Ok(paths.target_root().join("run/portalis/rootfs")),
        "persistent" => Ok(paths.state_dir().join("rootfs")),
        other => bail!("rootfs.cache must be runtime or persistent, found {other}"),
    }
}

/// Unpacks the embedded image once and returns its content-addressed cache.
///
/// Returns `Ok(None)` when this build carries no image.
pub fn prepare(paths: &Paths) -> Result<Option<PathBuf>> {
    if !embedded() {
        return Ok(None);
    }
    let digest = Sha256::digest(meta::IMAGE);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != meta::SHA256 {
        bail!(
            "the embedded rootfs image does not match its recorded hash: expected {}, got {}",
            meta::SHA256,
            actual
        );
    }

    let cache = cache_root(paths)?;
    let persistent = cache.starts_with(paths.state_dir());
    let root = cache.join(meta::SHA256);
    let marker = root.join(".complete");
    if marker.exists() {
        return Ok(Some(root));
    }
    if root.exists() {
        fs::remove_dir_all(&root)
            .with_context(|| format!("removing the unfinished rootfs {}", root.display()))?;
    }
    let parent = root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent: {}", root.display()))?;
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix("rootfs-")
        .tempdir_in(parent)?;
    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(meta::IMAGE))
        .context("opening the embedded rootfs image")?;
    crate::tar::extract_without_times(&mut decoder, temporary.path())
        .context("unpacking the embedded rootfs")?;
    fs::write(temporary.path().join(".complete"), b"")
        .context("writing the rootfs completion marker")?;
    if persistent {
        sync_filesystem(parent)?;
    }
    match fs::rename(temporary.path(), &root) {
        Ok(()) => {}
        Err(error) if root.exists() => {
            let _ = error;
            if !root.join(".complete").exists() {
                bail!(
                    "the rootfs cache {} appeared without a completion marker",
                    root.display()
                );
            }
        }
        Err(error) => return Err(error).context("moving the rootfs into place"),
    }
    if persistent {
        crate::util::sync_dir(parent)?;
    }
    Ok(Some(root))
}

fn sync_filesystem(path: &Path) -> Result<()> {
    let directory =
        fs::File::open(path).with_context(|| format!("opening {} for sync", path.display()))?;
    // Safety: syncfs only reads the directory descriptor.
    if unsafe { libc::syncfs(directory.as_raw_fd()) } != 0 {
        bail!(
            "syncing the rootfs filesystem: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(all(test, portalis_rootfs))]
mod tests {
    use super::prepare;
    use crate::paths::Paths;

    #[test]
    fn an_embedded_image_is_unpacked_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        let first = prepare(&paths).expect("prepare").expect("embedded image");
        assert!(first.join("usr/lib/portalis/rootfs.json").exists());
        assert!(first.join(".complete").exists());
        let second = prepare(&paths)
            .expect("prepare again")
            .expect("embedded image");
        assert_eq!(first, second);
    }
}

#[cfg(test)]
mod cache_tests {
    use super::cache_root;
    use crate::paths::Paths;

    fn paths_with(config: &str) -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        let config_dir = paths
            .config_file()
            .parent()
            .expect("config dir")
            .to_path_buf();
        std::fs::create_dir_all(config_dir).expect("config dir");
        std::fs::write(paths.config_file(), config).expect("config");
        (dir, paths)
    }

    #[test]
    fn the_default_cache_is_runtime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        assert_eq!(
            cache_root(&paths).expect("cache"),
            paths.target_root().join("run/portalis/rootfs")
        );
    }

    #[test]
    fn a_persistent_cache_is_selected_by_config() {
        let (_dir, paths) = paths_with("rootfs.cache = persistent\n");
        assert_eq!(
            cache_root(&paths).expect("cache"),
            paths.state_dir().join("rootfs")
        );
    }
}
