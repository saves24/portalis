//! Ownership, permission and store-boundary rules for link targets.

use anyhow::{bail, Result};
use std::path::Path;

pub(super) fn trusted_directory(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        bail!(
            "link target passes through a directory writable by another account: {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn trusted_final(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        bail!(
            "link target is writable by another account: {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn trusted_link(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_uid != 0 {
        bail!(
            "link target passes through a link not owned by root: {}",
            path.display()
        );
    }
    Ok(())
}

/// Which trust rule applies to the component being inspected.
pub(super) enum ComponentTrust {
    Link,
    Directory,
    Final,
}

pub(super) fn check_component_trust(
    kind: ComponentTrust,
    stat: &libc::stat,
    path: &Path,
) -> Result<()> {
    match kind {
        ComponentTrust::Link => trusted_link(stat, path),
        ComponentTrust::Directory => trusted_directory(stat, path),
        ComponentTrust::Final => trusted_final(stat, path),
    }
}

/// Rejects a target in another package's store, or one that left its own.
pub(super) fn check_store_boundary(
    path: &Path,
    store: Option<&Path>,
    store_root: Option<&Path>,
    require_own_store: bool,
) -> Result<bool> {
    let (Some(store), Some(store_root)) = (store, store_root) else {
        return Ok(require_own_store);
    };
    if path.starts_with(store_root) && !path.starts_with(store) {
        bail!(
            "link target points into another package's store: {}",
            path.display()
        );
    }
    if require_own_store && !path.starts_with(store) {
        bail!("link target leaves its package store: {}", path.display());
    }
    Ok(require_own_store || path.starts_with(store))
}
