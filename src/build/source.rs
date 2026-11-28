//! Unpacking the source archive and describing the paths the build must not
//! leak.
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::archive::{unpack_archive, validate_source_symlinks};
use crate::recipe::Recipe;
use crate::stage::{chown_tree, single_directory};
use crate::util;

use super::LocalFlags;

/// Unpacks the archive, fixes ownership and resolves the source directory.
pub(super) fn unpack_source(
    recipe: &Recipe,
    source: &mut fs::File,
    work: &Path,
    creds: Option<(u32, u32)>,
    log: &mut fs::File,
) -> Result<PathBuf> {
    let unpack = work.join("src");
    fs::create_dir_all(&unpack).context("creating the unpack directory")?;
    if let Some((uid, gid)) = creds {
        chown_tree(work, uid, gid).context("chowning the build directory")?;
    }

    unpack_archive(source, &unpack, work, creds, log)?;
    validate_source_symlinks(&unpack).context("validating archive symlinks")?;
    if let Some((uid, gid)) = creds {
        chown_tree(&unpack, uid, gid).context("chowning the unpacked source")?;
        writeln!(log, "build user {}:{}", uid, gid)?;
    }

    let srcdir = match recipe.source.dir.as_str() {
        "" => single_directory(&unpack).context("finding the archive top-level directory")?,
        dir => unpack.join(dir),
    };
    if !srcdir.is_dir() {
        bail!("source directory not found: {}", srcdir.display());
    }
    // Links are checked again against the build tree.
    validate_source_symlinks(&srcdir).context("validating archive symlinks")?;
    Ok(srcdir)
}

/// Store identity schema version.
pub const STORE_IDENTITY_SCHEMA: u32 = 7;

pub(crate) fn recipe_hash(
    recipe: &Recipe,
    local: Option<&LocalFlags>,
    dep_stores: &[PathBuf],
    scrub: bool,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Hashes fields that affect the store contents.
    let patches: Vec<(&str, &str, bool)> = recipe
        .build
        .patches
        .iter()
        .map(|patch| (patch.file.as_str(), patch.content.as_str(), patch.optional))
        .collect();
    hasher.update(serde_json::to_vec(&serde_json::json!({
        "package": &recipe.package,
        "kind": &recipe.source.kind,
        "sha256": &recipe.source.sha256,
        "source_dir": &recipe.source.dir,
        "system": &recipe.build.system,
        "args": &recipe.build.args,
        "cflags": &recipe.build.cflags,
        "cxxflags": &recipe.build.cxxflags,
        "rustflags": &recipe.build.rustflags,
        "isolation": &recipe.build.isolation,
        "env": &recipe.build.env,
        "network": &recipe.build.network,
        "writable": &recipe.build.writable,
        "read": &recipe.build.read,
        "patches": &patches,
        "setuid": &recipe.install.setuid,
        "setgid": &recipe.install.setgid,
        "prefix": &recipe.install.prefix,
        "deps_ignore": &recipe.install.deps_ignore,
    }))?);
    // Includes the store identity schema.
    hasher.update(b"identity-schema\0");
    hasher.update(STORE_IDENTITY_SCHEMA.to_le_bytes());
    if recipe.source.kind == "source" {
        hasher.update(b"sandbox\0");
        hasher.update([u8::from(util::sandbox_enabled())]);
        hasher.update(b"confinement\0");
        hasher.update(util::build_confinement().as_bytes());
        hasher.update(b"\0");
        // Hashes the host ABI fingerprint.
        hasher.update(b"host-abi\0");
        hasher.update(crate::host_abi::fingerprint()?.as_bytes());
        hasher.update(b"\0");
        hasher.update(b"rootfs\0");
        hasher.update(crate::rootfs::image_digest().unwrap_or("none").as_bytes());
        hasher.update(b"\0");
    }
    // Hashes the scrub switch.
    hasher.update(b"scrub\0");
    hasher.update([u8::from(scrub)]);
    let deps: Vec<String> = dep_stores
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    hasher.update(b"deps\0");
    for dep in deps {
        hasher.update(dep.as_bytes());
        hasher.update(b"\0");
    }
    if let Some(flags) = local {
        hasher.update(b"local\0");
        hasher.update(&flags.bytes);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Compiler mappings: the build tree only.
pub(super) fn flag_mappings(work: &Path) -> Vec<(String, String)> {
    vec![(work.to_string_lossy().to_string(), "/build".to_string())]
}
