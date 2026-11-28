//! Manifest, signature and signed-file checks.

use crate::db::Db;
use crate::paths::Paths;
use anyhow::{Context, Result};
use std::path::Path;

/// Checks a store's own tree, symlink targets included, against the digest its
/// completion marker names.
pub(super) fn store_content_problems(pkg: &crate::db::PackageRow) -> Result<usize> {
    let store = Path::new(&pkg.store_path);
    match std::fs::symlink_metadata(store) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            say!("CONTENT {} store is not a directory", pkg.name);
            return Ok(1);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            say!("CONTENT {} store is missing", pkg.name);
            return Ok(1);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", store.display()));
        }
    }
    let marker_path = store.join(crate::archive::STORE_MARKER);
    let marker = match std::fs::read_to_string(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            say!("CONTENT {} store has no completion marker", pkg.name);
            return Ok(1);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", marker_path.display()));
        }
    };
    let Some(recorded_files) = crate::archive::marker_digest(&marker) else {
        say!("CONTENT {} store marker has no usable digest", pkg.name);
        return Ok(1);
    };
    let recorded_tree = crate::archive::marker_tree(&marker);
    if crate::archive::marker_recipe(&marker) != Some(pkg.recipe_sha256.as_str()) {
        say!("CONTENT {} store marker names a different recipe", pkg.name);
        return Ok(1);
    }
    let files = crate::archive::collect_files(store)?;
    let content = if recorded_tree.is_some() {
        crate::archive::tree_digest(&files, &crate::archive::collect_dirs(store)?)?
    } else {
        crate::archive::digest_of(&files)?
    };
    let recorded = recorded_tree.unwrap_or(recorded_files);
    if content.trim() == recorded.trim() {
        return Ok(0);
    }
    say!(
        "CONTENT {} store does not match its completion marker",
        pkg.name
    );
    Ok(1)
}

pub(super) fn legacy_manifests(db: &Db, packages: &[crate::db::PackageRow]) -> Result<bool> {
    let mut recorded = 0usize;
    for pkg in packages {
        if db.manifest_of(&pkg.name)?.is_some() {
            recorded += 1;
        }
    }
    Ok(recorded == 0 && !packages.is_empty())
}

pub(super) fn signed_from_db(
    db: &Db,
    pkg: &crate::db::PackageRow,
) -> Result<Option<std::collections::HashMap<String, SignedFile>>> {
    let digest_ok = match db.manifest_of(&pkg.name)? {
        Some(canonical) => crate::util::sha256_bytes(canonical.as_bytes()) == pkg.manifest_digest,
        None => false,
    };
    if digest_ok {
        signed_files(db, &pkg.name)
    } else {
        Ok(None)
    }
}

/// The signed fields of one manifest entry.
pub(super) struct SignedFile {
    pub(super) sha256: String,
    pub(super) mode: u32,
    pub(super) link: Option<String>,
}

/// File hashes from the stored manifest, or None when there is none to read.
pub(super) fn signed_files(
    db: &Db,
    pkg: &str,
) -> Result<Option<std::collections::HashMap<String, SignedFile>>> {
    let Some(canonical) = db.manifest_of(pkg)? else {
        return Ok(None);
    };
    let Ok(manifest) = serde_json::from_str::<crate::recipe::BuildManifest>(&canonical) else {
        return Ok(None);
    };
    Ok(Some(
        manifest
            .files
            .into_iter()
            .map(|file| {
                (
                    file.path,
                    SignedFile {
                        sha256: file.sha256,
                        mode: file.mode,
                        link: file.link,
                    },
                )
            })
            .collect(),
    ))
}

pub(super) fn manifest_problems(
    db: &Db,
    paths: &Paths,
    pkg: &crate::db::PackageRow,
    _legacy: bool,
) -> Result<usize> {
    let mut problems = 0usize;
    let signature = pkg.signature.as_deref().filter(|sig| !sig.is_empty());
    if signature.is_none() && crate::resolve::require_signature(paths)? {
        say!(
            "UNSIGNED {} is unsigned and security.require_signature is true",
            pkg.name
        );
        return Ok(1);
    }
    let Some(canonical) = db.manifest_of(&pkg.name)? else {
        // The digest column is older than the stored manifests; a missing row
        // means there is nothing to check the signature against.
        if signature.is_some() {
            if crate::util::env_flag("PORTALIS_ALLOW_UNVERIFIED") {
                say!(
                    "note     {} has no recorded manifest, so its signature was not checked \
                     (PORTALIS_ALLOW_UNVERIFIED=1)",
                    pkg.name
                );
            } else {
                say!(
                    "UNVERIFIED {} is signed but no manifest is recorded, so the signature \
                     cannot be checked; reinstall it, or set PORTALIS_ALLOW_UNVERIFIED=1",
                    pkg.name
                );
                problems += 1;
            }
        }
        return Ok(problems);
    };
    let manifest = match serde_json::from_str::<crate::recipe::BuildManifest>(&canonical) {
        Ok(manifest) => manifest,
        Err(error) => {
            say!("MANIFEST {} is not readable: {error}", pkg.name);
            return Ok(problems + 1);
        }
    };
    if manifest.name != pkg.name
        || manifest.version != pkg.version
        || manifest.recipe_sha256 != pkg.recipe_sha256
    {
        say!("MANIFEST {} does not name this package", pkg.name);
        problems += 1;
    }
    let digest = crate::util::sha256_bytes(canonical.as_bytes());
    if digest != pkg.manifest_digest {
        say!(
            "MANIFEST {} records {} but the stored manifest hashes to {}",
            pkg.name,
            pkg.manifest_digest,
            digest
        );
        problems += 1;
    }
    let Some(signature) = signature else {
        return Ok(problems);
    };
    let trusted = paths.trusted_keys();
    if !crate::sign::has_trusted_keys(&trusted)? {
        if crate::util::env_flag("PORTALIS_ALLOW_UNVERIFIED") {
            say!(
                "note     {} is signed, but no trusted keys are configured \
                 (PORTALIS_ALLOW_UNVERIFIED=1)",
                pkg.name
            );
        } else {
            say!(
                "UNVERIFIED {} is signed, but no trusted keys are configured, so the signature \
                 was not checked; add a key to {}, or set PORTALIS_ALLOW_UNVERIFIED=1",
                pkg.name,
                trusted.display()
            );
            problems += 1;
        }
        return Ok(problems);
    }
    if !crate::sign::verify_bytes(canonical.as_bytes(), signature, &trusted)? {
        say!(
            "SIGNATURE {} is not accepted by any key in {}",
            pkg.name,
            trusted.display()
        );
        problems += 1;
    }
    Ok(problems)
}
