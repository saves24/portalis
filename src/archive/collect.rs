//! Collecting a tree's files, directories and digests.

use crate::recipe::{ManifestDir, ManifestFile};
use crate::util;
use anyhow::{bail, Result};
use std::path::Path;

use super::paths::validate_tree_links;
use super::STORE_MARKER;

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

pub(crate) fn validate_source_symlinks(root: &Path) -> Result<()> {
    validate_tree_links(root, false)
}

pub(crate) fn digest_of(files: &[ManifestFile]) -> Result<String> {
    serde_json::to_vec(files)
        .map(|bytes| util::sha256_bytes(&bytes))
        .map_err(Into::into)
}
