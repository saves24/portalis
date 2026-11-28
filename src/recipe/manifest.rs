//! The manifest that records what a finished build produced.
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::*;

/// Canonical digest input for signing: everything that determines the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    #[serde(default)]
    pub patches: Vec<String>,
    pub name: String,
    pub version: String,
    pub recipe_sha256: String,
    pub source_sha256: String,
    pub cflags: String,
    pub rustflags: String,
    #[serde(default)]
    pub rpath: Vec<String>,
    /// Declared sandbox relaxations; they are part of the signed manifest.
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub writable: Vec<String>,
    #[serde(default)]
    pub read: Vec<String>,
    /// The confinement the build steps ran under: bubblewrap, landlock or none.
    #[serde(default)]
    pub confinement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_required: Option<bool>,
    pub files: Vec<ManifestFile>,
    #[serde(default)]
    pub dirs: Vec<ManifestDir>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
    /// File mode bits (07777) recorded at build time.
    #[serde(default)]
    pub mode: u32,
    /// Relative target when the package ships a symbolic link.
    #[serde(default)]
    pub link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDir {
    pub path: String,
    /// Directory mode bits (0777) recorded before activation.
    #[serde(default)]
    pub mode: u32,
}

/// Bounds for a signed manifest.
const MAX_MANIFEST_FILES: usize = 200_000;
/// Largest inline patch a recipe may carry.
pub(super) const MAX_PATCH_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

impl BuildManifest {
    /// The manifest of a build that ran from this recipe.
    pub(crate) fn from_recipe(
        recipe: &Recipe,
        recipe_sha: &str,
        source_sha: &str,
        files: Vec<ManifestFile>,
    ) -> Self {
        Self {
            name: recipe.package.name.clone(),
            version: recipe.package.version.clone(),
            recipe_sha256: recipe_sha.to_string(),
            source_sha256: source_sha.to_string(),
            cflags: recipe.build.cflags.clone().unwrap_or_default(),
            rustflags: recipe.build.rustflags.clone().unwrap_or_default(),
            rpath: Vec::new(),
            patches: recipe
                .build
                .patches
                .iter()
                .map(|patch| format!("{}@{}", patch.file, patch.sha256))
                .collect(),
            network: recipe.build.network,
            writable: recipe.build.writable.clone(),
            read: recipe.build.read.clone(),
            confinement: crate::util::build_confinement().to_string(),
            check_command: recipe.check.command.clone(),
            check_timeout: recipe.check.timeout,
            check_required: recipe.check.command.as_ref().map(|_| recipe.check.required),
            files,
            dirs: Vec::new(),
        }
    }

    /// The manifest of a package that arrived already built.
    pub(crate) fn prebuilt(
        recipe: &Recipe,
        recipe_sha: &str,
        source_sha: &str,
        files: Vec<ManifestFile>,
    ) -> Self {
        Self {
            name: recipe.package.name.clone(),
            version: recipe.package.version.clone(),
            recipe_sha256: recipe_sha.to_string(),
            source_sha256: source_sha.to_string(),
            cflags: "prebuilt".into(),
            rustflags: "prebuilt".into(),
            rpath: Vec::new(),
            patches: Vec::new(),
            network: false,
            writable: Vec::new(),
            read: Vec::new(),
            confinement: "none".to_string(),
            check_command: recipe.check.command.clone(),
            check_timeout: recipe.check.timeout,
            check_required: recipe.check.command.as_ref().map(|_| recipe.check.required),
            files,
            dirs: Vec::new(),
        }
    }

    pub(crate) fn with_rpath(mut self, rpath: Vec<String>) -> Self {
        self.rpath = rpath;
        self
    }

    pub(crate) fn with_dirs(mut self, dirs: Vec<ManifestDir>) -> Self {
        self.dirs = dirs;
        self
    }

    pub(crate) fn with_patches(mut self, patches: Vec<String>) -> Self {
        self.patches = patches;
        self
    }

    pub(crate) fn with_flags(mut self, cflags: Option<&str>, rustflags: Option<&str>) -> Self {
        self.cflags = cflags.unwrap_or_default().to_string();
        self.rustflags = rustflags.unwrap_or_default().to_string();
        self
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut sorted = self.clone();
        sorted.files.sort_by(|a, b| a.path.cmp(&b.path));
        sorted.dirs.sort_by(|a, b| a.path.cmp(&b.path));
        if sorted.files.len() + sorted.dirs.len() > MAX_MANIFEST_FILES {
            bail!(
                "manifest has {} entries, limit is {}",
                sorted.files.len() + sorted.dirs.len(),
                MAX_MANIFEST_FILES
            );
        }
        let bytes = serde_json::to_vec(&sorted)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            bail!(
                "manifest is {} bytes, limit is {}",
                bytes.len(),
                MAX_MANIFEST_BYTES
            );
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(crate::util::sha256_bytes(&self.canonical_bytes()?))
    }
}
