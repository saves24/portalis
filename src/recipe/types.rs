//! The recipe file itself: what a package says about itself and how it builds.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Recipe {
    pub package: PackageInfo,
    pub source: Source,
    pub build: Build,
    pub install: Install,
    #[serde(default)]
    pub files: FilesPolicy,
    #[serde(default)]
    pub hooks: Hooks,
    #[serde(default)]
    pub check: Check,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    // Prose only: excluded from the recipe hash.
    #[serde(default, skip_serializing)]
    pub description: String,
    /// A recipe that marks itself held is not removed without `--force`.
    #[serde(default, skip_serializing)]
    pub hold: bool,
    #[serde(default)]
    pub depends: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    /// "source" builds from an archive, "binary" installs a prebuilt package.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Archive file name used to match an install path to this recipe.
    pub file: String,
    pub sha256: String,
    /// Directory name inside the archive; auto-detected when empty.
    #[serde(default)]
    pub dir: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Build {
    /// autotools | meson | cargo | custom
    #[serde(default = "default_system")]
    pub system: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Compiler and rust flags for this recipe.
    #[serde(default)]
    pub cflags: Option<String>,
    #[serde(default)]
    pub cxxflags: Option<String>,
    #[serde(default)]
    pub rustflags: Option<String>,
    /// Local patches applied after unpacking, in order.
    #[serde(default)]
    pub patches: Vec<Patch>,
    /// "rpath" writes DT_RUNPATH entries for dependency store paths.
    #[serde(default)]
    pub isolation: Option<String>,
    /// Extra environment for the build steps.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Allow network access inside the build sandbox.
    #[serde(default)]
    pub network: bool,
    /// Additional paths mounted read-write inside the build sandbox.
    #[serde(default)]
    pub writable: Vec<String>,
    /// Additional host paths mounted read-only inside the build sandbox.
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default = "default_jobs", skip_serializing)]
    pub jobs: String,
}

pub(crate) fn known_key(key: &str) -> bool {
    const KEYS: [&str; 30] = [
        "package.name",
        "package.version",
        "package.description",
        "package.hold",
        "package.depends",
        "source.kind",
        "source.file",
        "source.sha256",
        "source.dir",
        "build.system",
        "build.args",
        "build.cflags",
        "build.cxxflags",
        "build.rustflags",
        "build.isolation",
        "build.network",
        "build.writable",
        "build.read",
        "build.jobs",
        "install.prefix",
        "install.setuid",
        "install.setgid",
        "install.deps_ignore",
        "files.preserve",
        "hooks.ldconfig",
        "hooks.icon_cache",
        "hooks.daemon_reload",
        "check.command",
        "check.timeout",
        "check.required",
    ];
    KEYS.contains(&key)
        || key
            .strip_prefix("build.env.")
            .is_some_and(|name| !name.is_empty())
        || key == "build.patch"
}

/// Empty means "not pinned here"; the build then uses the configuration or, when
/// that is silent too, half of the machine.
pub(crate) fn default_jobs() -> String {
    String::new()
}

#[derive(Debug, Clone, Serialize)]
pub struct Patch {
    /// Name used in logs; also the file name for external patches.
    pub file: String,
    pub sha256: String,
    /// Inline patch text.
    pub content: String,
    /// Skip a patch that no longer applies.
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Install {
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Paths allowed to keep the setuid bit after install.
    #[serde(default)]
    pub setuid: Vec<String>,
    /// Paths allowed to keep the setgid bit after install.
    #[serde(default)]
    pub setgid: Vec<String>,
    /// Path prefixes whose ELF files resolve libraries through a private rpath.
    #[serde(default)]
    pub deps_ignore: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FilesPolicy {
    /// Paths that are configuration: copied to the live tree once, never overwritten.
    #[serde(default)]
    pub preserve: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hooks {
    #[serde(default)]
    pub ldconfig: bool,
    #[serde(default)]
    pub icon_cache: Vec<String>,
    #[serde(default)]
    pub daemon_reload: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Check {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub required: bool,
}

/// A group name a recipe can carry: printable, no separators, not too long.
pub(crate) fn usable_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.contains(':')
        && !name.chars().any(char::is_whitespace)
        && name.chars().all(|c| c.is_ascii_graphic())
}
