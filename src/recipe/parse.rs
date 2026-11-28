//! Reading and validating a recipe file.
use anyhow::{bail, Context, Result};
use std::path::Path;

use super::manifest::MAX_PATCH_BYTES;
use super::*;

impl Recipe {
    pub fn load(path: &Path) -> Result<Self> {
        let (recipe, _) = Self::load_with_bytes(path)?;
        Ok(recipe)
    }

    pub fn load_with_bytes(path: &Path) -> Result<(Self, Vec<u8>)> {
        let raw =
            std::fs::read(path).with_context(|| format!("reading recipe {}", path.display()))?;
        let text = std::str::from_utf8(&raw)
            .with_context(|| format!("recipe {} is not UTF-8", path.display()))?;
        let recipe =
            Self::parse(text).with_context(|| format!("parsing recipe {}", path.display()))?;
        recipe.validate()?;
        Ok((recipe, raw))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let conf = crate::util::Conf::parse_with(text, &["build.patch"])?;
        for key in conf.keys() {
            if !known_key(key) {
                bail!("unknown key {key}");
            }
        }
        let mut env = std::collections::BTreeMap::new();
        for key in conf.keys() {
            if let Some(name) = key.strip_prefix("build.env.") {
                if name.is_empty() {
                    bail!("build.env needs a variable name");
                }
                env.insert(name.to_string(), conf.get(key).unwrap_or_default());
            }
        }
        let mut patches = Vec::new();
        for body in conf.all("build.patch") {
            let patch = crate::util::Conf::parse(&body)
                .with_context(|| format!("patch {} of {}", patches.len(), "this recipe"))?;
            for key in patch.keys() {
                if !matches!(key, "file" | "sha256" | "content" | "optional") {
                    bail!("unknown patch key {key}");
                }
            }
            patches.push(Patch {
                file: patch.require("file")?,
                sha256: patch.require("sha256")?,
                content: patch.get("content").unwrap_or_default(),
                optional: patch.flag("optional", false)?,
            });
        }
        Ok(Recipe {
            package: PackageInfo {
                name: conf.require("package.name")?,
                version: conf.require("package.version")?,
                description: conf.get("package.description").unwrap_or_default(),
                hold: conf.flag("package.hold", false)?,
                depends: conf.list("package.depends"),
            },
            source: Source {
                kind: conf.get("source.kind").unwrap_or_else(|| "source".into()),
                file: conf.require("source.file")?,
                sha256: conf.require("source.sha256")?,
                dir: conf.get("source.dir").unwrap_or_default(),
            },
            build: Build {
                system: conf
                    .get("build.system")
                    .unwrap_or_else(|| crate::paths::DEFAULT_BUILD_SYSTEM.into()),
                args: conf.list("build.args"),
                cflags: conf.get("build.cflags"),
                cxxflags: conf.get("build.cxxflags"),
                rustflags: conf.get("build.rustflags"),
                patches,
                isolation: conf.get("build.isolation"),
                env,
                network: conf.flag("build.network", false)?,
                writable: conf.list("build.writable"),
                read: conf.list("build.read"),
                jobs: conf.get("build.jobs").unwrap_or_else(default_jobs),
            },
            install: Install {
                prefix: conf
                    .get("install.prefix")
                    .unwrap_or_else(|| crate::paths::DEFAULT_PREFIX.into()),
                setuid: conf.list("install.setuid"),
                setgid: conf.list("install.setgid"),
                deps_ignore: conf.list("install.deps_ignore"),
            },
            files: FilesPolicy {
                preserve: conf.list("files.preserve"),
            },
            hooks: Hooks {
                ldconfig: conf.flag("hooks.ldconfig", false)?,
                icon_cache: conf.list("hooks.icon_cache"),
                daemon_reload: conf.flag("hooks.daemon_reload", false)?,
            },
            check: Check {
                command: conf
                    .get("check.command")
                    .filter(|value| !value.trim().is_empty()),
                timeout: match conf.get("check.timeout") {
                    Some(value) => {
                        let seconds = value.parse::<u64>().with_context(|| {
                            format!("check.timeout must be a number, found {value}")
                        })?;
                        if seconds == 0 {
                            bail!("check.timeout must be greater than zero");
                        }
                        Some(seconds)
                    }
                    None => None,
                },
                required: conf.flag("check.required", false)?,
            },
        })
    }

    pub fn validate(&self) -> Result<()> {
        validate_names(self)?;
        validate_cargo_args(self)?;
        validate_patch_names(self)?;
        validate_prefix(self)?;
        validate_patch_content(self)?;
        validate_paths(self)?;
        validate_kinds(self)
    }
}

fn validate_names(recipe: &Recipe) -> Result<()> {
    if recipe.package.name.is_empty() || recipe.package.version.is_empty() {
        bail!("recipe needs package.name and package.version");
    }
    for (label, value) in [
        ("package.name", recipe.package.name.as_str()),
        ("package.version", recipe.package.version.as_str()),
    ] {
        if value.contains('/')
            || has_parent_component(value)
            || value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            bail!("{label} contains unsafe characters: {value}");
        }
    }
    if recipe.source.file.is_empty()
        || recipe.source.file.contains('/')
        || has_parent_component(&recipe.source.file)
    {
        bail!("source.file must be a plain archive file name");
    }
    if recipe.source.dir.starts_with('/')
        || has_parent_component(&recipe.source.dir)
        || recipe.source.dir.chars().any(|c| c.is_control())
    {
        bail!("source.dir must be a relative path without '..'");
    }
    Ok(())
}

fn validate_cargo_args(recipe: &Recipe) -> Result<()> {
    if recipe.build.system != "cargo" {
        return Ok(());
    }
    // one flag per entry; value flags carry their value after '='
    const VALUE_FLAGS: [&str; 4] = ["--features", "-F", "--target", "--config"];
    for argument in &recipe.build.args {
        if argument.chars().any(char::is_whitespace) {
            bail!(
                "build.args for a cargo recipe holds one flag per entry, and {argument:?} contains whitespace"
            );
        }
        if !argument.starts_with('-') {
            bail!(
                "build.args for a cargo recipe holds flags only; {argument:?} is a bare value (write --features={argument})"
            );
        }
        if argument.starts_with("-F") && !argument.starts_with("-F=") {
            bail!(
                "build.args for a cargo recipe must pass -F with '=', e.g. -F=extra; {argument:?} would be dropped before cargo install"
            );
        }
        if VALUE_FLAGS.contains(&argument.as_str()) {
            bail!(
                "build.args for a cargo recipe must pass {argument} with '=', e.g. {argument}=value; a separate entry would be dropped before cargo install"
            );
        }
    }
    Ok(())
}

fn validate_patch_names(recipe: &Recipe) -> Result<()> {
    for patch in &recipe.build.patches {
        if patch.file.is_empty() || patch.file.contains('/') || has_parent_component(&patch.file) {
            bail!("patch.file must be a plain name");
        }
        if patch.sha256.len() != 64 {
            bail!("patch.sha256 must be a 64 character hex digest");
        }
    }
    Ok(())
}

fn validate_prefix(recipe: &Recipe) -> Result<()> {
    if !recipe.install.prefix.starts_with('/') || has_parent_component(&recipe.install.prefix) {
        bail!("install.prefix must be an absolute path without '..'");
    }
    for prefix in &recipe.install.deps_ignore {
        if prefix.is_empty() || prefix.starts_with('/') || has_parent_component(prefix) {
            bail!("install.deps_ignore entries must be relative paths without '..'");
        }
    }
    Ok(())
}

fn validate_patch_content(recipe: &Recipe) -> Result<()> {
    for patch in &recipe.build.patches {
        if patch.content.is_empty() {
            bail!("inline patch {} is empty", patch.file);
        }
        if patch.content.len() > MAX_PATCH_BYTES {
            bail!(
                "inline patch {} is larger than {} bytes",
                patch.file,
                MAX_PATCH_BYTES
            );
        }
    }
    Ok(())
}

/// True when a path names a parent directory component.
fn has_parent_component(value: &str) -> bool {
    value.split('/').any(|part| part == "..")
}

fn validate_paths(recipe: &Recipe) -> Result<()> {
    for path in &recipe.install.setuid {
        if path.is_empty() || path.starts_with('/') || has_parent_component(path) {
            bail!("install.setuid entries must be relative paths without '..'");
        }
    }
    for entry in &recipe.install.setgid {
        let (path, group) = entry.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("install.setgid entry {entry} must name a group as path:group")
        })?;
        if path.is_empty() || path.starts_with('/') || has_parent_component(path) {
            bail!("install.setgid entries must be relative paths without '..'");
        }
        if group.is_empty() {
            bail!("install.setgid groups must not be empty");
        }
        if group.chars().all(|c| c.is_ascii_digit()) {
            if group.parse::<u32>().is_err() {
                bail!("install.setgid gid {group} does not fit in 32 bits");
            }
        } else if !usable_group_name(group) {
            bail!("install.setgid group {group} is not a usable group name");
        }
    }
    for path in &recipe.build.writable {
        if !path.starts_with('/') || path == "/" || has_parent_component(path) {
            bail!("build.writable entries must be absolute paths other than '/' without '..'");
        }
    }
    for path in &recipe.files.preserve {
        if !path.starts_with('/') || path == "/" || has_parent_component(path) {
            bail!("files.preserve entries must be absolute paths other than '/' without '..'");
        }
    }
    match recipe.build.isolation.as_deref() {
        None | Some("rpath") => {}
        Some(other) => bail!("unknown build.isolation '{other}'"),
    }
    // a read mount reaches into the sandbox: host secrets stay out of it
    const SECRETS: [&str; 11] = [
        "etc",
        "root",
        "home",
        "proc",
        "sys",
        "dev",
        "run",
        "var",
        "usr/portalis",
        "boot",
        "tmp",
    ];
    for path in &recipe.build.read {
        let trimmed = normalise_read_path(path)?;
        if SECRETS
            .iter()
            .any(|root| trimmed == *root || trimmed.starts_with(&format!("{root}/")))
        {
            bail!("build.read may not name {path}: that path holds host secrets");
        }
        if let Ok(resolved) = std::fs::canonicalize(path) {
            let resolved = resolved
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string();
            if SECRETS
                .iter()
                .any(|root| resolved == *root || resolved.starts_with(&format!("{root}/")))
            {
                bail!("build.read may not name {path}: it resolves to host secrets");
            }
        }
        for writable in &recipe.build.writable {
            let read = path.trim_end_matches('/');
            let writable = writable.trim_end_matches('/');
            if read == writable
                || read.starts_with(&format!("{writable}/"))
                || writable.starts_with(&format!("{read}/"))
            {
                bail!("build.read and build.writable overlap at {path} and {writable}");
            }
        }
    }
    Ok(())
}

/// Normalizes one absolute read path and removes redundant components.
fn normalise_read_path(path: &str) -> Result<String> {
    use std::path::Component;
    if !path.starts_with('/') {
        bail!("build.read entries must be absolute paths other than '/' without '..'");
    }
    let mut out = std::path::PathBuf::from("/");
    for component in std::path::Path::new(path).components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                bail!("build.read entries must be absolute paths other than '/' without '..'");
            }
        }
    }
    if out == std::path::Path::new("/") {
        bail!("build.read entries must be absolute paths other than '/' without '..'");
    }
    Ok(out.to_string_lossy().trim_start_matches('/').to_string())
}

fn validate_kinds(recipe: &Recipe) -> Result<()> {
    if recipe.source.sha256.len() != 64 {
        bail!("source.sha256 must be a 64 character hex digest");
    }
    match recipe.source.kind.as_str() {
        "source" | "binary" => {}
        other => bail!("unknown source.kind '{other}'"),
    }
    match recipe.build.system.as_str() {
        "autotools" | "meson" | "cargo" | "custom" => {}
        other => bail!("unknown build.system '{other}'"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::has_parent_component;

    #[test]
    fn a_double_dot_inside_a_name_is_not_a_parent_component() {
        assert!(!has_parent_component("foo..bar"));
        assert!(has_parent_component(".."));
        assert!(has_parent_component("dir/../file"));
        assert!(has_parent_component("/usr/../etc"));
    }
}
