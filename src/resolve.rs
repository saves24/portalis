//! Turning what the caller asked for into the recipe and paths an install uses.
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::db;
use crate::paths::Paths;
use crate::recipe;
use crate::{derive, paths, util};

/// A recipe whose source fields no longer match the archive. It is rewritten
/// only after the install has gone through.
pub(crate) struct PendingRecipe {
    pub(crate) path: std::path::PathBuf,
    pub(crate) version: Option<String>,
    pub(crate) file: String,
    pub(crate) sha: String,
}

fn archive_input(target: &str) -> Result<(std::path::PathBuf, String, String)> {
    let path = std::path::Path::new(target);
    if !path.exists() {
        return Err(crate::error::Coded::new(
            crate::error::Code::InputMissing,
            format!(
                "install requires an archive path (no such file: {})",
                path.display()
            ),
        )
        .into());
    }
    if !path.is_file() {
        return Err(crate::error::Coded::new(
            crate::error::Code::InputMissing,
            format!("{} is not a regular file", path.display()),
        )
        .into());
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?
        .to_string_lossy()
        .to_string();
    let sha = util::sha256_file(path)?;
    Ok((path.to_path_buf(), file_name, sha))
}

type RecipeMatch = (String, PathBuf, bool);
type RecipeScan = (
    Option<(String, PathBuf)>,
    Vec<RecipeMatch>,
    Vec<(String, PathBuf, String)>,
);

fn scan_recipes(paths: &Paths, file_name: &str) -> Result<RecipeScan> {
    let mut exact: Option<(String, PathBuf)> = None;
    let mut prefixed: Vec<(String, PathBuf, String)> = Vec::new();
    let mut broken: Vec<(String, PathBuf, String)> = Vec::new();
    for entry in std::fs::read_dir(paths.recipes())? {
        let entry = entry?;
        let recipe_path = entry.path();
        if recipe_path.extension().and_then(|e| e.to_str()) != Some(paths::RECIPE_EXTENSION) {
            continue;
        }
        let recipe = match recipe::Recipe::load(&recipe_path) {
            Ok(recipe) => recipe,
            Err(error) => {
                let stem = recipe_path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
                    .unwrap_or_default();
                broken.push((stem, recipe_path.clone(), format!("{error:#}")));
                eprintln!("warning: skipping {}: {error:#}", recipe_path.display());
                continue;
            }
        };
        if recipe.source.file == file_name {
            exact = Some((recipe.package.name.clone(), recipe_path.clone()));
            break;
        }
        if file_name.starts_with(&format!("{}-", recipe.package.name)) {
            prefixed.push((
                recipe.package.name.clone(),
                recipe_path.clone(),
                recipe.package.version.clone(),
            ));
        }
    }
    // exact version first, then the longest matching package name
    let mut matching: Vec<RecipeMatch> = prefixed
        .into_iter()
        .filter_map(|(name, path, version)| {
            let archive_version = version_from_file(file_name, &name)?;
            let exact = archive_version == version;
            // another release of the same package: its version starts with a digit
            if !exact && !archive_version.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            Some((name, path, exact))
        })
        .collect();
    matching
        .sort_by_key(|(name, _, exact)| (std::cmp::Reverse(*exact), std::cmp::Reverse(name.len())));
    Ok((exact, matching, broken))
}

fn select_recipe(
    paths: &Paths,
    file_name: &str,
    archive: &std::path::Path,
    exact: Option<(String, PathBuf)>,
    matching: Vec<RecipeMatch>,
    broken: &[(String, PathBuf, String)],
) -> Result<Option<(String, PathBuf)>> {
    if let Some(found) = exact.or_else(|| {
        matching
            .into_iter()
            .next()
            .map(|(name, path, _)| (name, path))
    }) {
        return Ok(Some(found));
    }
    let archive_stem = archive
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_default();
    let wanted = derive::split_name(&archive_stem).map(|(name, _)| name);
    for (stem, recipe_path, error) in broken {
        if wanted.as_deref() == Some(stem.as_str()) {
            bail!(
                "the recipe {} for this archive does not load: {error}",
                recipe_path.display()
            );
        }
    }
    if std::fs::read_dir(paths.recipes())
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("toml"))
        })
        .unwrap_or(false)
    {
        bail!(
            "no recipe matches {file_name}; {} holds only *.toml recipes, which this version no longer reads (rewrite them in the .port format)",
            paths.recipes().display()
        );
    }
    Ok(None)
}

pub(crate) fn resolve_target(
    paths: &Paths,
    target: &str,
    keep_privileged: bool,
) -> Result<(String, Option<derive::Derived>, Option<PendingRecipe>)> {
    let (path, file_name, sha) = archive_input(target)?;
    let (exact, matching, broken) = scan_recipes(paths, &file_name)?;
    let Some((name, recipe_path)) =
        select_recipe(paths, &file_name, &path, exact, matching, &broken)?
    else {
        // nothing declares this archive: import it as a prebuilt package
        let derived = derive::for_archive(&path, keep_privileged)?;
        say!(
            "import   {} {} (no recipe; prebuilt package)",
            derived.recipe.package.name,
            derived.recipe.package.version
        );
        return Ok((derived.recipe.package.name.clone(), Some(derived), None));
    };
    let recipe = recipe::Recipe::load(&recipe_path)?;
    let pending = (recipe.source.sha256 != sha).then(|| PendingRecipe {
        path: recipe_path.clone(),
        version: version_from_file(&file_name, &name),
        file: file_name.clone(),
        sha: sha.clone(),
    });
    Ok((name, None, pending))
}

/// Architecture segments a package name may carry, including the host's own.
pub(crate) const ARCH_SEGMENTS: &[&str] = &[
    "x86_64",
    "i686",
    "i386",
    "aarch64",
    "armv7h",
    "armv6h",
    "riscv64",
    "loongarch64",
    "ppc64le",
    "s390x",
    "any",
    "noarch",
    std::env::consts::ARCH,
];

pub(crate) fn version_from_file(file_name: &str, package: &str) -> Option<String> {
    let mut stem = file_name;
    for suffix in [
        ".tar.zst", ".tar.xz", ".tar.gz", ".tar.bz2", ".tgz", ".zip", ".tar",
    ] {
        if let Some(rest) = stem.strip_suffix(suffix) {
            stem = rest;
            break;
        }
    }
    let rest = stem.strip_prefix(&format!("{package}-"))?;
    // a trailing architecture segment is not part of the version
    let rest = match rest.rsplit_once('-') {
        Some((head, tail)) if ARCH_SEGMENTS.contains(&tail) => head,
        _ => rest,
    };
    if rest.is_empty()
        || !rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
    {
        return None;
    }
    Some(rest.to_string())
}

pub(crate) fn backup_recipe(path: &std::path::Path) -> Result<()> {
    let backup = path.with_extension(format!(
        "port.bak-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::copy(path, &backup)?;
    say!("recipe   backup {}", backup.display());
    Ok(())
}

pub(crate) fn update_recipe_source(
    path: &std::path::Path,
    version: Option<&str>,
    file: &str,
    sha: &str,
) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    if file.chars().any(char::is_control) || file.contains('#') {
        anyhow::bail!("the source file name cannot be written into a recipe: {file:?}");
    }
    let mut out = String::new();
    for line in text.lines() {
        let key = line
            .split_once('=')
            .map(|(key, _)| key.trim())
            .unwrap_or_default();
        match key {
            "package.version" if version.is_some() => {
                out.push_str(&format!(
                    "package.version = {}\n",
                    version.unwrap_or_default()
                ));
            }
            "source.file" => out.push_str(&format!("source.file = {file}\n")),
            "source.sha256" => out.push_str(&format!("source.sha256 = {sha}\n")),
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    let parsed = recipe::Recipe::parse(&out)
        .map_err(|error| anyhow::anyhow!("updated recipe is invalid: {error:#}"))?;
    parsed.validate()?;
    let tmp = path.with_extension("port.new");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub(crate) fn config_bool(paths: &Paths, section: &str, key: &str) -> Result<bool> {
    let conf = util::load_conf(&paths.config_file())?;
    conf.flag(&format!("{section}.{key}"), false)
}

pub(crate) fn require_signature(paths: &Paths) -> Result<bool> {
    config_bool(paths, "security", "require_signature")
}

/// Declared dependencies plus the recipes that could not be read.
pub(crate) struct DependencyGraph {
    pub(crate) edges: std::collections::BTreeMap<String, Vec<String>>,
    pub(crate) unreadable: Vec<String>,
}

pub(crate) fn dependency_graph(paths: &Paths, db: &db::Db) -> Result<DependencyGraph> {
    let mut graph = std::collections::BTreeMap::new();
    let mut unreadable = Vec::new();
    match std::fs::read_dir(paths.recipes()) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.with_context(|| {
                    format!("reading an entry of {}", paths.recipes().display())
                })?;
                if !paths::is_recipe(&entry.path()) {
                    continue;
                }
                match recipe::Recipe::load(&entry.path()) {
                    Ok(recipe) => {
                        graph.insert(recipe.package.name.clone(), recipe.package.depends.clone());
                    }
                    Err(_) => unreadable.push(entry.file_name().to_string_lossy().into_owned()),
                }
            }
        }
        // a fresh system has no recipe directory yet, and an import does not need one
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", paths.recipes().display()));
        }
    }
    for pkg in db.packages()? {
        if !graph.contains_key(&pkg.name) {
            graph.insert(pkg.name.clone(), db.depends_of(&pkg.name)?);
        }
    }
    Ok(DependencyGraph {
        edges: graph,
        unreadable,
    })
}

pub(crate) fn find_cycle(
    graph: &std::collections::BTreeMap<String, Vec<String>>,
    start: &str,
) -> Option<Vec<String>> {
    fn walk(
        graph: &std::collections::BTreeMap<String, Vec<String>>,
        node: &str,
        stack: &mut Vec<String>,
        seen: &mut std::collections::HashSet<String>,
    ) -> Option<Vec<String>> {
        stack.push(node.to_string());
        for dep in graph.get(node).cloned().unwrap_or_default() {
            if let Some(position) = stack.iter().position(|entry| entry == &dep) {
                let mut cycle = stack[position..].to_vec();
                cycle.push(dep);
                return Some(cycle);
            }
            if seen.contains(&dep) {
                continue;
            }
            if let Some(found) = walk(graph, &dep, stack, seen) {
                return Some(found);
            }
        }
        stack.pop();
        seen.insert(node.to_string());
        None
    }
    walk(
        graph,
        start,
        &mut Vec::new(),
        &mut std::collections::HashSet::new(),
    )
}

pub(crate) fn short_hash(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

pub(crate) fn load_recipe(paths: &Paths, name: &str) -> Result<(recipe::Recipe, PathBuf)> {
    let path = paths.recipe_file(name);
    if !path.exists() {
        return Err(crate::error::Coded::new(
            crate::error::Code::InputMissing,
            format!(
                "recipe not found: {} (looked in {})",
                path.display(),
                paths.recipes().display()
            ),
        )
        .into());
    }
    let recipe = recipe::Recipe::load(&path).map_err(|error| {
        crate::error::Coded::new(crate::error::Code::RecipeInvalid, format!("{error:#}"))
    })?;
    Ok((recipe, path))
}
