//! Static checks applied to a built package before it is activated.
use crate::build::BuildOutcome;
use crate::recipe::Recipe;
use anyhow::{bail, Context, Result};
use std::path::{Component, Path};

mod targets;
mod trust;
mod walk;

#[cfg(test)]
mod tests;

pub(crate) use targets::{allow_protected_paths, is_protected_path};

use targets::{is_protected_link_target, validate_sensitive_path};
use trust::check_store_boundary;
use walk::{
    absolute_target, finish_target_validation, normalise, resolve_target_root,
    walk_target_components,
};

/// Validates a manifest against the root it will be installed into.
#[cfg(test)]
pub fn validate(recipe: &Recipe, outcome: &BuildOutcome) -> Result<()> {
    validate_at(recipe, outcome, Path::new("/"))
}

/// Validates a manifest against the live root it will be installed into.
pub fn validate_at(recipe: &Recipe, outcome: &BuildOutcome, target_root: &Path) -> Result<()> {
    for file in &outcome.manifest.files {
        validate_path(&file.path)?;
        validate_sensitive_path(&file.path)?;
        validate_privileged(recipe, file)?;
        if let Some(target) = &file.link {
            validate_link(&file.path, target, target_root, &outcome.store_path)?;
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if path.chars().any(char::is_control) {
        bail!("manifest path holds a control character: {path:?}");
    }
    let parsed = Path::new(path);
    if !parsed.is_absolute() {
        bail!("manifest path is not absolute: {path}");
    }
    for component in parsed.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                if name.is_empty() {
                    bail!("manifest path has an empty component: {path}");
                }
            }
            _ => bail!("manifest path has an invalid component: {path}"),
        }
    }
    Ok(())
}

fn validate_privileged(recipe: &Recipe, file: &crate::recipe::ManifestFile) -> Result<()> {
    let path = normalise(&file.path);
    if file.mode & 0o4000 != 0
        && !recipe
            .install
            .setuid
            .iter()
            .any(|entry| normalise(entry) == path)
    {
        bail!("manifest keeps setuid on an undeclared path: {path}");
    }
    if file.mode & 0o2000 != 0
        && !recipe
            .install
            .setgid
            .iter()
            .any(|entry| normalise(entry.split(':').next().unwrap_or_default()) == path)
    {
        bail!("manifest keeps setgid on an undeclared path: {path}");
    }
    Ok(())
}

/// Checks a link target against the live root and the package store.
pub(crate) fn validate_link_target(
    target_root: &Path,
    live_path: &str,
    target: &str,
    store_path: Option<&Path>,
) -> Result<()> {
    if target.is_empty() || target.chars().any(char::is_control) {
        bail!("link target is empty or holds a control character: {target:?}");
    }
    let target_path = Path::new(target);
    let target_root = std::fs::canonicalize(target_root)
        .with_context(|| format!("resolving {}", target_root.display()))?;
    let mut walk = resolve_target_root(&target_root, target_path, live_path)?;
    let store =
        store_path.map(|path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
    let store_root = store
        .as_ref()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let require_own_store = check_store_boundary(
        &walk.lexical_target()?,
        store.as_deref(),
        store_root.as_deref(),
        false,
    )?;
    walk_target_components(&mut walk)?;
    finish_target_validation(
        &walk,
        &target_root,
        store.as_deref(),
        store_root.as_deref(),
        require_own_store,
    )
}

fn validate_link(path: &str, target: &str, target_root: &Path, store_path: &Path) -> Result<()> {
    let raw_target = target;
    if target.is_empty() || target.chars().any(char::is_control) {
        bail!("manifest link has an invalid target: {path} -> {target:?}");
    }
    let parsed = Path::new(target);
    let resolved = if parsed.is_absolute() {
        absolute_target(target)
    } else {
        let parent = Path::new(path).parent().unwrap_or(Path::new("/"));
        absolute_target(&format!("{}/{}", parent.display(), target))
    };
    let Some(target) = resolved else {
        bail!("manifest link climbs out of the live root: {path} -> {target}");
    };
    if target == "/" {
        bail!("manifest link points at the live root: {path}");
    }
    if !allow_protected_paths()
        && is_protected_path(&target)
        && !store_path
            .parent()
            .map(|root| Path::new(&target).starts_with(root))
            .unwrap_or(false)
    {
        bail!("manifest link points at a host-sensitive path: {path} -> {target}");
    }
    if !allow_protected_paths() && is_protected_link_target(&target, Some(store_path), target_root)
    {
        bail!("manifest link points at a protected host path: {path} -> {target}");
    }
    validate_link_target(target_root, path, raw_target, Some(store_path))?;
    Ok(())
}
