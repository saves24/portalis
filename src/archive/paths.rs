//! Path checks: the parts of a path, and links that stay inside a root.
use anyhow::{bail, Context, Result};
use std::path::Path;

/// Walks a finished tree and refuses a symlink whose target leaves it. An
/// absolute target is refused unless `allow_absolute` is set.
pub(crate) fn validate_tree_links(root: &Path, allow_absolute: bool) -> Result<()> {
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_symlink() {
            continue;
        }
        resolve_within(root, entry.path(), allow_absolute)?;
    }
    Ok(())
}

/// One step of a resolved path: a name, or a `..`/`.` that acts on the result
/// reached up to this point. Holds its own copy of the name.
enum Part {
    Normal(std::ffi::OsString),
    Parent,
    Cur,
}

fn parts_of(path: &Path) -> Result<Vec<Part>> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(name) => parts.push(Part::Normal(name.to_os_string())),
            std::path::Component::ParentDir => parts.push(Part::Parent),
            std::path::Component::CurDir => parts.push(Part::Cur),
            // an absolute target starts at the tree root, which is where the
            // walk already starts
            std::path::Component::RootDir => {}
            other => bail!("path holds an unsupported component: {other:?}"),
        }
    }
    Ok(parts)
}

/// Rewrites an absolute symlink target into the relative equivalent when the
/// target belongs to this tree. A target in the live root keeps its absolute
/// form. A target in neither place is refused.
#[cfg(test)]
pub(crate) fn close_absolute_links(root: &Path) -> Result<()> {
    close_absolute_links_at(root, Path::new("/"))
}

pub(crate) fn close_absolute_links_at(root: &Path, target_root: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_symlink() {
            continue;
        }
        let link = entry.path();
        let target = std::fs::read_link(link)?;
        if !target.is_absolute() {
            continue;
        }
        crate::policy::validate_link_target(target_root, "", &target.to_string_lossy(), None)?;
        let rest = match target.strip_prefix("/") {
            Ok(rest) => rest,
            Err(_) => bail!(
                "symlink has a target that is not a plain path: {} -> {}",
                link.display(),
                target.display()
            ),
        };
        if !exists_inside(root, rest) {
            // An absolute link names the live root; it is kept as the archive
            // wrote it.
            continue;
        }
        let parent = link.strip_prefix(root)?.parent().unwrap_or(Path::new(""));
        let relative = relative_target(parent, rest)?;
        std::fs::remove_file(link)?;
        std::os::unix::fs::symlink(&relative, link)?;
    }
    Ok(())
}

/// True when every component of `rel` exists below `root` and no intermediate
/// component is a symlink.
fn exists_inside(root: &Path, rel: &Path) -> bool {
    let parts: Vec<_> = rel.components().collect();
    let mut current = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        current.push(part.as_os_str());
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        if index + 1 < parts.len() && meta.file_type().is_symlink() {
            return false;
        }
    }
    true
}

/// The path that reaches `to` from the directory `from`, both relative to the
/// tree root.
fn relative_target(from: &Path, to: &Path) -> Result<std::path::PathBuf> {
    use std::path::Component;
    let parts = |path: &Path| -> Result<Vec<std::ffi::OsString>> {
        let mut out = Vec::new();
        for part in path.components() {
            match part {
                Component::Normal(name) => out.push(name.to_os_string()),
                Component::ParentDir => {
                    if out.pop().is_none() {
                        bail!("path climbs out of the tree: {}", path.display());
                    }
                }
                Component::CurDir | Component::RootDir => {}
                _ => bail!("path has an unsupported component: {}", path.display()),
            }
        }
        Ok(out)
    };
    let here = parts(from)?;
    let there = parts(to)?;
    let common = here
        .iter()
        .zip(&there)
        .take_while(|(left, right)| left == right)
        .count();
    let mut out = std::path::PathBuf::new();
    for _ in common..here.len() {
        out.push("..");
    }
    for part in &there[common..] {
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Ok(out)
}

/// Resolves a symlink and refuses a target that leaves `root`: every component
/// is walked in order, an intermediate symlink is expanded in place, and a
/// `..` that steps above the root ends the walk.
pub(super) fn resolve_within(root: &Path, link: &Path, allow_absolute: bool) -> Result<()> {
    const MAX_LINK_DEPTH: usize = 40;
    let relative = link
        .strip_prefix(root)
        .with_context(|| format!("symlink outside the tree: {}", link.display()))?;
    let target = std::fs::read_link(link)?;
    let mut pending: std::collections::VecDeque<Part> = std::collections::VecDeque::new();
    if target.is_absolute() {
        if !allow_absolute {
            bail!(
                "archive symlink has an absolute target: {} -> {}",
                link.display(),
                target.display()
            );
        }
        // an absolute target is read from the installed root, which is this tree
        for part in parts_of(&target)? {
            pending.push_back(part);
        }
    } else {
        for part in parts_of(relative.parent().unwrap_or(Path::new("")))? {
            pending.push_back(part);
        }
        for part in parts_of(&target)? {
            pending.push_back(part);
        }
    }

    let mut resolved: Vec<std::ffi::OsString> = Vec::new();
    let mut expansions = 0usize;
    while let Some(part) = pending.pop_front() {
        match part {
            Part::Cur => {}
            Part::Parent => {
                if resolved.pop().is_none() {
                    bail!(
                        "archive symlink escapes the tree: {} -> {}",
                        link.display(),
                        target.display()
                    );
                }
            }
            Part::Normal(name) => {
                let mut candidate = root.to_path_buf();
                for part in &resolved {
                    candidate.push(part);
                }
                candidate.push(&name);
                let is_link = std::fs::symlink_metadata(&candidate)
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false);
                if !is_link {
                    resolved.push(name);
                    continue;
                }
                expansions += 1;
                if expansions > MAX_LINK_DEPTH {
                    bail!(
                        "archive symlink chain is longer than {MAX_LINK_DEPTH} (the link may be a cycle): {}",
                        link.display()
                    );
                }
                let inner = std::fs::read_link(&candidate)?;
                if inner.is_absolute() {
                    if !allow_absolute {
                        bail!(
                            "archive symlink has an absolute target: {} -> {}",
                            candidate.display(),
                            inner.display()
                        );
                    }
                    resolved.clear();
                }
                for part in parts_of(&inner)?.into_iter().rev() {
                    pending.push_front(part);
                }
            }
        }
    }
    Ok(())
}
