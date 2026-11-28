#[cfg(test)]
use crate::archive::collect_files;
use crate::paths::Paths;
use crate::recipe::{BuildManifest, Recipe};
use crate::stage::{
    build_user, chown_tree, identify, install_binary, seal, unpack_user, Identified, Plan,
    SealInputs,
};
use crate::steps::run_build_steps;
use crate::util;

mod env;
mod housekeeping;
mod local_flags;
mod source;
mod validate;

use anyhow::{bail, Context, Result};
use env::{
    base_envs, check_scrubbed, compiler_envs, dependency_mounts, log_limits, prepare_stage,
    refresh_makeflags, sandbox_policy, scrub_logger,
};
pub(crate) use housekeeping::prune_logs;
pub use local_flags::{load_local_flags, local_config_path, LocalFlags};
pub(crate) use source::recipe_hash;
use source::unpack_source;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use validate::{validate_read, validate_writable};

/// What a finished build produced: the store, its manifest and the log.
pub struct BuildOutcome {
    pub store_path: PathBuf,
    pub manifest: BuildManifest,
    pub log_path: PathBuf,
}

/// Stops what a build left running when the build returns.
struct BuildDescendants;

impl Drop for BuildDescendants {
    fn drop(&mut self) {
        let Some((uid, _gid)) = build_user() else {
            return;
        };
        if let Err(error) = util::stop_build_descendants(uid) {
            eprintln!("warning: a process the build left behind was not stopped: {error:#}");
        }
    }
}

/// Applies the recipe patches, answering the ones that were applied.
fn apply_patches(
    recipe: &Recipe,
    work: &Path,
    srcdir: &Path,
    fs_creds: Option<(u32, u32)>,
    log: &mut fs::File,
) -> Result<Vec<String>> {
    let mut applied = Vec::new();
    for patch in &recipe.build.patches {
        let dir = work.join("patches");
        fs::create_dir_all(&dir)?;
        let path = dir.join(&patch.file);
        fs::write(&path, &patch.content)?;
        if let Some((uid, gid)) = fs_creds {
            if let Err(error) = chown_tree(&dir, uid, gid) {
                eprintln!(
                    "warning: cannot hand {} to the build user: {error}",
                    dir.display()
                );
            }
        }
        let sha = util::sha256_bytes(patch.content.as_bytes());
        if sha != patch.sha256 {
            bail!(
                "patch hash mismatch for {}: expected {}, got {}",
                patch.file,
                patch.sha256,
                sha
            );
        }
        // the dry run uses the same credentials as the real patch
        let dry = util::capture_unprivileged(
            "patch",
            &[
                "-p1".to_string(),
                "-N".to_string(),
                "-t".to_string(),
                "--forward".to_string(),
                "--dry-run".to_string(),
                "-i".to_string(),
                path.to_string_lossy().to_string(),
            ],
            srcdir,
            fs_creds,
        )?;
        if !dry.status.success() {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&dry.stdout),
                String::from_utf8_lossy(&dry.stderr),
            );
            if patch.optional {
                writeln!(
                    log,
                    "patch {} does not apply, skipped (optional)\n{text}",
                    patch.file
                )?;
                say!("patch    {} does not apply (optional, skipped)", patch.file);
                continue;
            }
            bail!("patch {} does not apply:\n{text}", patch.file);
        }
        util::run_unprivileged(
            "patch",
            &[
                "-p1".to_string(),
                "-N".to_string(),
                "-t".to_string(),
                "--forward".to_string(),
                "-i".to_string(),
                path.to_string_lossy().to_string(),
            ],
            srcdir,
            log,
            &[],
            fs_creds,
            &[srcdir],
        )?;
        applied.push(format!("{}@{sha}", patch.file));
        say!("patch    {} applied", patch.file);
    }
    Ok(applied)
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    recipe: &Recipe,
    recipe_path: &Path,
    paths: &Paths,
    source_path: &Path,
    dep_stores: &[PathBuf],
    local: Option<&LocalFlags>,
    allow_path_leak: bool,
    db: &crate::db::Db,
) -> Result<BuildOutcome> {
    // build descendants are stopped before the workspace is removed
    crate::stage::check_setgid_groups(paths, &recipe.install.setgid)?;
    let plan = match identify(
        recipe,
        recipe_path,
        paths,
        source_path,
        dep_stores,
        local,
        db,
    )? {
        Identified::Reuse(outcome) => return Ok(*outcome),
        Identified::Fresh(plan) => plan,
    };
    let Plan {
        mut source,
        source_sha,
        recipe_sha,
        mut log,
        log_path,
        store_path: planned_store,
        rpath: rpath_entries,
    } = plan;
    let work = tempfile::Builder::new()
        .prefix("build-")
        .tempdir_in(paths.state_dir())
        .context("creating build directory")?;
    let (scrub_paths, scrub_map, _scrub) = scrub_logger(paths, work.path(), &log_path);
    let _descendants = BuildDescendants;
    // ceilings apply to binary packages too: install_binary reads them
    log_limits(paths, work.path(), &mut log)?;
    if recipe.source.kind == "binary" {
        return install_binary(
            recipe,
            source_path,
            &mut source,
            &source_sha,
            &recipe_sha,
            paths,
            &log_path,
            work.path(),
            scrub_paths,
            &scrub_map,
            local,
            allow_path_leak,
            &mut log,
        );
    }
    validate_writable(recipe)?;
    validate_read(recipe)?;
    let deps = dependency_mounts(recipe, dep_stores)?;
    let build_root = crate::build_container::base(paths)?;
    let sandbox_policy = sandbox_policy(recipe, work.path(), build_root.as_deref(), &deps);
    let creds = build_user();
    // Unpacking and patching write the source tree with the lower privileges.
    let fs_creds = unpack_user();
    let srcdir = unpack_source(recipe, &mut source, work.path(), fs_creds, &mut log)?;
    let applied_patches = apply_patches(recipe, work.path(), &srcdir, fs_creds, &mut log)?;
    let stage = prepare_stage(work.path(), creds)?;
    let mut envs = base_envs(
        recipe,
        &stage,
        &srcdir,
        &rpath_entries,
        &planned_store,
        dep_stores,
        &deps,
    );
    let (eff_cflags, eff_rustflags) =
        compiler_envs(recipe, local, &mut envs, scrub_paths, work.path());
    refresh_makeflags(&mut envs, recipe);
    run_build_steps(
        recipe,
        &srcdir,
        &stage,
        &recipe.install.prefix,
        &envs,
        &rpath_entries,
        creds,
        &sandbox_policy,
        &mut log,
    )?;
    if fs::symlink_metadata(&stage)?.file_type().is_symlink() {
        bail!("build stage was replaced by a symlink; refusing to package it");
    }
    if let Some((uid, _gid)) = build_user() {
        util::stop_build_descendants(uid)?;
    }
    let mut allowed = vec![planned_store.clone()];
    allowed.extend(dep_stores.iter().cloned());
    check_scrubbed(&stage, scrub_paths, &scrub_map, &allowed, allow_path_leak)?;
    seal(
        SealInputs {
            recipe,
            stage: &stage,
            store_path: &planned_store,
            source_sha: &source_sha,
            recipe_sha: &recipe_sha,
            rpath: &rpath_entries,
            patches: &applied_patches,
            cflags: &eff_cflags,
            rustflags: &eff_rustflags,
            log_path: &log_path,
            paths,
        },
        &mut log,
    )
}

#[cfg(test)]
mod tests {
    use super::env::check_scrubbed;
    use super::*;
    use crate::scrub::{scrub_mappings, scrub_stage_allowing};

    /// Fails when a field of `Build` is neither hashed nor listed as excluded.
    #[test]
    fn recipe_hash_covers_every_build_field() {
        let hashed = [
            "args",
            "cflags",
            "cxxflags",
            "env",
            "isolation",
            "network",
            "patches",
            "read",
            "rustflags",
            "system",
            "writable",
        ];
        // build.jobs changes how long a build runs, not what it produces
        let excluded: [&str; 1] = ["jobs"];
        // the field list comes from the struct declaration, not from the
        // serialized form, which skips fields marked skip_serializing
        let source = include_str!("../recipe/types.rs");
        let block = source
            .split_once("pub struct Build {")
            .expect("Build is declared")
            .1
            .split_once("\n}")
            .expect("Build ends")
            .0;
        let declared: Vec<&str> = block
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub "))
            .filter_map(|rest| rest.split(':').next())
            .map(|name| name.trim())
            .collect();
        assert!(!declared.is_empty(), "no fields found in Build");
        for field in &declared {
            assert!(
                hashed.contains(field) || excluded.contains(field),
                "build.{field} is neither hashed into the store path nor listed as excluded"
            );
        }
        let value = serde_json::to_value(&sample("").build).expect("build serializes");
        let fields: Vec<&str> = value
            .as_object()
            .expect("build is an object")
            .keys()
            .map(|name| name.as_str())
            .collect();
        for field in hashed {
            assert!(
                declared.contains(&field),
                "recipe_hash hashes build.{field}, which no longer exists"
            );
            if field != "jobs" {
                assert!(fields.contains(&field), "build.{field} does not serialize");
            }
        }
    }

    #[test]
    fn a_declared_privileged_bit_changes_the_store_path() {
        let plain = recipe_hash(&sample(""), None, &[], true).expect("hash");
        let suid =
            recipe_hash(&sample("install.setuid = usr/bin/x\n"), None, &[], true).expect("hash");
        let sgid =
            recipe_hash(&sample("install.setgid = usr/bin/y:5\n"), None, &[], true).expect("hash");
        assert_ne!(plain, suid, "install.setuid did not move the store path");
        assert_ne!(plain, sgid, "install.setgid did not move the store path");
    }

    #[test]
    fn a_build_input_changes_the_store_path() {
        let base = recipe_hash(&sample(""), None, &[], true).expect("hash");
        let changed =
            recipe_hash(&sample("build.network = true\n"), None, &[], true).expect("hash");
        assert_ne!(base, changed, "a build input left the store path unchanged");
    }

    fn sample(extra: &str) -> crate::recipe::Recipe {
        let text = format!(
            "package.name = pkg
             package.version = 1.0
             source.file = pkg-1.0.tar.gz
             source.sha256 = {}
             build.system = custom
             install.prefix = /usr
{extra}",
            "a".repeat(64)
        );
        crate::recipe::Recipe::parse(&text).expect("sample recipe parses")
    }

    #[test]
    fn prose_and_core_count_do_not_move_the_store_path() {
        let plain = sample("");
        let described = sample(
            "package.description = a longer sentence
",
        );
        let pinned = sample(
            "build.jobs = 3
",
        );

        let hash =
            |recipe: &crate::recipe::Recipe| recipe_hash(recipe, None, &[], true).expect("hash");
        assert_eq!(
            hash(&plain),
            hash(&described),
            "a description changed the store path"
        );
        assert_eq!(
            hash(&plain),
            hash(&pinned),
            "a core count changed the store path"
        );
    }

    #[test]
    fn compiler_flags_still_move_the_store_path() {
        let plain = sample("");
        let flags = sample(
            "build.cflags = -O3
",
        );
        let hash =
            |recipe: &crate::recipe::Recipe| recipe_hash(recipe, None, &[], true).expect("hash");
        assert_ne!(
            hash(&plain),
            hash(&flags),
            "a flag change kept the store path"
        );
    }

    #[test]
    fn scrub_stage_rewrites_text_and_reports_binaries() {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(root.path());
        let work = root.path().join("var/lib/portalis/build-STAGE");
        let stage = work.join("stage");
        std::fs::create_dir_all(stage.join("usr/share")).expect("stage dir");
        let mappings = scrub_mappings(&work, &paths);

        let config = stage.join("usr/share/buildinfo.conf");
        std::fs::write(&config, format!("dir={}/src\n", work.display())).expect("write config");
        let binary = stage.join("usr/share/tool");
        let mut payload = b"\x7fELF".to_vec();
        payload.extend_from_slice(format!("{}/src", work.display()).as_bytes());
        std::fs::write(&binary, &payload).expect("write binary");

        let report = scrub_stage_allowing(&stage, &mappings, &[]).expect("scrub stage");
        let leaked = report.leaked;

        assert_eq!(leaked, 1, "the compiled file should be reported");
        let text = std::fs::read_to_string(&config).expect("read config");
        assert!(text.contains("/build/src"), "{text}");
        assert!(!text.contains("build-STAGE"), "{text}");
        assert_eq!(std::fs::read(&binary).expect("read binary"), payload);
    }

    #[test]
    fn a_store_runpath_is_not_a_builder_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(root.path());
        let work = root.path().join("var/lib/portalis/build-RPATH");
        let stage = work.join("stage");
        std::fs::create_dir_all(stage.join("usr/bin")).expect("stage dir");
        let store = root.path().join("usr/portalis/packages/git-1.0");
        let binary = stage.join("usr/bin/git");
        let mut payload = b"\x7fELF".to_vec();
        payload.extend_from_slice(format!("{}/usr/lib", store.display()).as_bytes());
        std::fs::write(&binary, &payload).expect("binary");
        let mappings = scrub_mappings(&work, &paths);

        let report = scrub_stage_allowing(&stage, &mappings, std::slice::from_ref(&store))
            .expect("scrub stage");
        assert_eq!(report.leaked, 0, "a store runpath was reported as a leak");
    }

    #[test]
    fn scrub_file_replaces_builder_paths() {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(root.path());
        let work = root.path().join("var/lib/portalis/build-ABC123");
        std::fs::create_dir_all(&work).expect("work dir");
        let log = root.path().join("build.log");
        std::fs::write(
            &log,
            format!(
                "cc {}/src/main.c -o {}/stage/usr/bin/tool\n",
                work.display(),
                work.display()
            ),
        )
        .expect("write log");

        crate::scrub::scrub_file(&log, &scrub_mappings(&work, &paths)).expect("scrub");

        let text = std::fs::read_to_string(&log).expect("read log");
        assert!(!text.contains("build-ABC123"), "{text}");
        assert!(text.contains("/build/src/main.c"), "{text}");
        assert!(text.contains("/build/stage/usr/bin/tool"), "{text}");
    }

    #[test]
    fn source_scrub_respects_the_path_leak_override() {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(root.path());
        let work = root.path().join("var/lib/portalis/build-ABC123");
        let stage = work.join("stage");
        std::fs::create_dir_all(stage.join("usr/bin")).expect("stage dir");
        let file = stage.join("usr/bin/tool");
        let mut payload = b"\x7fELF".to_vec();
        payload.extend_from_slice(work.to_string_lossy().as_bytes());
        std::fs::write(&file, payload).expect("binary");
        let map = scrub_mappings(&work, &paths);

        let refused = check_scrubbed(&stage, true, &map, &[], false);
        assert!(refused.is_err(), "a source build accepted a leaked path");
        let allowed = check_scrubbed(&stage, true, &map, &[], true);
        assert!(allowed.is_ok(), "the path leak override was ignored");
    }

    #[test]
    fn scrub_mappings_replace_the_most_specific_prefix() {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(root.path());
        let work = root.path().join("var/lib/portalis/build-XYZ");
        let mappings = scrub_mappings(&work, &paths);
        assert_eq!(mappings[0].0, work.to_string_lossy());
        assert_eq!(mappings[0].1, "/build");
        let root_mapping = mappings
            .iter()
            .find(|(from, _)| from == &root.path().to_string_lossy().to_string())
            .expect("root mapping");
        assert_eq!(root_mapping.1, "");
        assert!(mappings.len() >= 2);
    }

    #[test]
    fn prune_logs_keeps_the_newest_logs_within_the_limit() {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(root.path());
        std::fs::create_dir_all(paths.logs()).expect("logs dir");
        let now = std::time::SystemTime::now();
        for index in 0..util::BUILD_LOGS_PER_PACKAGE {
            let path = paths.logs().join(format!("alpha-1.0-{index:04}.log"));
            std::fs::write(&path, b"x").expect("write log");
            let stamp = now
                - std::time::Duration::from_secs((util::BUILD_LOGS_PER_PACKAGE - index + 1) as u64);
            let times = std::fs::FileTimes::new().set_modified(stamp);
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open log")
                .set_times(times)
                .expect("set times");
        }
        let current = paths.logs().join("alpha-1.0-current.log");
        std::fs::write(&current, b"x").expect("write log");

        prune_logs(&paths, "alpha", "1.0", util::BUILD_LOGS_PER_PACKAGE);

        let left = std::fs::read_dir(paths.logs()).expect("read logs").count();
        assert_eq!(left, util::BUILD_LOGS_PER_PACKAGE);
        assert!(current.exists(), "the current build log was pruned");
        assert!(!paths.logs().join("alpha-1.0-0000.log").exists());
    }

    #[test]
    fn rejects_special_files_in_the_build_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo available");
        assert!(status.success());
        let collected = collect_files(dir.path());
        assert!(collected.is_err());
    }
}
