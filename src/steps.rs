//! Dispatching a recipe's build steps for the supported build systems.

use crate::recipe::Recipe;
use crate::util;
use anyhow::{anyhow, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Returns the parallelism the recipe pins, or every core when it pins none.
fn parallel_jobs(recipe: &Recipe) -> usize {
    recipe
        .build
        .jobs
        .parse::<usize>()
        .ok()
        .filter(|count| *count > 0)
        .unwrap_or_else(util::jobs)
}

#[allow(clippy::too_many_arguments)]
fn run_autotools(
    recipe: &Recipe,
    srcdir: &Path,
    stage_s: &str,
    prefix_s: &str,
    envs: &[(&str, String)],
    creds: Option<(u32, u32)>,
    policy: &util::SandboxPolicy,
    log: &mut fs::File,
) -> Result<()> {
    let mut args = vec![format!("--prefix={prefix_s}")];
    args.extend(recipe.build.args.iter().cloned());
    util::run_logged_as("./configure", &args, srcdir, log, envs, creds, Some(policy))?;
    util::run_logged_as(
        "make",
        &[format!("-j{}", parallel_jobs(recipe))],
        srcdir,
        log,
        envs,
        creds,
        Some(policy),
    )?;
    util::run_logged_as(
        "make",
        &["install".to_string(), format!("DESTDIR={stage_s}")],
        srcdir,
        log,
        envs,
        creds,
        Some(policy),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_meson(
    recipe: &Recipe,
    srcdir: &Path,
    stage_s: &str,
    prefix_s: &str,
    envs: &[(&str, String)],
    rpath_entries: &[String],
    creds: Option<(u32, u32)>,
    policy: &util::SandboxPolicy,
    log: &mut fs::File,
) -> Result<()> {
    let build_dir = srcdir.join("build-portalis");
    let mut setup = vec![
        "setup".to_string(),
        build_dir.to_string_lossy().to_string(),
        format!("--prefix={prefix_s}"),
        "--buildtype=release".to_string(),
        "--wrap-mode=nodownload".to_string(),
    ];
    if !rpath_entries.is_empty() {
        let flags = rpath_entries
            .iter()
            .map(|p| format!("-Wl,-rpath,{p}"))
            .collect::<Vec<_>>()
            .join(" ")
            + " -Wl,--enable-new-dtags";
        setup.push(format!("-Dc_link_args={flags}"));
        setup.push(format!("-Dcpp_link_args={flags}"));
    }
    setup.extend(recipe.build.args.iter().cloned());
    util::run_logged_as("meson", &setup, srcdir, log, envs, creds, Some(policy))?;
    let jobs = format!("-j{}", parallel_jobs(recipe));
    util::run_logged_as(
        "ninja",
        &[
            "-C".to_string(),
            build_dir.to_string_lossy().to_string(),
            jobs.clone(),
        ],
        srcdir,
        log,
        envs,
        creds,
        Some(policy),
    )?;
    util::run_logged_as(
        "env",
        &[
            format!("DESTDIR={stage_s}"),
            "ninja".to_string(),
            "-C".to_string(),
            build_dir.to_string_lossy().to_string(),
            jobs,
            "install".to_string(),
        ],
        srcdir,
        log,
        envs,
        creds,
        Some(policy),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_cargo(
    recipe: &Recipe,
    srcdir: &Path,
    stage_s: &str,
    prefix_s: &str,
    envs: &[(&str, String)],
    creds: Option<(u32, u32)>,
    policy: &util::SandboxPolicy,
    log: &mut fs::File,
) -> Result<()> {
    // checked before the build step runs
    if !cargo_declares_a_binary(srcdir) {
        anyhow::bail!(
            "build.system = cargo needs a binary crate: no src/main.rs and no [[bin]] in Cargo.toml; use system = custom with an explicit install step"
        );
    }
    let mut args = vec!["build".to_string(), "--release".to_string()];
    args.extend(recipe.build.args.iter().cloned());
    let mut cargo_env = envs.to_vec();
    cargo_env.push(("CARGO_BUILD_JOBS", parallel_jobs(recipe).to_string()));
    util::run_logged_as("cargo", &args, srcdir, log, &cargo_env, creds, Some(policy))?;
    let root = format!("{stage_s}{prefix_s}");
    let (install_args, skipped) = install_arguments(&root, &recipe.build.args);
    for argument in skipped {
        writeln!(log, "note     {argument} is not passed to cargo install")?;
    }
    util::run_logged_as(
        "cargo",
        &install_args,
        srcdir,
        log,
        &cargo_env,
        creds,
        Some(policy),
    )?;
    writeln!(log, "cargo install finished into {stage_s}")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_build_steps(
    recipe: &Recipe,
    srcdir: &Path,
    stage: &Path,
    prefix: &str,
    envs: &[(&str, String)],
    rpath_entries: &[String],
    creds: Option<(u32, u32)>,
    sandbox_policy: &util::SandboxPolicy,
    log: &mut fs::File,
) -> Result<()> {
    util::set_jobs(parallel_jobs(recipe));
    let prefix_s = prefix.to_string();
    let stage_s = stage.to_string_lossy().to_string();
    match recipe.build.system.as_str() {
        "autotools" => run_autotools(
            recipe,
            srcdir,
            &stage_s,
            &prefix_s,
            envs,
            creds,
            sandbox_policy,
            log,
        ),
        "meson" => run_meson(
            recipe,
            srcdir,
            &stage_s,
            &prefix_s,
            envs,
            rpath_entries,
            creds,
            sandbox_policy,
            log,
        ),
        "cargo" => run_cargo(
            recipe,
            srcdir,
            &stage_s,
            &prefix_s,
            envs,
            creds,
            sandbox_policy,
            log,
        ),
        "custom" => {
            for command in &recipe.build.args {
                util::run_logged_as(
                    "sh",
                    &["-c".to_string(), command.clone()],
                    srcdir,
                    log,
                    envs,
                    creds,
                    Some(sandbox_policy),
                )?;
            }
            Ok(())
        }
        other => Err(anyhow!("unsupported build system {other}")),
    }
}

/// The flag an argument carries, without its value.
fn flag_of(argument: &str) -> &str {
    argument.split('=').next().unwrap_or(argument)
}

/// True when the argument is a flag that takes a value, repeatable per cargo.
fn takes_value(argument: &str) -> bool {
    const TAKES_VALUE: [&str; 7] = [
        "--features",
        "-F",
        "--target",
        "--config",
        "--profile",
        "--package",
        "-p",
    ];
    TAKES_VALUE.contains(&flag_of(argument))
}

/// True when `cargo install` accepts the argument.
fn install_accepts(argument: &str) -> bool {
    const FLAGS: [&str; 3] = ["--no-default-features", "--all-features", "--offline"];
    takes_value(argument) || FLAGS.contains(&flag_of(argument))
}

/// `cargo install` arguments: the baseline plus the recipe flags it accepts and
/// does not already carry. The second value lists what was dropped.
fn install_arguments(root: &str, recipe_args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut kept: Vec<String> = vec![
        "install".to_string(),
        "--path".to_string(),
        ".".to_string(),
        "--root".to_string(),
        root.to_string(),
        "--locked".to_string(),
        "--force".to_string(),
        "--no-track".to_string(),
    ];
    let mut skipped = Vec::new();
    for argument in recipe_args {
        // Cargo merges repeated value flags (--features=a --features=b); only a
        // boolean that is already present counts as a duplicate.
        let duplicate =
            !takes_value(argument) && kept.iter().any(|kept| flag_of(kept) == flag_of(argument));
        if !install_accepts(argument) || duplicate {
            skipped.push(argument.clone());
            continue;
        }
        kept.push(argument.clone());
    }
    (kept, skipped)
}

/// True when the crate ships a binary: `src/main.rs`, a file in `src/bin`, or a
/// `[[bin]]` section.
fn cargo_declares_a_binary(srcdir: &std::path::Path) -> bool {
    if srcdir.join("src/main.rs").exists() {
        return true;
    }
    if let Ok(entries) = std::fs::read_dir(srcdir.join("src/bin")) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_file() && name.ends_with(".rs") {
                return true;
            }
            if path.is_dir() && path.join("main.rs").exists() {
                return true;
            }
        }
    }
    std::fs::read_to_string(srcdir.join("Cargo.toml"))
        .map(|text| text.lines().any(|line| line.trim() == "[[bin]]"))
        .unwrap_or(false)
}

#[cfg(test)]
mod cargo_install_tests {
    use super::{cargo_declares_a_binary, install_accepts, install_arguments};

    #[test]
    fn a_bin_section_is_recognised() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\n\n[[bin]]\nname = \"x\"\npath = \"src/x.rs\"\n",
        )
        .expect("manifest");
        assert!(cargo_declares_a_binary(dir.path()));
    }

    #[test]
    fn a_file_in_src_bin_counts_as_a_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src/bin")).expect("src/bin");
        std::fs::write(dir.path().join("src/bin/tool.rs"), "fn main() {}\n").expect("tool");
        assert!(cargo_declares_a_binary(dir.path()));
    }

    #[test]
    fn a_build_only_flag_is_not_passed_to_install() {
        assert!(install_accepts("--features=extra"));
        assert!(install_accepts("--offline"));
        assert!(!install_accepts("--target-dir=/tmp/x"));
        assert!(!install_accepts("--release"));
        assert!(!install_accepts("--locked"));
    }

    #[test]
    fn install_tracks_nothing_and_carries_one_locked() {
        let (args, skipped) = install_arguments("/tmp/root", &["--locked".to_string()]);
        assert_eq!(args.iter().filter(|a| *a == "--locked").count(), 1);
        assert!(args.iter().any(|a| a == "--no-track"));
        assert_eq!(skipped, vec!["--locked".to_string()]);
    }

    #[test]
    fn repeated_feature_flags_are_kept() {
        let (args, skipped) = install_arguments(
            "/tmp/root",
            &["--features=a".to_string(), "--features=b".to_string()],
        );
        assert_eq!(
            args.iter().filter(|a| a.starts_with("--features=")).count(),
            2,
            "cargo merges repeated feature flags, both must survive: {args:?}"
        );
        assert!(skipped.is_empty());
    }

    #[test]
    fn a_recipe_feature_flag_reaches_install() {
        let (args, skipped) = install_arguments("/tmp/root", &["--features=extra".to_string()]);
        assert!(args.iter().any(|a| a == "--features=extra"));
        assert!(skipped.is_empty());
    }

    #[test]
    fn a_library_without_bins_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n")
            .expect("manifest");
        assert!(!cargo_declares_a_binary(dir.path()));
    }
}
