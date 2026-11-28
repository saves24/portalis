//! Generation retention, and the anchor that names the last good generation.

use crate::paths::Paths;
use anyhow::{Context, Result};
use std::io::Write;

/// Generation ids referenced by the boot and recovery anchors.
pub(super) fn protected_generations(paths: &Paths) -> Vec<i64> {
    [paths.last_good()]
        .iter()
        .filter_map(|path| {
            let raw = std::fs::read_to_string(path).ok()?;
            let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
            doc.get("generation")?.as_i64()
        })
        .collect()
}

/// `[maintenance] retain_generations`, default five.
const DEFAULT_RETAIN_GENERATIONS: usize = 5;

pub(super) fn generations_to_keep(paths: &Paths) -> usize {
    let file = paths.config_file();
    match std::fs::read_to_string(&file) {
        Ok(text) => match crate::util::Conf::parse(&text) {
            Ok(conf) => conf
                .get("maintenance.retain_generations")
                .and_then(|value| value.parse::<usize>().ok())
                .map(|value| value.clamp(1, 1000))
                .unwrap_or(DEFAULT_RETAIN_GENERATIONS),
            Err(error) => {
                eprintln!(
                    "warning: cannot parse {}: {error}; keeping {DEFAULT_RETAIN_GENERATIONS} generations",
                    file.display()
                );
                DEFAULT_RETAIN_GENERATIONS
            }
        },
        Err(_) => DEFAULT_RETAIN_GENERATIONS,
    }
}

pub(super) fn write_anchor(
    paths: &Paths,
    generation: i64,
    package: &str,
    files: &[crate::recipe::ManifestFile],
) -> Result<()> {
    let doc = serde_json::json!({
        "generation": generation,
        "package": package,
        "created": crate::now(),
        "files": files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(),
        "rollback": format!("moirse rollback {generation}"),
    });
    let bytes = serde_json::to_vec_pretty(&doc)?;
    let path = paths.last_good();
    let sequence = ANCHOR_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = path.with_file_name(format!(".last-good-{}-{sequence}", std::process::id()));
    let result = (|| -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("writing {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing {}", temporary.display()))?;
        drop(file);
        std::fs::rename(&temporary, &path).with_context(|| format!("moving {}", path.display()))?;
        crate::util::sync_dir(&paths.state_dir())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

static ANCHOR_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
