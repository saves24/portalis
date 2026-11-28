use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// File extensions and defaults that define the on-disk contract.
pub const RECIPE_EXTENSION: &str = "port";
pub const CONFIG_NAME: &str = "config.port";
pub const DEFAULT_PREFIX: &str = "/usr";
pub const DEFAULT_BUILD_SYSTEM: &str = "autotools";
/// Absolute location of the configuration directory, for callers that have no
/// `Paths` (the build sandbox masks it).
pub const ETC_DIR: &str = "/etc/portalis";
/// Store directory relative to a filesystem root.
pub const STORE_DIR: &str = "usr/portalis/packages";
/// Store directory on the live system.
pub const STORE_PATH: &str = "/usr/portalis/packages";
/// The systemd unit that applies deferred activations.
pub const SHUTDOWN_UNIT: &str = "portalis.service";

/// True when the path names a recipe file.
pub fn is_recipe(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some(RECIPE_EXTENSION)
}

/// All filesystem locations used by Portalis.
#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self::new()
    }
}

fn ensure_directory(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("refusing to traverse symlink {}", current.display())
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => bail!("{} is not a directory", current.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(create) if create.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create) => {
                        return Err(create)
                            .with_context(|| format!("creating {}", current.display()));
                    }
                }
                let meta = std::fs::symlink_metadata(&current)
                    .with_context(|| format!("reading {}", current.display()))?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    bail!("{} is not a directory", current.display());
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", current.display()));
            }
        }
    }
    Ok(())
}

fn close_directory(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("closing {}", path.display()))
}

impl Paths {
    pub fn new() -> Self {
        Self {
            root: root_from(std::env::var_os("PORTALIS_ROOT")),
        }
    }

    /// Builds a path set rooted at `root`, used by tests and sandboxes.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Prepends the configured root to an absolute path inside it.
    pub fn under_path(&self, p: &std::path::Path) -> PathBuf {
        if self.root == Path::new("/") {
            p.to_path_buf()
        } else {
            self.root.join(p.to_string_lossy().trim_start_matches('/'))
        }
    }

    fn under(&self, p: &str) -> PathBuf {
        if self.root == Path::new("/") {
            PathBuf::from(p)
        } else {
            self.root.join(p.trim_start_matches('/'))
        }
    }

    pub fn etc(&self) -> PathBuf {
        self.under(ETC_DIR)
    }

    pub fn config_file(&self) -> PathBuf {
        self.etc().join(CONFIG_NAME)
    }

    pub fn recipe_file(&self, name: &str) -> PathBuf {
        self.recipes().join(format!("{name}.{RECIPE_EXTENSION}"))
    }

    pub fn recipes(&self) -> PathBuf {
        self.etc().join("packages")
    }

    pub fn trusted_keys(&self) -> PathBuf {
        self.etc().join("trusted-keys")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.under("/var/lib/portalis")
    }

    pub fn shutdown_unit(&self) -> PathBuf {
        self.under(&format!(
            "/etc/systemd/system/shutdown.target.wants/{SHUTDOWN_UNIT}"
        ))
    }

    pub fn last_good(&self) -> PathBuf {
        self.state_dir().join("last-good.json")
    }

    pub fn db_dir(&self) -> PathBuf {
        self.under("/var/db/portalis")
    }

    pub fn db_file(&self) -> PathBuf {
        self.db_dir().join("db.sqlite")
    }

    pub fn store(&self) -> PathBuf {
        self.under(STORE_PATH)
    }

    pub fn store_etc(&self) -> PathBuf {
        self.under("/usr/portalis/etc")
    }

    pub fn appconfig(&self) -> PathBuf {
        self.under("/usr/portalis/appconfig")
    }

    pub fn logs(&self) -> PathBuf {
        self.under("/var/log/portalis/builds")
    }

    /// Target root where packages get activated (symlink farm).
    pub fn target_root(&self) -> PathBuf {
        self.under("/")
    }

    pub fn ensure_layout(&self) -> Result<()> {
        for dir in [
            self.etc(),
            self.recipes(),
            self.trusted_keys(),
            self.db_dir(),
            self.state_dir(),
            self.store(),
            self.store_etc(),
            self.logs(),
            self.appconfig(),
        ] {
            ensure_directory(&dir)?;
        }
        // recipe and ledger directories 0750; the state directory 0751
        for (dir, mode) in [
            (self.etc(), 0o750),
            (self.db_dir(), 0o750),
            (self.state_dir(), 0o751),
        ] {
            close_directory(&dir, mode)?;
        }
        Ok(())
    }

    pub fn package_store_path(&self, name: &str, version: &str, recipe_sha: &str) -> PathBuf {
        let short = &recipe_sha[..12.min(recipe_sha.len())];
        self.store().join(format!("{name}-{version}-{short}"))
    }
}

/// Root used by every path. An empty setting means the real root, not the
/// working directory.
fn root_from(value: Option<std::ffi::OsString>) -> PathBuf {
    value
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_root_setting_means_the_real_root() {
        assert_eq!(root_from(None), PathBuf::from("/"));
        assert_eq!(root_from(Some("".into())), PathBuf::from("/"));
        assert_eq!(
            root_from(Some("/tmp/sandbox".into())),
            PathBuf::from("/tmp/sandbox")
        );
    }

    #[test]
    fn a_symlinked_layout_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, root.join("etc")).expect("etc link");
        let paths = Paths::at(&root);
        let error = paths
            .ensure_layout()
            .expect_err("symlinked layout accepted");
        assert!(format!("{error}").contains("symlink"), "{error:#}");
    }
}
