//! The static root used for package builds.
use anyhow::Result;
use std::path::PathBuf;

use crate::paths::Paths;

/// Returns the cached static build root, when this build embeds one.
pub fn base(paths: &Paths) -> Result<Option<PathBuf>> {
    crate::rootfs::prepare(paths)
}

#[cfg(all(test, portalis_rootfs))]
mod tests {
    use super::*;

    #[test]
    fn the_build_root_is_a_static_busybox_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::at(dir.path());
        let base = base(&paths).expect("prepare").expect("embedded build root");
        assert!(base.join("busybox").is_file());
        assert_eq!(
            std::fs::read_link(base.join("bin/sh")).expect("busybox shell link"),
            std::path::PathBuf::from("/busybox")
        );
        assert!(base.join("usr/bin/bash").exists());
    }
}
