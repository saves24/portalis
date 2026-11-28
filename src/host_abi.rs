//! A stable fingerprint of the host ABI and compiler inputs used by builds.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::process::Command;

fn command_output(program: &str, args: &[&str]) -> Vec<u8> {
    let Some(program) = crate::util::trusted_program(program) else {
        return Vec::new();
    };
    Command::new(program)
        .env_clear()
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
        .unwrap_or_default()
}

/// Returns a hex digest of the host distribution, architecture, loader and
/// compiler versions.
pub fn fingerprint() -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(std::env::consts::ARCH.as_bytes());
    hasher.update(b"\0");
    hasher.update(
        std::fs::read("/etc/os-release")
            .with_context(|| "reading /etc/os-release for the host ABI")?,
    );
    hasher.update(b"\0");
    for (name, program, args) in [
        ("uname-m", "uname", &["-m"][..]),
        ("uname-r", "uname", &["-r"][..]),
        ("ldd", "ldd", &["--version"][..]),
        ("cc", "cc", &["--version"][..]),
        ("cxx", "c++", &["--version"][..]),
        ("rustc", "rustc", &["--version"][..]),
    ] {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(command_output(program, args));
        hasher.update(b"\0");
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
