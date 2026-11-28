use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs;
use std::path::Path;

const PRIVATE_KEY: &str = "signing.key";
pub fn sign_bytes(data: &[u8], paths: &crate::Paths) -> Result<Option<String>> {
    let key_path = paths.etc().join(PRIVATE_KEY);
    if !key_path.exists() {
        return Ok(None);
    }
    require_private_key(&key_path)?;
    let bytes = fs::read(&key_path)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("signing key has wrong length")?;
    let signing = SigningKey::from_bytes(&arr);
    let sig = signing.sign(data);
    Ok(Some(hex(&sig.to_bytes())))
}

pub fn verify_bytes(data: &[u8], signature_hex: &str, trusted_dir: &Path) -> Result<bool> {
    let sig_bytes = unhex(signature_hex)?;
    let sig = Signature::from_slice(&sig_bytes).context("malformed signature")?;
    if !trusted_dir.exists() {
        return Ok(false);
    }
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(trusted_dir)
            .with_context(|| format!("reading {}", trusted_dir.display()))?;
        if !meta.file_type().is_dir() || meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
            bail!(
                "{} is not a root-owned directory writable only by root; trusted keys are refused",
                trusted_dir.display()
            );
        }
    }
    for entry in fs::read_dir(trusted_dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading the trusted key {}", path.display()))?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            continue;
        }
        require_trusted_key(&path, &meta)?;
        let key_bytes = fs::read(&path)
            .with_context(|| format!("reading the trusted key {}", path.display()))?;
        let arr: [u8; 32] = match key_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                eprintln!(
                    "warning: {} is not a 32-byte Ed25519 public key; skipped",
                    path.display()
                );
                continue;
            }
        };
        let key = VerifyingKey::from_bytes(&arr)
            .with_context(|| format!("{} is not a valid Ed25519 key", path.display()))?;
        if key.verify_strict(data, &sig).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// True when the directory holds at least one key file. A missing directory means
/// "no trusted keys"; a directory that cannot be read is an error.
pub fn has_trusted_keys(dir: &Path) -> Result<bool> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("reading {}", dir.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", dir.display()));
            }
        };
        let symlink = entry
            .file_type()
            .map(|kind| kind.is_symlink())
            .unwrap_or(true);
        if !symlink && meta.is_file() && meta.len() == 32 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Refuses a trusted public key that another account can replace.
fn require_trusted_key(path: &Path, meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if meta.uid() != 0 {
        bail!(
            "{} is owned by uid {}, not root; it is refused as a trusted key",
            path.display(),
            meta.uid()
        );
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        bail!(
            "{} is writable beyond its owner (mode {:03o}); it is refused as a trusted key",
            path.display(),
            mode
        );
    }
    Ok(())
}

/// Refuses a signing key that other accounts can read.
fn require_private_key(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("signing key {} disappeared", path.display())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        bail!("signing key {} is not a regular file", path.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    let owner = std::os::unix::fs::MetadataExt::uid(&meta);
    if owner != 0 {
        bail!(
            "{} is owned by uid {owner}, not root; a key reachable by another account \
             cannot sign (chown root:root {})",
            path.display(),
            path.display()
        );
    }
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable beyond its owner (mode {:03o}); signing is refused until it is 600 \
             (run chmod 600 {})",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("odd length hex signature");
    }
    let chars: Vec<char> = text.chars().collect();
    if !chars.iter().all(|c| c.is_ascii_hexdigit()) {
        bail!("signature is not hexadecimal");
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in chars.chunks(2) {
        let s: String = pair.iter().collect();
        out.push(u8::from_str_radix(&s, 16).with_context(|| format!("bad hex byte '{s}'"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_hex_byte_must_be_hexadecimal() {
        assert!(unhex("+f").is_err());
        assert!(unhex("0f").is_ok());
        assert!(unhex("0f0").is_err());
    }

    #[test]
    fn a_world_writable_trusted_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = key.sign(b"payload");
        let public = key.verifying_key().to_bytes();
        let path = dir.path().join("trusted.pub");
        fs::write(&path, public).expect("write key");
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("writable key mode");
        let error = verify_bytes(b"payload", &hex(&signature.to_bytes()), dir.path())
            .expect_err("world-writable key was accepted");
        assert!(
            error.to_string().contains("writable"),
            "unexpected error: {error}"
        );
    }
}
