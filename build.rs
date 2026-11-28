use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;

fn value(manifest: &str, key: &str) -> String {
    let prefix = format!("{key} = \"");
    manifest
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_default()
        .to_string()
}

fn main() {
    println!("cargo:rerun-if-changed=image/manifest.toml");
    println!("cargo:rerun-if-env-changed=PORTALIS_ROOTFS_IMAGE");
    println!("cargo:rustc-check-cfg=cfg(portalis_rootfs)");

    let manifest = fs::read_to_string("image/manifest.toml").unwrap_or_default();
    let id = value(&manifest, "id");
    let version = value(&manifest, "version");
    let profile = value(&manifest, "profile");
    let distro = value(&manifest, "distro");
    let distro_version = value(&manifest, "distro_version");
    let codename = value(&manifest, "codename");
    let glibc = value(&manifest, "glibc");
    let arch = match env::var("TARGET").unwrap_or_default() {
        target if target.contains("aarch64") => "aarch64",
        target if target.contains("x86_64") => "x86_64",
        _ => "unknown",
    };
    let package_version = env::var("CARGO_PKG_VERSION").unwrap_or_default();

    let embedded_path = env::var_os("PORTALIS_ROOTFS_IMAGE").map(PathBuf::from);
    let embedded = embedded_path.is_some();
    if embedded && manifest.trim().is_empty() {
        panic!("PORTALIS_ROOTFS_IMAGE is set but image/manifest.toml is missing");
    }
    if embedded {
        println!("cargo:rustc-cfg=portalis_rootfs");
    }
    let (_bytes, sha256) = match embedded_path.as_ref() {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = fs::read(path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let digest = Sha256::digest(&bytes);
            let sha = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("rootfs.tar.zst");
            fs::write(&out, &bytes).expect("copying the rootfs image");
            (true, sha)
        }
        None => (false, String::new()),
    };

    let rootfs_version = if embedded {
        format!(
            "rootfs   {id} {version} ({profile})\ndistro   {distro} {distro_version} ({codename})\narch     {arch}\nglibc    {glibc}\nsha256   {sha256}"
        )
    } else {
        "rootfs   none".to_string()
    };
    let long_version = format!("{package_version}\n{rootfs_version}");

    let mut out = String::new();
    out.push_str("pub const EMBEDDED: bool = ");
    out.push_str(if embedded { "true" } else { "false" });
    out.push_str(";\n");
    out.push_str(&format!("pub const SHA256: &str = {:?};\n", sha256));
    out.push_str(&format!(
        "pub const LONG_VERSION: &str = {:?};\n",
        long_version
    ));
    if embedded {
        out.push_str(
            "pub static IMAGE: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/rootfs.tar.zst\"));\n",
        );
    } else {
        out.push_str("pub static IMAGE: &[u8] = &[];\n");
    }
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("rootfs_meta.rs");
    fs::write(out_path, out).expect("writing rootfs metadata");
}
