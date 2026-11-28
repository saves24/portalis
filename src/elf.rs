//! ELF inspection: dependencies, run paths and the edges recorded for a package.

use crate::db::Db;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) const VDSO_SONAMES: [&str; 2] = ["linux-vdso.so.1", "linux-gate.so.1"];

pub(crate) fn is_vdso(lib: &str) -> bool {
    VDSO_SONAMES.contains(&lib)
}

pub(crate) fn ldconfig_libraries() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Some(ldconfig) = crate::util::trusted_program("ldconfig") else {
        return map;
    };
    let Ok(output) = Command::new(ldconfig).env_clear().arg("-p").output() else {
        return map;
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let line = line.trim();
        let Some((name, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some((_, path)) = rest.rsplit_once("=> ") else {
            continue;
        };
        map.entry(name.to_string())
            .or_insert_with(|| path.trim().to_string());
    }
    map
}

/// Fields the manager reads from an ELF file.
pub(crate) struct ElfInfo {
    pub(crate) bits: u8,
    pub(crate) needed: Vec<String>,
    pub(crate) runpath: Option<Vec<String>>,
    pub(crate) soname: Option<String>,
    pub(crate) interpreter: Option<String>,
}

/// A binary above this size is not read.
const ELF_READ_LIMIT: u64 = 64 * 1024 * 1024;

pub(crate) fn elf_info(path: &Path) -> Option<ElfInfo> {
    // A file above the size ceiling is left unread and answers "unknown".
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let size = metadata.len();
    if size > ELF_READ_LIMIT {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    let elf = goblin::elf::Elf::parse(&data).ok()?;
    let needed = elf.libraries.iter().map(|name| name.to_string()).collect();
    let mut runpath = None;
    let mut soname = None;
    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            let value = elf.dynstrtab.get_at(entry.d_val as usize);
            match entry.d_tag {
                goblin::elf::dynamic::DT_RUNPATH | goblin::elf::dynamic::DT_RPATH => {
                    runpath = value.map(|text| text.split(':').map(String::from).collect());
                }
                goblin::elf::dynamic::DT_SONAME => {
                    soname = value.map(String::from);
                }
                _ => {}
            }
        }
    }
    Some(ElfInfo {
        bits: if elf.is_64 { 64 } else { 32 },
        needed,
        runpath,
        soname,
        interpreter: elf.interpreter.map(|value| value.to_string()),
    })
}

pub(crate) fn elf_needed(path: &Path) -> Option<(Vec<String>, Vec<PathBuf>, u8)> {
    let info = elf_info(path)?;
    let runpath = info
        .runpath
        .unwrap_or_default()
        .into_iter()
        .map(PathBuf::from)
        .collect();
    Some((info.needed, runpath, info.bits))
}

pub(crate) fn elf_interpreter(path: &Path) -> Option<String> {
    let info = elf_info(path)?;
    let value = info.interpreter?;
    Path::new(&value)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

pub(crate) fn record_sonames(db: &Db, pkg: &str) -> Result<()> {
    let mut sonames = Vec::new();
    for (_path, _sha, target, _mode) in db.files_of(pkg)? {
        if let Some(info) = elf_info(Path::new(&target)) {
            if let Some(soname) = info.soname {
                sonames.push((soname, info.bits));
            }
        }
    }
    db.set_sonames(pkg, &sonames)
}

pub(crate) fn record_needs(db: &Db, pkg: &str) -> Result<()> {
    let mut wanted: Vec<(String, u8)> = Vec::new();
    for (_path, _sha, target, _mode) in db.files_of(pkg)? {
        let Some(info) = elf_info(Path::new(&target)) else {
            continue;
        };
        for needed in info.needed {
            if !wanted
                .iter()
                .any(|(name, bits)| name == &needed && *bits == info.bits)
            {
                wanted.push((needed, info.bits));
            }
        }
    }
    let mut needs = Vec::new();
    for (soname, bits) in wanted {
        if soname.starts_with('/') {
            continue;
        }
        if let Some(owner) = db.soname_owner(&soname, bits)? {
            if owner != pkg {
                needs.push((owner, soname, bits));
            }
        }
    }
    db.set_needs(pkg, &needs)
}

pub(crate) fn record_elf_links(db: &Db, pkg: &str) -> Result<()> {
    db.in_transaction(|db| {
        record_sonames(db, pkg)?;
        record_needs(db, pkg)
    })
}

pub(crate) fn host_library_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = ldconfig_libraries()
        .values()
        .filter_map(|path| Path::new(path).canonicalize().ok())
        .filter_map(|path| path.parent().map(|dir| dir.to_path_buf()))
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

pub(crate) fn runpath_is_isolated(store: &Path, entry: &str, host_dirs: &[PathBuf]) -> bool {
    if entry.starts_with('$') {
        return !entry.split('/').any(|part| part == "..");
    }
    let entry = Path::new(entry);
    if !entry.is_absolute()
        || entry
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return false;
    }
    if entry.starts_with(store) {
        return true;
    }
    if host_dirs.is_empty() {
        return false;
    }
    !host_dirs.iter().any(|dir| entry.starts_with(dir))
}

pub(crate) fn store_path_for(store: &Path, absolute: &str) -> PathBuf {
    store.join(absolute.trim_start_matches('/'))
}

pub(crate) fn elf_soname(path: &Path) -> Option<String> {
    elf_info(path)?.soname
}

pub(crate) fn file_provides_soname(
    store: &Path,
    files: &[crate::recipe::ManifestFile],
    lib: &str,
) -> bool {
    files.iter().any(|file| {
        Path::new(&file.path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == lib)
            && elf_soname(&store_path_for(store, &file.path)).as_deref() == Some(lib)
    })
}

pub(crate) fn elf_header(path: &Path) -> Option<[u8; 18]> {
    use std::io::Read;
    let mut header = [0u8; 18];
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    file.read_exact(&mut header).ok()?;
    (&header[..4] == b"\x7fELF").then_some(header)
}

pub(crate) fn is_elf(path: &Path) -> bool {
    elf_header(path).is_some()
}
