use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::recipe::Recipe;

/// Archive suffixes we accept for an import, longest first.
const ARCHIVE_SUFFIXES: [&str; 7] = [
    ".tar.zst", ".tar.xz", ".tar.gz", ".tar.bz2", ".tgz", ".tar", ".deb",
];

/// Member names a `.deb` may carry its payload under.
const DATA_MEMBERS: [&str; 5] = [
    "data.tar",
    "data.tar.gz",
    "data.tar.xz",
    "data.tar.zst",
    "data.tar.bz2",
];

/// The same for the control archive.
const CONTROL_MEMBERS: [&str; 5] = [
    "control.tar",
    "control.tar.gz",
    "control.tar.xz",
    "control.tar.zst",
    "control.tar.bz2",
];

/// A package derived from an archive, plus the stream to unpack.
pub(crate) struct Derived {
    pub recipe: Recipe,
    /// The file to unpack: the archive itself, or the payload of a `.deb`.
    pub payload: PathBuf,
    /// Set when `payload` is a temporary file the caller should remove.
    pub temporary: bool,
    /// Directory holding the temporary payload, removed by the caller.
    pub work: PathBuf,
}

/// Builds the recipe a prebuilt package needs: no build steps, rooted at `/`.
///
/// Applies to an archive that matches no recipe in the recipe directory.
fn origin_text(
    archive: &Path,
    file_name: &str,
    payload: &Path,
    sha: &str,
    temporary: bool,
) -> Result<String> {
    if !temporary {
        return Ok(format!("imported from {file_name}"));
    }
    let archive_sha = crate::util::sha256_file(archive)
        .with_context(|| format!("hashing {}", archive.display()))?;
    Ok(format!(
        "imported from {file_name} (archive {}, payload {}, payload {})",
        &archive_sha[..12],
        leaf(payload),
        &sha[..12]
    ))
}

fn refuse_privileged(
    file_name: &str,
    setuid: &[String],
    setgid: &[String],
    keep_privileged: bool,
) -> Result<()> {
    if keep_privileged || (setuid.is_empty() && setgid.is_empty()) {
        return Ok(());
    }
    let mut listed: Vec<String> = setuid.iter().chain(setgid.iter()).cloned().collect();
    listed.sort();
    listed.dedup();
    bail!(
        "{file_name} ships files that keep a privileged bit ({});\n  \
         re-run with PORTALIS_KEEP_PRIVILEGED=1 to record them",
        listed.join(", ")
    );
}

fn derived_recipe(
    name: &str,
    version: &str,
    origin: &str,
    file_name: &str,
    sha: &str,
    setuid: &[String],
    setgid: &[String],
) -> Result<Recipe> {
    one_line("the package origin", origin)?;
    let mut text = format!(
        "package.name = {name}\n\
         package.version = {version}\n\
         package.description = {origin}\n\
         source.kind = binary\n\
         source.file = {file_name}\n\
         source.sha256 = {sha}\n\
         build.system = custom\n\
         install.prefix = /\n"
    );
    if !setuid.is_empty() {
        text.push_str(&format!("install.setuid = {}\n", setuid.join(", ")));
    }
    if !setgid.is_empty() {
        text.push_str(&format!("install.setgid = {}\n", setgid.join(", ")));
    }
    if !setuid.is_empty() || !setgid.is_empty() {
        one_line("the package name", name)?;
    }
    let recipe =
        Recipe::parse(&text).with_context(|| format!("building a recipe for {file_name}"))?;
    recipe.validate()?;
    Ok(recipe)
}

pub(crate) fn for_archive(archive: &Path, keep_privileged: bool) -> Result<Derived> {
    let file_name = archive
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", archive.display()))?
        .to_string_lossy()
        .to_string();
    one_line("the file name", &file_name)?;
    let suffix = suffix_of(&file_name).ok_or_else(|| {
        anyhow::anyhow!(
            "{file_name} is not something this can import; use a tar archive or a .deb \
             (an rpm or .run package has to be converted to a tar first)"
        )
    })?;
    let stem = file_name.trim_end_matches(suffix);
    // every temporary file made below is registered here before it exists
    let work = crate::archive::private_dir()?;
    let creds = crate::stage::unpack_user();
    let mut cleanup = TempGuard::default();
    cleanup.keep_dir(work.clone());
    let (mut payload, from_member, control) = if suffix == ".deb" {
        let control = deb_control(archive, &work, creds, &mut cleanup)?;
        let (payload, _) = ar_member(archive, &DATA_MEMBERS, &work, &mut cleanup)?
            .ok_or_else(|| anyhow::anyhow!("{} holds no data.tar member", archive.display()))?;
        (payload, true, control)
    } else {
        (archive.to_path_buf(), false, None)
    };
    // One decompression serves both the mode scan and the unpack: the payload
    // is expanded once into a plain tar, which both read.
    let mut temporary = from_member;
    let expanded = work.join(format!("{file_name}.tar"));
    {
        let mut file = std::fs::File::open(&payload)
            .with_context(|| format!("opening {}", payload.display()))?;
        if crate::archive::decompress_to(&mut file, &expanded, creds)? {
            if from_member {
                cleanup.keep(payload.clone());
            }
            payload = expanded;
            temporary = true;
        }
    }
    let parsed = control.or_else(|| {
        if suffix == ".deb" {
            split_deb_name(stem)
        } else {
            split_name(stem)
        }
    });
    let (name, version) = parsed.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot read a package name and version from {file_name};\n  \
             rename it to <name>-<version>-<arch>.tar.zst or <name>_<version>_<arch>.deb \
             (for example thing-1.2.0-x86_64.tar.zst)"
        )
    })?;

    // the caller takes over the payload on success; anything registered in the
    // guard goes when this returns early
    let (setuid, setgid) = privileged_modes(&payload, creds)?;
    refuse_privileged(&file_name, &setuid, &setgid, keep_privileged)?;
    let sha = crate::util::sha256_file(&payload)
        .with_context(|| format!("hashing {}", payload.display()))?;
    let origin = origin_text(archive, &file_name, &payload, &sha, temporary)?;
    let recipe = derived_recipe(&name, &version, &origin, &file_name, &sha, &setuid, &setgid)?;
    cleanup.disarm();
    Ok(Derived {
        recipe,
        payload,
        temporary,
        work,
    })
}

/// Removes what it registered unless the caller takes the payload over.
#[derive(Default)]
struct TempGuard {
    files: Vec<PathBuf>,
    dir: Option<PathBuf>,
}

impl TempGuard {
    fn keep(&mut self, path: PathBuf) {
        self.files.push(path);
    }

    fn keep_dir(&mut self, path: PathBuf) {
        self.dir = Some(path);
    }

    fn disarm(&mut self) {
        self.files.clear();
        self.dir = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        for path in self.files.drain(..) {
            let _ = std::fs::remove_file(path);
        }
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Paths that carry the setuid bit and paths that carry the setgid bit, read
/// from the archive headers.
fn privileged_modes(
    payload: &Path,
    creds: Option<(u32, u32)>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut file =
        std::fs::File::open(payload).with_context(|| format!("opening {}", payload.display()))?;
    let mut setuid = Vec::new();
    let mut setgid = Vec::new();
    for member in crate::archive::member_modes(&mut file, creds)? {
        let relative = member
            .path
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        let privileged = member.mode & 0o6000 != 0;
        if privileged {
            one_line("a privileged path", &relative)?;
            if relative.contains('#') || relative.contains('"') || relative.contains('\'') {
                return Err(anyhow::anyhow!(
                    "{relative} carries a character a recipe cannot express"
                ));
            }
        }
        if member.mode & 0o4000 != 0 {
            if relative.contains(',') {
                return Err(anyhow::anyhow!(
                    "{relative} carries a comma, which install.setuid cannot express"
                ));
            }
            setuid.push(relative.clone());
        }
        if member.mode & 0o2000 != 0 {
            // the group the archive names, not root: a setgid program runs with
            // the group it was built for (tty, shadow, crontab)
            if relative.contains(':') {
                return Err(anyhow::anyhow!(
                    "{relative} carries setgid but its name contains ':', which install.setgid cannot express"
                ));
            }
            let group = match member.gname {
                Some(name) if crate::recipe::usable_group_name(&name) => name,
                Some(name) => {
                    return Err(anyhow::anyhow!(
                        "{relative} carries setgid but its header names the group {name}, which install.setgid cannot carry"
                    ));
                }
                None => member.gid.map(|gid| gid.to_string()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{relative} carries setgid but its header names no group this recipe can use"
                    )
                })
                .inspect(|gid| {
                    eprintln!(
                        "note: {relative} carries setgid but its header names no group; recording gid {gid}"
                    );
                })?,
            };
            setgid.push(format!("{relative}:{group}"));
        }
    }
    Ok((setuid, setgid))
}

/// Refuses text that cannot sit on a single recipe line.
fn one_line(label: &str, value: &str) -> Result<()> {
    if value.chars().any(|c| c.is_control()) {
        bail!("{label} carries a control character, so it cannot go into a recipe");
    }
    Ok(())
}

fn leaf(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn suffix_of(file_name: &str) -> Option<&'static str> {
    ARCHIVE_SUFFIXES
        .iter()
        .find(|suffix| file_name.ends_with(**suffix))
        .copied()
}

/// `thing-1.2.0-x86_64` becomes `("thing", "1.2.0")`; a trailing release
/// number stays with the version.
pub(crate) fn split_name(stem: &str) -> Option<(String, String)> {
    let mut parts: Vec<&str> = stem.split('-').filter(|part| !part.is_empty()).collect();
    if parts.len() > 1 && crate::ARCH_SEGMENTS.contains(parts.last()?) {
        parts.pop();
    }
    // The version starts at the first component that begins with a digit; a
    // trailing release number stays with it: thing-1.2.0-1-x86_64
    let version_at = parts
        .iter()
        .position(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    if version_at == 0 {
        return None;
    }
    let name = parts[..version_at].join("-");
    let version = parts[version_at..].join("-");
    if !plain(&name) || !plain(&version) {
        return None;
    }
    Some((name, version))
}

/// dpkg names a package `name_version_arch`, with the architecture optional.
fn split_deb_name(stem: &str) -> Option<(String, String)> {
    let mut parts = stem.split('_').filter(|part| !part.is_empty());
    let name = parts.next()?;
    let version = parts.next()?;
    if !plain(name) || !plain(version) {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// dpkg versions may carry an epoch (`1:1.0.0.87`); the store path should not
/// contain a colon, and the epoch rarely distinguishes two builds.
fn strip_epoch(version: &str) -> String {
    match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) => {
            rest.to_string()
        }
        _ => version.to_string(),
    }
}

fn version_ok(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-' | ':'))
}

fn plain(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-'))
}

/// Reads the `Version:` and `Package:` fields of a `.deb` control file.
fn deb_control(
    archive: &Path,
    work: &Path,
    creds: Option<(u32, u32)>,
    cleanup: &mut TempGuard,
) -> Result<Option<(String, String)>> {
    let Some((control_tar, _)) = ar_member(archive, &CONTROL_MEMBERS, work, cleanup)? else {
        return Ok(None);
    };
    let mut file = std::fs::File::open(&control_tar)
        .with_context(|| format!("opening {}", control_tar.display()))?;
    let body = crate::archive::read_member(&mut file, "control", creds);
    let Some(bytes) = body? else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Package:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version:") {
            version = Some(rest.trim().to_string());
        }
    }
    match (name, version) {
        (Some(name), Some(version)) if plain(&name) && version_ok(&version) => {
            Ok(Some((name, strip_epoch(&version))))
        }
        _ => Ok(None),
    }
}

/// Reads an `ar` member name: spaces and one trailing slash come off. The
/// symbol table (`/`) and the long-name table (`//`) have no name of their own
/// and come back as `None`; anything else has to be a plain name.
fn member_name(raw: &[u8]) -> Result<Option<String>> {
    let trimmed = match raw.iter().position(|b| *b == b' ') {
        Some(end) => &raw[..end],
        None => raw,
    };
    if trimmed == b"/" || trimmed == b"//" {
        return Ok(None);
    }
    let trimmed = trimmed.strip_suffix(b"/").unwrap_or(trimmed);
    let name = std::str::from_utf8(trimmed)
        .map_err(|_| anyhow::anyhow!("a .deb member name is not valid UTF-8"))?;
    if name.is_empty()
        || name.contains('/')
        || name.contains("..")
        || name.chars().any(|c| !c.is_ascii_graphic())
    {
        bail!("a .deb member is named {name:?}, which is not a plain member name");
    }
    Ok(Some(name.to_string()))
}

/// Lifts one member out of a `.deb` (an `ar` archive) into a temporary file.
fn ar_member(
    archive: &Path,
    accepted: &[&str],
    work: &Path,
    cleanup: &mut TempGuard,
) -> Result<Option<(PathBuf, String)>> {
    let mut file =
        std::fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .with_context(|| format!("reading {}", archive.display()))?;
    if &magic != b"!<arch>\n" {
        bail!(
            "{} is not a .deb archive (the ar header is missing)",
            archive.display()
        );
    }
    loop {
        let mut header = [0u8; 60];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        // every member header ends with the ar terminator; a broken one means
        // the file is not the archive we think it is
        if &header[58..60] != b"`\n" {
            bail!(
                "{} has a damaged ar member header; it is not a usable .deb",
                archive.display()
            );
        }
        let Some(name) = member_name(&header[0..16])? else {
            let size = member_size(&header[48..58], archive, None)?;
            skip_member(&mut file, size, archive, None)?;
            continue;
        };
        let size = member_size(&header[48..58], archive, Some(&name))?;
        if accepted.contains(&name.as_str()) {
            let temporary = work.join(format!("{name}.member"));
            let mut out = crate::archive::create_private(&temporary)?;
            cleanup.keep(temporary.clone());
            let copied = std::io::copy(&mut (&mut file).take(size), &mut out)
                .with_context(|| format!("copying {name} out of {}", archive.display()))?;
            if copied != size {
                bail!("{} ended while extracting {name}", archive.display());
            }
            return Ok(Some((temporary, name)));
        }
        skip_member(&mut file, size, archive, Some(&name))?;
    }
}

/// Reads the decimal size field of an `ar` member header.
fn member_size(raw: &[u8], archive: &Path, member: Option<&str>) -> Result<u64> {
    let text = String::from_utf8_lossy(raw);
    text.trim().parse().with_context(|| {
        let what = match member {
            Some(name) => format!("the size of {name}"),
            None => "a member size".to_string(),
        };
        format!("reading {what} in {}", archive.display())
    })
}

/// Consumes one member's data, keeping the even-byte boundary the format uses.
fn skip_member(
    file: &mut std::fs::File,
    size: u64,
    archive: &Path,
    member: Option<&str>,
) -> Result<()> {
    let padded = size
        .checked_add(size % 2)
        .ok_or_else(|| anyhow::anyhow!("ar member size overflows: {size}"))?;
    let mut window = (&mut *file).take(padded);
    let what = match member {
        Some(name) => format!("skipping {name}"),
        None => "skipping a member without a name".to_string(),
    };
    std::io::copy(&mut window, &mut std::io::sink())
        .with_context(|| format!("{what} in {}", archive.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_name_may_not_climb_out_of_the_work_directory() {
        assert_eq!(
            member_name(b"data.tar.xz/      ").expect("valid"),
            Some("data.tar.xz".to_string())
        );
        assert_eq!(
            member_name(b"control.tar       ").expect("valid"),
            Some("control.tar".to_string())
        );
        assert_eq!(member_name(b"/               ").expect("table"), None);
        assert_eq!(member_name(b"//              ").expect("table"), None);
        for bad in [
            b"../../etc/passwd ".as_slice(),
            b"a/b              ".as_slice(),
            b"..               ".as_slice(),
            b"                 ".as_slice(),
            b"bad\x00name       ".as_slice(),
        ] {
            assert!(
                member_name(bad).is_err(),
                "accepted a member name: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_value_that_spans_two_lines_is_refused() {
        assert!(one_line("the name", "thing").is_ok());
        let error =
            one_line("the name", "thing\npackage.hold = true").expect_err("a newline was accepted");
        assert!(
            format!("{error}").contains("control character"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn splits_a_name_a_version_and_an_architecture() {
        assert_eq!(
            split_name("thing-1.2.0-x86_64"),
            Some(("thing".to_string(), "1.2.0".to_string()))
        );
        assert_eq!(
            split_name("nvidia-prime-1.0-any"),
            Some(("nvidia-prime".to_string(), "1.0".to_string()))
        );
        assert_eq!(
            split_name("thing-1.0-armv7h"),
            Some(("thing".to_string(), "1.0".to_string()))
        );
        assert_eq!(
            split_name("thing-1.0-loongarch64"),
            Some(("thing".to_string(), "1.0".to_string()))
        );
        assert_eq!(
            split_name("firefox-140.0"),
            Some(("firefox".to_string(), "140.0".to_string()))
        );
    }

    #[test]
    fn keeps_a_release_number_with_the_version() {
        assert_eq!(
            split_name("thing-1.2.0-1-x86_64"),
            Some(("thing".to_string(), "1.2.0-1".to_string()))
        );
    }

    #[test]
    fn splits_a_dpkg_name() {
        assert_eq!(
            split_deb_name("google-chrome-stable_140.0.7339.80_amd64"),
            Some((
                "google-chrome-stable".to_string(),
                "140.0.7339.80".to_string()
            ))
        );
        assert_eq!(
            split_deb_name("code_1.104.0"),
            Some(("code".to_string(), "1.104.0".to_string()))
        );
        assert_eq!(split_deb_name("code"), None);
    }

    #[test]
    fn drops_a_dpkg_epoch() {
        assert_eq!(strip_epoch("1:1.0.0.87"), "1.0.0.87");
        assert_eq!(strip_epoch("2:3.4"), "3.4");
        assert_eq!(strip_epoch("1.0.0"), "1.0.0");
    }

    #[test]
    fn refuses_a_name_without_a_version() {
        assert_eq!(split_name("thing"), None);
        assert_eq!(split_name("1.2.3"), None);
        assert_eq!(split_name("thing-extra"), None);
    }

    #[test]
    fn recognises_the_suffix() {
        assert_eq!(suffix_of("a-1.0.tar.zst"), Some(".tar.zst"));
        assert_eq!(suffix_of("a-1.0.deb"), Some(".deb"));
        assert_eq!(suffix_of("a-1.0.rpm"), None);
        assert_eq!(suffix_of("a-1.0.run"), None);
    }
}
