//! Building archives by hand and checking what the reader makes of them.
use super::*;
use crate::tar::parse::{BLOCK, MAX_UNPACKED_BYTES};

/// Assembles a record the way tar writes one: the length counts the whole
/// record, including the digits of the length itself.
fn pax_record(name: &str, value: &str) -> String {
    let body = format!("{name}={value}\n");
    let mut length = body.len() + 2;
    loop {
        let candidate = format!("{length} {body}");
        if candidate.len() == length {
            return candidate;
        }
        length = candidate.len();
    }
}

#[test]
fn pax_records_end_where_the_length_says() {
    // The value holds a newline.
    let body = format!(
        "{}{}",
        pax_record("path", "dir/a\nline b.txt"),
        pax_record("linkpath", "target")
    );
    let records = pax_records(body.as_bytes()).expect("records parse");
    assert_eq!(
        records,
        vec![
            ("path".to_string(), "dir/a\nline b.txt".to_string()),
            ("linkpath".to_string(), "target".to_string()),
        ]
    );
}

#[test]
fn a_pax_record_that_is_not_utf8_is_refused() {
    // a length-prefixed record whose value holds an invalid byte
    let mut body = b"12 path=\xff\xfe\n".to_vec();
    body[0] = b'1';
    assert!(pax_records(&body).is_err(), "invalid UTF-8 was accepted");
}

#[test]
fn a_pax_path_survives_an_unreadable_header_name() {
    let name = "pkg-1.0/café.txt";
    let body = pax_record("path", name);
    let mut data = Vec::new();
    data.extend_from_slice(&header("pax", body.len() as u64, 'x', ""));
    data.extend_from_slice(body.as_bytes());
    data.extend(std::iter::repeat_n(
        0u8,
        padding(body.len() as u64) as usize,
    ));
    let mut member = header("", 0, '0', "");
    member[0] = 0xff;
    member[1] = 0xfe;
    reseal(&mut member);
    data.extend_from_slice(&member);
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));

    let found = members(&mut data.as_slice()).expect("pax path is used");
    assert_eq!(found[0].path, name);
}

#[test]
fn a_pax_link_path_survives_an_unreadable_header_link() {
    let target = "pkg-1.0/target.txt";
    let body = pax_record("linkpath", target);
    let mut data = Vec::new();
    data.extend_from_slice(&header("pax", body.len() as u64, 'x', ""));
    data.extend_from_slice(body.as_bytes());
    data.extend(std::iter::repeat_n(
        0u8,
        padding(body.len() as u64) as usize,
    ));
    let mut member = header("pkg-1.0/link", 0, '2', "");
    member[157] = 0xff;
    member[158] = 0xfe;
    reseal(&mut member);
    data.extend_from_slice(&member);
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));

    let found = members(&mut data.as_slice()).expect("pax link path is used");
    assert_eq!(found[0].link_target.as_deref(), Some(target));
}

#[test]
fn a_base256_number_that_overflows_is_refused() {
    // 11 value bytes: far more than a u64 holds
    let mut field = [0xffu8; 12];
    field[0] = 0x80;
    let error = parse_number(&field).expect_err("overflow accepted");
    assert!(
        error.to_string().contains("does not fit"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_negative_base256_number_is_refused() {
    let mut field = [0u8; 12];
    field[0] = 0xc0;
    let error = parse_number(&field).expect_err("negative accepted");
    assert!(
        error.to_string().contains("negative"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_global_header_with_only_a_comment_is_skipped() {
    // git archive writes exactly this: one global record holding the commit
    let body = pax_record("comment", "c3a3a9808ad3ab4a3336836833f83288b672ccbf");
    let data = archive(&[
        (
            "pax_global_header",
            body.len() as u64,
            'g',
            "",
            body.as_bytes(),
        ),
        ("pkg-1.0/file.txt", 2, '0', "", b"hi"),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, "pkg-1.0/file.txt");
}

#[test]
fn a_global_header_that_names_a_path_is_refused() {
    let body = pax_record("path", "elsewhere/file");
    let data = archive(&[
        (
            "pax_global_header",
            body.len() as u64,
            'g',
            "",
            body.as_bytes(),
        ),
        ("pkg-1.0/file.txt", 2, '0', "", b"hi"),
    ]);
    let error = members(&mut data.as_slice()).expect_err("must refuse");
    assert!(error.to_string().contains("global pax header"), "{error}");
}

#[test]
fn header_count_is_bounded() {
    let mut cursor = Cursor::new(std::io::empty());
    cursor.headers = MAX_HEADERS - 1;
    cursor.count_header().expect("the last header fits");
    let error = cursor.count_header().expect_err("the budget is enforced");
    assert!(
        error.to_string().contains("headers"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_pax_record_with_a_bad_length_is_refused() {
    assert!(pax_records(b"99 path=x\n").is_err());
    assert!(pax_records(b"x path=x\n").is_err());
    assert!(pax_records(b"9 path=x\n").is_ok());
}

fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let digits = format!("{:0width$o}", value, width = width);
    field[..width].copy_from_slice(digits.as_bytes());
    field[width] = 0;
}

fn header(name: &str, size: u64, typeflag: char, link: &str) -> [u8; BLOCK] {
    // a directory without its execute bits cannot hold anything, and real
    // archives never carry one
    let mode = if typeflag == '5' { 0o755 } else { 0o644 };
    raw_header(name, size, typeflag, link, mode)
}

fn raw_header(name: &str, size: u64, typeflag: char, link: &str, mode: u32) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    let bytes = name.as_bytes();
    block[..bytes.len().min(100)].copy_from_slice(&bytes[..bytes.len().min(100)]);
    octal(&mut block[100..108], mode as u64);
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], 0);
    block[148..156].copy_from_slice(b"        ");
    block[156] = typeflag as u8;
    let link_bytes = link.as_bytes();
    block[157..157 + link_bytes.len().min(100)]
        .copy_from_slice(&link_bytes[..link_bytes.len().min(100)]);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let sum: u64 = block.iter().map(|byte| *byte as u64).sum();
    let field = format!("{:06o}\0 ", sum);
    block[148..156].copy_from_slice(field.as_bytes());
    block
}

fn archive(entries: &[(&str, u64, char, &str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, size, typeflag, link, body) in entries {
        out.extend_from_slice(&header(name, *size, *typeflag, link));
        out.extend_from_slice(body);
        let pad = padding(*size) as usize;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, BLOCK));
    out.extend(std::iter::repeat_n(0u8, BLOCK));
    out
}

/// Deterministic generator: every case starts from the same seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Recomputes a header's checksum after a mutation.
fn reseal(block: &mut [u8]) {
    block[148..156].fill(b' ');
    let sum: u64 = block.iter().take(BLOCK).map(|byte| *byte as u64).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// Malformed archives: the reader answers Ok or Err, never panics, and a
/// buffer of a few blocks never costs unbounded time.
#[test]
fn malformed_archives_are_refused_without_panicking() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let seed = archive(&[
        ("pkg-1.0/plain.txt", 5, '0', "", b"hello"),
        ("pkg-1.0/deep", 0, '5', "", b""),
        ("pkg-1.0/deep/link", 0, '2', "../plain.txt", b""),
    ]);
    let scratch = tempfile::tempdir().expect("tempdir");
    let started = std::time::Instant::now();

    for round in 0..2000usize {
        let mut data = seed.clone();
        match round % 5 {
            0 => {
                // flip bits anywhere, including the header fields
                for _ in 0..(rng.next() % 8 + 1) {
                    let index = (rng.next() as usize) % data.len();
                    data[index] ^= (rng.next() as u8) | 1;
                }
            }
            1 => {
                let keep = (rng.next() as usize) % data.len();
                data.truncate(keep);
            }
            2 => {
                // overwrite part of a numeric field: size, mode or checksum
                let index = [124, 100, 148][round % 3] + (rng.next() as usize) % 8;
                for offset in 0..(rng.next() % 8 + 1) as usize {
                    if index + offset < data.len() {
                        data[index + offset] = rng.next() as u8;
                    }
                }
            }
            3 => {
                // splice random bytes into the payload
                let index = (rng.next() as usize) % data.len();
                for offset in 0..(rng.next() % 32) as usize {
                    if index + offset < data.len() {
                        data[index + offset] = rng.next() as u8;
                    }
                }
            }
            _ => {
                // Rewrites the first member's name or link target and reseals it.
                let field = if rng.next().is_multiple_of(2) {
                    0..100
                } else {
                    157..257
                };
                for index in field {
                    if rng.next().is_multiple_of(3) {
                        data[index] = b"../ \x00x"[(rng.next() % 6) as usize];
                    }
                }
                reseal(&mut data[..BLOCK]);
            }
        }

        let _ = members(&mut data.as_slice());
        let dir = scratch.path().join(format!("round-{round}"));
        std::fs::create_dir_all(&dir).expect("round directory");
        let _ = extract(&mut data.as_slice(), &dir);
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "2000 malformed archives took {elapsed:?}"
    );
}

#[test]
fn reads_files_directories_and_symlinks() {
    let data = archive(&[
        ("pkg-1.0/", 0, '5', "", b""),
        ("pkg-1.0/file.txt", 5, '0', "", b"hello"),
        ("pkg-1.0/link", 0, '2', "file.txt", b""),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].kind, Kind::Directory);
    assert_eq!(found[1].path, "pkg-1.0/file.txt");
    assert_eq!(found[1].size, 5);
    assert_eq!(found[2].kind, Kind::Symlink);
    assert_eq!(found[2].link_target.as_deref(), Some("file.txt"));
}

#[test]
fn reports_a_device_node_as_unsupported() {
    let data = archive(&[("pkg-1.0/console", 0, '3', "", b"")]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, Kind::Unsupported('3'));
}

#[test]
fn reads_a_gnu_long_name() {
    let long = "pkg-1.0/".to_string() + &"a".repeat(120);
    let data = archive(&[
        ("././@LongLink", long.len() as u64 + 1, 'L', "", {
            let mut body = long.clone().into_bytes();
            body.push(0);
            Box::leak(body.into_boxed_slice())
        }),
        ("pkg-1.0/short", 2, '0', "", b"hi"),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, long);
}

#[test]
fn reads_a_pax_size_override() {
    // the header block claims 0 bytes; the extended header says 5, and the
    // stream then carries 5
    let entry = pax_record("size", "1024").into_bytes();
    let body = Box::leak(entry.into_boxed_slice());
    // A whole number of blocks, with the size field left at 0.
    let payload = Box::leak(vec![b'x'; 1024].into_boxed_slice());
    let data = archive(&[
        ("pkg/./pax", body.len() as u64, 'x', "", body),
        ("pkg-1.0/file", 0, '0', "", payload),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].size, 1024, "the pax size override was ignored");
}

#[test]
fn reads_a_pax_path_override() {
    let long = "pkg-1.0/".to_string() + &"b".repeat(120);
    let entry = pax_record("path", &long).into_bytes();
    let body = Box::leak(entry.into_boxed_slice());
    let data = archive(&[
        ("pkg/./pax", body.len() as u64, 'x', "", body),
        ("pkg-1.0/short", 2, '0', "", b"hi"),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, long);
}

#[test]
fn refuses_a_corrupt_checksum() {
    let mut data = archive(&[("pkg-1.0/file", 1, '0', "", b"x")]);
    data[10] ^= 0xff;
    let error = members(&mut data.as_slice()).expect_err("must refuse");
    assert!(error.to_string().contains("checksum"), "{error}");
}

#[test]
fn reads_what_gnu_tar_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("pkg-1.0");
    std::fs::create_dir_all(&root).expect("source directory");
    std::fs::write(root.join("plain.txt"), b"hello").expect("file");
    let long = "l".repeat(120);
    std::fs::write(root.join(&long), b"long name").expect("long file");
    std::os::unix::fs::symlink("plain.txt", root.join("link")).expect("symlink");

    let archive = dir.path().join("pkg.tar");
    let status = std::process::Command::new("tar")
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(dir.path())
        .arg("pkg-1.0")
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let mut file = std::fs::File::open(&archive).expect("open archive");
    let found = members(&mut file).expect("parses the real archive");
    let names: Vec<&str> = found.iter().map(|m| m.path.as_str()).collect();
    assert!(names.contains(&"pkg-1.0/plain.txt"), "{names:?}");
    assert!(
        names.contains(&format!("pkg-1.0/{long}").as_str()),
        "{names:?}"
    );
    assert_eq!(found.iter().filter(|m| m.kind == Kind::Symlink).count(), 1);
    assert!(found
        .iter()
        .all(|m| !matches!(m.kind, Kind::Unsupported(_))));
}

#[test]
fn refuses_a_truncated_header() {
    let mut data = archive(&[
        ("pkg-1.0/a", 0, '0', "", b""),
        ("pkg-1.0/b", 0, '0', "", b""),
    ]);
    data.truncate(BLOCK + 200);
    let error = members(&mut data.as_slice()).expect_err("must refuse");
    assert!(error.to_string().contains("header block"), "{error}");
}

#[test]
fn refuses_an_archive_that_ends_inside_a_member() {
    let mut data = archive(&[("pkg-1.0/file", 400, '0', "", &[7u8; 400])]);
    data.truncate(BLOCK + 100);
    assert!(members(&mut data.as_slice()).is_err());
}

#[test]
fn refuses_a_hard_link_to_a_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A hard link to the symlink itself gives its target a second home.
    let data = archive(&[
        // legal where it stands: from pkg-1.0/deep the target lands on the root
        ("pkg-1.0/deep/link", 0, '2', "../..", b""),
        // The same text, aliased one level up.
        ("pkg-1.0/alias", 0, '1', "pkg-1.0/deep/link", b""),
    ]);
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(error.to_string().contains("regular file"), "{error}");
    assert!(!dir.path().join("pkg-1.0/alias").exists());
}

#[test]
fn refuses_an_archive_that_claims_to_expand_past_the_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The size is written in the base-256 form.
    let mut header = raw_header("pkg-1.0/huge", 0, '0', "", 0o644);
    let mut size = [0u8; 12];
    size[0] = 0x80;
    let mut value = MAX_UNPACKED_BYTES + 1;
    for index in (1..12).rev() {
        size[index] = (value & 0xff) as u8;
        value >>= 8;
    }
    header[124..136].copy_from_slice(&size);
    header[148..156].copy_from_slice(b"        ");
    let sum: u64 = header.iter().map(|byte| *byte as u64).sum();
    let field = format!("{:06o}\0 ", sum);
    header[148..156].copy_from_slice(field.as_bytes());

    let mut data = header.to_vec();
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(error.to_string().contains("expands past"), "{error}");
    assert!(!dir.path().join("pkg-1.0/huge").exists());
}

#[test]
fn refuses_a_hard_link_through_a_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    // the archive plants a link to the host, then a hard link whose target
    // path walks through it
    let data = archive(&[
        ("pkg-1.0/escape", 0, '2', "/etc", b""),
        ("pkg-1.0/shadow", 0, '1', "pkg-1.0/escape/shadow", b""),
    ]);
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(
        error.to_string().contains("No such file")
            || error.to_string().contains("Not a directory")
            || error.to_string().contains("unsupported"),
        "{error}"
    );
    assert!(!dir.path().join("pkg-1.0/shadow").exists());
}

#[test]
fn refuses_oversized_metadata() {
    let mut data = archive(&[("pkg-1.0/file", 1, '0', "", b"x")]);
    let mut header = raw_header("././@LongLink", 2 * 1024 * 1024, 'L', "", 0o644);
    // rebuild the checksum for the new size
    header[148..156].copy_from_slice(b"        ");
    let sum: u64 = header.iter().map(|byte| *byte as u64).sum();
    let field = format!("{:06o}\0 ", sum);
    header[148..156].copy_from_slice(field.as_bytes());
    data.splice(0..512, header.iter().copied());
    let error = members(&mut data.as_slice()).expect_err("must refuse");
    assert!(error.to_string().contains("metadata"), "{error}");
}

#[test]
fn link_depth_ignores_redundant_components() {
    let dir = tempfile::tempdir().expect("tempdir");
    // "./x" sits at depth 0 and its target ".." leaves the tree.
    let data = archive(&[("./x", 0, '2', "..", b"")]);
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(error.to_string().contains("outside"), "{error}");
}

#[test]
fn ignores_a_root_member_named_dot() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A first member named "./" describes the root and creates nothing.
    let data = archive(&[
        ("./", 0, '5', "", b""),
        ("pkg-1.0/file.txt", 2, '0', "", b"hi"),
    ]);
    let created = extract(&mut data.as_slice(), dir.path()).expect("extracts");
    assert_eq!(created, 1);
    assert!(dir.path().join("pkg-1.0/file.txt").exists());
}

#[test]
fn extract_writes_files_directories_and_links() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = archive(&[
        ("pkg-1.0/", 0, '5', "", b""),
        ("pkg-1.0/sub/", 0, '5', "", b""),
        ("pkg-1.0/sub/file.txt", 5, '0', "", b"hello"),
        ("pkg-1.0/sub/link", 0, '2', "file.txt", b""),
    ]);
    let created = extract(&mut data.as_slice(), dir.path()).expect("extracts");
    assert_eq!(created, 4);
    let body = std::fs::read(dir.path().join("pkg-1.0/sub/file.txt")).expect("file");
    assert_eq!(body, b"hello");
    let link = std::fs::read_link(dir.path().join("pkg-1.0/sub/link")).expect("link");
    assert_eq!(link.to_string_lossy(), "file.txt");
}

#[test]
fn extract_replaces_a_repeated_symlink() {
    let data = archive(&[
        ("pkg-1.0/link", 0, '2', "one.txt", b""),
        ("pkg-1.0/link", 0, '2', "two.txt", b""),
    ]);
    let dir = tempfile::tempdir().expect("tempdir");
    extract(&mut data.as_slice(), dir.path()).expect("extracts");
    assert_eq!(
        std::fs::read_link(dir.path().join("pkg-1.0/link")).expect("link"),
        std::path::PathBuf::from("two.txt")
    );
}

#[test]
fn extract_refuses_a_device_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = archive(&[("pkg-1.0/console", 0, '3', "", b"")]);
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(error.to_string().contains("unsupported type"), "{error}");
    assert!(!dir.path().join("pkg-1.0/console").exists());
}

#[test]
fn extract_refuses_a_path_that_climbs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = archive(&[("pkg-1.0/../../../escape.txt", 4, '0', "", b"nope")]);
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(error.to_string().contains("climbs"), "{error}");
}

#[test]
fn extract_refuses_a_link_that_leaves_the_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = archive(&[("pkg-1.0/deep/link", 0, '2', "../../../outside", b"")]);
    let error = extract(&mut data.as_slice(), dir.path()).expect_err("must refuse");
    assert!(error.to_string().contains("outside"), "{error}");
}

#[test]
fn extract_keeps_a_link_that_stays_inside() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = archive(&[
        ("pkg-1.0/a/file.txt", 2, '0', "", b"hi"),
        ("pkg-1.0/b/link", 0, '2', "../a/file.txt", b""),
    ]);
    extract(&mut data.as_slice(), dir.path()).expect("extracts");
    let link = std::fs::read_link(dir.path().join("pkg-1.0/b/link")).expect("link");
    assert_eq!(link.to_string_lossy(), "../a/file.txt");
}

#[test]
fn extract_makes_a_hard_link_inside_the_tree() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = archive(&[
        ("pkg-1.0/file.txt", 2, '0', "", b"hi"),
        ("pkg-1.0/alias.txt", 0, '1', "pkg-1.0/file.txt", b""),
    ]);
    extract(&mut data.as_slice(), dir.path()).expect("extracts");
    let first = std::fs::metadata(dir.path().join("pkg-1.0/file.txt")).expect("first");
    let alias = std::fs::metadata(dir.path().join("pkg-1.0/alias.txt")).expect("alias");
    assert_eq!(first.ino(), alias.ino());
}

#[test]
fn a_member_name_that_is_not_utf8_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut header = raw_header("placeholder", 0, '0', "", 0o644);
    header[..12].copy_from_slice(b"pkg/bad\xff.txt");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| *byte as u32).sum();
    header[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
    let mut data = header.to_vec();
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));

    let error = extract(&mut data.as_slice(), dir.path())
        .expect_err("a name that cannot be represented must not be installed")
        .to_string();
    assert!(
        error.contains("not valid UTF-8"),
        "the refusal did not name the reason: {error}"
    );
}

#[test]
fn extract_strips_setuid_bits() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut data = Vec::new();
    data.extend_from_slice(&raw_header("pkg-1.0/rooted", 2, '0', "", 0o4755));
    data.extend_from_slice(b"hi");
    data.extend(std::iter::repeat_n(0u8, padding(2) as usize));
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    extract(&mut data.as_slice(), dir.path()).expect("extracts");
    let mode = std::fs::metadata(dir.path().join("pkg-1.0/rooted"))
        .expect("file")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode & 0o6000, 0, "setuid or setgid survived: {mode:o}");
}

#[test]
fn reads_a_gnu_long_link_target() {
    let long = "a".repeat(120);
    let mut body = long.clone().into_bytes();
    body.push(0);
    let body: &[u8] = Box::leak(body.into_boxed_slice());
    let data = archive(&[
        ("././@LongLink", long.len() as u64 + 1, 'K', "", body),
        ("pkg-1.0/link", 0, '2', "short", b""),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found[0].link_target.as_deref(), Some(long.as_str()));
}

#[test]
fn reads_a_pax_link_target() {
    let long = "b".repeat(120);
    let entry = pax_record("linkpath", &long).into_bytes();
    let body = Box::leak(entry.into_boxed_slice());
    let data = archive(&[
        ("pkg/./pax", body.len() as u64, 'x', "", body),
        ("pkg-1.0/link", 0, '2', "short", b""),
    ]);
    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found[0].link_target.as_deref(), Some(long.as_str()));
}

#[test]
fn refuses_gnu_sparse_metadata() {
    let mut entry = b"GNU.sparse.name=pkg-1.0/image".to_vec();
    let length = entry.len() + 3;
    entry = [format!("{length} ").into_bytes(), entry].concat();
    let body = Box::leak(entry.into_boxed_slice());
    let data = archive(&[
        ("pkg/./pax", body.len() as u64, 'x', "", body),
        ("pkg-1.0/GNUSparseFile/image", 0, '0', "", b""),
    ]);
    let error = members(&mut data.as_slice()).expect_err("must refuse");
    assert!(error.to_string().contains("sparse"), "{error}");
}

#[test]
fn keeps_a_directory_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut data = Vec::new();
    data.extend_from_slice(&raw_header("pkg-1.0/", 0, '5', "", 0o750));
    data.extend_from_slice(&raw_header("pkg-1.0/inside", 2, '0', "", 0o644));
    data.extend_from_slice(b"hi");
    data.extend(std::iter::repeat_n(0u8, padding(2) as usize));
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    extract(&mut data.as_slice(), dir.path()).expect("extracts");
    let mode = std::fs::metadata(dir.path().join("pkg-1.0"))
        .expect("directory")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o750, "the archive directory mode was not kept");
}

#[test]
fn a_link_that_claims_data_does_not_shift_the_stream() {
    // A symlink member that carries a size keeps the reader's place.
    let mut data = Vec::new();
    data.extend_from_slice(&raw_header("pkg-1.0/link", 3, '2', "target", 0o777));
    data.extend_from_slice(b"abc");
    data.extend(std::iter::repeat_n(0u8, padding(3) as usize));
    data.extend_from_slice(&raw_header("pkg-1.0/after", 2, '0', "", 0o644));
    data.extend_from_slice(b"hi");
    data.extend(std::iter::repeat_n(0u8, padding(2) as usize));
    data.extend(std::iter::repeat_n(0u8, BLOCK));
    data.extend(std::iter::repeat_n(0u8, BLOCK));

    let found = members(&mut data.as_slice()).expect("parses");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].kind, Kind::Symlink);
    assert_eq!(found[1].path, "pkg-1.0/after");
}
