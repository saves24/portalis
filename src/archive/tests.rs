use super::paths::resolve_within;
use super::stream::drain_tail;
use super::{collect_files, copy_tree, STORE_MARKER};

#[test]
fn a_copy_does_not_write_through_a_destination_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source/bin");
    let destination = dir.path().join("destination/bin");
    std::fs::create_dir_all(&source).expect("source");
    std::fs::create_dir_all(&destination).expect("destination");
    std::fs::write(source.join("sh"), b"package").expect("source file");
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"keep").expect("outside");
    std::os::unix::fs::symlink(&outside, destination.join("sh")).expect("destination link");

    let error = copy_tree(
        dir.path().join("source").as_path(),
        dir.path().join("destination").as_path(),
    )
    .expect_err("a symlinked destination was followed");
    assert!(
        format!("{error:#}").contains("symlink"),
        "the refusal does not name the link: {error:#}"
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside"),
        b"keep",
        "the copy wrote through the destination link"
    );
}

#[test]
fn the_marker_text_round_trips() {
    let text = super::marker_text("abc123", "def456", "789abc");
    assert_eq!(super::marker_recipe(&text), Some("abc123"));
    assert_eq!(super::marker_digest(&text), Some("def456"));
    assert_eq!(super::marker_tree(&text), Some("789abc"));
}

#[test]
fn a_package_may_not_ship_the_marker_name() {
    let dir = std::env::temp_dir().join(format!("portalis-marker-own-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(STORE_MARKER), b"not ours\n").unwrap();
    let error = collect_files(&dir).expect_err("a shipped marker name was accepted");
    assert!(
        format!("{error:#}").contains("reserved"),
        "the refusal does not say why: {error:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_shipped_marker_name_that_is_a_link_is_refused() {
    let dir = std::env::temp_dir().join(format!("portalis-marker-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload"), b"x").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", dir.join(STORE_MARKER)).unwrap();
    let error = collect_files(&dir).expect_err("a marker-shaped link was accepted");
    assert!(
        format!("{error:#}").contains("reserved"),
        "the refusal does not say why: {error:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_marker_is_not_part_of_the_manifest() {
    let dir = std::env::temp_dir().join(format!("portalis-marker-manifest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload"), b"x").unwrap();
    std::fs::write(
        dir.join(STORE_MARKER),
        crate::archive::marker_text("recipe-hash", &"a".repeat(64), &"b".repeat(64)),
    )
    .unwrap();
    let files = collect_files(&dir).expect("collect");
    let names: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        names,
        vec!["/payload"],
        "the marker leaked into the manifest"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_absolute_link_inside_the_tree_becomes_relative() {
    let dir = super::private_dir().expect("private dir");
    let root = dir.join("tree");
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    std::fs::create_dir_all(root.join("usr/lib/okpkg")).expect("lib");
    std::fs::write(root.join("usr/lib/okpkg/data"), b"x").expect("data");
    std::os::unix::fs::symlink("/usr/lib/okpkg/data", root.join("usr/bin/abslink")).expect("link");
    super::close_absolute_links(&root).expect("rewrite");
    let target = std::fs::read_link(root.join("usr/bin/abslink")).expect("read link");
    assert_eq!(
        target,
        std::path::PathBuf::from("../lib/okpkg/data"),
        "the absolute target was not rewritten: {}",
        target.display()
    );
    super::validate_tree_links(&root, false).expect("the rewritten tree still validates");
}

#[test]
fn an_absolute_link_to_the_live_root_keeps_its_form() {
    let dir = super::private_dir().expect("private dir");
    let root = dir.join("tree");
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    std::os::unix::fs::symlink("/usr/lib/libfoo.so.1", root.join("usr/bin/other")).expect("link");
    super::close_absolute_links(&root).expect("a cross-package link");
    let target = std::fs::read_link(root.join("usr/bin/other")).expect("read link");
    assert_eq!(
        target,
        std::path::PathBuf::from("/usr/lib/libfoo.so.1"),
        "a link to the live root was rewritten: {}",
        target.display()
    );
}

#[test]
fn an_absolute_link_to_another_package_is_left_alone() {
    let dir = super::private_dir().expect("private dir");
    let root = dir.join("tree");
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    std::os::unix::fs::symlink("/usr/bin/other-package", root.join("usr/bin/alias")).expect("link");
    super::close_absolute_links(&root).expect("a cross-package link");
    let target = std::fs::read_link(root.join("usr/bin/alias")).expect("read link");
    assert_eq!(
        target,
        std::path::PathBuf::from("/usr/bin/other-package"),
        "the cross-package link was rewritten: {}",
        target.display()
    );
}

#[test]
fn a_copy_that_grows_past_the_limit_is_refused() {
    let dir = super::private_dir().expect("private dir");
    let path = dir.join("out");
    let mut out = super::create_private(&path).expect("file");
    let mut source = std::io::Cursor::new(vec![b'x'; 4096]);
    let later = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let error = super::copy_bounded(&mut source, &mut out, 1024, later)
        .expect_err("the limit was not enforced");
    assert!(
        format!("{error}").contains("expands past"),
        "unexpected error: {error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_pipe_that_stays_quiet_times_out() {
    use std::io::Read as _;

    let (mut reader, writer) = std::os::unix::net::UnixStream::pair().expect("pair");
    let fd = std::os::fd::AsRawFd::as_raw_fd(&reader);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(60);
    let mut bounded = super::DeadlineReader::new(&mut reader, fd, deadline);
    let mut buf = [0u8; 8];
    let error = bounded
        .read(&mut buf)
        .expect_err("a quiet pipe was read from");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(writer);
}

#[test]
fn a_private_file_cannot_be_created_twice() {
    let dir = super::private_dir().expect("private dir");
    let path = dir.join("once");
    let first = super::create_private(&path);
    assert!(
        first.is_ok(),
        "the first creation failed: {:?}",
        first.err()
    );
    let second = super::create_private(&path);
    assert!(
        second.is_err(),
        "a second creation over the same path was allowed"
    );
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(&path).expect("metadata").permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o600, "the file is not owner-only: {mode:04o}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_absolute_link_is_resolved_from_the_tree_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("usr/bin")).expect("directories");
    std::os::unix::fs::symlink("/usr/lib/portalis/portalis", root.join("usr/bin/moirse"))
        .expect("link");
    resolve_within(root, &root.join("usr/bin/moirse"), true)
        .expect("a binary package may carry an absolute target");
    assert!(
        resolve_within(root, &root.join("usr/bin/moirse"), false).is_err(),
        "a source archive may not"
    );
}

#[test]
fn a_link_chain_that_climbs_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tree = dir.path().join("pkg");
    std::fs::create_dir_all(tree.join("deep")).expect("directories");
    std::os::unix::fs::symlink("..", tree.join("deep/x")).expect("first link");
    std::os::unix::fs::symlink("x/../etc/passwd", tree.join("deep/a")).expect("second link");
    let error = resolve_within(&tree, &tree.join("deep/a"), false)
        .expect_err("the chained targets were accepted");
    assert!(error.to_string().contains("escapes the tree"), "{error}");
}

#[test]
fn a_tail_beyond_the_ceiling_is_refused() {
    let at_limit = vec![0u8; 8];
    assert_eq!(
        drain_tail(&mut at_limit.as_slice(), 8).expect("at the ceiling"),
        8
    );
    let past_limit = vec![0u8; 9];
    let error = drain_tail(&mut past_limit.as_slice(), 8).expect_err("past the ceiling");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
