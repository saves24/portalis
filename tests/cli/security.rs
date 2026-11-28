use super::*;

#[test]
fn defers_packages_that_target_boot() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "kernelbit",
        "1.0",
        "/",
        "mkdir -p $DESTDIR/boot && cp payload.txt $DESTDIR/boot/kernelbit",
    );

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("staged"),
        "a package writing into /boot must wait for shutdown:\n{out}"
    );
    assert!(
        !sb.root.join("boot/kernelbit").exists(),
        "late path was written before activation"
    );

    sb.activate_pending();
    assert!(
        sb.root.join("boot/kernelbit").exists(),
        "pending package was never activated"
    );
}

#[test]
fn a_symlink_chain_cannot_escape_the_source_tree() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture_with_source(
        &sb,
        "chain",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/chain && cp payload.txt $DESTDIR$PREFIX/share/chain/",
        |src| {
            let deep = src.join("deep");
            fs::create_dir_all(&deep).expect("deep directory");
            std::os::unix::fs::symlink("..", deep.join("x")).expect("first link");
            std::os::unix::fs::symlink("x/../etc/passwd", deep.join("a")).expect("second link");
        },
    );

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "the chained links were accepted:\n{text}"
    );
    assert!(
        text.contains("escapes the tree"),
        "the refusal did not name the escape:\n{text}"
    );
}

#[test]
fn an_archive_without_a_recipe_is_imported() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_archive(
        &sb,
        "thing-1.2.0-x86_64.tar",
        &[
            ("usr/bin/thing", b"#!/bin/sh\necho thing\n"),
            ("usr/share/thing/data.txt", b"data\n"),
        ],
    );
    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(out.contains("import"), "no import line:\n{out}");
    assert!(sb.root.join("usr/bin/thing").exists());
    assert!(sb.ok(&["--file", "/usr/bin/thing"]).contains("thing"));
    sb.ok(&["--verify"]);
    sb.ok(&["remove", "thing"]);
    assert!(!sb.root.join("usr/bin/thing").exists());
}

#[test]
fn an_archive_that_does_not_match_the_pin_is_refused_until_it_is_repinned() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("pinned-1.0.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/pinned", b"binary\n".as_slice(), 0o755, 0)]),
    )
    .expect("write archive");
    let recipe = sb.recipe_dir().join("pinned.port");
    fs::write(
        &recipe,
        "package.name = pinned\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = pinned-1.0.tar\n\
         source.sha256 = 1111111111111111111111111111111111111111111111111111111111111111\n\
         install.prefix = /\n",
    )
    .expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an archive with a foreign hash was accepted:\n{text}"
    );
    assert!(
        text.contains("does not match the hash pinned"),
        "the refusal does not explain the pin:\n{text}"
    );
    assert!(
        text.contains("11111111111111"),
        "the refusal does not show the pinned hash:\n{text}"
    );
    assert!(!sb.root.join("usr/bin/pinned").exists());
    assert_failed_install_left_nothing(&sb, &["usr/bin/pinned"]);

    let out = sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_UPDATE_PIN", "1")],
    );
    assert!(
        out.contains("recipe   updated"),
        "the repin did not report the rewrite:\n{out}"
    );
    let written = fs::read_to_string(&recipe).expect("read recipe");
    assert!(
        !written.contains("11111111111111"),
        "the recipe still holds the old pin:\n{written}"
    );
    assert!(
        sb.root.join("usr/bin/pinned").exists(),
        "the repinned archive was not installed"
    );
}

#[test]
fn an_imported_link_to_another_package_is_left_absolute() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let src = sb.root.join("fixtures/escape");
    fs::create_dir_all(src.join("usr/lib")).expect("lib");
    fs::write(src.join("usr/lib/liby.so.1"), "elf\n").expect("file");
    std::os::unix::fs::symlink("/nope/nowhere", src.join("usr/lib/liby.so")).expect("link");
    let archive = sb.root.join("fixtures/escape-1.0.tar");
    assert!(
        Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .arg("usr")
            .status()
            .expect("tar")
            .success(),
        "tar failed"
    );

    sb.ok(&["install", archive.to_str().unwrap()]);
    let store = fs::read_dir(sb.root.join("usr/portalis/packages"))
        .expect("store")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("a store directory");
    let target = fs::read_link(store.join("usr/lib/liby.so")).expect("store link");
    assert_eq!(
        target,
        Path::new("/nope/nowhere"),
        "a link to an uninstalled package was rewritten: {}",
        target.display()
    );
}

#[test]
fn an_archive_wrapped_in_a_directory_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_archive(
        &sb,
        "wrapped-1.0-x86_64.tar",
        &[("wrapped-1.0/usr/bin/inner", b"x\n")],
    );
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a wrapped archive was accepted:\n{text}"
    );
    assert!(
        text.contains("wrapped in a single directory"),
        "the refusal did not name the reason:\n{text}"
    );
}

#[test]
fn an_archive_whose_name_has_no_version_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_archive(&sb, "nameless.tar", &[("usr/bin/nameless", b"x\n")]);
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an unparsable name was accepted:\n{text}"
    );
    assert!(
        text.contains("cannot read a package name and version"),
        "the refusal was not actionable:\n{text}"
    );
}

#[test]
fn a_compressed_tar_is_imported_through_the_decompressor() {
    if !require_root() || !require_tool("zstd") {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let stage = sb.root.join("stage/usr/bin");
    fs::create_dir_all(&stage).expect("stage");
    fs::write(stage.join("tool"), b"binary\n").expect("member");
    let archive = sb.root.join("fixtures/zst-1.0-x86_64.tar.zst");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixtures");
    let status = std::process::Command::new("tar")
        .arg("-C")
        .arg(sb.root.join("stage"))
        .arg("--zstd")
        .arg("-cf")
        .arg(&archive)
        .arg("usr/bin/tool")
        .status()
        .expect("tar runs");
    assert!(status.success(), "tar could not write the archive");
    sb.ok(&["install", archive.to_str().unwrap()]);
    let live = sb.root.join("usr/bin/tool");
    assert!(live.exists(), "the compressed archive was not installed");
    let report = sb.ok(&["--verify"]);
    assert!(
        report.contains("clean"),
        "the imported tree does not verify: {report}"
    );
}

#[test]
fn a_setgid_file_keeps_the_group_the_archive_names() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let mut out = Vec::new();
    out.extend_from_slice(b"!<arch>\n");
    ar_write(
        &mut out,
        "control.tar",
        &raw_tar(&[("control", b"Package: grouped\nVersion: 2.0\n")]),
    );
    // tty is gid 5 on Debian and Ubuntu
    ar_write(
        &mut out,
        "data.tar",
        &raw_tar_full(&[("usr/bin/grouped", b"binary\n".as_slice(), 0o2755, 5)]),
    );
    let archive = sb.root.join("fixtures/grouped_2.0_amd64.deb");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixtures");
    fs::write(&archive, out).expect("write deb");

    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    let live = sb.root.join("usr/bin/grouped");
    let meta = fs::metadata(&live).expect("live file");
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777;
    assert!(mode & 0o2000 != 0, "the setgid bit was dropped: {mode:04o}");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        meta.gid(),
        5,
        "the file runs with group {} instead of the group the archive named",
        meta.gid()
    );
}

#[test]
fn a_group_name_is_resolved_in_the_target_root() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // a group that only exists inside the tree being installed into
    let etc = sb.root.join("etc");
    fs::write(etc.join("group"), "root:x:0:\ncustom:x:4321:\n").expect("write group file");
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("offline-1.0.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/offline", b"binary\n".as_slice(), 0o2755, 0)]),
    )
    .expect("write archive");
    let recipe = format!(
        "package.name = offline\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         install.prefix = /\n\
         install.setgid = usr/bin/offline:custom\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("offline.port"), recipe).expect("write recipe");

    sb.ok(&["install", archive.to_str().unwrap()]);
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(sb.root.join("usr/bin/offline")).expect("live file");
    assert_eq!(
        meta.gid(),
        4321,
        "the group was resolved outside the target root"
    );
}

#[test]
fn an_absolute_symlink_in_a_source_archive_is_rejected() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // Source archives reject absolute links; binary packages keep them.
    let archive = fixture_with_source(
        &sb,
        "abs",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/abs",
        |source| {
            std::os::unix::fs::symlink("/usr/share/target", source.join("absolute-link"))
                .expect("symlink");
        },
    );

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a source archive carrying an absolute symlink was accepted"
    );
    assert!(
        !sb.root.join("usr/bin/abs").exists(),
        "a rejected archive still produced links"
    );
}

#[test]
fn a_symlink_escaping_the_source_tree_is_rejected() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture_with_source(
        &sb,
        "rel",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/rel",
        |source| {
            std::os::unix::fs::symlink("../../../outside", source.join("escapes"))
                .expect("symlink");
        },
    );

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "an archive whose symlink leaves the build tree was accepted"
    );
}

#[test]
fn an_absolute_member_is_rejected() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let outside = tempfile::tempdir().expect("outside directory");
    let planted = outside.path().join("planted.port");
    let member = planted.to_string_lossy().to_string();
    let members: [(&str, &[u8]); 2] = [
        ("absolute-1.0/payload.txt", b"hello\n"),
        (member.as_str(), b"package.name = planted\n"),
    ];
    let archive = fixture_from_raw_tar(&sb, "absolute", &members);

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "an archive with an absolute member name was accepted"
    );
    assert!(
        !planted.exists(),
        "an absolute member wrote outside the build tree"
    );
    assert!(
        !sb.root.join("etc/portalis/packages/planted.port").exists(),
        "an absolute member wrote into the target tree"
    );
}

#[test]
fn a_device_node_in_the_archive_is_rejected() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    // type flag '3' is a character device; unpacking runs as the builder, which
    // has no permission to create one
    let archive = sb.root.join("fixtures/dev-1.0.tar");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixture directory");
    fs::write(
        &archive,
        raw_tar_typed(&[
            ("dev-1.0/payload.txt", b"hello\n", b'0'),
            ("dev-1.0/console", b"", b'3'),
        ]),
    )
    .expect("write raw tar");
    let recipe = format!(
        "package.name = dev\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/dev && cp payload.txt $DESTDIR$PREFIX/share/dev/\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("dev.port"), recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "an archive carrying a device node was accepted:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("unsupported type") || text.contains("unsupported member type"),
        "the archive was rejected for the wrong reason: {text}"
    );
    let packages = sb.root.join("usr/portalis/packages");
    let stores = fs::read_dir(&packages)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .filter(|name| name.starts_with("dev-"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        stores.is_empty(),
        "a rejected archive still produced a store entry: {stores:?}"
    );
}

#[test]
fn installs_from_a_compressed_archive() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    // xz is the common shape for a source archive; the unpacker has to choose
    // the decompressor from the file's first bytes
    let top = "squeezed-1.0";
    let src = sb.root.join("fixtures").join(top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), "hello\n").expect("fixture payload");
    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.xz"));
    let status = Command::new("tar")
        .arg("-cJf")
        .arg(&archive)
        .arg("-C")
        .arg(&fixtures)
        .arg(top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let recipe = format!(
        "package.name = squeezed\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/squeezed && cp payload.txt $DESTDIR$PREFIX/share/squeezed/\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("squeezed.port"), recipe).expect("write recipe");

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "the compressed package was not applied:\n{out}"
    );
    assert!(sb.root.join("usr/share/squeezed/payload.txt").exists());
    assert!(sb.ok(&["--verify"]).contains("clean"));
}

#[test]
fn installs_from_a_zstd_archive() {
    if !require_root() {
        return;
    }
    if Command::new("zstd").arg("--version").output().is_err()
        && allow_skip("zstd is not installed")
    {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    let top = "pressed-1.0";
    let src = sb.root.join("fixtures").join(top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), "hello\n").expect("fixture payload");
    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.zst"));
    let script = format!(
        "tar -cf - -C '{}' '{}' | zstd -q -o '{}'",
        fixtures.display(),
        top,
        archive.display()
    );
    let status = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .status()
        .expect("shell available");
    assert!(status.success(), "packing with zstd failed");

    let recipe = format!(
        "package.name = pressed\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/pressed && cp payload.txt $DESTDIR$PREFIX/share/pressed/\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("pressed.port"), recipe).expect("write recipe");

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "zstd archive was not applied:\n{out}"
    );
    assert!(sb.root.join("usr/share/pressed/payload.txt").exists());
}

#[test]
fn installs_from_a_bzip2_archive() {
    if !require_root() {
        return;
    }
    if Command::new("bzip2").arg("--help").output().is_err() && allow_skip("bzip2 is not installed")
    {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    let top = "buzzed-1.0";
    let src = sb.root.join("fixtures").join(top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), "hello\n").expect("fixture payload");
    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.bz2"));
    let status = Command::new("tar")
        .arg("-cjf")
        .arg(&archive)
        .arg("-C")
        .arg(&fixtures)
        .arg(top)
        .status()
        .expect("tar available");
    assert!(status.success(), "packing with bzip2 failed");

    let recipe = format!(
        "package.name = buzzed\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/buzzed && cp payload.txt $DESTDIR$PREFIX/share/buzzed/\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("buzzed.port"), recipe).expect("write recipe");

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "bzip2 archive was not applied:\n{out}"
    );
    assert!(sb.root.join("usr/share/buzzed/payload.txt").exists());
}

#[test]
fn installs_an_archive_with_trailing_padding() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    // tar pads the stream after the end-of-archive marker; a reader that stops
    // there leaves the decompressor blocked on a full pipe
    let top = "padded-1.0";
    let src = sb.root.join("fixtures").join(top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), "body\n").expect("fixture payload");
    let fixtures = sb.root.join("fixtures");
    let plain = fixtures.join(format!("{top}.tar"));
    let status = Command::new("tar")
        .arg("-cf")
        .arg(&plain)
        .arg("-C")
        .arg(&fixtures)
        .arg(top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");
    let mut padded = fs::read(&plain).expect("read tar");
    padded.extend(std::iter::repeat_n(0u8, 200 * 1024));
    fs::write(&plain, &padded).expect("pad the archive");

    let gz = Command::new("gzip")
        .arg("-c")
        .arg(&plain)
        .output()
        .expect("gzip");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    fs::write(&archive, gz.stdout).expect("write gzip");

    let recipe = format!(
        "package.name = padded\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/padded && cp payload.txt $DESTDIR$PREFIX/share/padded/\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("padded.port"), recipe).expect("write recipe");

    // a bounded wait
    let out = Command::new("timeout")
        .arg("30")
        .arg(env!("CARGO_BIN_EXE_portalis"))
        .arg("install")
        .arg(&archive)
        .env("PORTALIS_ROOT", &sb.root)
        .env("PORTALIS_NO_BWRAP", "1")
        .output()
        .expect("running portalis");
    assert!(
        out.status.success(),
        "a padded archive did not install: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sb.root.join("usr/share/padded/payload.txt").exists());
}

/// Bytes flipped across a valid archive end in a refusal or an install, never
/// in a crash: the parser and the unpacker may reject anything they cannot read.
#[test]
fn a_mutated_archive_never_crashes_the_cli() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let rounds: usize = std::env::var("PORTALIS_FUZZ_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40);
    let archive = fixture(
        &sb,
        "mutated",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/mutated",
    );
    // the plain tar reaches the header parser; the gzip one stops at the stream
    let plain_dir = sb.root.join("fixtures/plain");
    fs::create_dir_all(&plain_dir).expect("plain dir");
    fs::write(plain_dir.join("payload.txt"), b"payload\n").expect("payload");
    let plain = sb.root.join("fixtures/mutated-case-1.0.tar");
    let packed = Command::new("tar")
        .arg("-cf")
        .arg(&plain)
        .arg("-C")
        .arg(&plain_dir)
        .arg("payload.txt")
        .output()
        .expect("running tar");
    assert!(packed.status.success(), "tar failed: {packed:?}");

    for (label, original, file_name) in [
        (
            "tar",
            fs::read(&plain).expect("plain tar"),
            "mutated-case-1.0.tar",
        ),
        (
            "tar.gz",
            fs::read(&archive).expect("archive"),
            "mutated-case-1.0.tar.gz",
        ),
    ] {
        let path = sb.root.join(format!("fixtures/{file_name}"));
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        for round in 0..rounds {
            let mut bytes = original.clone();
            for _ in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let index = (seed as usize) % bytes.len();
                bytes[index] = (seed >> 32) as u8;
            }
            fs::write(&path, &bytes).expect("write case");
            let out = sb.run(&["install", path.to_str().unwrap()]);
            let code = out.status.code();
            assert!(
                code == Some(0) || code == Some(1),
                "{label} round {round} ended with {code:?} instead of a refusal: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

/// Rewrites one header field of a member and repairs the header checksum.
fn field_mutation(tar: &[u8], offset: usize, value: &[u8], length: usize) -> Vec<u8> {
    let mut bytes = tar.to_vec();
    let start = offset;
    let end = start + length;
    for byte in &mut bytes[start..end] {
        *byte = 0;
    }
    bytes[start..start + value.len()].copy_from_slice(value);
    for byte in &mut bytes[148..156] {
        *byte = b' ';
    }
    let sum: u32 = bytes[..512].iter().map(|byte| *byte as u32).sum();
    let text = format!("{sum:06o}\0 ");
    bytes[148..156].copy_from_slice(text.as_bytes());
    bytes
}

/// Fields the parser reads are changed one at a time: every case ends in a
/// refusal or an install, and none may crash.
#[test]
fn a_mutated_header_field_never_crashes_the_cli() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let mut tar = raw_tar(&[("payload.txt", b"payload\n")]);
    // pad to a whole member plus a terminator, as a real archive is
    tar.resize(tar.len().div_ceil(1024) * 1024, 0);
    let path = sb.root.join("fixtures/field-1.0.tar");
    fs::create_dir_all(path.parent().expect("fixtures")).expect("fixtures");

    let cases: [(&str, usize, &[u8], usize); 8] = [
        ("name", 0, b"../../etc/shadow", 100),
        ("mode", 100, b"0000009\0", 8),
        ("size", 124, b"99999999999\0", 12),
        ("typeflag", 156, b"5", 1),
        ("linkname", 157, b"../../../etc/passwd", 100),
        ("long name", 0, &[b'a'; 100], 100),
        ("gid", 116, b"7777777\0", 8),
        ("mtime", 136, b"77777777777\0", 12),
    ];
    for (label, offset, value, length) in cases {
        fs::write(&path, field_mutation(&tar, offset, value, length)).expect("write case");
        let out = sb.run(&["install", path.to_str().unwrap()]);
        let code = out.status.code();
        assert!(
            code == Some(0) || code == Some(1),
            "{label} ended with {code:?} instead of a refusal: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
