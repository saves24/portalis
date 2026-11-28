use super::*;

#[test]
fn an_imported_link_into_the_live_root_keeps_its_form() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // the target lives in the target root, supplied by another package
    fs::create_dir_all(sb.root.join("usr/lib")).expect("live lib");
    fs::write(sb.root.join("usr/lib/libx.so.6"), "elf\n").expect("soname in the live root");
    let src = sb.root.join("fixtures/linker");
    fs::create_dir_all(src.join("usr/lib")).expect("lib");
    std::os::unix::fs::symlink("/usr/lib/libx.so.6", src.join("usr/lib/libx.so")).expect("link");
    fs::write(src.join("usr/lib/libx.so.7"), "elf\n").expect("a file of this package");
    let archive = sb.root.join("fixtures/linker-1.0.tar");
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
    let target = fs::read_link(store.join("usr/lib/libx.so")).expect("store link");
    assert_eq!(
        target,
        Path::new("/usr/lib/libx.so.6"),
        "a link into the target root was rewritten: {}",
        target.display()
    );
}

#[test]
fn a_link_to_a_shared_temporary_directory_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let source = sb.root.join("fixtures/link-target");
    fs::create_dir_all(source.join("usr/bin")).expect("link source");
    let target = format!("/tmp/portalis-shared-{}", std::process::id());
    std::os::unix::fs::symlink(&target, source.join("usr/bin/evil")).expect("link");
    let archive = sb.root.join("fixtures/link-target-1.0.tar");
    assert!(
        Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("usr")
            .status()
            .expect("tar")
            .success(),
        "tar failed"
    );
    fs::write(
        sb.recipe_dir().join("link-target.port"),
        format!(
            "package.name = link-target\npackage.version = 1.0\n\
             source.kind = binary\nsource.file = link-target-1.0.tar\n\
             source.sha256 = {}\ninstall.prefix = /\n",
            sha256_file(&archive)
        ),
    )
    .expect("recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "an unsafe link was installed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !sb.root.join("usr/bin/evil").exists(),
        "the unsafe link reached the live tree"
    );
}

#[test]
fn a_link_to_a_host_configuration_file_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let source = sb.root.join("fixtures/host-config");
    fs::create_dir_all(source.join("usr/bin")).expect("link source");
    std::os::unix::fs::symlink("/etc/hosts", source.join("usr/bin/hosts-link")).expect("link");
    let archive = sb.root.join("fixtures/host-config-1.0.tar");
    assert!(
        Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("usr")
            .status()
            .expect("tar")
            .success(),
        "tar failed"
    );
    fs::write(
        sb.recipe_dir().join("host-config.port"),
        format!(
            "package.name = host-config\npackage.version = 1.0\n\
             source.kind = binary\nsource.file = host-config-1.0.tar\n\
             source.sha256 = {}\ninstall.prefix = /\n",
            sha256_file(&archive)
        ),
    )
    .expect("recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a link to a host configuration file was installed:\n{text}"
    );
    assert!(
        !sb.root.join("usr/bin/hosts-link").exists(),
        "the host link reached the live tree"
    );
    assert!(
        text.contains("protected host path") || text.contains("host-sensitive"),
        "the refusal did not name the protected target:\n{text}"
    );
}

#[test]
fn a_new_version_of_the_same_recipe_needs_the_pin() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("bumped-1.1.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/bumped", b"binary\n".as_slice(), 0o755, 0)]),
    )
    .expect("write archive");
    let recipe = sb.recipe_dir().join("bumped.port");
    fs::write(
        &recipe,
        "package.name = bumped\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = bumped-1.0.tar\n\
         source.sha256 = 2222222222222222222222222222222222222222222222222222222222222222\n\
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
        "a bumped archive was accepted without the pin:\n{text}"
    );
    assert!(
        text.contains("the recipe pins version 1.0"),
        "the refusal does not name the version:\n{text}"
    );
    assert!(
        text.contains("PORTALIS_UPDATE_PIN"),
        "the refusal does not name the switch:\n{text}"
    );

    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_UPDATE_PIN", "1")],
    );
    let written = fs::read_to_string(&recipe).expect("read recipe");
    assert!(
        written.contains("package.version = 1.1"),
        "the recipe version was not bumped:\n{written}"
    );
    assert!(
        written.contains("bumped-1.1.tar"),
        "the recipe still names the old archive:\n{written}"
    );
}

#[test]
fn an_import_works_without_a_recipe_directory() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    fs::remove_dir_all(sb.recipe_dir()).expect("remove the recipe directory");
    let archive = raw_archive(
        &sb,
        "norecipes-1.0-x86_64.tar",
        &[("usr/bin/norecipes", b"#!/bin/sh\n")],
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        sb.root.join("usr/bin/norecipes").exists(),
        "the import did not apply"
    );
}

#[test]
fn a_member_whose_name_only_looks_like_the_payload_is_not_used() {
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
        &raw_tar(&[("control", b"Package: near\nVersion: 1.0\n")]),
    );
    // the payload member name is a prefix of another member
    ar_write(
        &mut out,
        "data.tarfoo",
        &raw_tar(&[("usr/bin/x", b"binary\n")]),
    );
    let archive = sb.root.join("fixtures/near_1.0_amd64.deb");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixtures");
    fs::write(&archive, out).expect("write deb");

    let result = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !result.status.success(),
        "a member named data.tarfoo was accepted as the payload"
    );
    let text = String::from_utf8_lossy(&result.stderr);
    assert!(
        text.contains("data.tar"),
        "the refusal does not say what is missing: {text}"
    );
    assert!(
        !sb.root.join("usr/bin/x").exists(),
        "the payload was unpacked anyway"
    );
}

#[test]
fn a_broken_recipe_stops_the_install_instead_of_importing() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("broken-1.0-x86_64.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/broken", b"binary\n".as_slice(), 0o2755, 0)]),
    )
    .expect("write archive");
    // the recipe names no group
    fs::write(
        sb.recipe_dir().join("broken.port"),
        "package.name = broken\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = broken-1.0-x86_64.tar\n\
         source.sha256 = 0000000000000000000000000000000000000000000000000000000000000000\n\
         install.prefix = /\n\
         install.setgid = usr/bin/broken\n",
    )
    .expect("write recipe");

    let out = sb.run_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    assert!(
        !out.status.success(),
        "a broken recipe was ignored and the archive imported instead"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("does not load"),
        "the refusal does not name the broken recipe: {text}"
    );
    assert_failed_install_left_nothing(&sb, &["usr/bin/broken"]);
}

#[test]
fn a_failed_group_lookup_leaves_no_store_behind() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("nogroup-1.0.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/x", b"binary\n".as_slice(), 0o755, 0)]),
    )
    .expect("write archive");
    let recipe = format!(
        "package.name = nogroup\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         install.prefix = /\n\
         install.setgid = usr/bin/x:no-such-group\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("nogroup.port"), recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(!out.status.success(), "the install should have failed");
    let stores = sb.root.join("usr/portalis/packages");
    let left = match fs::read_dir(&stores) {
        Ok(entries) => entries.count(),
        Err(_) => 0,
    };
    assert_eq!(left, 0, "a failed install left {left} store director(ies)");
}

#[test]
fn a_group_name_the_recipe_cannot_carry_is_refused() {
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
        &raw_tar(&[("control", b"Package: spaced\nVersion: 1.0\n")]),
    );
    ar_write(
        &mut out,
        "data.tar",
        &raw_tar_gname(&[(
            "usr/bin/spaced",
            b"binary\n".as_slice(),
            0o2755,
            0,
            "bad group",
        )]),
    );
    let archive = sb.root.join("fixtures/spaced_1.0_amd64.deb");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixtures");
    fs::write(&archive, out).expect("write deb");

    let result = sb.run_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    assert!(
        !result.status.success(),
        "a group name with a space was accepted"
    );
    let text = String::from_utf8_lossy(&result.stderr);
    assert!(
        text.contains("cannot carry"),
        "the refusal does not explain the group name: {text}"
    );
}

#[test]
fn a_setgid_member_follows_its_group_name() {
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
        &raw_tar(&[("control", b"Package: named\nVersion: 1.0\n")]),
    );
    // tty is gid 5; the numeric gid points somewhere else on purpose
    ar_write(
        &mut out,
        "data.tar",
        &raw_tar_gname(&[("usr/bin/named", b"binary\n".as_slice(), 0o2755, 9999, "tty")]),
    );
    let archive = sb.root.join("fixtures/named_1.0_amd64.deb");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixtures");
    fs::write(&archive, out).expect("write deb");

    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(sb.root.join("usr/bin/named")).expect("live file");
    assert_eq!(
        meta.gid(),
        5,
        "the group name was ignored and gid {} was used",
        meta.gid()
    );
}

#[test]
fn an_unknown_group_name_is_refused_at_install() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("groupname-1.0.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/x", b"binary\n".as_slice(), 0o755, 0)]),
    )
    .expect("write archive");
    let recipe = format!(
        "package.name = groupname\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         install.prefix = /\n\
         install.setgid = usr/bin/x:no-such-group\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("groupname.port"), recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a package naming a group the system does not have was installed"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("no group named no-such-group"),
        "the refusal does not name the missing group: {text}"
    );
}

#[test]
fn a_base256_group_id_is_read_not_treated_as_root() {
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
        &raw_tar(&[("control", b"Package: basegid\nVersion: 1.0\n")]),
    );
    ar_write(
        &mut out,
        "data.tar",
        &raw_tar_base256_gid(&[("usr/bin/basegid", b"binary\n".as_slice(), 0o2755, 5)]),
    );
    let archive = sb.root.join("fixtures/basegid_1.0_amd64.deb");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixtures");
    fs::write(&archive, out).expect("write deb");

    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(sb.root.join("usr/bin/basegid")).expect("live file");
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777;
    assert!(mode & 0o2000 != 0, "the setgid bit was dropped: {mode:04o}");
    assert_eq!(
        meta.gid(),
        5,
        "a base-256 group id was read as {}",
        meta.gid()
    );
}

#[test]
fn a_rejected_local_import_leaves_no_temporary_directory() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let temp = sb.root.join("tmp");
    fs::create_dir_all(&temp).expect("temp dir");
    let archive = raw_deb(
        &sb,
        "localrefused_1.0_amd64.deb",
        &[("usr/bin/x", b"binary\n".as_slice(), 0o755)],
    );
    let before = fs::read_dir(&temp).expect("list").count();
    let out = {
        let mut command = sb.command();
        command.env("TMPDIR", &temp);
        command.env("PORTALIS_LOCAL", "1");
        command
            .args(["install", archive.to_str().unwrap()])
            .output()
            .expect("running portalis")
    };
    assert!(
        !out.status.success(),
        "--local on a prebuilt package was accepted"
    );
    let after = fs::read_dir(&temp).expect("list").count();
    assert_eq!(
        before,
        after,
        "the refused import left {} temporary entries behind",
        after - before
    );
}

#[test]
fn an_import_with_a_privileged_file_needs_the_flag() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb(
        &sb,
        "privileged_1.0_amd64.deb",
        &[("usr/bin/helper", b"binary\n".as_slice(), 0o4755)],
    );
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "an import carrying a privileged bit was accepted without PORTALIS_KEEP_PRIVILEGED"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("PORTALIS_KEEP_PRIVILEGED"),
        "the refusal does not say how to proceed: {text}"
    );
}

#[test]
fn a_recipe_may_name_a_setgid_path_with_a_dot_slash() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("slashed-3.0.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/slashed", b"binary\n".as_slice(), 0o2755, 5)]),
    )
    .expect("write archive");

    let recipe = format!(
        "package.name = slashed\n\
         package.version = 3.0\n\
         source.kind = binary\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         install.prefix = /\n\
         install.setgid = ./usr/bin/slashed:5\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("slashed.port"), recipe).expect("write recipe");

    sb.ok(&["install", archive.to_str().unwrap()]);
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(sb.root.join("usr/bin/slashed")).expect("live file");
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777;
    assert!(
        mode & 0o2000 != 0,
        "a setgid path written with ./ was ignored: mode {mode:04o}"
    );
    assert_eq!(meta.gid(), 5, "the declared group was not applied");
}

#[test]
fn a_setgid_member_named_with_a_colon_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb(
        &sb,
        "colon_1.0_amd64.deb",
        &[("usr/bin/a:b", b"binary\n".as_slice(), 0o2755)],
    );
    let out = sb.run_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    assert!(
        !out.status.success(),
        "a setgid member whose name holds a colon was accepted"
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("cannot express"),
        "the refusal does not explain the colon: {text}"
    );
}

#[test]
fn a_setgid_file_keeps_the_setgid_bit_only() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb(
        &sb,
        "grouped_1.0_amd64.deb",
        &[("usr/bin/grouped", b"binary\n".as_slice(), 0o2755)],
    );
    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    let live = sb.root.join("usr/bin/grouped");
    let permissions = fs::metadata(&live).expect("live file").permissions();
    let mode = std::os::unix::fs::PermissionsExt::mode(&permissions) & 0o7777;
    assert!(
        mode & 0o2000 != 0,
        "the setgid bit was dropped: mode {mode:04o}"
    );
    assert!(
        mode & 0o4000 == 0,
        "a setgid file came back setuid: mode {mode:04o}"
    );
}

#[test]
fn an_import_leaves_no_temporary_file_behind() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let temp = sb.root.join("tmp");
    fs::create_dir_all(&temp).expect("temp dir");
    let archive = raw_deb(
        &sb,
        "cleanly_1.0_amd64.deb",
        &[("usr/bin/clean", b"binary\n".as_slice(), 0o755)],
    );
    let before = fs::read_dir(&temp).expect("list").count();
    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("TMPDIR", temp.to_str().unwrap())],
    );
    let after = fs::read_dir(&temp).expect("list").count();
    assert_eq!(
        before,
        after,
        "the import left {} file(s) in {}",
        after - before,
        temp.display()
    );
}

#[test]
fn the_control_file_names_the_package_not_the_file_name() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb_with_control(
        &sb,
        "whatever_9.9_amd64.deb",
        b"Package: real-name\nVersion: 1.2.3\n",
        &[("usr/bin/thing", b"#!/bin/sh\n".as_slice(), 0o755)],
    );
    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("real-name 1.2.3"),
        "the control fields were not used:\n{out}"
    );
    assert!(sb.ok(&["--file", "/usr/bin/thing"]).contains("real-name"));
}

#[test]
fn a_deb_package_is_imported() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb(
        &sb,
        "thing_1.2.0_amd64.deb",
        &[
            (
                "usr/bin/thing",
                b"#!/bin/sh\necho thing\n".as_slice(),
                0o755,
            ),
            ("usr/share/thing/data.txt", b"data\n".as_slice(), 0o644),
        ],
    );
    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(out.contains("import"), "no import line:\n{out}");
    assert!(sb.root.join("usr/bin/thing").exists());
    assert!(sb.root.join("usr/share/thing/data.txt").exists());
    sb.ok(&["--verify"]);
    sb.ok(&["remove", "thing"]);
    assert!(!sb.root.join("usr/bin/thing").exists());
}

#[test]
fn a_deb_shipping_a_setuid_file_keeps_the_bit() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb(
        &sb,
        "sandboxed_1.0_amd64.deb",
        &[("usr/bin/helper", b"binary\n".as_slice(), 0o4755)],
    );
    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    let live = sb.root.join("usr/bin/helper");
    let permissions = fs::metadata(&live).expect("live file").permissions();
    let mode = std::os::unix::fs::PermissionsExt::mode(&permissions) & 0o7777;
    assert!(
        mode & 0o4000 != 0,
        "the setuid bit was dropped: mode {mode:04o}"
    );
}

#[test]
fn a_held_recipe_is_not_removed_without_force() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "held",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/held && cp payload.txt $DESTDIR$PREFIX/share/held/",
    );
    // the fixture recipe is rewritten with the hold flag
    let recipe_path = sb.recipe_dir().join("held.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("package.hold = true\n");
    fs::write(&recipe_path, recipe).expect("write recipe");
    sb.ok(&["install", archive.to_str().unwrap()]);

    let out = sb.run(&["remove", "held"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "a held package was removed:\n{text}");
    assert!(
        text.contains("marks it held"),
        "the refusal did not mention the recipe:\n{text}"
    );
    assert!(sb.root.join("usr/share/held/payload.txt").exists());

    let out = sb.run(&["remove", "held", "--force"]);
    assert!(
        out.status.success(),
        "the forced removal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_cargo_package_installs_without_crates_tracking_files() {
    if !require_root() {
        return;
    }
    // the build step resolves programs from a fixed PATH
    let cargo_missing = Command::new("sh")
        .args(["-c", "PATH=/usr/local/bin:/usr/bin:/bin command -v cargo"])
        .output()
        .map(|out| !out.status.success())
        .unwrap_or(true);
    if cargo_missing && allow_skip("cargo is not reachable from the build PATH") {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = cargo_fixture(&sb, "carbin", "0.1.0");

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "the crate was not installed:\n{out}"
    );

    let mut binary: Option<PathBuf> = None;
    let mut tracking = Vec::new();
    let store = sb.root.join("usr/portalis/packages");
    let mut stack = vec![store];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "carbin" {
                binary = Some(path.clone());
            }
            if name == ".crates.toml" || name == ".crates2.json" {
                tracking.push(path);
            }
        }
    }

    let binary = binary.expect("the installed crate has no binary in the store");
    assert!(
        binary.ends_with("usr/bin/carbin"),
        "the binary did not land in usr/bin: {}",
        binary.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&binary)
            .expect("metadata")
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "the binary is not executable: {mode:o}");
    }
    assert!(
        tracking.is_empty(),
        "cargo left its tracking files in the package: {tracking:?}"
    );
}

#[test]
fn an_unknown_trusted_key_rejects_the_package() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "signed",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/signed",
    );

    let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let foreign = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let private = sb.root.join("etc/portalis/signing.key");
    fs::write(&private, signing.to_bytes()).expect("signing key");
    let mut permissions = fs::metadata(&private).expect("key metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
    fs::set_permissions(&private, permissions).expect("key mode");
    let keys = sb.root.join("etc/portalis/trusted-keys");
    fs::create_dir_all(&keys).expect("trusted key directory");
    fs::write(
        keys.join("someone-else.pub"),
        foreign.verifying_key().to_bytes(),
    )
    .expect("foreign key");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a package signed by this machine was accepted while only a foreign key was trusted"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("signature") || text.contains("key"),
        "the rejection did not mention the signature: {text}"
    );
    assert!(
        !sb.root.join("usr/bin/signed").exists(),
        "a rejected package was installed anyway"
    );
}

#[test]
fn installs_a_prebuilt_binary_package() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    // a binary package ships its files at the archive root, with no build step
    let top = "tool-2.0";
    let src = sb.root.join("fixtures").join(top).join("usr/bin");
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("tool"), b"#!/bin/sh\necho tool\n").expect("fixture payload");
    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(fixtures.join(top))
        .arg("usr")
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let recipe = format!(
        "package.name = tool\n\
         package.version = 2.0\n\
         source.kind = binary\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         install.prefix = /\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("tool.port"), recipe).expect("write recipe");

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "binary package was not applied:\n{out}"
    );
    assert!(
        sb.root.join("usr/bin/tool").exists(),
        "binary payload missing"
    );
    assert!(sb.ok(&["--verify"]).contains("clean"));

    sb.ok(&["remove", "tool"]);
    assert!(!sb.root.join("usr/bin/tool").exists());
}

#[test]
fn a_member_climbing_out_of_the_tree_is_rejected() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture_from_raw_tar(
        &sb,
        "climb",
        &[
            ("climb-1.0/payload.txt", b"hello\n"),
            ("climb-1.0/../../../escape.txt", b"escaped\n"),
        ],
    );

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "an archive whose member climbs out of the tree was accepted"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("parent") || text.contains("escape") || text.contains("climb"),
        "the rejection did not name the problem: {text}"
    );
    let mut stack = vec![sb.root.clone()];
    let mut escaped = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|name| name.to_str()) == Some("escape.txt") {
                escaped.push(path.clone());
            }
            if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                stack.push(path);
            }
        }
    }
    assert!(
        escaped.is_empty(),
        "a member escaped the build tree: {escaped:?}"
    );
}

#[test]
fn a_binary_package_with_an_escaping_link_is_rejected() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    // a binary payload may carry absolute links, but a relative one that climbs
    // out of the package is still refused
    let top = "evil-1.0";
    let src = sb.root.join("fixtures").join(top).join("usr/share/evil");
    fs::create_dir_all(&src).expect("fixture source");
    std::os::unix::fs::symlink("../../../../../etc/passwd", src.join("link")).expect("symlink");
    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(fixtures)
        .arg(top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    let recipe = format!(
        "package.name = evil\n\
         package.version = 1.0\n\
         source.kind = binary\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         install.prefix = /\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("evil.port"), recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a binary package with an escaping link was accepted"
    );
    assert!(
        !sb.root.join("usr/share/evil/link").exists(),
        "the escaping link reached the live tree"
    );
}
