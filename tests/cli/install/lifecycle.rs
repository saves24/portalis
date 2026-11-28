use super::*;

/// A failure reports a code a caller can branch on.
#[test]
fn a_failure_carries_a_code() {
    if !require_root() {
        return;
    }
    let sb = Sandbox::new();
    let missing = sb.root.join("fixtures/absent-1.0.tar.gz");
    let out = sb.events(&["install", missing.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "installing a missing archive succeeded"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let event: serde_json::Value = serde_json::from_str(stdout.lines().last().expect("an event"))
        .expect("the failure is an event");
    assert_eq!(event["event"], "error");
    assert_eq!(event["code"], "INPUT_MISSING");
}

#[test]
fn removing_a_package_whose_file_is_mapped_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "busy",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/busy && cp payload.txt $DESTDIR$PREFIX/share/busy/",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    let file = sb.root.join("usr/share/busy/payload.txt");
    assert!(file.exists());

    // a process that maps the file keeps it in use
    let mut holder = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import mmap,time; f=open({:?},'rb'); m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ); time.sleep(120)",
            file.to_str().unwrap()
        ))
        .spawn()
        .expect("python3");
    // the live path is a symlink into the store
    let mut mapped = false;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let maps = fs::read_to_string(format!("/proc/{}/maps", holder.id())).unwrap_or_default();
        if maps.contains("packages/busy-") {
            mapped = true;
            break;
        }
    }
    assert!(mapped, "the test process never mapped the file");

    let out = sb.run(&["remove", "busy"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "a mapped file was removed:\n{text}");
    assert!(
        text.contains("in use"),
        "the refusal did not explain why:\n{text}"
    );
    assert!(file.exists(), "the file went away anyway");

    let out = sb.run(&["remove", "busy", "--force"]);
    assert!(
        out.status.success(),
        "the forced removal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = holder.kill();
    let _ = holder.wait();
}

#[test]
fn a_boot_chain_package_is_not_removed_without_force() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "kernelish",
        "1.0",
        "/",
        "mkdir -p $DESTDIR/boot && cp payload.txt $DESTDIR/boot/kernelish",
    );
    assert!(sb
        .ok(&["install", archive.to_str().unwrap()])
        .contains("staged"));
    assert!(
        !sb.root.join("boot/kernelish").exists(),
        "a boot-chain package was written before activation"
    );
    sb.activate_pending();
    assert!(sb.root.join("boot/kernelish").exists());

    let out = sb.run(&["remove", "kernelish"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a boot-chain package was removed:\n{text}"
    );
    assert!(
        text.contains("boot chain"),
        "the refusal did not name the reason:\n{text}"
    );
    assert!(sb.root.join("boot/kernelish").exists());

    let out = sb.run(&["remove", "kernelish", "--force"]);
    assert!(
        out.status.success(),
        "the forced removal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_unfinished_activation_is_reported() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_archive(
        &sb,
        "thing-1.0-x86_64.tar",
        &[("usr/bin/thing", b"#!/bin/sh\n")],
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    // what a kill -9 between the first link and the commit leaves behind
    let marker = sb.root.join("var/lib/portalis/activating");
    fs::write(&marker, b"thing 1.0\n").expect("marker");

    let out = sb.run(&["--verify"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an unfinished activation was reported as clean:\n{text}"
    );
    assert!(
        text.contains("never finished"),
        "the report did not name the unfinished activation:\n{text}"
    );

    fs::remove_file(&marker).expect("remove marker");
    sb.ok(&["--verify"]);
}

/// A command that finishes leaves no operation marker behind.
#[test]
fn a_finished_remove_leaves_no_operation_marker() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "clean",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/clean",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    sb.ok(&["remove", "clean"]);
    let marker = sb.root.join("var/lib/portalis/operation");
    assert!(
        !marker.exists(),
        "a finished remove left its operation marker behind"
    );
    let journals: Vec<String> = fs::read_dir(sb.root.join("var/lib/portalis"))
        .expect("state directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with("operation-journal-"))
        .collect();
    assert!(
        journals.is_empty(),
        "a finished remove left an operation journal behind: {journals:?}"
    );
}

#[test]
fn a_zero_in_the_environment_does_not_force() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    fs::create_dir_all(sb.root.join("usr/bin")).expect("bin");
    fs::write(sb.root.join("usr/bin/occupied"), "user file\n").expect("unmanaged file");
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("occupied-1.0.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/occupied", b"binary\n".as_slice(), 0o755, 0)]),
    )
    .expect("write archive");

    let out = sb.run_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_FORCE", "0")],
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "PORTALIS_FORCE=0 forced the install anyway:\n{text}"
    );
    assert!(
        text.contains("unmanaged file exists"),
        "the refusal does not explain the conflict:\n{text}"
    );
    assert!(
        fs::read_to_string(sb.root.join("usr/bin/occupied"))
            .map(|body| body.contains("user file"))
            .unwrap_or(false),
        "the unmanaged file was replaced"
    );

    sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_FORCE", "1")],
    );
}

#[test]
fn removing_a_package_puts_back_the_file_it_took_over() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // a file the machine already has, owned by no package
    let legacy = sb.root.join("usr/share/legacy/thing.txt");
    fs::create_dir_all(legacy.parent().expect("parent")).expect("directories");
    fs::write(&legacy, "base system\n").expect("original file");

    let archive = fixture(
        &sb,
        "legacy",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/legacy && cp payload.txt $DESTDIR$PREFIX/share/legacy/thing.txt",
    );
    let out = sb.ok_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_FORCE", "1")],
    );
    assert!(
        out.contains("applied"),
        "the takeover was not applied:\n{out}"
    );
    assert!(
        fs::symlink_metadata(&legacy)
            .expect("live path")
            .file_type()
            .is_symlink(),
        "the package did not take the file over"
    );

    let out = sb.ok(&["remove", "legacy"]);
    assert!(out.contains("restored"), "no restore was reported:\n{out}");
    let content = fs::read_to_string(&legacy).expect("the original file is back");
    assert_eq!(content, "base system\n", "the wrong content came back");
}

#[test]
fn an_activation_that_keeps_an_unmanaged_file_does_not_delete_it() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let first = fixture(
        &sb,
        "keptfile",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/keptfile \
         && cp payload.txt $DESTDIR$PREFIX/share/keptfile/a.txt \
         && cp payload.txt $DESTDIR$PREFIX/share/keptfile/b.txt",
    );
    assert!(sb
        .ok(&["install", first.to_str().unwrap()])
        .contains("applied"));

    // the upgrade writes /boot and waits for the shutdown activation
    let second = fixture(
        &sb,
        "keptfile",
        "2.0",
        "/usr",
        "mkdir -p $DESTDIR/usr/share/keptfile $DESTDIR/boot \
         && cp payload.txt $DESTDIR/usr/share/keptfile/a.txt \
         && cp payload.txt $DESTDIR/usr/share/keptfile/b.txt \
         && cp payload.txt $DESTDIR/boot/keptfile",
    );
    let out = sb.ok(&["install", second.to_str().unwrap()]);
    assert!(out.contains("staged"), "expected a staged upgrade:\n{out}");
    assert!(
        !sb.root.join("boot/keptfile").exists(),
        "a staged upgrade wrote its late path before activation"
    );

    // an unmanaged file appears at one of the staged paths before shutdown
    let kept = sb.root.join("usr/share/keptfile/a.txt");
    fs::remove_file(&kept).expect("remove the installed link");
    fs::write(&kept, "user data\n").expect("user file");
    let other = sb.root.join("usr/share/keptfile/b.txt");
    let other_before = fs::read_link(&other).expect("the other link");

    let out = sb.activate_pending();
    assert!(
        out.contains("still unmanaged"),
        "the activation did not report the kept file:\n{out}"
    );
    assert_eq!(
        fs::read_to_string(&kept).expect("the user file was removed"),
        "user data\n",
        "the activation replaced an unmanaged file"
    );
    let other_after = fs::read_link(&other).expect("the other link");
    assert_eq!(
        other_before, other_after,
        "the link this attempt replaced was not restored"
    );
    assert!(
        sb.ok(&["--show", "keptfile"]).contains("1.0"),
        "the staged version took over after the rollback"
    );
}

#[test]
fn dropping_a_staged_copy_keeps_the_installed_version() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let first = fixture(
        &sb,
        "dual",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/dual && cp payload.txt $DESTDIR$PREFIX/share/dual/",
    );
    assert!(sb
        .ok(&["install", first.to_str().unwrap()])
        .contains("applied"));

    // the second version writes into /boot and waits for shutdown
    let second = fixture(
        &sb,
        "dual",
        "2.0",
        "/",
        "mkdir -p $DESTDIR$PREFIX/share/dual $DESTDIR/boot && cp payload.txt $DESTDIR$PREFIX/share/dual/ && cp payload.txt $DESTDIR/boot/dual",
    );
    let out = sb.ok(&["install", second.to_str().unwrap()]);
    assert!(out.contains("staged"), "expected a staged upgrade:\n{out}");
    assert!(
        !sb.root.join("boot/dual").exists(),
        "a staged upgrade wrote its late path before activation"
    );

    let out = sb.ok(&["remove", "dual", "--pending"]);
    assert!(out.contains("staged copy"), "unexpected output:\n{out}");
    assert!(
        sb.root.join("usr/share/dual/payload.txt").exists(),
        "the installed version was removed as well"
    );
    assert!(sb.ok(&["--show", "dual"]).contains("1.0"));
    assert!(sb.ok(&["--verify"]).contains("clean"));
    assert!(
        !sb.root.join("boot/dual").exists(),
        "a staged file was written"
    );
}

#[test]
fn remove_takes_the_package_out_again() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "gone",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/gone",
    );

    sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(sb.root.join("usr/bin/gone").exists());

    sb.ok(&["remove", "gone"]);
    assert!(
        !sb.root.join("usr/bin/gone").exists(),
        "link survived the removal"
    );
    assert!(sb.ok(&["--verify"]).contains("clean"));
}

#[test]
fn a_failed_rollback_can_be_retried() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let alpha = fixture(
        &sb,
        "alpha",
        "1.0",
        "/opt/alpha",
        "mkdir -p $DESTDIR$PREFIX/bin $DESTDIR$PREFIX/lib \
         && cp payload.txt $DESTDIR$PREFIX/bin/alpha \
         && cp payload.txt $DESTDIR$PREFIX/lib/alpha.so",
    );
    sb.ok(&["install", alpha.to_str().unwrap()]);

    let beta = fixture(
        &sb,
        "beta",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/beta",
    );
    sb.ok(&["install", beta.to_str().unwrap()]);

    // the generation recorded when alpha became active is the one to return to
    let history = sb.ok(&["--history"]);
    let target = history
        .lines()
        .find(|line| line.contains("activate alpha 1.0"))
        .and_then(|line| line.split_whitespace().next())
        .expect("alpha has an activation generation")
        .to_string();

    // Replaces the directory that holds the second link with a regular file.
    let blocked = sb.root.join("opt/alpha/lib");
    fs::remove_dir_all(&blocked).expect("drop the directory");
    fs::write(&blocked, b"not a directory").expect("block the path");

    let failed = sb.run(&["rollback", &target]);
    assert!(
        !failed.status.success(),
        "rollback reported success while a path was blocked"
    );

    // with the obstruction gone the same command has to finish the job
    fs::remove_file(&blocked).expect("clear the block");
    fs::create_dir_all(&blocked).expect("restore the directory");
    sb.ok(&["rollback", &target]);
    assert!(
        sb.root.join("opt/alpha/bin/alpha").exists(),
        "retried rollback did not restore the older tree"
    );
    assert!(
        !sb.root.join("usr/bin/beta").exists(),
        "retried rollback left the newer package in place"
    );
    assert!(sb.ok(&["--verify"]).contains("clean"));
}

#[test]
fn a_rollback_leaves_the_packages_verifiable() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    let first = fixture(
        &sb,
        "kept",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/kept \
         && cp payload.txt $DESTDIR$PREFIX/share/kept/a.txt",
    );
    sb.ok(&["install", first.to_str().unwrap()]);

    let second = fixture(
        &sb,
        "kept",
        "1.1",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/kept \
         && cp payload.txt $DESTDIR$PREFIX/share/kept/a.txt \
         && cp payload.txt $DESTDIR$PREFIX/share/kept/b.txt",
    );
    sb.ok(&["install", second.to_str().unwrap()]);

    let history = sb.ok(&["--history"]);
    let target = history
        .lines()
        .find(|line| line.contains("activate kept 1.0") && !line.contains("1.1"))
        .and_then(|line| line.split_whitespace().next())
        .expect("the first activation generation");

    // the manifest travels with the generation
    sb.ok(&["rollback", target]);
    assert!(
        sb.ok(&["--show", "kept"]).contains("1.0"),
        "the rollback did not restore the first version"
    );
    assert!(
        sb.root.join("usr/share/kept/a.txt").exists(),
        "the first version's file is missing after the rollback"
    );
    assert!(
        !sb.root.join("usr/share/kept/b.txt").exists(),
        "a later version's file survived the rollback"
    );
    let out = sb.ok(&["--verify"]);
    assert!(
        out.contains("clean"),
        "verification after a rollback did not come back clean:\n{out}"
    );
}

#[test]
fn an_upgrade_drops_the_files_the_new_version_no_longer_ships() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    let first = fixture(
        &sb,
        "shrinker",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/shrinker \
         && cp payload.txt $DESTDIR$PREFIX/share/shrinker/kept.txt \
         && cp payload.txt $DESTDIR$PREFIX/share/shrinker/dropped.txt",
    );
    sb.ok(&["install", first.to_str().unwrap()]);
    assert!(
        sb.root.join("usr/share/shrinker/dropped.txt").exists(),
        "the first version did not install both files"
    );

    let second = fixture(
        &sb,
        "shrinker",
        "1.1",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/shrinker \
         && cp payload.txt $DESTDIR$PREFIX/share/shrinker/kept.txt",
    );
    let out = sb.ok(&["install", second.to_str().unwrap()]);
    assert!(
        out.contains("removed"),
        "the upgrade did not report what it dropped:\n{out}"
    );
    assert!(
        !sb.root.join("usr/share/shrinker/dropped.txt").exists(),
        "a file the new version does not ship is still linked"
    );
    assert!(
        sb.root.join("usr/share/shrinker/kept.txt").exists(),
        "the file both versions ship was removed"
    );
}

#[test]
fn an_unsigned_install_is_refused_when_a_signature_is_required() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "unsigned-policy",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/unsigned-policy",
    );
    fs::write(
        sb.root.join("etc/portalis/config.port"),
        b"security.require_signature = true\n",
    )
    .expect("write the config");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an unsigned install ran under require_signature:\n{text}"
    );
    assert!(
        text.contains("signature") || text.contains("unsigned"),
        "the refusal did not name the signature policy:\n{text}"
    );
    assert!(
        !sb.root.join("usr/bin/unsigned-policy").exists(),
        "an unsigned package reached the live tree"
    );
}

#[test]
fn a_signing_key_other_accounts_can_read_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "leaky-key",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/leaky-key",
    );

    let key = sb.root.join("etc/portalis/signing.key");
    fs::write(&key, [3u8; 32]).expect("signing key");
    let mut permissions = fs::metadata(&key).expect("key metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
    fs::set_permissions(&key, permissions).expect("key mode");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a key readable by every account still produced a signature:\n{text}"
    );
    assert!(
        text.contains("readable beyond its owner"),
        "the refusal did not explain the key mode:\n{text}"
    );
}

#[test]
fn a_compressed_tail_past_the_marker_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    // data after the end-of-archive marker is outside the member budget
    let top = "fat-tail-1.0";
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
    padded.extend(std::iter::repeat_n(0u8, 18 * 1024 * 1024));
    fs::write(&plain, &padded).expect("pad the archive");

    let gz = Command::new("gzip")
        .arg("-c")
        .arg(&plain)
        .output()
        .expect("gzip");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    fs::write(&archive, gz.stdout).expect("write gzip");

    let recipe = format!(
        "package.name = fat-tail\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/fat-tail && cp payload.txt $DESTDIR$PREFIX/share/fat-tail/\n\
         install.prefix = /usr\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("fat-tail.port"), recipe).expect("write recipe");

    let out = Command::new("timeout")
        .arg("60")
        .arg(env!("CARGO_BIN_EXE_portalis"))
        .arg("install")
        .arg(&archive)
        .env("PORTALIS_ROOT", &sb.root)
        .env("PORTALIS_NO_BWRAP", "1")
        .output()
        .expect("running portalis");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "an oversized tail was accepted:\n{text}"
    );
    assert!(
        text.contains("end-of-archive marker"),
        "the refusal did not explain the tail:\n{text}"
    );
}

#[test]
fn removing_a_package_with_an_installed_dependent_is_refused() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let library = fixture(
        &sb,
        "needed",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/lib && cp payload.txt $DESTDIR$PREFIX/lib/libneeded.so",
    );
    let library_out = sb.ok(&["install", library.to_str().unwrap()]);
    let library_store = library_out
        .lines()
        .find_map(|line| line.trim().strip_prefix("store    "))
        .expect("install prints the store path")
        .to_string();

    let app = fixture(
        &sb,
        "consumer",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/consumer",
    );
    let app_recipe = sb.recipe_dir().join("consumer.port");
    let mut recipe = fs::read_to_string(&app_recipe).expect("consumer recipe");
    recipe.push_str("package.depends = needed\n");
    fs::write(&app_recipe, recipe).expect("add dependency");
    sb.ok(&["install", app.to_str().unwrap()]);

    let out = sb.run(&["remove", "needed", "--purge"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "removing a package with an installed dependent succeeded:\n{text}"
    );
    assert!(
        text.contains("depend"),
        "the refusal did not name the dependent:\n{text}"
    );
    assert!(
        Path::new(&library_store).exists(),
        "the refused purge deleted the store"
    );

    let forced = sb.run(&["remove", "needed", "--purge", "--force"]);
    assert!(
        forced.status.success(),
        "remove --force still refused a package with a dependent:\n{}{}",
        String::from_utf8_lossy(&forced.stdout),
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(
        String::from_utf8_lossy(&forced.stdout).contains("unlinked"),
        "the forced remove did not report unlinking the package"
    );
}

#[cfg(portalis_rootfs)]
#[test]
fn a_check_command_runs_before_activation() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "checked",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/checked && cp payload.txt $DESTDIR$PREFIX/share/checked/",
    );
    let recipe_path = sb.recipe_dir().join("checked.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("check.command = true\n");
    fs::write(&recipe_path, recipe).expect("recipe with check");
    let text = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        text.contains("check    checked 1.0 passed"),
        "the check did not run:\n{text}"
    );
}

#[cfg(portalis_rootfs)]
#[test]
fn a_failed_check_blocks_activation() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "blocked",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/blocked && cp payload.txt $DESTDIR$PREFIX/share/blocked/",
    );
    let recipe_path = sb.recipe_dir().join("blocked.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("check.command = false\ncheck.required = true\n");
    fs::write(&recipe_path, recipe).expect("recipe with check");
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "a failed check was ignored:\n{text}");
    assert!(
        text.contains("check failed"),
        "the refusal was silent:\n{text}"
    );
    assert!(
        !sb.root.join("usr/share/blocked/payload.txt").exists(),
        "the package was activated after its check failed"
    );
}
