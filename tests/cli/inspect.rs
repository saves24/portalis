use super::*;

/// With `PORTALIS_JSON` set, stdout carries one JSON object per stage and the
/// human lines move to stderr.
#[test]
fn the_machine_stream_describes_a_whole_install() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "events",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/payload.txt",
    );
    let out = sb.events(&["install", archive.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let events: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}")))
        .collect();
    assert_eq!(
        events.first().and_then(|event| event["event"].as_str()),
        Some("phase"),
        "the first event is a phase"
    );
    let phases: Vec<&str> = events
        .iter()
        .filter_map(|event| event["phase"].as_str())
        .collect();
    assert_eq!(phases, vec!["build", "activate"], "phases: {phases:?}");
    let last = events.last().expect("a last event");
    assert_eq!(last["event"], "done");
    assert_eq!(last["package"], "events");
    assert_eq!(last["version"], "1.0");
    assert_eq!(last["applied"], true);
    assert_eq!(last["files"], 1);

    // the human lines are still there, on stderr
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("building events 1.0") || stderr.contains("applied  events 1.0"),
        "the human lines left stdout but did not appear on stderr: {stderr}"
    );
}

/// A removal reports what it unlinked.
#[test]
fn the_machine_stream_reports_a_remove() {
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
    let out = sb.events(&["remove", "gone"]);
    assert!(
        out.status.success(),
        "remove failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let event: serde_json::Value = serde_json::from_str(stdout.lines().last().expect("an event"))
        .expect("the removal ends with an event");
    assert_eq!(event["event"], "done");
    assert_eq!(event["package"], "gone");
    assert_eq!(event["unlinked"], 1);
    assert_eq!(event["kept"], 0);
    assert_eq!(event["store"], "kept");
}

#[test]
fn a_remove_keeps_a_file_the_user_replaced() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "replaced",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/replaced",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    let live = sb.root.join("usr/bin/replaced");
    fs::remove_file(&live).expect("remove the link");
    fs::write(&live, "user data\n").expect("user file");

    let out = sb.events(&["remove", "replaced"]);
    assert!(
        out.status.success(),
        "remove failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let event: serde_json::Value = serde_json::from_str(stdout.lines().last().expect("an event"))
        .expect("the removal ends with an event");
    assert_eq!(
        event["kept"], 1,
        "the replaced file was not reported: {stdout}"
    );
    assert_eq!(event["unlinked"], 0, "a user file was unlinked: {stdout}");
    assert_eq!(
        fs::read_to_string(&live).expect("the user file was removed"),
        "user data\n"
    );
}

#[test]
fn a_deferred_upgrade_keeps_verify_clean() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let body = "mkdir -p $DESTDIR/boot && cp payload.txt $DESTDIR/boot/kernelbit";

    let first = fixture(&sb, "kernelbit", "1.0", "/", body);
    assert!(sb
        .ok(&["install", first.to_str().unwrap()])
        .contains("staged"));
    assert!(
        !sb.root.join("boot/kernelbit").exists(),
        "a deferred install wrote its late path before activation"
    );
    sb.activate_pending();
    assert!(
        sb.ok(&["--verify"]).contains("clean"),
        "the activated package has to verify"
    );

    // the second version waits for shutdown; the installed copy stays 1.0
    // and the manifest on record has to describe 1.0 as well
    let second = fixture_with_source(&sb, "kernelbit", "2.0", "/", body, |src| {
        fs::write(src.join("extra.txt"), "second\n").expect("extra payload");
    });
    assert!(sb
        .ok(&["install", second.to_str().unwrap()])
        .contains("staged"));
    assert!(
        sb.ok(&["--show", "kernelbit"]).contains("1.0"),
        "the deferred upgrade replaced the installed version"
    );
    let out = sb.ok(&["--verify"]);
    assert!(
        out.contains("clean"),
        "a deferred upgrade made verify report a problem:\n{out}"
    );

    sb.activate_pending();
    let out = sb.ok(&["--verify"]);
    assert!(
        out.contains("clean"),
        "verify after the deferred upgrade was applied:\n{out}"
    );
}

#[test]
fn an_unprivileged_account_can_list_the_packages() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "readable",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/readable",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);

    // the sandbox belongs to root, as the real layout does
    let status = Command::new("chmod")
        .arg("-R")
        .arg("a+rX")
        .arg(&sb.root)
        .status()
        .expect("chmod");
    assert!(status.success(), "chmod failed");

    let root = sb.root.to_str().expect("sandbox path");
    let binary = std::env::temp_dir().join(format!("portalis-unprivileged-{}", std::process::id()));
    fs::copy(env!("CARGO_BIN_EXE_portalis"), &binary).expect("copy the manager");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("make it executable");
    }
    let out = Command::new("su")
        .arg("-s")
        .arg("/bin/sh")
        .arg("nobody")
        .arg("-c")
        .arg(format!(
            "PORTALIS_ROOT={root} PORTALIS_NO_BWRAP=1 {}",
            binary.display()
        ))
        .output()
        .expect("running the manager as nobody");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_file(&binary);
    assert!(
        out.status.success(),
        "listing as an unprivileged account failed:\n{text}"
    );
    assert!(
        text.contains("readable"),
        "the package was not listed:\n{text}"
    );
}

#[test]
fn verify_notices_a_tampered_store() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "secure",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/secure",
    );

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    let store = out
        .lines()
        .find_map(|line| line.trim().strip_prefix("store    "))
        .expect("install prints the store path")
        .to_string();

    let target = Path::new(&store).join("usr/bin/secure");
    let mut bytes = fs::read(&target).expect("read stored file");
    bytes.extend_from_slice(b"tampered");
    fs::write(&target, bytes).expect("tamper");

    let out = sb.run(&["--verify"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "verify accepted a modified store file:\n{stdout}{stderr}"
    );
    assert!(
        stdout.contains("store file modified") || stderr.contains("problems found"),
        "verify failed without naming the problem:\n{stdout}{stderr}"
    );
}

#[test]
fn a_missing_store_marker_fails_verification() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "unmarked",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/unmarked",
    );
    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    let store = out
        .lines()
        .find_map(|line| line.trim().strip_prefix("store    "))
        .expect("install prints the store path")
        .to_string();
    fs::remove_file(Path::new(&store).join(".portalis-complete"))
        .expect("remove the completion marker");

    let out = sb.run(&["--verify"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "verify accepted a store with no completion marker:\n{stdout}{stderr}"
    );
    assert!(
        stdout.contains("completion marker") || stderr.contains("completion marker"),
        "the report did not name the missing marker:\n{stdout}{stderr}"
    );
}

#[test]
fn a_missing_store_directory_fails_verification() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "gone-store",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/gone-store",
    );
    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    let store = out
        .lines()
        .find_map(|line| line.trim().strip_prefix("store    "))
        .expect("install prints the store path")
        .to_string();
    fs::remove_dir_all(&store).expect("remove the store directory");

    let out = sb.run(&["--verify"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "verify accepted a missing store directory:\n{text}"
    );
    assert!(
        text.contains("store is missing"),
        "verify did not name the missing store:\n{text}"
    );
}

#[test]
fn verify_enforces_required_signatures() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "unsigned",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/unsigned",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    fs::write(
        sb.root.join("etc/portalis/config.port"),
        b"security.require_signature = true\n",
    )
    .expect("write the config");

    let out = sb.run(&["--verify"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "verify accepted an unsigned package under require_signature:\n{text}"
    );
    assert!(
        text.contains("require_signature") || text.contains("UNSIGNED"),
        "verify did not name the signature policy:\n{text}"
    );
}

/// Retargeting a symlink inside the store changes what the package runs, so
/// verification compares the store's own tree with its completion marker.
#[test]
fn a_retargeted_store_symlink_fails_verification() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "alias",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/lib && cp payload.txt $DESTDIR$PREFIX/lib/real \
         && ln -s lib/real $DESTDIR$PREFIX/lib/alias",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(sb.ok(&["--verify"]).contains("clean"));

    let packages = sb.root.join("usr/portalis/packages");
    let store = fs::read_dir(&packages)
        .expect("store dir")
        .next()
        .expect("one store")
        .expect("entry")
        .path();
    let inside = store.join("usr/lib/alias");
    fs::remove_file(&inside).expect("drop the store link");
    std::os::unix::fs::symlink("/etc/shadow", &inside).expect("retarget the store link");

    let out = sb.run(&["--verify"]);
    assert!(
        !out.status.success(),
        "a retargeted store symlink verified clean"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("does not match its completion marker"),
        "the report did not name the store content:\n{text}"
    );
}
