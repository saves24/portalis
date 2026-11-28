use super::*;

/// A process the build leaves behind is stopped before the stage is handled as
/// root, and the build itself still succeeds.
#[test]
fn a_process_a_build_leaves_behind_is_stopped_before_the_stage_is_sealed() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // a duration only this case uses
    let body = "mkdir -p $DESTDIR$PREFIX/bin; cp payload.txt $DESTDIR$PREFIX/bin/leftover; \
                setsid sleep 4242 >/dev/null 2>&1 &"
        .to_string();
    let archive = fixture(&sb, "leftover", "1.0", "/usr", &body);
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // the build account must have no process of its own left behind
    let left = build_account_processes("sleep 4242");
    assert!(
        left.is_empty(),
        "the process the build left behind is still running: {left:?}"
    );
    let installed = sb.root.join("usr/bin/leftover");
    assert!(installed.exists(), "the build did not install its file");
}

/// A build that fails before its stage is sealed stops what it left running.
#[test]
fn a_failed_build_stops_the_process_it_left_behind() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // a step that detaches a process and then fails
    let body = "setsid sleep 4343 >/dev/null 2>&1 & false".to_string();
    let archive = fixture(&sb, "failed", "1.0", "/usr", &body);
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a build step that failed still installed"
    );

    let left = build_account_processes("sleep 4343");
    assert!(
        left.is_empty(),
        "the process a failed build left behind is still running: {left:?}"
    );
}

#[test]
fn a_preserved_config_file_is_not_reported_as_missing() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let body = "mkdir -p $DESTDIR/etc && printf 'default\\n' > $DESTDIR/etc/cfgprobe.conf";
    let archive = fixture(&sb, "cfgprobe", "1.0", "/", body);
    let recipe_path = sb.recipe_dir().join("cfgprobe.port");
    let recipe = fs::read_to_string(&recipe_path).expect("recipe");
    fs::write(
        &recipe_path,
        format!("{recipe}files.preserve = /etc/cfgprobe.conf\n"),
    )
    .expect("preserve");

    sb.ok(&["install", archive.to_str().unwrap()]);
    let checked = sb.ok(&["--verify"]);
    assert!(
        checked.contains("clean"),
        "verify was not clean:\n{checked}"
    );

    sb.ok(&["remove", "cfgprobe"]);
    assert!(
        sb.root.join("etc/cfgprobe.conf").exists(),
        "removing the package deleted its preserved configuration"
    );
}

#[test]
fn installs_a_package_into_the_sandbox() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "hello",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/hello",
    );

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "expected an applied package:\n{out}"
    );
    assert!(
        sb.root.join("usr/bin/hello").exists(),
        "payload was not linked into the root"
    );
    assert!(sb.ok(&["--show", "hello"]).contains("hello"));
    assert!(sb.ok(&["--verify"]).contains("clean"));
}

#[test]
fn unpacking_is_limited_without_a_credential_switch() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // a member larger than the ceiling the configuration asks for
    let archive = fixture_with_source(
        &sb,
        "bomb",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/bomb && cp payload.txt $DESTDIR$PREFIX/share/bomb/",
        |src| {
            fs::write(src.join("big.bin"), vec![0u8; 4 * 1024 * 1024]).expect("big member");
        },
    );
    fs::write(
        sb.root.join("etc/portalis/config.port"),
        "build.limit_file_mb = 1\n",
    )
    .expect("config");

    let out = sb
        .command()
        .env("PORTALIS_ROOT_BUILD", "1")
        .args(["install", archive.to_str().unwrap()])
        .output()
        .expect("running portalis");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "unpacking ran without ceilings when the credentials were left alone:\n{text}"
    );
    assert!(
        text.contains("unpacking"),
        "the failure did not come from unpacking:\n{text}"
    );
}

#[test]
fn the_generation_count_stays_at_the_limit() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_archive(&sb, "sk-1.0-x86_64.tar", &[("usr/share/sk/x", b"x\n")]);
    for _ in 0..6 {
        sb.ok_env(
            &["install", archive.to_str().unwrap()],
            &[("PORTALIS_FORCE", "1")],
        );
        sb.ok(&["remove", "sk"]);
    }
    let out = sb.ok(&["--history"]);
    let rows = out
        .lines()
        .filter(|line| {
            line.trim_start()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert_eq!(rows, 5, "generations drifted to {rows}:\n{out}");
}

#[test]
fn a_read_only_root_fails_the_install_without_leaving_a_store() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let mount = sb.root.clone();
    let Some(tmpfs) = Tmpfs::new(&mount, "32m") else {
        return;
    };
    for dir in [
        "etc/portalis/packages",
        "var/log/portalis/builds",
        "var/db/portalis",
    ] {
        fs::create_dir_all(mount.join(dir)).expect("layout on tmpfs");
    }
    fs::write(mount.join("etc/group"), "root:x:0:\n").expect("group file");
    let archive = std::env::temp_dir().join(format!("portalis-ro-{}.deb", std::process::id()));
    let mut deb = Vec::new();
    deb.extend_from_slice(b"!<arch>\n");
    ar_write(
        &mut deb,
        "control.tar",
        &raw_tar(&[("control", b"Package: ro\nVersion: 1.0\n")]),
    );
    ar_write(
        &mut deb,
        "data.tar",
        &raw_tar(&[("usr/bin/ro", b"binary\n".as_slice())]),
    );
    fs::write(&archive, &deb).expect("write archive");

    tmpfs.remount_read_only();

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let _ = fs::remove_file(&archive);
    assert!(
        !out.status.success(),
        "an install into a read-only root claimed success"
    );
    assert_failed_install_left_nothing(&sb, &["usr/bin/ro"]);
}

#[test]
fn a_full_disk_fails_the_install_without_leaving_a_store() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let mount = sb.root.clone();
    let Some(_tmpfs) = Tmpfs::new(&mount, "8m") else {
        return;
    };
    // the mount hides what the build created; the layout is made again
    for dir in [
        "etc/portalis/packages",
        "var/log/portalis/builds",
        "var/db/portalis",
    ] {
        fs::create_dir_all(mount.join(dir)).expect("layout on tmpfs");
    }
    fs::write(mount.join("etc/group"), "root:x:0:\n").expect("group file");

    let payload = vec![0u8; 12 * 1024 * 1024];
    let mut deb = Vec::new();
    deb.extend_from_slice(b"!<arch>\n");
    ar_write(
        &mut deb,
        "control.tar",
        &raw_tar(&[("control", b"Package: full\nVersion: 1.0\n")]),
    );
    ar_write(
        &mut deb,
        "data.tar",
        &raw_tar_modes(&[("usr/bin/full", payload.as_slice(), 0o755)]),
    );
    let archive = std::env::temp_dir().join(format!("portalis-full-{}.deb", std::process::id()));
    fs::write(&archive, &deb).expect("write archive");

    let out = sb.run_env(
        &["install", archive.to_str().unwrap()],
        &[("PORTALIS_KEEP_PRIVILEGED", "1")],
    );
    let _ = fs::remove_file(&archive);
    assert!(
        !out.status.success(),
        "the install claimed success on a full disk"
    );
    assert_failed_install_left_nothing(&sb, &["usr/bin/full"]);
}

#[test]
fn the_build_sandbox_cannot_read_the_host_configuration() {
    if !require_root() {
        return;
    }
    // This case needs host configuration and bubblewrap.
    let ready = Path::new("/etc/portalis/signing.key").exists()
        && Command::new("bwrap").arg("--version").output().is_ok();
    if !ready {
        // Skips when the host configuration or bubblewrap is absent.
        if std::env::var_os("PORTALIS_ALLOW_SKIP_HOST_CONFIG").is_some() {
            eprintln!(
                "skipping: no /etc/portalis/signing.key or no bubblewrap, allowed by PORTALIS_ALLOW_SKIP_HOST_CONFIG"
            );
            return;
        }
        panic!(
            "no /etc/portalis/signing.key or no bubblewrap; set PORTALIS_ALLOW_SKIP_HOST_CONFIG=1 to run without them"
        );
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "peek",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/peek \
         && { ls -a /etc/portalis; \
              test -e /etc/portalis/signing.key && echo KEY-VISIBLE || echo key-hidden; \
              test -e /etc/portalis/config.port && echo CONFIG-VISIBLE || echo config-hidden; } \
            > $DESTDIR$PREFIX/share/peek/probe.txt",
    );

    let out = sb.sandboxed(&["install", archive.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "a sandboxed build failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let probe = fs::read_to_string(sb.root.join("usr/share/peek/probe.txt"))
        .expect("the build step wrote its probe");
    assert!(
        probe.contains("key-hidden"),
        "the build could reach the signing key:\n{probe}"
    );
    assert!(
        probe.contains("config-hidden"),
        "the build could reach the recipe configuration:\n{probe}"
    );
    assert!(
        !probe.contains("KEY-VISIBLE") && !probe.contains("CONFIG-VISIBLE"),
        "the build saw configuration it should not:\n{probe}"
    );
    let entries: Vec<&str> = probe
        .lines()
        .filter(|line| !line.contains("hidden") && !line.is_empty() && !line.starts_with('/'))
        .collect();
    assert_eq!(
        entries,
        vec![".", ".."],
        "the configuration directory was not empty inside the build:\n{probe}"
    );
}

#[test]
fn a_landlock_build_cannot_read_outside_the_toolchain() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let secret = sb.root.join("private-key");
    fs::write(&secret, b"KEY-VISIBLE\n").expect("secret fixture");

    let command = format!(
        "mkdir -p $DESTDIR$PREFIX/share/peekll && {{ \
         if cat /etc/passwd >/dev/null 2>&1; then echo passwd-visible; else echo passwd-hidden; fi; \
         if cat /usr/bin/sh >/dev/null 2>&1; then echo tool-visible; else echo tool-hidden; fi; \
         if cat {secret} >/dev/null 2>&1; then echo secret-visible; else echo secret-hidden; fi; \
         if cat /etc/shadow >/dev/null 2>&1; then echo shadow-visible; else echo shadow-hidden; fi; \
         }} > $DESTDIR$PREFIX/share/peekll/probe.txt",
        secret = secret.to_string_lossy()
    );
    let archive = fixture(&sb, "peekll", "1.0", "/usr", &command);
    sb.ok(&["install", archive.to_str().unwrap()]);

    let probe = fs::read_to_string(sb.root.join("usr/share/peekll/probe.txt"))
        .expect("the build step wrote its probe");
    assert!(probe.contains("passwd-visible"), "{probe}");
    assert!(probe.contains("tool-visible"), "{probe}");
    assert!(probe.contains("secret-hidden"), "{probe}");
    assert!(probe.contains("shadow-hidden"), "{probe}");
    assert!(
        !probe.contains("secret-visible") && !probe.contains("shadow-visible"),
        "{probe}"
    );
}

#[test]
fn a_build_step_cannot_write_outside_the_workspace() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let host_probe = format!("/root/portalis-write-probe-{}", std::process::id());
    let body = format!(
        "mkdir -p $DESTDIR$PREFIX/share/escapee && {{ if touch {host_probe} 2>/dev/null; then echo ROOT-WRITABLE; else echo root-read-only; fi; }} > $DESTDIR$PREFIX/share/escapee/probe.txt; cp payload.txt $DESTDIR$PREFIX/share/escapee/escapee"
    );
    let archive = fixture(&sb, "escapee", "1.0", "/usr", &body);

    sb.ok(&["install", archive.to_str().unwrap()]);
    let probe = fs::read_to_string(sb.root.join("usr/share/escapee/probe.txt"))
        .expect("the build step wrote its probe");
    let host_exists = Path::new(&host_probe).exists();
    let _ = fs::remove_file(&host_probe);
    assert!(
        probe.contains("root-read-only"),
        "the build could write into /root:\n{probe}"
    );
    assert!(
        !probe.contains("ROOT-WRITABLE"),
        "the build could write into /root:\n{probe}"
    );
    assert!(!host_exists, "a build step wrote into /root");
}

#[test]
fn a_declared_setuid_path_keeps_its_bit_after_install() {
    use std::os::unix::fs::PermissionsExt;
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "suidprobe",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/suidprobe && chmod 4755 $DESTDIR$PREFIX/bin/suidprobe",
    );
    let recipe_path = sb.recipe_dir().join("suidprobe.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("install.setuid = usr/bin/suidprobe\n");
    fs::write(&recipe_path, recipe).expect("recipe with setuid");

    sb.ok(&["install", archive.to_str().unwrap()]);
    let live = sb.root.join("usr/bin/suidprobe");
    let mode = fs::metadata(&live)
        .expect("the installed file")
        .permissions()
        .mode()
        & 0o7777;
    assert!(mode & 0o4000 != 0, "the setuid bit was dropped: {mode:04o}");
    assert!(sb.ok(&["--verify"]).contains("clean"));
}

#[test]
fn a_patch_is_applied_before_the_build_step() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();

    let payload = "hello\n";
    let patch = "--- a/payload.txt\n\
                 +++ b/payload.txt\n\
                 @@ -1 +1 @@\n\
                 -hello\n\
                 +patched\n";

    let top = "pfixed-1.0";
    let src = sb.root.join("fixtures").join(top);
    fs::create_dir_all(&src).expect("fixture source");
    fs::write(src.join("payload.txt"), payload).expect("fixture payload");
    let fixtures = sb.root.join("fixtures");
    let archive = fixtures.join(format!("{top}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&fixtures)
        .arg(top)
        .status()
        .expect("tar available");
    assert!(status.success(), "tar failed");

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(patch.as_bytes());
    let patch_sha = format!("{:x}", hasher.finalize());

    let recipe = format!(
        "package.name = pfixed\n\
         package.version = 1.0\n\
         source.file = {}\n\
         source.sha256 = {}\n\
         build.system = custom\n\
         build.args = mkdir -p $DESTDIR$PREFIX/share/pfixed && cp payload.txt $DESTDIR$PREFIX/share/pfixed/\n\
         install.prefix = /usr\n\
         build.patch = <<BLOCK\n\
         file = fix.patch\n\
         sha256 = {patch_sha}\n\
         content = <<BODY\n\
         --- a/payload.txt\n\
         +++ b/payload.txt\n\
         @@ -1 +1 @@\n\
         -hello\n\
         +patched\n\
         BODY\n\
         BLOCK\n",
        archive.file_name().unwrap().to_string_lossy(),
        sha256_file(&archive)
    );
    fs::write(sb.recipe_dir().join("pfixed.port"), recipe).expect("write recipe");

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "the patched package was not applied:\n{out}"
    );

    let installed = fs::read_to_string(sb.root.join("usr/share/pfixed/payload.txt"))
        .expect("the build step installed the file");
    assert_eq!(
        installed, "patched\n",
        "the patch was not applied before the build"
    );
}

#[test]
fn a_build_cannot_exceed_the_file_size_ceiling() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    fs::write(
        sb.root.join("etc/portalis/config.port"),
        "build.limit_file_mb = 1\n",
    )
    .expect("write configuration");

    let archive = fixture(
        &sb,
        "greedy",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/greedy \
         && dd if=/dev/zero of=$DESTDIR$PREFIX/share/greedy/blob bs=1M count=4",
    );

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a build wrote far past the configured ceiling:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !sb.root.join("usr/share/greedy/blob").exists(),
        "the oversized file reached the live tree"
    );
}

#[test]
fn the_default_ceilings_leave_room_for_a_real_build() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // no configuration at all: the build runs under the half-of-this-machine
    // defaults and still has to produce a package
    let archive = fixture(
        &sb,
        "normal",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/normal \
         && dd if=/dev/zero of=$DESTDIR$PREFIX/share/normal/blob bs=1M count=8",
    );

    sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        sb.root.join("usr/share/normal/blob").exists(),
        "a normal build was stopped by the default ceilings"
    );
}

#[test]
fn a_recipe_cannot_make_run_writable() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "socket-mount",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/socket-mount \
         && cp payload.txt $DESTDIR$PREFIX/share/socket-mount/",
    );
    // /run holds live sockets (docker, systemd); a writable mount there would
    // hand the build the host's own service endpoints
    let recipe_path = sb.recipe_dir().join("socket-mount.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("build.writable = /run\n");
    fs::write(&recipe_path, recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the recipe was accepted:\n{text}");
    assert!(
        text.contains("may not name /run"),
        "the refusal did not name the path:\n{text}"
    );
}

#[test]
fn an_offline_build_cannot_open_a_udp_socket() {
    if !require_root() {
        return;
    }
    if Command::new("bash")
        .arg("-c")
        .arg("true")
        .status()
        .map(|status| !status.success())
        .unwrap_or(true)
        && allow_skip("bash is not installed")
    {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "udp-probe",
        "1.0",
        "/usr",
        "bash -c 'exec 3<>/dev/udp/1.1.1.1/53'",
    );
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a UDP socket was opened inside an offline build:\n{text}"
    );
    let mut log_text = String::new();
    if let Ok(entries) = fs::read_dir(sb.root.join("var/log/portalis/builds")) {
        for entry in entries.flatten() {
            if let Ok(body) = fs::read_to_string(entry.path()) {
                log_text.push_str(&body);
            }
        }
    }
    assert!(
        log_text.contains("Permission denied")
            || log_text.contains("Operation not permitted")
            || text.contains("Permission denied")
            || text.contains("Operation not permitted"),
        "the refusal did not come from the socket filter; log:\n{log_text}\noutput:\n{text}"
    );
}

#[test]
fn a_recipe_cannot_make_host_tmp_writable() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "tmp-mount",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/tmp-mount \
         && cp payload.txt $DESTDIR$PREFIX/share/tmp-mount/",
    );
    // The build gets a private /tmp.
    let recipe_path = sb.recipe_dir().join("tmp-mount.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("build.writable = /tmp\n");
    fs::write(&recipe_path, recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the recipe was accepted:\n{text}");
    assert!(
        text.contains("may not name /tmp"),
        "the refusal did not name the path:\n{text}"
    );
}

#[test]
fn a_recipe_cannot_make_a_system_directory_writable() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "greedy-mount",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/greedy-mount \
         && cp payload.txt $DESTDIR$PREFIX/share/greedy-mount/",
    );
    // the fixture recipe is rewritten with the extra key
    let recipe_path = sb.recipe_dir().join("greedy-mount.port");
    let mut recipe = fs::read_to_string(&recipe_path).expect("recipe");
    recipe.push_str("build.writable = /etc\n");
    fs::write(&recipe_path, recipe).expect("write recipe");

    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "the recipe was accepted:\n{text}");
    assert!(
        text.contains("may not name /etc"),
        "the refusal did not name the path:\n{text}"
    );
}

#[test]
fn a_build_step_runs_as_the_builder_account() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "whoami",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/share/whoami && id -u > $DESTDIR$PREFIX/share/whoami/uid.txt",
    );

    let out = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        out.contains("applied"),
        "the package was not installed:\n{out}"
    );

    let uid = fs::read_to_string(sb.root.join("usr/share/whoami/uid.txt"))
        .expect("the build step reported its account")
        .trim()
        .to_string();
    assert_eq!(
        uid, "65534",
        "a build step did not run as the builder account"
    );
}

#[test]
fn a_build_cannot_write_outside_the_workspace() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let marker = std::env::temp_dir().join(format!("portalis-write-marker-{}", std::process::id()));
    let _ = fs::remove_file(&marker);

    let body = format!(
        "mkdir -p $DESTDIR$PREFIX/share/writer && cp payload.txt $DESTDIR$PREFIX/share/writer/; if touch {} 2>/dev/null; then echo HOST-WRITABLE; else echo host-read-only; fi > $DESTDIR$PREFIX/share/writer/probe.txt",
        marker.display()
    );
    let archive = fixture(&sb, "writer", "1.0", "/usr", &body);

    let out = sb.ok(&["install", archive.to_str().expect("archive")]);
    let probe = fs::read_to_string(sb.root.join("usr/share/writer/probe.txt"))
        .expect("the build step wrote its probe");
    let host_exists = marker.exists();
    let _ = fs::remove_file(&marker);
    assert!(
        probe.contains("host-read-only"),
        "the build could write outside the workspace:\n{probe}\n{out}"
    );
    assert!(
        !probe.contains("HOST-WRITABLE"),
        "the build could write outside the workspace:\n{probe}\n{out}"
    );
    assert!(
        !host_exists,
        "a build step wrote to the host filesystem:\n{probe}\n{out}"
    );
}
