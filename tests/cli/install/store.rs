use super::*;

#[test]
fn clean_keeps_the_backup_of_an_adopted_file() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
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

    // the backup keeps the mtime of the file it replaced
    let mut backups = Vec::new();
    let mut stack = vec![sb.root.join("var/lib/portalis/backup")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                backups.push(path);
            }
        }
    }
    assert_eq!(
        backups.len(),
        1,
        "expected exactly one adopted backup, got {backups:?}"
    );
    let backup = backups.remove(0);
    let aged = std::process::Command::new("touch")
        .args(["-d", "40 days ago"])
        .arg(&backup)
        .status()
        .expect("touch is available");
    assert!(aged.success(), "could not age the backup");

    sb.ok(&["clean", "--backups", "--yes"]);

    assert!(
        backup.exists(),
        "clean deleted the backup of a file the adopted table still owns"
    );
    let out = sb.ok(&["remove", "legacy"]);
    assert!(out.contains("restored"), "no restore after clean:\n{out}");
    assert_eq!(
        fs::read_to_string(&legacy).expect("the original file is back"),
        "base system\n",
        "the wrong content came back"
    );
}

#[test]
fn a_missing_database_is_reported_as_missing() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // nothing installed yet: the read path must not blame permissions
    let out = sb.run(&[]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("no package database yet"),
        "the empty state was reported as something else:\n{text}"
    );
    assert!(
        !text.contains("run this as root"),
        "a missing database was blamed on permissions:\n{text}"
    );
}

#[test]
fn a_corrupt_database_is_reported_not_a_panic() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = raw_deb(
        &sb,
        "dbcorrupt_1.0_amd64.deb",
        &[("usr/bin/dbcorrupt", b"binary\n".as_slice(), 0o755)],
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    let db = sb.root.join("var/db/portalis/db.sqlite");
    assert!(db.exists(), "the install did not create a database");
    fs::write(&db, b"this is not a sqlite database").expect("corrupt the database");

    let out = sb.run(&["--verify"]);
    assert!(
        !out.status.success(),
        "a corrupt database was reported as clean"
    );
    let text = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        !text.contains("panicked"),
        "the tool panicked instead of reporting: {text}"
    );
    assert!(
        text.contains("database") || text.contains("sqlite") || text.contains("no such table"),
        "the failure does not mention the database: {text}"
    );
}

#[test]
fn clean_reports_before_it_deletes() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "kept",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/kept",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);

    // a store directory nothing points at
    let ghost = sb.root.join("usr/portalis/packages/ghost-1.0-deadbeef");
    fs::create_dir_all(&ghost).expect("ghost store");
    fs::write(ghost.join("payload.txt"), b"junk").expect("ghost payload");

    let dry_run = sb.ok(&["clean", "--store"]);
    assert!(
        dry_run.contains("would delete") && dry_run.contains("ghost-1.0-deadbeef"),
        "the dry run did not report the unreferenced store:\n{dry_run}"
    );
    assert!(ghost.exists(), "the dry run deleted something");
}

#[test]
fn clean_keeps_stores_that_packages_use() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "keeper",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/keeper",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);

    let ghost = sb.root.join("usr/portalis/packages/ghost-1.0-deadbeef");
    fs::create_dir_all(&ghost).expect("ghost store");
    fs::write(ghost.join("payload.txt"), b"junk").expect("ghost payload");

    let out = sb.ok(&["clean", "--store", "--yes"]);
    assert!(
        out.contains("deleted"),
        "clean did not report a deletion:\n{out}"
    );
    assert!(!ghost.exists(), "the unreferenced store survived");

    assert!(
        sb.root.join("usr/bin/keeper").exists(),
        "the live package lost its link"
    );
    assert!(sb.ok(&["--show", "keeper"]).contains("keeper"));
    assert!(sb.ok(&["--verify"]).contains("clean"));
}

#[test]
fn clean_backups_does_not_follow_symlinked_directories() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    fixture(
        &sb,
        "linked",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/linked",
    );
    let outside = sb.root.join("outside-backup");
    fs::create_dir_all(&outside).expect("outside directory");
    let victim = outside.join("old.txt");
    fs::write(&victim, b"must survive\n").expect("outside file");
    let status = Command::new("touch")
        .args(["-d", "40 days ago"])
        .arg(&victim)
        .status()
        .expect("touch is available");
    assert!(status.success(), "could not age the outside file");

    let backup_root = sb.root.join("var/lib/portalis/backup");
    fs::create_dir_all(&backup_root).expect("backup root");
    let stale = backup_root.join("stale.txt");
    fs::write(&stale, b"stale backup\n").expect("stale backup");
    let status = Command::new("touch")
        .args(["-d", "40 days ago"])
        .arg(&stale)
        .status()
        .expect("touch is available");
    assert!(status.success(), "could not age the stale backup");
    std::os::unix::fs::symlink(&outside, backup_root.join("outside-link"))
        .expect("symlink into the backup root");

    sb.ok(&["clean", "--backups", "--yes"]);

    assert!(
        !stale.exists(),
        "clean did not delete an aged backup inside the backup root"
    );
    assert!(
        victim.exists(),
        "clean followed a backup symlink and deleted a file outside the backup root"
    );
}

#[test]
fn clean_backups_does_not_follow_a_symlinked_backup_root() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    fixture(
        &sb,
        "rootlink",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/rootlink",
    );
    let outside = sb.root.join("outside-root-backup");
    fs::create_dir_all(&outside).expect("outside directory");
    let victim = outside.join("old.txt");
    fs::write(&victim, b"must survive\n").expect("outside file");
    let status = Command::new("touch")
        .args(["-d", "40 days ago"])
        .arg(&victim)
        .status()
        .expect("touch is available");
    assert!(status.success(), "could not age the outside file");

    let backup_root = sb.root.join("var/lib/portalis/backup");
    let _ = fs::remove_dir_all(&backup_root);
    std::os::unix::fs::symlink(&outside, &backup_root).expect("symlink the backup root");

    sb.ok(&["clean", "--backups", "--yes"]);

    assert!(
        victim.exists(),
        "clean followed a symlinked backup root and deleted an outside file"
    );
}

#[test]
fn clean_backups_keeps_the_newest_copy() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    fixture(
        &sb,
        "edited",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/edited",
    );
    let recipe = sb.recipe_dir().join("edited.port");
    for index in 1..=3 {
        let backup = sb.recipe_dir().join(format!("edited.port.bak-{index}"));
        fs::copy(&recipe, &backup).expect("backup copy");
        let age = std::time::Duration::from_secs((4 - index) * 10);
        let when = std::time::SystemTime::now() - age;
        let times = std::fs::FileTimes::new().set_modified(when);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&backup)
            .expect("backup file")
            .set_times(times)
            .expect("backup mtime");
    }

    sb.ok(&["clean", "--backups", "--yes"]);

    let left: Vec<String> = fs::read_dir(sb.recipe_dir())
        .expect("recipe directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.contains(".bak-"))
        .collect();
    assert_eq!(
        left,
        vec!["edited.port.bak-3".to_string()],
        "clean did not keep the newest backup: {left:?}"
    );
    assert!(recipe.exists(), "clean removed the recipe itself");
}
