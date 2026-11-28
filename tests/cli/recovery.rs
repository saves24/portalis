use super::*;

/// A remove that died between unlinking and the ledger write is repaired by the
/// next command that writes.
#[test]
fn a_killed_remove_is_repaired_by_the_next_write_command() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "killed",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/payload.txt",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    let live = sb.root.join("usr/bin/payload.txt");
    assert!(live.exists(), "the install left no link");

    // the state a kill leaves: the marker is on disk and one link is gone
    let marker = sb.root.join("var/lib/portalis/operation");
    fs::write(&marker, "remove of killed\n").expect("marker");
    fs::remove_file(&live).expect("unlink");

    // the command itself fails, and the repair runs first
    let out = sb.run(&["remove", "not-installed", "--pending"]);
    assert!(
        !out.status.success(),
        "removing an unknown package succeeded"
    );
    assert!(
        live.exists(),
        "the link an interrupted remove had taken away was not put back"
    );
    assert!(!marker.exists(), "the operation marker survived the repair");
}

#[test]
fn an_operation_journal_restores_a_link_the_ledger_does_not_know() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "journaled",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/journaled",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);

    let packages = sb.root.join("usr/portalis/packages");
    let store = fs::read_dir(&packages)
        .expect("store directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("journaled-"))
                .unwrap_or(false)
        })
        .expect("journaled store");
    let target = store.join("usr/bin/journaled");
    let live = sb.root.join("usr/bin/operation-journal-probe");
    std::os::unix::fs::symlink(&target, &live).expect("probe link");
    let target_text = target.to_string_lossy().to_string();
    fs::remove_file(&live).expect("remove probe link");

    let state = sb.root.join("var/lib/portalis");
    let entry = serde_json::json!({
        "path": "/usr/bin/operation-journal-probe",
        "previous": { "kind": "symlink", "target": target_text },
    });
    let journal = state.join("operation-journal-remove-of-probe.jsonl");
    fs::write(&journal, format!("# operation remove of probe\n{entry}\n"))
        .expect("operation journal");
    fs::write(state.join("operation"), "remove of probe\n").expect("operation marker");

    let out = sb.run(&["remove", "not-installed", "--pending"]);
    assert!(
        !out.status.success(),
        "removing an unknown package succeeded"
    );
    assert_eq!(
        fs::read_link(&live).expect("the journaled link was not restored"),
        target
    );
    assert!(!journal.exists(), "the replayed operation journal was kept");
    assert!(
        !state.join("operation").exists(),
        "the operation marker survived the repair"
    );
}

/// A journal the replay cannot read stops every write command.
#[test]
fn a_damaged_journal_stops_write_commands() {
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
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/blocked",
    );
    let journal = sb
        .root
        .join("var/lib/portalis/activation-journal-blocked.jsonl");
    fs::create_dir_all(journal.parent().expect("state dir")).expect("state dir");
    // a record that is complete on disk and still cannot be read
    fs::write(&journal, "{\"path\":123}\n").expect("damaged journal");

    let out = sb.events(&["install", archive.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a write command ran with a damaged journal"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let event: serde_json::Value =
        serde_json::from_str(stdout.lines().last().expect("an event")).expect("an event");
    assert_eq!(
        event["code"], "RECOVERY_BLOCKED",
        "the refusal did not carry the recovery code: {stdout}"
    );
    assert!(
        journal.exists(),
        "the damaged journal was dropped instead of kept"
    );
}

/// A bulk archive of `files` members under `dir`.
fn bulk_archive_as(
    sb: &Sandbox,
    files: usize,
    pkg: &str,
    version: &str,
    dir: &str,
) -> std::path::PathBuf {
    let owned: Vec<(String, Vec<u8>, u8)> = (0..files)
        .map(|index| (format!("{dir}/{index:05}"), b"x".to_vec(), b'0'))
        .collect();
    let view: Vec<(&str, &[u8], u8)> = owned
        .iter()
        .map(|(name, body, flag)| (name.as_str(), body.as_slice(), *flag))
        .collect();
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join(format!("{pkg}-{version}-x86_64.tar"));
    fs::write(&archive, raw_tar_typed(&view)).expect("write archive");
    archive
}

/// A bulk archive of `files` members under `/usr/share/bulk`.
fn bulk_archive(sb: &Sandbox, files: usize) -> std::path::PathBuf {
    bulk_archive_as(sb, files, "bulk", "1.0", "usr/share/bulk")
}

/// Starts an install and stops it once the first link exists; answers how many
/// links the tree held when the process died.
fn kill_after_first_link(sb: &Sandbox, archive: &std::path::Path, live: &std::path::Path) -> usize {
    let mut child = sb
        .command()
        .args(["install", archive.to_str().expect("archive path")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn install");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut links_seen = 0usize;
    while std::time::Instant::now() < deadline {
        if let Ok(entries) = fs::read_dir(live) {
            links_seen = entries.flatten().count();
            if links_seen > 0 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    child.kill().expect("kill the install");
    let _ = child.wait();
    links_seen
}

/// A kill during the replay of an earlier activation still converges: the next
/// write command replays the record again and leaves a consistent tree.
#[test]
fn a_kill_during_recovery_still_converges() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = bulk_archive(&sb, 20_000);
    let live = sb.root.join("usr/share/bulk");
    let links_seen = kill_after_first_link(&sb, &archive, &live);
    assert!(
        links_seen > 0,
        "the first activation made no link to interrupt"
    );
    assert!(
        links_seen < 20_000,
        "the first activation completed before it could be interrupted"
    );

    // stop the second run while it replays the record
    let journal = sb
        .root
        .join("var/lib/portalis/activation-journal-bulk.jsonl");
    assert!(
        journal.exists(),
        "the interrupted activation left no journal"
    );
    let mut second = sb
        .command()
        .args(["install", archive.to_str().expect("archive path")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the replaying install");
    std::thread::sleep(std::time::Duration::from_millis(15));
    assert!(
        second
            .try_wait()
            .expect("poll the replaying install")
            .is_none(),
        "the replaying install finished before it could be interrupted"
    );
    let _ = second.kill();
    let _ = second.wait();

    sb.ok(&["install", archive.to_str().expect("archive path")]);
    sb.ok(&["--verify"]);
    assert!(
        !sb.root
            .join("var/lib/portalis/activation-journal-bulk.jsonl")
            .exists(),
        "the journal survived the activation that finished"
    );
    assert!(
        !sb.root.join("var/lib/portalis/activating").exists(),
        "the marker survived the activation that finished"
    );
}

/// The store directory a link under `/usr/bin` points into.
fn store_dir_of(sb: &Sandbox, name: &str) -> String {
    let link = fs::read_link(sb.root.join(format!("usr/bin/{name}"))).expect("link");
    let text = link.to_string_lossy().to_string();
    let marker = "/usr/portalis/packages/";
    let rest = &text[text.find(marker).expect("store path") + marker.len()..];
    let store = rest.split('/').next().expect("store name");
    sb.root
        .join("usr/portalis/packages")
        .join(store)
        .to_string_lossy()
        .to_string()
}

/// A journal naming a store the ledger holds is dropped, not replayed: the
/// activation it describes already reached the database.
#[test]
fn a_journal_for_a_finished_activation_is_dropped() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "window",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/window",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    let live = sb.root.join("usr/bin/window");
    assert!(live.exists(), "the install left no link");

    let store = store_dir_of(&sb, "window");
    let journal = sb
        .root
        .join("var/lib/portalis/activation-journal-window.jsonl");
    fs::write(
        &journal,
        format!(
            "# window 1.0 {store}\n{{\"path\":\"/usr/bin/window\",\"previous\":{{\"kind\":\"missing\"}}}}\n"
        ),
    )
    .expect("journal");

    let other = fixture(
        &sb,
        "other",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/other",
    );
    sb.ok(&["install", other.to_str().unwrap()]);
    assert!(
        !journal.exists(),
        "a journal for a finished activation was kept"
    );
    assert!(
        live.exists(),
        "a journal for a finished activation was replayed"
    );
}

/// A journal that carries the commit line is dropped even when the ledger names
/// another store: the activation reached the database before the crash.
#[test]
fn a_journal_with_a_commit_line_is_dropped() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "commit",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/commit",
    );
    sb.ok(&["install", archive.to_str().unwrap()]);
    let live = sb.root.join("usr/bin/commit");
    assert!(live.exists(), "the install left no link");

    let journal = sb
        .root
        .join("var/lib/portalis/activation-journal-commit.jsonl");
    fs::write(
        &journal,
        "# commit 1.0 /nonexistent-store\n\
         {\"path\":\"/usr/bin/commit\",\"previous\":{\"kind\":\"missing\"}}\n\
         commit\n",
    )
    .expect("journal");

    let other = fixture(
        &sb,
        "later",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/later",
    );
    sb.ok(&["install", other.to_str().unwrap()]);
    assert!(!journal.exists(), "a committed journal was kept");
    assert!(live.exists(), "a committed journal was replayed");
}

/// A rollback killed while it rewrites links converges on the next write: the
/// tree is put back in step with the ledger.
#[test]
fn a_killed_rollback_converges_on_the_next_write() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let total = 3_000usize;
    let first = bulk_archive_as(&sb, total, "bulk", "1.0", "usr/share/bulk-old");
    let second = bulk_archive_as(&sb, total, "bulk", "2.0", "usr/share/bulk-new");
    sb.ok(&["install", first.to_str().expect("first")]);
    sb.ok(&["install", second.to_str().expect("second")]);

    let history = sb.ok(&["--history"]);
    let target = history
        .lines()
        .find(|line| line.contains("activate bulk 1.0"))
        .and_then(|line| line.split_whitespace().next())
        .expect("bulk 1.0 has an activation generation")
        .to_string();

    let watched = sb.root.join("usr/share/bulk-new");
    let mut child = sb
        .command()
        .args(["rollback", &target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn rollback");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut shrank = false;
    while std::time::Instant::now() < deadline {
        let left = fs::read_dir(&watched)
            .map(|entries| entries.count())
            .unwrap_or(0);
        if left < total {
            shrank = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        shrank,
        "the rollback finished before it could be interrupted"
    );

    let after = fixture(
        &sb,
        "after",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/after",
    );
    sb.ok(&["install", after.to_str().unwrap()]);
    sb.ok(&["--verify"]);
}

/// An activation that cannot write its record before the first move stops
/// there: the tree is untouched and the same command finishes once the path is
/// free again.
#[test]
fn an_activation_that_cannot_write_its_record_leaves_the_tree_alone() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "record",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/record",
    );
    let journal = sb
        .root
        .join("var/lib/portalis/activation-journal-record.jsonl");
    fs::create_dir_all(&journal).expect("occupy the journal path");

    let blocked = sb.run(&["install", archive.to_str().unwrap()]);
    assert!(
        !blocked.status.success(),
        "an install ran without a record of the moves it makes"
    );
    assert!(
        !sb.root.join("usr/bin/record").exists(),
        "the tree changed without a record of the moves"
    );

    fs::remove_dir_all(&journal).expect("clear the journal path");
    sb.ok(&["install", archive.to_str().unwrap()]);
    sb.ok(&["--verify"]);
}

#[test]
fn killing_an_install_mid_activation_is_reported_and_retried() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let files = 20_000usize;
    let archive = bulk_archive(&sb, files);
    let live = sb.root.join("usr/share/bulk");
    let mut child = sb
        .command()
        .args(["install", archive.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn install");

    // stop the install once the first link exists
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut links_seen = 0usize;
    while std::time::Instant::now() < deadline {
        if let Ok(entries) = fs::read_dir(&live) {
            links_seen = entries.flatten().count();
            if links_seen > 0 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    child.kill().expect("kill the install");
    let _ = child.wait();
    assert!(
        links_seen > 0,
        "the activation never created a link to interrupt"
    );
    assert!(
        links_seen < files,
        "the activation finished before it could be interrupted"
    );

    let marker = sb.root.join("var/lib/portalis/activating");
    assert!(marker.exists(), "a killed activation left no marker");

    // the plan of the moves reaches the disk before the first move
    let journal = sb
        .root
        .join("var/lib/portalis")
        .join("activation-journal-bulk.jsonl");
    assert!(
        journal.exists(),
        "a killed activation left no journal to replay"
    );

    let out = sb.run(&["--verify"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a half-applied install verified clean:\n{text}"
    );
    assert!(
        text.contains("never finished"),
        "the report did not name the unfinished activation:\n{text}"
    );

    // installing the same package again has to finish the job and clear the marker
    let recovered = sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        recovered.contains("recovered"),
        "the interrupted activation was not replayed before the install:\n{recovered}"
    );
    assert!(
        !journal.exists(),
        "the journal survived the activation that finished"
    );
    sb.ok(&["--verify"]);
    assert!(
        !marker.exists(),
        "the marker survived a successful reinstall"
    );
    assert!(
        live.join("00000").exists(),
        "the reinstalled package left no link"
    );
}

#[test]
fn a_damaged_ar_header_is_reported() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // correct ar magic, then a header without the backtick-newline terminator
    let mut body = Vec::new();
    body.extend_from_slice(b"!<arch>\n");
    body.extend_from_slice(format!("{:<60}", "debian-binary").as_bytes());
    let archive = sb.root.join("fixtures").join("damaged_1.0_amd64.deb");
    fs::create_dir_all(archive.parent().unwrap()).expect("fixture directory");
    fs::write(&archive, body).expect("write deb");
    let out = sb.run(&["install", archive.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a damaged archive was accepted:\n{text}"
    );
    assert!(
        text.contains("damaged ar member header"),
        "the report did not name the damage:\n{text}"
    );
}

/// The record that blocks a write command can be dropped on request, after the
/// command names what it removes.
#[test]
fn an_operator_can_drop_a_blocking_record() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let archive = fixture(
        &sb,
        "outlet",
        "1.0",
        "/usr",
        "mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/outlet",
    );
    let journal = sb
        .root
        .join("var/lib/portalis/activation-journal-outlet.jsonl");
    fs::create_dir_all(journal.parent().expect("state dir")).expect("state dir");
    fs::write(&journal, "{\"path\":123}\n").expect("damaged journal");

    let blocked = sb.run(&["install", archive.to_str().expect("archive")]);
    assert!(
        !blocked.status.success(),
        "a write command ran past a damaged record"
    );

    let dropped = sb.ok(&["--discard-recovery"]);
    assert!(
        dropped.contains("dropped"),
        "the command did not name the record it removed:\n{dropped}"
    );
    assert!(!journal.exists(), "the record survived the discard");

    sb.ok(&["install", archive.to_str().expect("archive")]);
    sb.ok(&["--verify"]);
}
