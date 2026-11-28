use super::{activation_blocked, relink_after_failed_remove, Previous};
use crate::db::Db;
use crate::install::activate::{apply_pending_file, restore_created};
use crate::install::hooks::{hook_line, is_icon_theme_dir};
use crate::links::safe_symlink;
use crate::paths::Paths;
use crate::proc::is_critical_path;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn a_path_whose_backup_is_missing_is_left_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    let live = root.join("usr/bin/tool");
    std::fs::write(&live, b"user data").expect("user file");

    let created = vec![(
        "usr/bin/tool".to_string(),
        Previous::Displaced {
            backup: root.join("backup/usr/bin/tool").display().to_string(),
        },
    )];
    restore_created(root, &created);

    assert_eq!(
        std::fs::read(&live).expect("the user file was removed"),
        b"user data"
    );
}

#[test]
fn a_link_and_a_new_path_are_restored() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    std::fs::write(root.join("usr/bin/new"), b"x").expect("file");

    let created = vec![
        ("usr/bin/new".to_string(), Previous::Missing),
        (
            "usr/bin/old".to_string(),
            Previous::Symlink {
                target: "/store/x".to_string(),
            },
        ),
    ];
    restore_created(root, &created);

    assert!(
        !root.join("usr/bin/new").exists(),
        "a new path was left behind"
    );
    let target = std::fs::read_link(root.join("usr/bin/old")).expect("link");
    assert_eq!(target, PathBuf::from("/store/x"));
}

#[test]
fn a_failed_link_puts_the_adopted_file_back() {
    use crate::db::{Access, PackageRow, PackageState};
    use crate::recipe::{Hooks, ManifestFile};

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    let paths = Paths::at(root);
    paths.ensure_layout().expect("layout");
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    let live = root.join("usr/bin/tool");
    std::fs::write(&live, b"user data").expect("user file");
    let store = root.join("store/pkg/tool");
    std::fs::create_dir_all(store.parent().expect("store dir")).expect("store dir");
    std::fs::write(&store, b"binary").expect("store file");

    let db = Db::open(&paths, Access::Write).expect("db");
    let file = ManifestFile {
        path: "/usr/bin/tool".into(),
        sha256: crate::util::sha256_file(&store).expect("sha"),
        mode: 0,
        link: None,
    };
    db.stage_file("pkg", &file, store.to_str().expect("utf8"), "file")
        .expect("stage");

    let pkg = PackageRow {
        name: "pkg".into(),
        version: "1.0".into(),
        store_path: "store/pkg".into(),
        recipe_sha256: String::new(),
        manifest_digest: String::new(),
        installed_at: String::new(),
        build_log: String::new(),
        signature: None,
        rpath: Vec::new(),
        hooks: Hooks::default(),
        state: PackageState::StagedForced,
    };

    crate::links::FAIL_NEXT_LINK.with(|flag| flag.set(true));
    let mut kept = 0usize;
    let entry = (
        "/usr/bin/tool".to_string(),
        file.sha256.clone(),
        store.to_str().expect("utf8").to_string(),
        0u32,
        "file".to_string(),
    );
    let result = apply_pending_file(&db, &pkg, &paths, root, entry, &mut kept);
    assert!(result.is_err(), "the injected link failure was swallowed");
    assert_eq!(
        std::fs::read(&live).expect("the user file is gone"),
        b"user data"
    );
    assert!(
        !paths.state_dir().join("backup/usr/bin/tool").exists(),
        "the backup was left behind"
    );
}

#[test]
fn an_old_pending_link_to_a_shared_directory_is_refused() {
    use crate::db::{Access, PackageRow, PackageState};
    use crate::recipe::Hooks;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    let paths = Paths::at(root);
    paths.ensure_layout().expect("layout");
    let db = Db::open(&paths, Access::Write).expect("db");
    let pkg = PackageRow {
        name: "pkg".into(),
        version: "1.0".into(),
        store_path: root.join("store/pkg").to_string_lossy().into_owned(),
        recipe_sha256: String::new(),
        manifest_digest: String::new(),
        installed_at: String::new(),
        build_log: String::new(),
        signature: None,
        rpath: Vec::new(),
        hooks: Hooks::default(),
        state: PackageState::Staged,
    };
    let mut kept = 0usize;
    let entry = (
        "/usr/bin/old".to_string(),
        String::new(),
        "/tmp/evil".to_string(),
        0u32,
        "symlink".to_string(),
    );
    let error = apply_pending_file(&db, &pkg, &paths, root, entry, &mut kept)
        .expect_err("the old pending link was accepted");
    assert!(
        format!("{error}").contains("link target") || format!("{error}").contains("writable"),
        "{error:#}"
    );
    assert!(!root.join("usr/bin/old").exists());
}

#[test]
fn a_staged_package_does_not_replace_an_unowned_symlink() {
    use crate::db::{Access, PackageRow, PackageState};
    use crate::recipe::Hooks;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    let paths = Paths::at(root);
    paths.ensure_layout().expect("layout");
    std::fs::create_dir_all(root.join("usr/bin")).expect("bin");
    let live = root.join("usr/bin/tool");
    std::os::unix::fs::symlink("/tmp/elsewhere", &live).expect("existing link");
    let store = root.join("store/pkg/tool");
    std::fs::create_dir_all(store.parent().expect("store dir")).expect("store dir");
    std::fs::write(&store, b"binary").expect("store file");

    let db = Db::open(&paths, Access::Write).expect("db");
    let pkg = PackageRow {
        name: "pkg".into(),
        version: "1.0".into(),
        store_path: root.join("store/pkg").to_string_lossy().into_owned(),
        recipe_sha256: String::new(),
        manifest_digest: String::new(),
        installed_at: String::new(),
        build_log: String::new(),
        signature: None,
        rpath: Vec::new(),
        hooks: Hooks::default(),
        state: PackageState::Staged,
    };
    let mut kept = 0usize;
    let entry = (
        "/usr/bin/tool".to_string(),
        crate::util::sha256_file(&store).expect("sha"),
        store.to_string_lossy().into_owned(),
        0u32,
        "file".to_string(),
    );
    let error = apply_pending_file(&db, &pkg, &paths, root, entry, &mut kept)
        .expect_err("the unowned link was replaced");
    assert!(format!("{error}").contains("unowned"), "{error:#}");
    assert_eq!(
        std::fs::read_link(&live).expect("the existing link was removed"),
        PathBuf::from("/tmp/elsewhere")
    );
}

#[test]
fn a_hook_that_succeeds_reports_nothing() {
    let result = std::process::Command::new("true").status();
    assert!(hook_line("true", result).is_none());
}

#[test]
fn a_hook_that_fails_is_reported_with_its_status() {
    let result = std::process::Command::new("false").status();
    let line = hook_line("ldconfig in /tmp/x", result).expect("the failure was swallowed");
    assert!(
        line.contains("ldconfig in /tmp/x"),
        "unexpected text: {line}"
    );
    assert!(line.contains("exited"), "no exit status: {line}");
}

#[test]
fn a_hook_that_cannot_start_is_reported() {
    let result = std::process::Command::new("definitely-not-a-command").status();
    let line = hook_line("icon cache", result).expect("the failure was swallowed");
    assert!(line.contains("could not run"), "unexpected text: {line}");
}

#[test]
fn a_backup_path_never_escapes_the_backup_directory() {
    let state = Path::new("/var/lib/portalis");
    for path in ["/etc/rpc", "etc/rpc", "/usr/lib/libc.so.6"] {
        let backup = state.join("backup").join(path.trim_start_matches('/'));
        assert!(
            backup.starts_with("/var/lib/portalis/backup/"),
            "{path} produced {backup:?}"
        );
    }
}

#[test]
fn elf_info_reads_the_running_binary() {
    let exe = std::env::current_exe().expect("current executable");
    let info = crate::elf::elf_info(&exe).expect("parses as ELF");
    assert!(!info.needed.is_empty(), "no NEEDED entries");
    assert!(info.interpreter.is_some(), "no program interpreter");
}

#[test]
fn runpath_entries_reaching_host_library_dirs_are_not_isolated() {
    let store = PathBuf::from("/usr/portalis/packages/pkg-1.0-abcdef123456");
    let host = vec![PathBuf::from("/usr/lib"), PathBuf::from("/usr/lib64")];
    assert!(crate::elf::runpath_is_isolated(
        &store,
        "/usr/portalis/packages/pkg-1.0-abcdef123456/usr/lib",
        &host
    ));
    assert!(!crate::elf::runpath_is_isolated(
        &store,
        "$ORIGIN/../lib",
        &host
    ));
    assert!(crate::elf::runpath_is_isolated(
        &store,
        "/opt/vendor/lib",
        &host
    ));
    assert!(!crate::elf::runpath_is_isolated(&store, "/usr/lib", &host));
    assert!(!crate::elf::runpath_is_isolated(
        &store,
        "/usr/lib64",
        &host
    ));
    assert!(!crate::elf::runpath_is_isolated(&store, "lib", &host));
    assert!(!crate::elf::runpath_is_isolated(
        &store,
        "/opt/vendor/lib",
        &[]
    ));
}

#[test]
fn live_paths_are_derived_from_store_locations() {
    let paths = Paths::new();
    assert_eq!(
        crate::proc::live_from_store(
            &paths,
            "/usr/portalis/packages/systemd-261.2-abc/usr/lib/systemd/systemd"
        ),
        Some("/usr/lib/systemd/systemd".into())
    );
    assert_eq!(
        crate::proc::live_from_store(&paths, "/usr/bin/firefox"),
        None
    );
}

#[test]
fn criticality_follows_actual_use_plus_boot_artifacts() {
    let mut used = std::collections::HashSet::new();
    used.insert("/usr/lib/libc.so.6".to_string());
    assert!(is_critical_path("/usr/lib/libc.so.6", &used));
    assert!(is_critical_path("/boot/vmlinuz", &used));
    assert!(!is_critical_path("/usr/bin/firefox", &used));
}

#[test]
fn safe_symlink_rejects_parent_components() {
    let root = std::env::temp_dir().join(format!("portalis-link-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let error = safe_symlink(&root, "../escape", "target").unwrap_err();
    assert!(
        format!("{error:#}").contains("parent component"),
        "unexpected error: {error:#}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_failed_remove_recreates_the_links_it_deleted() {
    let root = std::env::temp_dir().join(format!("portalis-relink-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let files = vec![(
        "usr/bin/x".to_string(),
        "0".repeat(64),
        "store/x/bin".to_string(),
        0o755u32,
    )];
    let (relinked, skipped) = relink_after_failed_remove(&root, &files);
    assert_eq!(
        (relinked, skipped),
        (1, 0),
        "the missing link was not recreated"
    );
    assert_eq!(
        fs::read_link(root.join("usr/bin/x")).unwrap(),
        PathBuf::from("store/x/bin")
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_restored_original_survives_a_failed_remove() {
    let root = std::env::temp_dir().join(format!("portalis-relink-own-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("etc/conf"), "original\n").unwrap();
    let files = vec![(
        "etc/conf".to_string(),
        "0".repeat(64),
        "store/conf".to_string(),
        0o644u32,
    )];
    let (relinked, skipped) = relink_after_failed_remove(&root, &files);
    assert_eq!(
        (relinked, skipped),
        (0, 1),
        "a restored file was overwritten"
    );
    assert_eq!(
        fs::read_to_string(root.join("etc/conf")).unwrap(),
        "original\n"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn safe_symlink_creates_nested_link() {
    let root = std::env::temp_dir().join(format!("portalis-link-ok-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    safe_symlink(&root, "usr/lib/libx.so.1", "store/libx.so.1").unwrap();
    let link = root.join("usr/lib/libx.so.1");
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("store/libx.so.1")
    );
    let _ = fs::remove_dir_all(&root);
}
#[test]
fn boot_artifacts_always_defer_activation() {
    let files = vec![crate::recipe::ManifestFile {
        path: "/boot/vmlinuz".into(),
        sha256: String::new(),
        mode: 0o644,
        link: None,
    }];
    assert!(activation_blocked(&Paths::at("/"), &files).unwrap());
}

#[test]
fn only_theme_directories_under_share_are_accepted() {
    assert!(is_icon_theme_dir("/usr/share/icons/hicolor"));
    assert!(is_icon_theme_dir("/usr/share/pixmaps"));
    assert!(!is_icon_theme_dir("/etc"));
    assert!(!is_icon_theme_dir("/usr/share/icons/../../etc"));
    assert!(!is_icon_theme_dir("usr/share/icons/hicolor"));
    assert!(!is_icon_theme_dir("/usr/share/pixmaps-evil"));
}
