use super::{copy_into_live, remove_in_live, safe_symlink, writable_parents};
use std::fs;
use std::path::Path;

fn scratch(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("portalis-links-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("etc")).unwrap();
    root
}

#[test]
fn a_symlinked_parent_is_judged_by_its_target() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("symlink-parent");
    let shared = root.join("srv/share");
    fs::create_dir_all(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    std::os::unix::fs::symlink(&shared, root.join("opt")).unwrap();
    let flagged = writable_parents(&root, "/opt/bin/tool");
    assert!(
        !flagged.is_empty(),
        "a world-writable target behind a symlinked parent went unnoticed"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_shared_parent_without_the_sticky_bit_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("writable");
    let open = root.join("srv");
    fs::create_dir_all(open.join("app")).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    let found = super::writable_parents(&root, "/srv/app/bin");
    assert_eq!(
        found,
        vec!["/srv".to_string()],
        "a world-writable parent was missed"
    );

    fs::set_permissions(&open, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(
        super::writable_parents(&root, "/srv/app/bin").is_empty(),
        "a sticky directory was reported"
    );

    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(super::writable_parents(&root, "/srv/app/bin").is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_resolved_live_path_follows_a_symlinked_parent() {
    let root = scratch("resolved-parent");
    fs::create_dir_all(root.join("opt")).unwrap();
    std::os::unix::fs::symlink("../etc", root.join("opt/link")).unwrap();
    let resolved = super::resolved_live_target(&root, "/opt/link/evil").expect("resolve");
    assert_eq!(resolved, root.join("etc/evil"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_copy_never_lands_outside_the_root() {
    let root = scratch("escape");
    let outside = root.with_extension("outside");
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(&outside).unwrap();
    // etc/ssh is a symlink that leaves the root
    std::os::unix::fs::symlink(&outside, root.join("etc/ssh")).unwrap();
    let source = root.join("payload");
    fs::write(&source, b"x").unwrap();

    let refused = copy_into_live(&root, "/etc/ssh/config", &source, None);
    assert!(refused.is_err(), "a copy followed a symlinked parent");
    assert!(
        !outside.join("config").exists(),
        "the file landed outside the root"
    );
    let _ = fs::remove_dir_all(&outside);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_copy_does_not_overwrite_what_appeared_first() {
    let root = scratch("noreplace");
    let source = root.join("payload");
    fs::write(&source, b"new").unwrap();
    fs::write(root.join("etc/config"), b"user edit").unwrap();

    let refused = copy_into_live(&root, "/etc/config", &source, None);
    assert!(refused.is_err(), "an existing file was overwritten");
    assert_eq!(fs::read(root.join("etc/config")).unwrap(), b"user edit");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_copy_keeps_the_source_mode() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch("mode");
    let source = root.join("payload");
    fs::write(&source, b"secret").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    copy_into_live(&root, "/etc/secret", &source, None).expect("copy");
    let mode = fs::metadata(root.join("etc/secret"))
        .expect("copied file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the source mode was lost");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn removing_a_link_keeps_its_target() {
    let root = scratch("unlink");
    fs::write(root.join("etc/real"), b"keep").unwrap();
    std::os::unix::fs::symlink(root.join("etc/real"), root.join("etc/link")).unwrap();
    remove_in_live(&root, "/etc/link").expect("removes");
    assert!(!Path::new(&root.join("etc/link")).exists());
    assert_eq!(fs::read(root.join("etc/real")).unwrap(), b"keep");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_link_cannot_be_placed_through_a_symlinked_parent() {
    let root = scratch("linkescape");
    let outside = root.with_extension("outside2");
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("etc/ssh")).unwrap();
    let refused = safe_symlink(&root, "/etc/ssh/key", "/somewhere");
    assert!(refused.is_err(), "a link was placed outside the root");
    assert!(!outside.join("key").exists());
    let _ = fs::remove_dir_all(&outside);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_missing_package_symlink_is_recreated_from_its_record() {
    let root = scratch("symlink-repair");
    let paths = crate::paths::Paths::at(root.clone());
    paths.ensure_layout().expect("layout");
    let db = crate::db::Db::open(&paths, crate::db::Access::Write).expect("db");
    let store = paths.store().join("linkpkg-1.0-aaaa");
    fs::create_dir_all(store.join("usr/lib")).expect("store");
    fs::write(store.join("usr/lib/real"), b"payload").expect("payload");
    std::os::unix::fs::symlink("real", store.join("usr/lib/link")).expect("store link");
    db.conn()
        .execute(
            "INSERT INTO packages (name, version, store_path, recipe_sha256, \
             manifest_digest, installed_at, build_log) \
             VALUES ('linkpkg', '1.0', ?1, 'x', 'y', 'now', 'log')",
            rusqlite::params![store.to_string_lossy().to_string()],
        )
        .expect("package row");
    db.conn()
        .execute(
            "INSERT INTO files (pkg, path, sha256, link_target, mode) \
             VALUES ('linkpkg', '/usr/lib/link', '', 'real', 0)",
            [],
        )
        .expect("file row");

    super::repair_links(&db, &paths).expect("repair");

    let live = root.join("usr/lib/link");
    assert_eq!(
        fs::read_link(&live).expect("live link"),
        std::path::PathBuf::from("real")
    );
    let recorded: String = db
        .conn()
        .query_row(
            "SELECT link_target FROM files WHERE pkg = 'linkpkg' AND path = '/usr/lib/link'",
            [],
            |row| row.get(0),
        )
        .expect("recorded target");
    assert_eq!(recorded, "real", "the record was rewritten as a store path");
    let _ = fs::remove_dir_all(&root);
}
