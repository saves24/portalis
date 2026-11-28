use super::overlap::leftover_problems;

use crate::db::{Access, Db};
use crate::paths::Paths;
use std::fs;

fn scratch(tag: &str) -> (std::path::PathBuf, Paths, Db) {
    let root = std::env::temp_dir().join(format!("portalis-verify-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("var/db/portalis")).unwrap();
    let paths = Paths::at(root.clone());
    fs::create_dir_all(paths.state_dir()).unwrap();
    let db = Db::open(&paths, Access::Write).unwrap();
    (root, paths, db)
}

#[test]
fn leftovers_without_an_owner_are_reported() {
    let (root, paths, db) = scratch("leftover");
    db.conn()
        .execute(
            "INSERT INTO files (pkg, path, sha256, link_target, mode) \
             VALUES ('gone', '/usr/share/gone/a', 'aa', '/x/a', 420)",
            [],
        )
        .unwrap();
    fs::write(paths.state_dir().join("activating"), "gone 1.0\n").unwrap();

    let found = leftover_problems(&db, &paths).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].contains("never finished"), "{found:?}");
    assert!(found[1].contains("no package row"), "{found:?}");

    fs::remove_file(paths.state_dir().join("activating")).unwrap();
    assert!(leftover_problems(&db, &paths).unwrap().len() == 1);
    let _ = fs::remove_dir_all(root);
}
