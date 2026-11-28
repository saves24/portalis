use super::*;

#[test]
fn a_failed_command_leaves_the_state_unlocked() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let out = sb.run(&["remove", "no-such-package"]);
    assert!(
        !out.status.success(),
        "removing a missing package succeeded"
    );
    // the next command takes the same lock
    let report = sb.ok(&["clean", "--store", "--yes"]);
    assert!(
        report.contains("nothing") || report.contains("0 "),
        "the command after a failure did not run: {report}"
    );
}

#[test]
fn a_broken_recipe_for_another_package_does_not_block_an_import() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    // a recipe that fails to load, for a package the archive is not
    fs::write(
        sb.recipe_dir().join("prefix.port"),
        "package.name = prefix\nversion = nonsense\n",
    )
    .expect("write broken recipe");
    let fixtures = sb.root.join("fixtures");
    fs::create_dir_all(&fixtures).expect("fixtures");
    let archive = fixtures.join("prefix-tool-1.0-x86_64.tar");
    fs::write(
        &archive,
        raw_tar_full(&[("usr/bin/prefix-tool", b"binary\n".as_slice(), 0o755, 0)]),
    )
    .expect("write archive");

    sb.ok(&["install", archive.to_str().unwrap()]);
    assert!(
        sb.root.join("usr/bin/prefix-tool").exists(),
        "the import did not apply"
    );
}

#[test]
fn concurrent_installs_do_not_collide() {
    if !require_root() {
        return;
    }
    let _slot = take_build_slot();
    let sb = Sandbox::new();
    let first = fixture(
        &sb,
        "conc1",
        "1.0",
        "/usr",
        "sleep 1; mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/conc1",
    );
    let second = fixture(
        &sb,
        "conc2",
        "1.0",
        "/usr",
        "sleep 1; mkdir -p $DESTDIR$PREFIX/bin && cp payload.txt $DESTDIR$PREFIX/bin/conc2",
    );

    let mut a = sb
        .command()
        .args(["install", first.to_str().unwrap()])
        .spawn()
        .expect("spawn first install");
    let mut b = sb
        .command()
        .args(["install", second.to_str().unwrap()])
        .spawn()
        .expect("spawn second install");

    let first_status = a.wait().expect("wait first");
    let second_status = b.wait().expect("wait second");
    assert!(
        first_status.success() && second_status.success(),
        "a concurrent install failed (first={first_status:?}, second={second_status:?})"
    );
    assert!(sb.root.join("usr/bin/conc1").exists());
    assert!(sb.root.join("usr/bin/conc2").exists());
    assert!(sb.ok(&["--verify"]).contains("clean"));
}
