use super::targets::is_protected_link_target;
use super::validate;
use crate::build::BuildOutcome;
use crate::recipe::{BuildManifest, ManifestFile, Recipe};
use std::path::Path;

fn recipe(extra: &str) -> Recipe {
    let text = format!(
        "package.name = p\npackage.version = 1\nsource.file = p.tar\nsource.sha256 = {}\nbuild.system = custom\ninstall.prefix = /usr\n{extra}",
        "0".repeat(64)
    );
    Recipe::parse(&text).expect("recipe")
}

fn outcome(file: ManifestFile) -> BuildOutcome {
    BuildOutcome {
        store_path: "/usr/portalis/packages/p-1-deadbeef".into(),
        manifest: BuildManifest {
            patches: Vec::new(),
            name: "p".into(),
            version: "1".into(),
            recipe_sha256: "0".repeat(64),
            source_sha256: "0".repeat(64),
            cflags: String::new(),
            rustflags: String::new(),
            rpath: Vec::new(),
            network: false,
            writable: Vec::new(),
            read: Vec::new(),
            confinement: "bubblewrap".into(),
            check_command: None,
            check_timeout: None,
            check_required: None,
            files: vec![file],
            dirs: Vec::new(),
        },
        log_path: "/tmp/build.log".into(),
    }
}

fn file(path: &str) -> ManifestFile {
    ManifestFile {
        path: path.into(),
        sha256: "0".repeat(64),
        mode: 0o644,
        link: None,
    }
}

#[test]
fn a_regular_manifest_passes() {
    validate(&recipe(""), &outcome(file("/usr/share/p/file"))).expect("valid");
}

#[test]
fn a_sensitive_regular_path_is_refused() {
    let error = validate(&recipe(""), &outcome(file("/etc/ld.so.preload")))
        .expect_err("sensitive path accepted");
    assert!(format!("{error}").contains("host-sensitive"));
}

#[test]
fn a_manager_owned_path_is_refused() {
    let error = validate(
        &recipe(""),
        &outcome(file("/etc/portalis/trusted-keys/attacker")),
    )
    .expect_err("manager path accepted");
    assert!(format!("{error}").contains("host-sensitive"));
}

#[test]
fn a_reserved_helper_path_is_refused() {
    let error = validate(&recipe(""), &outcome(file("/usr/bin/bwrap")))
        .expect_err("reserved path accepted");
    assert!(format!("{error}").contains("reserved"));
}

#[test]
fn a_relative_link_that_stays_inside_passes() {
    let mut entry = file("/usr/bin/tool");
    entry.link = Some("../lib/p/tool".into());
    validate(&recipe(""), &outcome(entry)).expect("relative link");
}

#[test]
fn an_undeclared_setuid_file_is_refused() {
    let mut entry = file("/usr/bin/p");
    entry.mode = 0o4755;
    let error = validate(&recipe(""), &outcome(entry)).expect_err("setuid accepted");
    assert!(format!("{error}").contains("setuid"));
}

#[test]
fn a_declared_setgid_file_passes() {
    let mut entry = file("/usr/bin/p");
    entry.mode = 0o2755;
    validate(&recipe("install.setgid = usr/bin/p:5\n"), &outcome(entry)).expect("declared setgid");
}

#[test]
fn a_link_to_a_host_sensitive_path_is_refused() {
    let mut entry = file("/usr/share/p/link");
    entry.link = Some("/etc/shadow".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("sensitive link accepted");
    assert!(format!("{error}").contains("host-sensitive"));
}

#[test]
fn a_link_to_a_host_configuration_path_is_refused() {
    let mut entry = file("/usr/share/p/link");
    entry.link = Some("/etc/hosts".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("host config link accepted");
    assert!(
        format!("{error}").contains("protected host path")
            || format!("{error}").contains("host-sensitive"),
        "{error:#}"
    );
}

#[test]
fn the_package_store_is_not_a_protected_link_target() {
    let store = Path::new("/usr/portalis/packages/p-1-deadbeef");
    assert!(!is_protected_link_target(
        "/usr/portalis/packages/p-1-deadbeef/usr/lib/p",
        Some(store),
        Path::new("/"),
    ));
    assert!(is_protected_link_target(
        "/root/.ssh/id_rsa",
        None,
        Path::new("/")
    ));
    assert!(!is_protected_link_target(
        "/usr/lib/libc.so.6",
        None,
        Path::new("/")
    ));
}

#[test]
fn a_link_with_a_dot_prefix_is_still_refused() {
    let mut entry = file("/usr/share/p/link");
    entry.link = Some("/./etc/shadow".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("sensitive link accepted");
    assert!(format!("{error}").contains("host-sensitive"));
}

#[test]
fn a_link_to_the_live_root_is_refused() {
    let mut entry = file("/usr/share/p/link");
    entry.link = Some("/".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("root link accepted");
    assert!(format!("{error}").contains("live root"));
}

#[test]
fn a_normal_absolute_link_passes() {
    let mut entry = file("/usr/bin/p");
    entry.link = Some("/usr/lib/p/p".into());
    validate(&recipe(""), &outcome(entry)).expect("normal link");
}

#[test]
fn a_link_to_a_shared_temporary_directory_is_refused() {
    let mut entry = file("/usr/bin/p");
    entry.link = Some("/tmp/evil".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("temporary link accepted");
    assert!(
        format!("{error}").contains("protected host path")
            || format!("{error}").contains("writable")
            || format!("{error}").contains("link target"),
        "{error:#}"
    );
}

#[test]
fn a_relative_link_into_a_shared_directory_is_refused() {
    let mut entry = file("/usr/bin/p");
    entry.link = Some("../../tmp/evil".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("temporary link accepted");
    assert!(
        format!("{error}").contains("protected host path")
            || format!("{error}").contains("writable")
            || format!("{error}").contains("link target"),
        "{error:#}"
    );
}

#[test]
fn a_link_to_another_store_is_refused() {
    let mut entry = file("/usr/bin/p");
    entry.link = Some("/usr/portalis/packages/other-1.0/usr/lib/p".into());
    let error = validate(&recipe(""), &outcome(entry)).expect_err("other store accepted");
    assert!(format!("{error}").contains("store"), "{error:#}");
}

#[test]
fn a_link_inside_this_store_is_allowed() {
    let mut entry = file("/usr/bin/p");
    entry.link = Some("/usr/portalis/packages/p-1-deadbeef/usr/lib/p".into());
    validate(&recipe(""), &outcome(entry)).expect("own store link");
}

#[test]
fn a_climbing_manifest_path_is_refused() {
    let error = validate(&recipe(""), &outcome(file("/usr/../etc/shadow")))
        .expect_err("climbing path accepted");
    assert!(format!("{error}").contains("invalid component"));
}

#[test]
fn an_ssh_client_config_is_not_a_sensitive_path() {
    validate(&recipe(""), &outcome(file("/etc/ssh/ssh_config"))).expect("client config");
}

#[test]
fn an_sshd_config_is_still_refused() {
    let error = validate(&recipe(""), &outcome(file("/etc/ssh/sshd_config")))
        .expect_err("sshd config accepted");
    assert!(format!("{error}").contains("host-sensitive"));
}

#[test]
fn an_init_script_is_not_a_sensitive_path() {
    validate(&recipe(""), &outcome(file("/etc/init.d/rsync"))).expect("init script");
}

#[test]
fn a_link_into_etc_is_not_a_protected_target() {
    assert!(!is_protected_link_target(
        "/etc/localtime",
        None,
        Path::new("/")
    ));
    assert!(!is_protected_link_target(
        "/etc/ssl/private",
        None,
        Path::new("/")
    ));
}
