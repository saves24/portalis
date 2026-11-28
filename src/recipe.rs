mod manifest;
mod parse;
mod types;

pub use manifest::{BuildManifest, ManifestDir, ManifestFile};
pub(crate) use types::{default_jobs, known_key, usable_group_name};
pub use types::{Build, Check, FilesPolicy, Hooks, Install, PackageInfo, Patch, Recipe, Source};

#[cfg(test)]
mod tests {
    use super::*;

    fn cargo_recipe(args: &[&str]) -> String {
        let mut text = BASE
            .replace("{name}", "x")
            .replace("{file}", "somefile.tar")
            .replace("{sha}", &"a".repeat(64))
            .replace("{prefix}", "/")
            .replace("build.system = custom", "build.system = cargo");
        if !args.is_empty() {
            text.push_str(&format!("build.args = {}\n", args.join(", ")));
        }
        text
    }

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn mutated_recipes_are_rejected_without_panicking() {
        let base = BASE
            .replace("{name}", "x")
            .replace("{file}", "somefile.tar")
            .replace("{sha}", &"a".repeat(64))
            .replace("{prefix}", "/");
        let bytes = base.into_bytes();
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..2000 {
            let mut data = bytes.clone();
            let edits = 1 + (next_random(&mut state) % 4) as usize;
            for _ in 0..edits {
                let index = (next_random(&mut state) as usize) % data.len();
                data[index] = (next_random(&mut state) % 256) as u8;
            }
            let Ok(text) = String::from_utf8(data) else {
                continue;
            };
            if let Ok(recipe) = Recipe::parse(&text) {
                let _ = recipe.validate();
            }
        }
    }

    #[test]
    fn a_cargo_value_flag_needs_the_equals_form() {
        let recipe = Recipe::parse(&cargo_recipe(&["--features", "extra"])).expect("parses");
        let error = recipe
            .validate()
            .expect_err("a separate value entry was accepted");
        assert!(
            format!("{error}").contains("--features=value"),
            "the refusal does not name the shape: {error}"
        );
    }

    #[test]
    fn a_preserved_path_must_be_absolute() {
        let text = format!(
            "{BASE}\nfiles.preserve = etc/foo.conf\n",
            BASE = BASE
                .replace("{name}", "x")
                .replace("{file}", "f.tar")
                .replace("{sha}", &"a".repeat(64))
                .replace("{prefix}", "/usr")
        );
        let error = Recipe::parse(&text)
            .expect("recipe parses")
            .validate()
            .expect_err("a relative preserve path was accepted");
        assert!(
            format!("{error:#}").contains("files.preserve entries must be absolute"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn an_unknown_isolation_is_refused() {
        let text = format!(
            "{BASE}\nbuild.isolation = RPATH\n",
            BASE = BASE
                .replace("{name}", "x")
                .replace("{file}", "f.tar")
                .replace("{sha}", &"a".repeat(64))
                .replace("{prefix}", "/usr")
        );
        let error = Recipe::parse(&text)
            .expect("recipe parses")
            .validate()
            .expect_err("a misspelled isolation was accepted");
        assert!(
            format!("{error:#}").contains("unknown build.isolation"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn a_read_path_must_be_absolute() {
        let text = format!(
            "{BASE}\nbuild.read = opt/toolchain\n",
            BASE = BASE
                .replace("{name}", "x")
                .replace("{file}", "f.tar")
                .replace("{sha}", &"a".repeat(64))
                .replace("{prefix}", "/usr")
        );
        let error = Recipe::parse(&text)
            .expect("recipe parses")
            .validate()
            .expect_err("a relative read path was accepted");
        assert!(
            format!("{error:#}").contains("build.read entries must be absolute"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn a_read_path_cannot_climb_out() {
        let text = format!(
            "{BASE}\nbuild.read = /opt/../etc\n",
            BASE = BASE
                .replace("{name}", "x")
                .replace("{file}", "f.tar")
                .replace("{sha}", &"a".repeat(64))
                .replace("{prefix}", "/usr")
        );
        let error = Recipe::parse(&text)
            .expect("recipe parses")
            .validate()
            .expect_err("a climbing read path was accepted");
        assert!(
            format!("{error:#}").contains("build.read entries must be absolute"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn a_read_path_lands_in_the_manifest() {
        let text = format!(
            "{BASE}\nbuild.read = /opt/toolchain\n",
            BASE = BASE
                .replace("{name}", "x")
                .replace("{file}", "f.tar")
                .replace("{sha}", &"a".repeat(64))
                .replace("{prefix}", "/usr")
        );
        let recipe = Recipe::parse(&text).expect("recipe parses");
        assert_eq!(recipe.build.read, vec!["/opt/toolchain".to_string()]);
    }

    #[test]
    fn an_attached_short_feature_flag_is_refused() {
        let recipe = Recipe::parse(&cargo_recipe(&["-Fextra"])).expect("parses");
        let error = recipe
            .validate()
            .expect_err("an attached -F value was accepted");
        assert!(
            format!("{error}").contains("-F=extra"),
            "the refusal does not name the shape: {error}"
        );
    }

    #[test]
    fn the_equals_form_is_accepted() {
        let recipe =
            Recipe::parse(&cargo_recipe(&["--features=extra", "-F=other"])).expect("parses");
        recipe.validate().expect("the equals form was refused");
    }

    #[test]
    fn a_setgid_entry_without_a_group_is_refused() {
        let text = BASE
            .replace("{name}", "x")
            .replace("{file}", "somefile.tar")
            .replace("{sha}", &"a".repeat(64))
            .replace("{prefix}", "/")
            + "install.setgid = usr/bin/x\n";
        let recipe = Recipe::parse(&text).expect("recipe parses");
        let error = recipe
            .validate()
            .expect_err("a setgid entry without a group was accepted");
        assert!(
            format!("{error}").contains("path:group"),
            "the refusal does not show the shape: {error}"
        );
    }

    #[test]
    fn a_setgid_gid_that_does_not_fit_is_refused() {
        let text = BASE
            .replace("{name}", "x")
            .replace("{file}", "somefile.tar")
            .replace("{sha}", &"a".repeat(64))
            .replace("{prefix}", "/")
            + "install.setgid = usr/bin/x:4294967296\n";
        let recipe = Recipe::parse(&text).expect("recipe parses");
        let error = recipe
            .validate()
            .expect_err("a gid wider than 32 bits was accepted");
        assert!(
            format!("{error}").contains("32 bits"),
            "the refusal does not explain the range: {error}"
        );
    }

    #[test]
    fn a_setgid_group_name_is_accepted() {
        let text = BASE
            .replace("{name}", "x")
            .replace("{file}", "somefile.tar")
            .replace("{sha}", &"a".repeat(64))
            .replace("{prefix}", "/")
            + "install.setgid = usr/bin/x:tty\n";
        let recipe = Recipe::parse(&text).expect("recipe parses");
        recipe.validate().expect("a group name was refused");
    }

    #[test]
    fn a_setgid_path_that_climbs_out_is_refused() {
        let text = BASE
            .replace("{name}", "x")
            .replace("{file}", "somefile.tar")
            .replace("{sha}", &"a".repeat(64))
            .replace("{prefix}", "/")
            + "install.setgid = ../etc/shadow\n";
        let recipe = Recipe::parse(&text).expect("recipe parses");
        let error = recipe
            .validate()
            .expect_err("a climbing setgid path was accepted");
        assert!(
            format!("{error}").contains("install.setgid"),
            "the refusal does not name the key: {error}"
        );
    }

    const BASE: &str = "\
package.name = {name}
package.version = 1.0
source.file = {file}
source.sha256 = {sha}
build.system = custom
install.prefix = {prefix}
";

    fn parse(name: &str, file: &str, sha: &str, prefix: &str) -> Recipe {
        Recipe::parse(
            &BASE
                .replace("{name}", name)
                .replace("{file}", file)
                .replace("{sha}", sha)
                .replace("{prefix}", prefix),
        )
        .expect("recipe parses")
    }

    fn digest() -> String {
        "0".repeat(64)
    }

    #[test]
    fn parses_the_check_section() {
        let text = BASE
            .replace("{name}", "x")
            .replace("{file}", "x.tar")
            .replace("{sha}", &digest())
            .replace("{prefix}", "/usr")
            + "check.command = printf ok\ncheck.timeout = 42\ncheck.required = false\n";
        let recipe = Recipe::parse(&text).expect("parses");
        assert_eq!(recipe.check.command.as_deref(), Some("printf ok"));
        assert_eq!(recipe.check.timeout, Some(42));
        assert!(!recipe.check.required);
    }

    #[test]
    fn parses_patch_blocks_in_order() {
        let text = "\
package.name = demo
package.version = 1.0
source.file = demo-1.0.tar.xz
source.sha256 = 0000000000000000000000000000000000000000000000000000000000000000
build.system = custom
build.patch = <<PATCH
file = first.patch
sha256 = 1111111111111111111111111111111111111111111111111111111111111111
content = <<DIFF
--- a/one
+++ b/one
DIFF
PATCH
build.patch = <<PATCH
file = second.patch
sha256 = 2222222222222222222222222222222222222222222222222222222222222222
optional = true
content = <<DIFF
--- a/two
+++ b/two
DIFF
PATCH
install.prefix = /usr
";
        let recipe = Recipe::parse(text).expect("parses");
        assert_eq!(recipe.build.patches.len(), 2);
        assert_eq!(recipe.build.patches[0].file, "first.patch");
        assert!(recipe.build.patches[0].content.contains("+++ b/one"));
        assert!(recipe.build.patches[1].optional);
        assert!(recipe.build.patches[1].content.contains("+++ b/two"));
    }

    #[test]
    fn rejects_path_traversal_in_names_and_files() {
        assert!(parse("../evil", "a.tar.gz", &digest(), "/usr")
            .validate()
            .is_err());
        assert!(parse("ok", "../a.tar.gz", &digest(), "/usr")
            .validate()
            .is_err());
        assert!(parse("ok", "sub/a.tar.gz", &digest(), "/usr")
            .validate()
            .is_err());
        assert!(parse("ok", "a.tar.gz", &digest(), "usr")
            .validate()
            .is_err());
        assert!(parse("ok", "a.tar.gz", &digest(), "/usr/../etc")
            .validate()
            .is_err());
        assert!(parse("ok", "a.tar.gz", &digest(), "/usr")
            .validate()
            .is_ok());
    }

    #[test]
    fn rejects_source_dir_escape() {
        let mut recipe = parse("ok", "a.tar.gz", &digest(), "/usr");
        recipe.source.dir = "../..".into();
        assert!(recipe.validate().is_err());
        recipe.source.dir = "/etc".into();
        assert!(recipe.validate().is_err());
        recipe.source.dir = "sub/dir".into();
        assert!(recipe.validate().is_ok());
    }

    #[test]
    fn manifest_digest_ignores_file_order() {
        let file_a = ManifestFile {
            path: "/usr/bin/a".into(),
            sha256: digest(),
            mode: 0o755,
            link: None,
        };
        let file_b = ManifestFile {
            path: "/usr/bin/b".into(),
            sha256: digest(),
            mode: 0o644,
            link: None,
        };
        let mut one = BuildManifest {
            name: "x".into(),
            version: "1".into(),
            recipe_sha256: digest(),
            source_sha256: digest(),
            cflags: String::new(),
            rustflags: String::new(),
            rpath: Vec::new(),
            patches: Vec::new(),
            network: false,
            writable: Vec::new(),
            read: Vec::new(),
            confinement: "none".to_string(),
            check_command: None,
            check_timeout: None,
            check_required: None,
            files: vec![file_a.clone(), file_b.clone()],
            dirs: Vec::new(),
        };
        let mut two = one.clone();
        two.files = vec![file_b, file_a];
        assert_eq!(one.digest().unwrap(), two.digest().unwrap());
        one.files[0].sha256 = "1".repeat(64);
        assert_ne!(one.digest().unwrap(), two.digest().unwrap());
    }
}
