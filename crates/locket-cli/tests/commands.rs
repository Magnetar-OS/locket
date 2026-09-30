//! `locket-cli` commands against a vault in a temporary directory.
//!
//! No bus is given to these runs: the environment is emptied, so the tool
//! finds no session bus and no daemon, which it treats as the ordinary case.

use std::path::Path;
use std::process::{Output, Stdio};

const PASSPHRASE: &str = "correct horse battery";

fn cli(vault: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_locket-cli"))
        .arg("--vault")
        .arg(vault)
        .args(["--passphrase-env", "LOCKET_TEST_PASSPHRASE"])
        .args(args)
        .env_clear()
        .env("LOCKET_TEST_PASSPHRASE", PASSPHRASE)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn vault_with(labels: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("test.vault");
    let created = cli(&vault, &["init"]);
    assert!(created.status.success(), "{}", text(&created.stderr));
    for label in labels {
        let added = cli(&vault, &["add", label, "--generate"]);
        assert!(added.status.success(), "{}", text(&added.stderr));
    }
    (dir, vault)
}

/// `get` prints a secret for a script to use, so a query that fits several
/// items is an error, as it is for the commands that change things. It used
/// to print whichever item happened to come first — another login's password,
/// silently.
#[test]
fn an_ambiguous_get_prints_no_secret() {
    let (_dir, vault) = vault_with(&["github personal", "github work"]);

    let got = cli(&vault, &["get", "github"]);
    assert!(!got.status.success(), "an ambiguous query printed a secret");
    assert!(got.stdout.is_empty());
    assert!(
        text(&got.stderr).contains("github work"),
        "{}",
        text(&got.stderr)
    );

    let got = cli(&vault, &["get", "github work"]);
    assert!(got.status.success(), "{}", text(&got.stderr));
    assert_eq!(
        got.stdout.len(),
        21,
        "a 20-character password and a newline"
    );
}

/// `--memory-mib` is multiplied into KiB. An overflow used to wrap, which in a
/// release build re-derived the vault at a small cost that looked valid.
#[test]
fn an_impossible_memory_cost_is_refused_by_name() {
    let (_dir, vault) = vault_with(&[]);
    let changed = cli(
        &vault,
        &["passwd", "--rederive-only", "--memory-mib", "4194368"],
    );
    assert_eq!(changed.status.code(), Some(1), "{}", text(&changed.stderr));
    assert!(
        text(&changed.stderr).contains("--memory-mib is too large"),
        "{}",
        text(&changed.stderr)
    );
}

/// The dry run of `import-env` counted an unreadable file as one holding no
/// variables, where the import itself would fail on it.
#[test]
fn a_dry_run_names_an_unreadable_env_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let env = project.join(".env");
    std::fs::write(&env, "API_TOKEN=abc123def456ghi789\n").unwrap();
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&env).is_ok() {
        // Running as root: permissions do not stop the read, so there is
        // nothing to show.
        return;
    }

    let scanned = cli(
        &dir.path().join("unused.vault"),
        &["import-env", dir.path().to_str().unwrap(), "--dry-run"],
    );
    assert!(scanned.status.success(), "{}", text(&scanned.stderr));
    assert!(
        text(&scanned.stdout).contains("unreadable"),
        "{}",
        text(&scanned.stdout)
    );
}

/// Restoring a revision went through `edit_item`, which files the current
/// state first. With the history full that pushed the oldest revision out
/// and shifted every number down before the restore read it, so `--restore
/// 0` brought back the second-oldest and lost the one asked for.
#[test]
fn restoring_from_a_full_history_restores_the_revision_asked_for() {
    let (_dir, vault) = vault_with(&["rotated"]);
    for n in 1..=11 {
        let edited = cli(&vault, &["edit", "rotated", "--set", &format!("note=v{n}")]);
        assert!(edited.status.success(), "{}", text(&edited.stderr));
    }
    // Ten revisions kept: the states holding v1 to v10, oldest first.
    let restored = cli(&vault, &["history", "rotated", "--restore", "0"]);
    assert!(restored.status.success(), "{}", text(&restored.stderr));

    let note = cli(&vault, &["get", "rotated", "--field", "note"]);
    assert_eq!(text(&note.stdout).trim(), "v1");
}
