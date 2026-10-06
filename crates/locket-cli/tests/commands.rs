//! `locket-cli` commands against a vault in a temporary directory.
//!
//! No bus is given to these runs: the environment is emptied and the bus
//! address points at nothing, so the tool finds no session bus and no daemon,
//! which it treats as the ordinary case.

use std::path::Path;
use std::process::{Output, Stdio};

const PASSPHRASE: &str = "correct horse battery";

/// An address nothing listens on. An emptied environment alone is not "no
/// bus": without the variable zbus falls back to `/run/user/<uid>/bus`, the
/// session bus of whoever runs the tests, with their real daemon on it.
const NO_BUS: &str = "unix:path=/nonexistent/locket-tests/bus";

fn cli(vault: &Path, args: &[&str]) -> Output {
    cli_with(vault, args, &[])
}

/// [`cli`] with more in its environment; a later entry replaces an earlier
/// one of the same name, the passphrase included.
fn cli_with(vault: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_locket-cli"))
        .arg("--vault")
        .arg(vault)
        .args(["--passphrase-env", "LOCKET_TEST_PASSPHRASE"])
        .args(args)
        .env_clear()
        .env("LOCKET_TEST_PASSPHRASE", PASSPHRASE)
        .env("LOCKET_TEST_KDBX_PASSPHRASE", "for the database")
        .env("DBUS_SESSION_BUS_ADDRESS", NO_BUS)
        .envs(env.iter().copied())
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

/// What an import could not bring across is in its notes, and the command
/// line printed the notes of two importers only. An authenticator export
/// with an entry locket cannot generate reported success and said nothing
/// about the entry left behind.
#[test]
fn an_import_names_what_it_left_out() {
    let (dir, vault) = vault_with(&[]);
    let export = dir.path().join("aegis.json");
    std::fs::write(
        &export,
        r#"{"db":{"entries":[
            {"type":"totp","name":"ada","issuer":"GitHub","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"hotp","name":"counter","issuer":"Bank","info":{"secret":"JBSWY3DPEHPK3PXP","counter":1}}
        ]}}"#,
    )
    .unwrap();

    let imported = cli(&vault, &["import-totp", export.to_str().unwrap()]);
    assert!(imported.status.success(), "{}", text(&imported.stderr));
    assert!(
        text(&imported.stderr).contains("Bank"),
        "the entry left behind was not named: {}",
        text(&imported.stderr)
    );
}

/// The scan skips a directory it cannot read rather than failing on it, and
/// the dry run said nothing about the skip, so a tree looked fully covered.
#[test]
fn a_dry_run_names_an_unreadable_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let closed = dir.path().join("pgdata");
    std::fs::create_dir(&closed).unwrap();
    std::fs::write(closed.join(".env"), "API_TOKEN=abc123def456ghi789\n").unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&closed).is_ok();

    let scanned = cli(
        &dir.path().join("unused.vault"),
        &["import-env", dir.path().to_str().unwrap(), "--dry-run"],
    );
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
    if readable {
        // Running as root: nothing is unreadable to show.
        return;
    }
    assert!(scanned.status.success(), "{}", text(&scanned.stderr));
    let out = text(&scanned.stdout);
    assert!(
        out.contains("pgdata") && out.contains("unreadable"),
        "{out}"
    );
}

/// Run `locket-cli` able to write no file past one block (512 or 1024 bytes,
/// as the shell counts them), the limit reported to it as a failed write —
/// the signal that would otherwise end the process is ignored first.
fn cli_on_a_full_disk(vault: &Path, args: &[&str]) -> Output {
    std::process::Command::new("/bin/sh")
        .args(["-c", "trap '' XFSZ; ulimit -f 1; exec \"$@\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_locket-cli"))
        .arg("--vault")
        .arg(vault)
        .args(["--passphrase-env", "LOCKET_TEST_PASSPHRASE"])
        .args(args)
        .env_clear()
        .env("LOCKET_TEST_PASSPHRASE", PASSPHRASE)
        .env("LOCKET_TEST_KDBX_PASSPHRASE", "for the database")
        .env("DBUS_SESSION_BUS_ADDRESS", NO_BUS)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A write that fails part-way leaves nothing where the file was going. A
/// KDBX export cut short used to stay there — an encrypted database nothing
/// can open, under the name the backup was to have — and so did a saved
/// attachment, in the clear.
#[test]
fn a_write_that_fails_part_way_leaves_no_file() {
    let (dir, vault) = vault_with(&[]);

    // Enough items that every format runs past the limit.
    let entries: Vec<String> = (0..40)
        .map(|n| {
            format!(
                r#"{{"type":"totp","name":"account-{n}","issuer":"Service {n}","info":{{"secret":"JBSWY3DPEHPK3PXP"}}}}"#
            )
        })
        .collect();
    let seeds = dir.path().join("aegis.json");
    std::fs::write(
        &seeds,
        format!(r#"{{"db":{{"entries":[{}]}}}}"#, entries.join(",")),
    )
    .unwrap();
    let imported = cli(&vault, &["import-totp", seeds.to_str().unwrap()]);
    assert!(imported.status.success(), "{}", text(&imported.stderr));

    let document = dir.path().join("recovery-codes.txt");
    std::fs::write(&document, vec![b'x'; 4096]).unwrap();
    let attached = cli(
        &vault,
        &["attach", "add", "Service 0", document.to_str().unwrap()],
    );
    assert!(attached.status.success(), "{}", text(&attached.stderr));

    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let kdbx = out.join("export.kdbx");
    let json = out.join("export.json");
    let csv = out.join("export.csv");
    let saved = out.join("recovery-codes.txt");
    let runs: [(&Path, Vec<&str>); 4] = [
        (
            &kdbx,
            vec![
                "export",
                kdbx.to_str().unwrap(),
                "--format",
                "kdbx",
                "--kdbx-passphrase-env",
                "LOCKET_TEST_KDBX_PASSPHRASE",
            ],
        ),
        (
            &json,
            vec![
                "export",
                json.to_str().unwrap(),
                "--format",
                "json",
                "--i-understand-this-is-plaintext",
            ],
        ),
        (
            &csv,
            vec![
                "export",
                csv.to_str().unwrap(),
                "--format",
                "csv",
                "--i-understand-this-is-plaintext",
            ],
        ),
        (
            &saved,
            vec![
                "attach",
                "save",
                "Service 0",
                "recovery-codes.txt",
                "--out",
                saved.to_str().unwrap(),
            ],
        ),
    ];

    for (path, args) in &runs {
        let failed = cli_on_a_full_disk(&vault, args);
        assert!(
            !failed.status.success(),
            "{}: the write was not cut short",
            path.display()
        );
        // The failure being tested, and not some other one.
        assert!(
            text(&failed.stderr).contains("File too large"),
            "{}",
            text(&failed.stderr)
        );
        let left: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "{}: left {left:?}", path.display());
    }

    // The same commands, with room to finish, write the files whole.
    for (path, args) in &runs {
        let written = cli(&vault, args);
        assert!(written.status.success(), "{}", text(&written.stderr));
        assert!(std::fs::metadata(path).unwrap().len() > 1024);
    }
}

/// A TPM factor from the command line, against a software TPM: added, used
/// to open the vault with no passphrase, used to set a new passphrase in
/// place of a forgotten one, and removed. Nothing but the application could
/// add or remove a factor before, and nothing at all could unlock with one.
#[test]
fn a_tpm_factor_is_added_unlocks_and_is_removed() {
    let swtpm = locket_tpm::testing::Swtpm::start();
    let (dir, vault) = vault_with(&["github"]);
    let on_tpm = |args: &[&str], extra: &[(&str, &str)]| {
        let mut env = vec![
            ("TCTI", swtpm.tcti()),
            ("LOCKET_TEST_PIN", "135790"),
            ("LOCKET_TEST_WRONG_PIN", "000000"),
            ("LOCKET_TEST_EMPTY", ""),
            ("LOCKET_TEST_NEW", "a new passphrase"),
        ];
        env.extend_from_slice(extra);
        cli_with(&vault, args, &env)
    };
    const BY_PIN: [&str; 4] = ["--unlock-with", "tpm", "--pin-env", "LOCKET_TEST_PIN"];
    let by_pin = |args: &[&str]| on_tpm(&[&BY_PIN[..], args].concat(), &[]);

    // No factor yet: said before any PIN is asked for or tried.
    let none = by_pin(&["list"]);
    assert!(!none.status.success());
    assert!(
        text(&none.stderr).contains("no TPM factor"),
        "{}",
        text(&none.stderr)
    );

    // A factor needs a PIN; then one is added, and only one.
    let empty = on_tpm(
        &["slots", "add-tpm", "--new-pin-env", "LOCKET_TEST_EMPTY"],
        &[],
    );
    assert!(
        !empty.status.success(),
        "a TPM factor was added without a PIN"
    );
    let added = on_tpm(
        &["slots", "add-tpm", "--new-pin-env", "LOCKET_TEST_PIN"],
        &[],
    );
    assert!(added.status.success(), "{}", text(&added.stderr));
    let again = on_tpm(
        &["slots", "add-tpm", "--new-pin-env", "LOCKET_TEST_PIN"],
        &[],
    );
    assert!(!again.status.success(), "a second TPM factor was added");
    assert!(text(&again.stderr).contains("already has a TPM factor"));

    let listed = text(&cli(&vault, &["slots"]).stdout);
    let id_of = |what: &str| {
        listed
            .lines()
            .find(|line| line.contains(what))
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_else(|| panic!("no {what} slot in:\n{listed}"))
            .to_owned()
    };
    let (passphrase_slot, tpm_slot) = (id_of("argon2id"), id_of("TPM 2.0 + PIN"));

    // The PIN opens the vault with no passphrase given; a wrong one, and
    // none, do not.
    let secret = cli(&vault, &["get", "github"]);
    let by_tpm = by_pin(&["get", "github"]);
    assert!(by_tpm.status.success(), "{}", text(&by_tpm.stderr));
    assert_eq!(by_tpm.stdout, secret.stdout);
    for wrong in ["LOCKET_TEST_WRONG_PIN", "LOCKET_TEST_EMPTY"] {
        let refused = on_tpm(
            &["--unlock-with", "tpm", "--pin-env", wrong, "get", "github"],
            &[],
        );
        assert!(!refused.status.success(), "{wrong} opened the vault");
        assert!(refused.stdout.is_empty());
    }

    // What needs the passphrase itself says so, and a factor the vault does
    // not have is not looked for on the bus.
    let rederive = by_pin(&["passwd", "--rederive-only"]);
    assert!(!rederive.status.success());
    assert!(text(&rederive.stderr).contains("needs the passphrase"));
    let token = on_tpm(&["--unlock-with", "security-key", "list"], &[]);
    assert!(!token.status.success());
    assert!(text(&token.stderr).contains("no security-key factor"));
    let init = on_tpm(&["--unlock-with", "tpm", "init"], &[]);
    assert!(!init.status.success());

    // The passphrase forgotten: the TPM factor lets a new one be set, and
    // goes on opening the vault afterwards.
    let reset = by_pin(&["passwd", "--new-passphrase-env", "LOCKET_TEST_NEW"]);
    assert!(reset.status.success(), "{}", text(&reset.stderr));
    assert!(
        !cli(&vault, &["list"]).status.success(),
        "the old passphrase still opens it"
    );
    let renewed = [("LOCKET_TEST_PASSPHRASE", "a new passphrase")];
    assert!(on_tpm(&["list"], &renewed).status.success());
    assert_eq!(by_pin(&["get", "github"]).stdout, secret.stdout);

    // The last passphrase stays; the TPM factor goes, and with it the PIN.
    let passphrase_slot =
        id_of_passphrase_after_rekey(&on_tpm(&["slots"], &renewed), &passphrase_slot);
    let kept = on_tpm(&["slots", "rm", &passphrase_slot], &renewed);
    assert!(!kept.status.success(), "the only passphrase was removed");
    let removed = on_tpm(&["slots", "rm", &tpm_slot], &renewed);
    assert!(removed.status.success(), "{}", text(&removed.stderr));
    assert!(
        !by_pin(&["list"]).status.success(),
        "a removed factor still opens the vault"
    );
    assert!(on_tpm(&["list"], &renewed).status.success());
    drop(dir);
}

/// The passphrase slot's id after a passphrase change, which replaces the
/// slot: whichever listed slot is the Argon2id one. `before` is the id it
/// had, to show the change really made a new slot.
fn id_of_passphrase_after_rekey(slots: &Output, before: &str) -> String {
    let listed = text(&slots.stdout);
    let id = listed
        .lines()
        .find(|line| line.contains("argon2id"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("no passphrase slot in:\n{listed}"))
        .to_owned();
    assert_ne!(id, before, "the passphrase slot was not re-made");
    id
}
