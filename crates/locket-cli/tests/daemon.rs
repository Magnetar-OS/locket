//! `locket-cli` beside a running daemon.
//!
//! The command line writes the vault file itself. A daemon serving that file
//! has to be told, or its libsecret clients and SSH agent go on seeing what it
//! read before — and the command line must stay usable, and quiet, when there
//! is no daemon to tell. Every bus here is a private one; see
//! [`locket_secret::testing`].

use std::path::Path;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use locket_secret::testing::{Daemon, PASSPHRASE, PrivateBus};

/// An address nothing listens on, for a run that is to find no bus.
///
/// Leaving the variable out does not do that: without it zbus falls back to
/// `/run/user/<uid>/bus`, which on a desktop is the session bus of whoever
/// runs the tests, with their real daemon on it.
const NO_BUS: &str = "unix:path=/nonexistent/locket-tests/bus";

/// Run `locket-cli` with an environment holding the given bus address and
/// nothing else, so it cannot find the session bus of whoever runs the tests.
async fn cli(bus: Option<&str>, vault: &Path, args: &[&str]) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_locket-cli"));
    command
        .arg("--vault")
        .arg(vault)
        .args(["--passphrase-env", "LOCKET_TEST_PASSPHRASE"])
        .args(args)
        .env_clear()
        .env("LOCKET_TEST_PASSPHRASE", PASSPHRASE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("DBUS_SESSION_BUS_ADDRESS", bus.unwrap_or(NO_BUS))
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("locket-cli did not finish")
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const ADD: [&str; 3] = ["add", "from the command line", "--generate"];

/// An item added from a terminal is there for the daemon's clients straight
/// away. It used to stay invisible to them until the daemon's own next write,
/// or the next unlock.
#[tokio::test]
async fn a_write_reaches_the_running_daemon() {
    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    assert!(client.search_all().await.unwrap().is_empty());

    let added = cli(Some(daemon.bus.address()), daemon.vault_path(), &ADD).await;
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(!stderr(&added).contains("daemon"), "{}", stderr(&added));

    let paths = client.search_all().await.unwrap();
    assert_eq!(
        paths.len(),
        1,
        "the daemon still serves what it read before"
    );
    assert_eq!(
        client.item_label(&paths[0]).await.unwrap(),
        "from the command line"
    );
}

/// A locked daemon has nothing to re-read, and that is not worth a word.
#[tokio::test]
async fn a_locked_daemon_is_not_an_error() {
    let daemon = Daemon::start().await;
    daemon
        .state
        .lock()
        .await
        .lock_vault(locket_secret::service::LockReason::Request);

    let added = cli(Some(daemon.bus.address()), daemon.vault_path(), &ADD).await;
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(!stderr(&added).contains("daemon"), "{}", stderr(&added));
}

/// No daemon, and no session bus at all: the write succeeds and says nothing
/// about either. Running without a daemon is a supported arrangement.
#[tokio::test]
async fn without_a_daemon_the_command_line_is_silent() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("alone.vault");

    let bus = PrivateBus::start();
    let created = cli(Some(bus.address()), &vault, &["init"]).await;
    assert!(created.status.success(), "{}", stderr(&created));
    let added = cli(Some(bus.address()), &vault, &ADD).await;
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(!stderr(&added).contains("daemon"), "{}", stderr(&added));

    let added = cli(None, &vault, &["add", "with no bus", "--generate"]).await;
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(!stderr(&added).contains("daemon"), "{}", stderr(&added));

    let listed = cli(None, &vault, &["list"]).await;
    let listed = String::from_utf8_lossy_owned(listed.stdout);
    assert!(listed.contains("from the command line"), "{listed}");
    assert!(listed.contains("with no bus"), "{listed}");
}

/// Telling a running daemon must never *start* one. A call to a name nobody
/// owns makes the bus activate whatever service is registered for it, and the
/// installed daemon is registered for `org.freedesktop.secrets` — so a
/// recovery tool run because the daemon will not start would wait on exactly
/// that.
#[tokio::test]
async fn a_write_does_not_start_a_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("alone.vault");
    let started = dir.path().join("activated");
    let services = dir.path().join("services");
    std::fs::create_dir(&services).unwrap();
    for name in locket_secret::client::BUS_NAMES {
        std::fs::write(
            services.join(format!("{name}.service")),
            format!(
                "[D-BUS Service]\nName={name}\nExec=/bin/sh -c 'touch {}; sleep 30'\n",
                started.display()
            ),
        )
        .unwrap();
    }
    let bus = PrivateBus::start_activating(&services);

    let created = cli(Some(bus.address()), &vault, &["init"]).await;
    assert!(created.status.success(), "{}", stderr(&created));
    let began = Instant::now();
    let added = cli(Some(bus.address()), &vault, &ADD).await;
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(
        began.elapsed() < Duration::from_secs(4),
        "the command line waited on a daemon that was not running"
    );
    assert!(!started.exists(), "saving started the daemon");
}

/// What the unlock dialog does with a TPM factor, end to end but for the
/// window: a software TPM releases the slot's key for the PIN, and that key,
/// sent to the daemon, unlocks it for its clients. A wrong PIN releases
/// nothing to send.
#[tokio::test]
async fn the_key_a_tpm_releases_unlocks_the_daemon() {
    use locket_core::{Item, ItemKind, Vault, crypto::KdfParams};

    let swtpm = locket_tpm::testing::Swtpm::start();
    let tpm = swtpm.tpm();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.vault");
    let mut vault = Vault::create(&path, PASSPHRASE, KdfParams::insecure_fast()).unwrap();
    vault.add_item_default(Item::new(ItemKind::Login, "behind the PIN").with_secret("hunter2"));
    vault.save().unwrap();
    tpm.enroll_into(&mut vault, "24680").unwrap();
    drop(vault);

    let daemon = Daemon::start_locked(dir, path.clone()).await;
    let client = daemon.client().await;
    let manager = client.manager().await;

    // The dialog's side: read the slots from the locked file, ask the TPM.
    let slots = Vault::read_slots(&path).unwrap();
    assert!(tpm.unlock_key(&slots, Some("13579")).is_err());
    assert!(daemon.state.lock().await.is_locked());

    let key = tpm.unlock_key(&slots, Some("24680")).unwrap();
    let opened: bool = manager
        .call("UnlockWithKey", &("tpm2", key.expose().to_vec()))
        .await
        .unwrap();
    assert!(opened, "the daemon refused the key the TPM released");

    let paths = client.search_all().await.unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        client.item_label(&paths[0]).await.unwrap(),
        "behind the PIN"
    );
}
