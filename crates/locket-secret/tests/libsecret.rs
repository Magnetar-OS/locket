//! The daemon's objects, driven by libsecret itself.
//!
//! `secret-tool` is libsecret's own command line: the same
//! `secret_password_store` and `secret_password_lookup` calls that
//! `git credential-libsecret`, Chromium and GNOME applications make. These
//! tests run it against a daemon on a private bus (see
//! [`locket_secret::testing`]), so what is checked is what a real client sees
//! — above all how long it waits, which no hand-written client would tell us.
//!
//! The defect this file was written for: a locked vault held `SearchItems` and
//! `CreateItem` open while it asked to be unlocked, for up to two minutes.
//! GDBus gives a call 25 seconds. With nobody at the keyboard every
//! `git push` spent 25 seconds in the lookup and 25 more in the store, and
//! each reported "Timeout was reached".

use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use locket_secret::testing::{Daemon, PROMPT_TIMEOUT, UNLOCK_WAIT};
use tokio::io::AsyncWriteExt as _;

/// Run `secret-tool` against the daemon's private bus, and nothing else: the
/// environment is emptied first, so there is no session bus to fall back to.
async fn secret_tool(daemon: &Daemon, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = tokio::process::Command::new("secret-tool")
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("DBUS_SESSION_BUS_ADDRESS", daemon.bus.address())
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("secret-tool (libsecret-tools) must be installed to run the libsecret tests");
    let mut input = child.stdin.take().expect("piped stdin");
    if let Some(text) = stdin {
        input.write_all(text.as_bytes()).await.unwrap();
    }
    drop(input);
    // Longer than GDBus's own 25 seconds, so a call held past that shows up
    // as libsecret's timeout rather than as ours.
    tokio::time::timeout(Duration::from_secs(40), child.wait_with_output())
        .await
        .expect("secret-tool did not finish")
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const ATTRIBUTES: [&str; 4] = ["service", "example.test", "user", "ada"];

async fn store(daemon: &Daemon, secret: &str) -> Output {
    let mut args = vec!["store", "--label=an example"];
    args.extend(ATTRIBUTES);
    secret_tool(daemon, &args, Some(secret)).await
}

async fn lookup(daemon: &Daemon) -> Output {
    let mut args = vec!["lookup"];
    args.extend(ATTRIBUTES);
    secret_tool(daemon, &args, None).await
}

#[tokio::test]
async fn libsecret_stores_finds_replaces_and_clears() {
    let daemon = Daemon::start().await;

    let stored = store(&daemon, "hunter2").await;
    assert!(stored.status.success(), "{}", stderr(&stored));
    let found = lookup(&daemon).await;
    assert!(found.status.success(), "{}", stderr(&found));
    assert_eq!(found.stdout, b"hunter2");

    // The same attributes again replace the secret; they do not add a second.
    let stored = store(&daemon, "correct battery").await;
    assert!(stored.status.success(), "{}", stderr(&stored));
    assert_eq!(lookup(&daemon).await.stdout, b"correct battery");
    let mut search = vec!["search", "--all"];
    search.extend(ATTRIBUTES);
    let listed = secret_tool(&daemon, &search, None).await;
    assert!(listed.status.success(), "{}", stderr(&listed));
    let listed = String::from_utf8_lossy_owned(listed.stdout);
    assert_eq!(listed.matches("secret = ").count(), 1, "{listed}");
    assert!(listed.contains("label = an example"), "{listed}");

    let mut clear = vec!["clear"];
    clear.extend(ATTRIBUTES);
    let cleared = secret_tool(&daemon, &clear, None).await;
    assert!(cleared.status.success(), "{}", stderr(&cleared));
    let gone = lookup(&daemon).await;
    assert!(!gone.status.success(), "a cleared secret was still found");
    assert!(gone.stdout.is_empty());
}

/// Locked, and the person answers the dialog: both calls succeed. The store
/// goes through libsecret's own `Unlock` and `Prompt`; the lookup is held
/// until the vault opens.
#[tokio::test]
async fn libsecret_waits_for_the_person_to_unlock() {
    let daemon = Daemon::start().await;
    daemon
        .lock_and_serve_prompts(|| Ok("nobody".to_owned()))
        .await;

    let person = daemon.unlock_after(Duration::from_millis(700));
    let stored = store(&daemon, "hunter2").await;
    person.await.unwrap();
    assert!(stored.status.success(), "{}", stderr(&stored));

    daemon
        .state
        .lock()
        .await
        .lock_vault(locket_secret::service::LockReason::Request);
    let person = daemon.unlock_after(Duration::from_millis(700));
    let found = lookup(&daemon).await;
    person.await.unwrap();
    assert!(found.status.success(), "{}", stderr(&found));
    assert_eq!(found.stdout, b"hunter2");
}

/// Locked, and nobody answers: libsecret is told so, by the daemon, before
/// its own call timeout. It never sees "Timeout was reached".
#[tokio::test]
async fn libsecret_is_told_the_vault_is_locked_not_left_to_time_out() {
    let daemon = Daemon::start().await;
    daemon
        .lock_and_serve_prompts(|| Ok("nobody".to_owned()))
        .await;

    let started = Instant::now();
    let found = lookup(&daemon).await;
    assert!(!found.status.success());
    assert!(found.stdout.is_empty());
    assert!(
        !stderr(&found).contains("Timeout"),
        "the lookup was held past libsecret's call timeout: {}",
        stderr(&found)
    );
    assert!(started.elapsed() < UNLOCK_WAIT + Duration::from_secs(3));

    // The store waits on the unlock prompt, which the dialog's own time limit
    // ends; no single call is held for it.
    let started = Instant::now();
    let stored = store(&daemon, "hunter2").await;
    assert!(!stored.status.success());
    assert!(
        !stderr(&stored).contains("Timeout"),
        "the store was held past libsecret's call timeout: {}",
        stderr(&stored)
    );
    assert!(started.elapsed() < PROMPT_TIMEOUT + Duration::from_secs(5));
}
