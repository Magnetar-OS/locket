//! The daemon's objects, exercised over a real (private) message bus.
//!
//! See [`locket_secret::testing`] for why the bus is a private `dbus-daemon`
//! with no service directories, and never the session bus.

use locket_secret::testing::Daemon;

/// `confirm-each-use` exists to stop a process running as you from signing
/// with your key unattended. The answer to the question must therefore not be
/// something a bus peer can send: when it was (`Manager1.AnswerConfirm`, fed by
/// a broadcast `ConfirmRequested` carrying sequential ids), any process could
/// ask the agent for a signature and approve it itself before the dialog was
/// even drawn.
#[tokio::test]
async fn no_bus_peer_can_answer_a_signing_confirmation() {
    let daemon = Daemon::start().await;
    let client = daemon.client().await;

    let manager = client
        .introspect(locket_secret::manager::MANAGER_PATH)
        .await;
    assert!(
        manager.contains("org.locket.Manager1"),
        "the manager is not published: {manager}"
    );
    assert!(
        !manager.contains("AnswerConfirm"),
        "a bus peer can answer a signing confirmation"
    );
    assert!(
        !manager.contains("ConfirmRequested"),
        "signing confirmations are broadcast to every bus peer"
    );
}
