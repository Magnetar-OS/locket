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

/// The portal's master key lives in the vault like any item, but a bus peer
/// deleting or rewriting it would re-key every sandboxed application at once.
#[tokio::test]
async fn the_portal_master_cannot_be_deleted_or_rewritten_over_the_bus() {
    use locket_core::model::{Item, ItemKind, internal};

    let daemon = Daemon::start().await;
    let path = {
        let mut state = daemon.state.lock().await;
        let vault = state.vault.as_mut().unwrap();
        let item = Item::new(ItemKind::Application, "XDG Secret portal master key")
            .with_attribute(internal::ATTRIBUTE, internal::PORTAL_MASTER);
        let collection = vault.data().collections[0].id;
        let id = vault.add_item(collection, item).unwrap();
        vault.save().unwrap();
        locket_secret::service::item_path(collection, id)
    };
    locket_secret::service::register_vault_objects(daemon.server.object_server(), &daemon.state)
        .await
        .unwrap();
    let client = daemon.client().await;
    let item = client
        .proxy(path.as_str(), "org.freedesktop.Secret.Item")
        .await;

    let deleted: zbus::Result<zbus::zvariant::OwnedObjectPath> = item.call("Delete", &()).await;
    assert!(
        deleted.is_err(),
        "the portal master was deleted over the bus"
    );
    let untagged = item
        .set_property(
            "Attributes",
            std::collections::HashMap::<String, String>::new(),
        )
        .await;
    assert!(
        untagged.is_err(),
        "the portal master's tag was stripped over the bus"
    );

    let state = daemon.state.lock().await;
    let vault = state.vault.as_ref().unwrap();
    let (_, id) = locket_secret::service::parse_item_path(path.as_str()).unwrap();
    assert!(vault.item(id).is_some_and(|i| i.is_internal()));
}
