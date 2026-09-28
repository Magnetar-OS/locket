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
    locket_secret::service::sync_objects(daemon.server.object_server(), &daemon.state)
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

/// The GUI writes the vault file itself and then asks the daemon to reload.
/// The daemon's `SearchItems` saw the new item, but its path had no object
/// behind it, so the native host and the applet — which read `Label` and
/// `Attributes` off each path — could not see it until the next unlock.
#[tokio::test]
async fn an_item_another_writer_added_is_reachable_after_a_reload() {
    use locket_core::model::{Item, ItemKind};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;

    let mut gui = locket_core::Vault::open(daemon.vault_path(), support_passphrase()).unwrap();
    gui.add_item_default(Item::new(ItemKind::Note, "written by the GUI"));
    gui.save().unwrap();

    let reloaded: bool = client.manager().await.call("Reload", &()).await.unwrap();
    assert!(reloaded);

    let paths = client.search_all().await.unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        client.item_label(&paths[0]).await.unwrap(),
        "written by the GUI",
        "the new item's path has no object behind it"
    );
}

/// A locked vault does not advertise how many items it holds: the item
/// objects come off the bus on every lock, however it happens.
#[tokio::test]
async fn locking_takes_the_item_objects_off_the_bus() {
    use locket_core::model::{Item, ItemKind};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let path = {
        let mut state = daemon.state.lock().await;
        let vault = state.vault.as_mut().unwrap();
        let collection = vault.data().collections[0].id;
        let id = vault
            .add_item(collection, Item::new(ItemKind::Note, "n"))
            .unwrap();
        vault.save().unwrap();
        locket_secret::service::item_path(collection, id)
    };
    locket_secret::service::sync_objects(daemon.server.object_server(), &daemon.state)
        .await
        .unwrap();
    assert!(client.exists(path.as_str()).await);

    // Over the bus.
    let () = client.manager().await.call("Lock", &()).await.unwrap();
    assert!(
        !client.exists(path.as_str()).await,
        "a locked vault still publishes its items"
    );

    // And the way the idle timer and the session lock do it: straight on the
    // state, with nobody on the bus to tidy up after.
    let unlocked: bool = client
        .manager()
        .await
        .call("Unlock", &(locket_secret::testing::PASSPHRASE,))
        .await
        .unwrap();
    assert!(unlocked);
    assert!(client.exists(path.as_str()).await);
    daemon.state.lock().await.close_vault();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while client.exists(path.as_str()).await {
        assert!(
            std::time::Instant::now() < deadline,
            "an idle lock left the items published"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// libsecret stores into `/aliases/default` directly. That object has to
/// follow the alias when it moves, or every `secret-tool store` keeps landing
/// in the old collection until the daemon restarts.
#[tokio::test]
async fn aliases_follow_their_collection() {
    use std::collections::HashMap;
    use zbus::zvariant::{OwnedObjectPath, Value};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let service = client.service().await;

    let mut properties = HashMap::new();
    properties.insert(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work"),
    );
    let (work, _prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call("CreateCollection", &(properties.clone(), "work"))
        .await
        .unwrap();
    assert!(
        client.exists("/org/freedesktop/secrets/aliases/work").await,
        "a collection created with an alias is not reachable by it"
    );

    // Created again for the same alias: the spec returns the existing one.
    let (again, _prompt): (OwnedObjectPath, OwnedObjectPath) = service
        .call("CreateCollection", &(properties, "work"))
        .await
        .unwrap();
    assert_eq!(again, work, "two collections now share one alias");

    let () = service.call("SetAlias", &("default", &work)).await.unwrap();
    let label: String = client
        .proxy(
            "/org/freedesktop/secrets/aliases/default",
            "org.freedesktop.Secret.Collection",
        )
        .await
        .get_property("Label")
        .await
        .unwrap();
    assert_eq!(
        label, "Work",
        "/aliases/default still names the old collection"
    );

    let _: OwnedObjectPath = client
        .proxy(work.as_str(), "org.freedesktop.Secret.Collection")
        .await
        .call("Delete", &())
        .await
        .unwrap();
    assert!(
        !client
            .exists("/org/freedesktop/secrets/aliases/default")
            .await
    );
    assert!(!client.exists("/org/freedesktop/secrets/aliases/work").await);
}

fn support_passphrase() -> &'static str {
    locket_secret::testing::PASSPHRASE
}

/// A store that did not reach the disk must not be reported as stored: the
/// client would stop holding a secret the vault does not have. It used to
/// return success after logging the conflict, and publish an object for an
/// item that no longer existed.
#[tokio::test]
async fn a_store_that_did_not_reach_the_disk_is_an_error() {
    use std::collections::HashMap;
    use zbus::zvariant::{OwnedObjectPath, Value};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let session = client.open_session().await;

    // A change still pending in memory — what an earlier failed save used to
    // leave behind — so the write below is built on a stale copy...
    daemon.state.lock().await.vault.as_mut().unwrap().data_mut();
    // ...while another writer gets to the file first.
    let mut gui = locket_core::Vault::open(daemon.vault_path(), support_passphrase()).unwrap();
    gui.add_item_default(locket_core::model::Item::new(
        locket_core::model::ItemKind::Note,
        "written by the GUI",
    ));
    gui.save().unwrap();

    let mut attributes = HashMap::new();
    attributes.insert("app", "example");
    let mut properties = HashMap::new();
    properties.insert(
        "org.freedesktop.Secret.Item.Label",
        Value::from("from an app"),
    );
    properties.insert(
        "org.freedesktop.Secret.Item.Attributes",
        Value::from(attributes),
    );
    let secret = (session, Vec::<u8>::new(), b"s3cret".to_vec(), "text/plain");
    let stored: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = client
        .proxy(
            "/org/freedesktop/secrets/aliases/default",
            "org.freedesktop.Secret.Collection",
        )
        .await
        .call("CreateItem", &(properties, secret, false))
        .await;
    assert!(
        stored.is_err(),
        "a store that was never saved reported success"
    );

    let state = daemon.state.lock().await;
    let labels: Vec<String> = state
        .vault
        .as_ref()
        .unwrap()
        .data()
        .all_items()
        .map(|(_, i)| i.label.clone())
        .collect();
    assert!(!labels.contains(&"from an app".to_owned()));
    assert!(
        labels.contains(&"written by the GUI".to_owned()),
        "the other writer's change was not picked up"
    );
}
