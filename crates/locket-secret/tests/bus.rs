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

/// libsecret decides between "unlock and retry" and "give up" on the D-Bus
/// error *name*. Only `Collection.SearchItems` used to return the
/// specification's names; everything else answered a generic `Failed` for a
/// locked vault and `UnknownObject` for a missing session.
#[tokio::test]
async fn errors_carry_the_secret_service_names() {
    use std::collections::HashMap;
    use zbus::zvariant::OwnedObjectPath;

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let service = client.service().await;

    // A session nobody opened.
    let bogus = OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s999").unwrap();
    let result: zbus::Result<HashMap<OwnedObjectPath, locket_secret::service::SecretStruct>> =
        service
            .call("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &bogus))
            .await;
    assert_eq!(
        locket_secret::testing::error_name(&result.unwrap_err()),
        "org.freedesktop.Secret.Error.NoSession"
    );

    // Locked, with no frontend to ask: the answer is IsLocked, by name.
    let () = client.manager().await.call("Lock", &()).await.unwrap();
    let result: zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> = service
        .call("SearchItems", &(HashMap::<String, String>::new(),))
        .await;
    assert_eq!(
        locket_secret::testing::error_name(&result.unwrap_err()),
        "org.freedesktop.Secret.Error.IsLocked"
    );
}

/// `Prompt()` returns at once and the outcome arrives by `Completed`. It used
/// to wait for the person inside the call, and a GDBus client gives up on a
/// call after 25 seconds by default — an unlock that took longer failed on
/// the client's side even though it succeeded.
#[tokio::test]
async fn a_prompt_returns_before_the_person_answers() {
    use futures_util::StreamExt as _;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let (tx, mut requests) = tokio::sync::mpsc::channel(1);
    daemon.state.lock().await.prompts = Some(tx);
    let () = client.manager().await.call("Lock", &()).await.unwrap();

    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = client
        .service()
        .await
        .call("Unlock", &(Vec::<OwnedObjectPath>::new(),))
        .await
        .unwrap();
    let prompt = client
        .proxy(prompt.as_str(), "org.freedesktop.Secret.Prompt")
        .await;
    let mut completed = prompt.receive_signal("Completed").await.unwrap();

    // The person takes their time.
    let answer = tokio::spawn(async move {
        let request = requests
            .recv()
            .await
            .expect("the prompt reached the frontend");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = request.reply.send(true);
    });

    let started = std::time::Instant::now();
    let () = prompt.call("Prompt", &("",)).await.unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "Prompt() waited for the answer ({:?})",
        started.elapsed()
    );

    let signal = tokio::time::timeout(std::time::Duration::from_secs(10), completed.next())
        .await
        .expect("Completed never arrived")
        .unwrap();
    let (dismissed, _result): (bool, OwnedValue) = signal.body().deserialize().unwrap();
    assert!(!dismissed);
    answer.await.unwrap();
}

/// Sessions — each holding a DH key — were never closed when their client
/// went away, nor taken off the bus by `LockService`, which dropped them.
#[tokio::test]
async fn sessions_end_with_their_client_and_with_lock_service() {
    let daemon = Daemon::start().await;

    let leaving = daemon.client().await;
    let session = leaving.open_session().await;
    let watcher = daemon.client().await;
    assert!(watcher.exists(session.as_str()).await);
    drop(leaving);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while watcher.exists(session.as_str()).await {
        assert!(
            std::time::Instant::now() < deadline,
            "a departed client's session is still open"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let session = watcher.open_session().await;
    let () = watcher
        .service()
        .await
        .call("LockService", &())
        .await
        .unwrap();
    assert!(
        !watcher.exists(session.as_str()).await,
        "LockService left its sessions published"
    );
}

/// A session belongs to the client that opened it.
#[tokio::test]
async fn one_client_cannot_use_anothers_session() {
    use std::collections::HashMap;
    use zbus::zvariant::OwnedObjectPath;

    let daemon = Daemon::start().await;
    let owner = daemon.client().await;
    let session = owner.open_session().await;
    let other = daemon.client().await;

    let result: zbus::Result<HashMap<OwnedObjectPath, locket_secret::service::SecretStruct>> =
        other
            .service()
            .await
            .call("GetSecrets", &(Vec::<OwnedObjectPath>::new(), &session))
            .await;
    assert_eq!(
        locket_secret::testing::error_name(&result.unwrap_err()),
        "org.freedesktop.Secret.Error.NoSession"
    );
}

/// Two unlocks racing — PAM at login and the GUI — derive their keys with
/// the state released. The second to finish used to replace the vault the
/// first had installed, and with it anything written there in between.
#[tokio::test]
async fn a_late_unlock_does_not_replace_the_open_vault() {
    use locket_core::model::{Item, ItemKind};

    let daemon = Daemon::start().await;
    let late = locket_core::Vault::open(daemon.vault_path(), support_passphrase()).unwrap();
    {
        let mut state = daemon.state.lock().await;
        let vault = state.vault.as_mut().unwrap();
        vault.add_item_default(Item::new(ItemKind::Note, "not yet saved"));
    }
    assert!(!daemon.state.lock().await.install_unlocked(late));
    let state = daemon.state.lock().await;
    assert!(
        state
            .vault
            .as_ref()
            .unwrap()
            .data()
            .all_items()
            .any(|(_, i)| i.label == "not yet saved"),
        "the open vault was replaced by a late unlock"
    );
}

/// Dismissing the unlock dialog refuses the request that raised it. It used
/// to leave the application waiting out the daemon's two-minute timeout.
#[tokio::test]
async fn dismissing_the_unlock_dialog_refuses_the_prompt() {
    use futures_util::StreamExt as _;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    daemon.state.lock().await.prompts = Some(tx);
    // Never the real GUI: a test must not start anything on this desktop.
    tokio::spawn(locket_secret::manager::serve_prompts(
        daemon.server.clone(),
        daemon.state.clone(),
        rx,
        || Ok("nothing".to_owned()),
    ));
    let () = client.manager().await.call("Lock", &()).await.unwrap();

    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = client
        .service()
        .await
        .call("Unlock", &(Vec::<OwnedObjectPath>::new(),))
        .await
        .unwrap();
    let prompt = client
        .proxy(prompt.as_str(), "org.freedesktop.Secret.Prompt")
        .await;
    let mut completed = prompt.receive_signal("Completed").await.unwrap();
    let () = prompt.call("Prompt", &("",)).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let () = client
        .manager()
        .await
        .call("CancelUnlock", &())
        .await
        .unwrap();

    let signal = tokio::time::timeout(std::time::Duration::from_secs(5), completed.next())
        .await
        .expect("the dismissed prompt was not answered")
        .unwrap();
    let (dismissed, _): (bool, OwnedValue) = signal.body().deserialize().unwrap();
    assert!(dismissed);
}

/// Deletions and edits are announced, not only creations: a client that
/// lists items (Seahorse, say) otherwise keeps showing a deleted one. And an
/// item already deleted is `NoSuchObject`, not a second success.
#[tokio::test]
async fn deletions_and_edits_are_announced() {
    use futures_util::StreamExt as _;
    use locket_core::model::{Item, ItemKind};

    let daemon = Daemon::start().await;
    let client = daemon.client().await;
    let (collection, path) = {
        let mut state = daemon.state.lock().await;
        let vault = state.vault.as_mut().unwrap();
        let collection = vault.data().collections[0].id;
        let id = vault
            .add_item(collection, Item::new(ItemKind::Note, "n"))
            .unwrap();
        vault.save().unwrap();
        (
            collection,
            locket_secret::service::item_path(collection, id),
        )
    };
    locket_secret::service::sync_objects(daemon.server.object_server(), &daemon.state)
        .await
        .unwrap();
    let collection = client
        .proxy(
            locket_secret::service::collection_path(collection).as_str(),
            "org.freedesktop.Secret.Collection",
        )
        .await;
    let mut changed = collection.receive_signal("ItemChanged").await.unwrap();
    let mut deleted = collection.receive_signal("ItemDeleted").await.unwrap();
    let item = client
        .proxy(path.as_str(), "org.freedesktop.Secret.Item")
        .await;

    item.set_property("Label", "renamed").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), changed.next())
        .await
        .expect("no ItemChanged for a new label");

    let _: zbus::zvariant::OwnedObjectPath = item.call("Delete", &()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), deleted.next())
        .await
        .expect("no ItemDeleted");

    // The object went with it, so a stale client's second Delete fails.
    let again: zbus::Result<zbus::zvariant::OwnedObjectPath> = item.call("Delete", &()).await;
    assert!(again.is_err(), "deleting a deleted item succeeded");
}
