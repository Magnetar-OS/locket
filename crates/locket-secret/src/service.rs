//! The `org.freedesktop.secrets` object tree.
//!
//! Object layout mirrors gnome-keyring's, because some clients hard-code
//! assumptions about the shape even though the spec says they should not:
//!
//! ```text
//! /org/freedesktop/secrets                          Service
//! /org/freedesktop/secrets/collection/c<uuid>       Collection
//! /org/freedesktop/secrets/collection/c<uuid>/i<uuid>  Item
//! /org/freedesktop/secrets/session/s<n>             Session
//! /org/freedesktop/secrets/prompt/p<n>              Prompt
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use locket_core::{
    Vault,
    model::{Item, ItemKind, now},
    vault::CollectionIndex,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Type, Value};
use zbus::{ObjectServer, fdo, interface};

use crate::{Error, Result, SessionStore};

/// The `(oayays)` struct every secret crosses the bus in.
#[derive(Debug, Clone, Serialize, Deserialize, Type, Value, OwnedValue)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    /// Algorithm-dependent parameters — the AES-CBC IV, for DH sessions.
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

/// Property keys used in `CreateItem` / `CreateCollection`.
mod prop {
    pub const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
    pub const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
    pub const ITEM_TYPE: &str = "org.freedesktop.Secret.Item.Type";
    pub const COLLECTION_LABEL: &str = "org.freedesktop.Secret.Collection.Label";
}

/// A request the service needs a human to answer.
#[derive(Debug)]
pub enum PromptRequest {
    /// Unlock the vault so a client's call can proceed.
    Unlock { reply: oneshot::Sender<bool> },
    /// Allow one SSH signature with a key that asks to be confirmed.
    ConfirmSigning {
        /// The key's comment — what the user will recognise it by.
        key: String,
        reply: oneshot::Sender<bool>,
    },
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Bus name to claim. Defaults to the development name so that starting
    /// the daemon does not silently displace a running gnome-keyring.
    pub bus_name: String,
    /// Persist to disk after every mutation. Off only in tests.
    pub autosave: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            bus_name: crate::DEV_NAME.to_owned(),
            autosave: true,
        }
    }
}

/// Notified whenever the unlocked vault appears, changes or goes away.
///
/// The SSH agent is the reason this exists. It holds decrypted copies of every
/// key, which have to appear when the vault is unlocked — the daemon normally
/// starts locked so PAM can unlock it, so "load the keys once at startup" gets
/// zero of them — and have to be dropped when it locks, or locking the vault
/// would leave the keys usable by anything that can reach the agent socket.
///
/// Deliberately not the agent itself: this crate serves the Secret Service and
/// has no business knowing what SSH is.
pub trait VaultObserver: Send + Sync {
    /// The vault is open. Called on unlock and after an external reload.
    fn vault_opened(&self, vault: &Vault);
    /// The vault is gone. Called on lock.
    fn vault_closed(&self);
}

/// Everything the D-Bus objects share.
pub struct ServiceState {
    /// `None` while locked. All item access goes through this, so locking is
    /// simply dropping the vault (and with it the DEK).
    pub vault: Option<Vault>,
    /// Which collections exist, readable while locked.
    ///
    /// A locked service still has to answer `ReadAlias` and `Collections`.
    /// Returning nothing there does not read as "locked" to a client — it
    /// reads as "no keyring is installed", which is exactly what libsecret
    /// applications then report to the user.
    pub index: Vec<CollectionIndex>,
    pub sessions: SessionStore,
    pub config: ServiceConfig,
    pub prompts: Option<tokio::sync::mpsc::Sender<PromptRequest>>,
    prompt_counter: AtomicU64,
    observers: Vec<Arc<dyn VaultObserver>>,
    /// Signing confirmations waiting for an answer, by id.
    ///
    /// `None` means "asked, still waiting"; `Some` is the answer. Kept here
    /// rather than in a channel because the answer arrives on a different
    /// D-Bus call than the one that is waiting for it.
    confirmations: std::collections::HashMap<u32, Option<bool>>,
    next_confirmation_id: u32,
    /// Lock the vault after this many idle seconds; 0 disables it.
    ///
    /// Lives here rather than in the idle task's arguments because the
    /// frontend changes it at runtime: the number belongs to the person using
    /// the desktop, and it is stored in `cosmic-config` where the rest of
    /// their settings are.
    auto_lock_seconds: AtomicU64,
    /// When a client last reached for a secret, as seconds since the epoch.
    ///
    /// Drives the daemon's idle lock. An atomic because the read paths take
    /// `&self` and touching this must not force them to take the write lock.
    last_activity: AtomicU64,
}

impl ServiceState {
    pub fn new(config: ServiceConfig) -> Self {
        Self {
            vault: None,
            index: Vec::new(),
            sessions: SessionStore::new(),
            config,
            prompts: None,
            prompt_counter: AtomicU64::new(0),
            observers: Vec::new(),
            confirmations: std::collections::HashMap::new(),
            next_confirmation_id: 0,
            auto_lock_seconds: AtomicU64::new(0),
            last_activity: AtomicU64::new(now()),
        }
    }

    /// Register a pending signing confirmation and return its id.
    pub fn next_confirmation(&mut self, _key: String) -> u32 {
        self.next_confirmation_id = self.next_confirmation_id.wrapping_add(1);
        let id = self.next_confirmation_id;
        self.confirmations.insert(id, None);
        id
    }

    /// Record a frontend's answer. Unknown ids are dropped.
    pub fn answer_confirmation(&mut self, id: u32, allow: bool) {
        if let Some(slot) = self.confirmations.get_mut(&id) {
            *slot = Some(allow);
        }
    }

    /// The answer to a pending confirmation, if one has arrived.
    pub fn confirmation_answer(&self, id: u32) -> Option<bool> {
        self.confirmations.get(&id).copied().flatten()
    }

    /// Drop a confirmation once it has been resolved or timed out.
    pub fn forget_confirmation(&mut self, id: u32) {
        self.confirmations.remove(&id);
    }

    /// How long the vault may sit idle before it locks itself. 0 is never.
    pub fn auto_lock_seconds(&self) -> u64 {
        self.auto_lock_seconds.load(Ordering::Relaxed)
    }

    /// Change the idle timeout. Takes effect on the next tick.
    pub fn set_auto_lock_seconds(&self, seconds: u64) {
        self.auto_lock_seconds.store(seconds, Ordering::Relaxed);
    }

    /// Note that something used the vault, for the idle timer's benefit.
    pub fn touch(&self) {
        self.last_activity.store(now(), Ordering::Relaxed);
    }

    /// How long since anything asked this service for a secret.
    pub fn idle_seconds(&self) -> u64 {
        now().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    /// Register something that has to follow the vault's lock state.
    pub fn add_observer(&mut self, observer: Arc<dyn VaultObserver>) {
        if let Some(vault) = self.vault.as_ref() {
            observer.vault_opened(vault);
        }
        self.observers.push(observer);
    }

    /// Put an unlocked vault in place and tell everyone watching.
    pub fn open_vault(&mut self, vault: Vault) {
        self.vault = Some(vault);
        self.notify_opened();
    }

    /// Drop the vault — and with it the DEK — and tell everyone watching.
    pub fn close_vault(&mut self) {
        self.vault = None;
        for observer in &self.observers {
            observer.vault_closed();
        }
    }

    /// Re-announce the current vault, after its contents changed underneath.
    pub fn notify_opened(&self) {
        if let Some(vault) = self.vault.as_ref() {
            for observer in &self.observers {
                observer.vault_opened(vault);
            }
        }
    }

    pub fn is_locked(&self) -> bool {
        self.vault.is_none()
    }

    /// The collection list, from the vault when open and from the plaintext
    /// index when not.
    pub fn collection_index(&self) -> Vec<CollectionIndex> {
        match self.vault.as_ref() {
            Some(v) => v
                .data()
                .collections
                .iter()
                .map(|c| CollectionIndex {
                    id: c.id,
                    label: c.label.clone(),
                    alias: c.alias.clone(),
                })
                .collect(),
            None => self.index.clone(),
        }
    }

    fn vault(&self) -> Result<&Vault> {
        self.touch();
        self.vault.as_ref().ok_or(Error::Locked)
    }

    /// The vault, refreshed first if another process has written to it.
    ///
    /// The GUI edits the vault file directly whenever it is not going through
    /// this daemon, so "someone else wrote it" is an ordinary event. Reloading
    /// before we mutate means our write is built on their state rather than
    /// discarding it. Only safe while our own copy is clean, which autosave
    /// keeps it: a reload throws away unsaved edits.
    fn vault_mut(&mut self) -> Result<&mut Vault> {
        self.touch();
        let vault = self.vault.as_mut().ok_or(Error::Locked)?;
        if self.config.autosave && !vault.is_dirty() && vault.changed_on_disk() {
            match vault.reload() {
                Ok(()) => tracing::info!("vault changed on disk; reloaded before writing"),
                // Most likely the key material changed — a passphrase change
                // from another process. Carry on with what we have; the save
                // will refuse and say so rather than clobbering it.
                Err(e) => tracing::warn!("could not reload the changed vault: {e}"),
            }
        }
        self.vault.as_mut().ok_or(Error::Locked)
    }

    /// Persist, unless autosave is off. Errors are logged rather than
    /// propagated: a client that just stored a secret should be told the store
    /// succeeded in memory, and a failing disk is a daemon-level problem.
    fn persist(&mut self) {
        if !self.config.autosave {
            return;
        }
        let Some(v) = self.vault.as_mut() else {
            return;
        };
        match v.save() {
            Ok(()) => {}
            Err(locket_core::Error::ChangedOnDisk { .. }) => {
                // Another writer got in between our reload and this save. We
                // do not overwrite them; the change we were persisting is lost
                // and saying so is the only honest option.
                tracing::error!(
                    "the vault was written by another process mid-update; \
                     this change was not saved"
                );
                if let Err(e) = v.reload() {
                    tracing::error!("and reloading it failed: {e}");
                }
            }
            Err(e) => tracing::error!("failed to persist vault: {e}"),
        }
    }

    /// Ask the frontend to unlock, and report whether it did.
    ///
    /// Returns `false` immediately when no frontend is attached, so a headless
    /// daemon fails fast instead of stalling every caller.
    pub async fn request_unlock(state: &SharedState) -> bool {
        let sender = {
            let guard = state.lock().await;
            if !guard.is_locked() {
                return true;
            }
            guard.prompts.clone()
        };
        let Some(tx) = sender else {
            return false;
        };
        let (reply, wait) = oneshot::channel();
        if tx.send(PromptRequest::Unlock { reply }).await.is_err() {
            return false;
        }
        wait.await.unwrap_or(false)
    }

    /// Ask the frontend to unlock, and block this call until it answers.
    ///
    /// Every method that actually touches secret data funnels through here.
    /// The alternative — answering "locked" or, worse, "no such item" — is
    /// what makes clients misbehave: Chromium and Electron's `safeStorage`
    /// treat a failed lookup as "no key yet" and generate a *new* one, which
    /// silently orphans everything they had already encrypted. Prompting is
    /// both friendlier and safer.
    ///
    /// Property reads deliberately do not call this: D-Bus property traffic is
    /// constant and background, and a passphrase dialog raised by a property
    /// get would be unattributable to any user action.
    pub async fn ensure_unlocked(state: &SharedState) -> Result<()> {
        if !state.lock().await.is_locked() {
            return Ok(());
        }
        if Self::request_unlock(state).await {
            Ok(())
        } else {
            Err(Error::Locked)
        }
    }

    fn next_prompt_path(&self) -> Result<OwnedObjectPath> {
        let n = self.prompt_counter.fetch_add(1, Ordering::Relaxed);
        OwnedObjectPath::try_from(format!("{}/p{n}", crate::PROMPT_PREFIX))
            .map_err(|e| Error::Other(e.to_string()))
    }
}

pub type SharedState = Arc<Mutex<ServiceState>>;

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

pub fn collection_path(id: Uuid) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{}/c{}", crate::COLLECTION_PREFIX, id.simple()))
        .expect("uuid hex is always a valid object path element")
}

pub fn item_path(collection: Uuid, item: Uuid) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!(
        "{}/c{}/i{}",
        crate::COLLECTION_PREFIX,
        collection.simple(),
        item.simple()
    ))
    .expect("uuid hex is always a valid object path element")
}

/// The path an aliased collection is additionally published at.
///
/// Returns `None` for aliases that are not valid object-path elements, rather
/// than panicking on a name a bus peer chose.
pub fn alias_path(alias: &str) -> Option<OwnedObjectPath> {
    if alias.is_empty()
        || !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    OwnedObjectPath::try_from(format!("{}/{alias}", crate::ALIAS_PREFIX)).ok()
}

/// The `/` path, meaning "no prompt needed" / "no such object".
pub fn null_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("`/` is a valid object path")
}

/// Recover the UUID from the last element of a collection or item path.
fn uuid_from_element(element: &str, prefix: char) -> Option<Uuid> {
    let hex = element.strip_prefix(prefix)?;
    Uuid::parse_str(hex).ok()
}

/// Parse a collection path into its UUID.
pub fn parse_collection_path(path: &str) -> Option<Uuid> {
    let s = path;
    let rest = s.strip_prefix(crate::COLLECTION_PREFIX)?.strip_prefix('/')?;
    if rest.contains('/') {
        return None;
    }
    uuid_from_element(rest, 'c')
}

/// Parse an item path into `(collection, item)`.
pub fn parse_item_path(path: &str) -> Option<(Uuid, Uuid)> {
    let s = path;
    let rest = s.strip_prefix(crate::COLLECTION_PREFIX)?.strip_prefix('/')?;
    let (c, i) = rest.split_once('/')?;
    Some((uuid_from_element(c, 'c')?, uuid_from_element(i, 'i')?))
}

// ---------------------------------------------------------------------------
// Property extraction
// ---------------------------------------------------------------------------

fn take_string(props: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    props.get(key).and_then(|v| String::try_from(v.clone()).ok())
}

fn take_attributes(
    props: &HashMap<String, OwnedValue>,
    key: &str,
) -> std::collections::BTreeMap<String, String> {
    props
        .get(key)
        .and_then(|v| HashMap::<String, String>::try_from(v.clone()).ok())
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Guess an item kind from the attributes a foreign client supplied.
///
/// Clients tag their secrets with a `xdg:schema` attribute; using it means a
/// Chromium cookie key or a NetworkManager Wi-Fi passphrase shows up in the
/// UI with the right icon instead of as an anonymous blob.
fn infer_kind(attributes: &std::collections::BTreeMap<String, String>) -> ItemKind {
    match attributes.get("xdg:schema").map(String::as_str) {
        Some("org.freedesktop.Secret.Note") => ItemKind::Note,
        Some("org.gnome.NetworkManager.Connection") => ItemKind::WifiNetwork,
        Some(s) if s.contains("Login") || s.contains("login") => ItemKind::Login,
        _ => {
            if attributes.contains_key("username") || attributes.contains_key("user") {
                ItemKind::Login
            } else {
                ItemKind::Application
            }
        }
    }
}

// ---------------------------------------------------------------------------
// org.freedesktop.Secret.Service
// ---------------------------------------------------------------------------

pub struct SecretService {
    pub state: SharedState,
}

impl SecretService {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    /// Negotiate a transport. `libsecret` calls this before anything else.
    async fn open_session(
        &self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        // For `plain` the input is an empty string, so a failed byte-array
        // conversion is expected rather than an error.
        let peer_public: Option<Vec<u8>> = Vec::<u8>::try_from(input).ok();
        let owner = header.sender().map(|s| s.to_string());

        let (session, output) = {
            let mut state = self.state.lock().await;
            state
                .sessions
                .open(&algorithm, peer_public.as_deref(), owner)
                .map_err(fdo::Error::from)?
        };

        let output = if output.is_empty() {
            OwnedValue::try_from(Value::from(String::new()))
        } else {
            OwnedValue::try_from(Value::from(output))
        }
        .map_err(|e| fdo::Error::Failed(e.to_string()))?;

        server
            .at(
                session.path.clone(),
                SessionIface {
                    state: self.state.clone(),
                    path: session.path.clone(),
                },
            )
            .await?;

        Ok((output, session.path))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = take_string(&properties, prop::COLLECTION_LABEL)
            .unwrap_or_else(|| "Unnamed".to_owned());

        let (path, id) = {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut().map_err(fdo::Error::from)?;

            let mut collection = locket_core::Collection::new(label);
            if !alias.is_empty() {
                collection.alias = Some(alias);
            }
            let id = collection.id;
            vault.add_collection(collection);
            state.persist();
            (collection_path(id), id)
        };

        server
            .at(
                path.clone(),
                CollectionIface {
                    state: self.state.clone(),
                    id,
                },
            )
            .await?;
        SecretService::collection_created(&emitter, path.as_ref()).await?;

        Ok((path, null_path()))
    }

    /// Attribute search across every collection.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        // A locked locket vault cannot be enumerated at all: labels and
        // attributes live inside the sealed body, which is the point — nothing
        // about your secrets leaks at rest. gnome-keyring can list locked items
        // because its metadata is plaintext.
        //
        // The consequence is that returning "no matches" here would be a lie
        // that clients believe: libsecret would report the secret as missing
        // rather than prompting. So ask for an unlock and wait.
        ServiceState::ensure_unlocked(&self.state)
            .await
            .map_err(fdo::Error::from)?;

        let state = self.state.lock().await;
        let vault = state.vault().map_err(fdo::Error::from)?;

        let query: std::collections::BTreeMap<String, String> = attributes.into_iter().collect();
        let mut unlocked = Vec::new();
        for collection in &vault.data().collections {
            for item in collection.search(&query) {
                unlocked.push(item_path(collection.id, item.id));
            }
        }
        Ok((unlocked, Vec::new()))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let state = self.state.lock().await;
        if !state.is_locked() {
            return Ok((objects, null_path()));
        }

        // Locked: hand back a Prompt the client must call `Prompt()` on. That
        // is what lets the unlock dialog be raised by *our* UI at a moment the
        // user is expecting it, rather than from a background D-Bus call.
        let path = state.next_prompt_path().map_err(fdo::Error::from)?;
        drop(state);

        server
            .at(
                path.clone(),
                PromptIface {
                    state: self.state.clone(),
                    path: path.clone(),
                    objects,
                },
            )
            .await?;
        Ok((Vec::new(), path))
    }

    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut state = self.state.lock().await;
        state.persist();
        state.close_vault();
        Ok((objects, null_path()))
    }

    /// Drop the DEK and every session. The vault must be reopened from the
    /// passphrase after this.
    async fn lock_service(&self) -> fdo::Result<()> {
        let mut state = self.state.lock().await;
        state.persist();
        state.close_vault();
        state.sessions = SessionStore::new();
        Ok(())
    }

    async fn change_lock(&self, _collection: OwnedObjectPath) -> fdo::Result<OwnedObjectPath> {
        // Changing the passphrase is a first-class UI flow, not something a
        // random bus peer gets to trigger headlessly.
        Err(fdo::Error::NotSupported(
            "change the passphrase from the locket application".into(),
        ))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> fdo::Result<HashMap<OwnedObjectPath, SecretStruct>> {
        ServiceState::ensure_unlocked(&self.state)
            .await
            .map_err(fdo::Error::from)?;

        let state = self.state.lock().await;
        let vault = state.vault().map_err(fdo::Error::from)?;
        let sess = state.sessions.get(&session).map_err(fdo::Error::from)?;

        let mut out = HashMap::new();
        for path in items {
            let Some((_, item_id)) = parse_item_path(path.as_str()) else {
                continue;
            };
            let Some(item) = vault.item(item_id) else {
                continue;
            };
            let (parameters, value) = sess
                .encode(&item.secret_bytes())
                .map_err(fdo::Error::from)?;
            out.insert(
                path,
                SecretStruct {
                    session: session.clone(),
                    parameters,
                    value,
                    content_type: item.content_type.clone(),
                },
            );
        }
        Ok(out)
    }

    async fn read_alias(&self, name: String) -> fdo::Result<OwnedObjectPath> {
        // Answered from the plaintext index when locked. Returning `/` here
        // tells a client the collection does not exist, which is a very
        // different claim from "it exists and is locked".
        let state = self.state.lock().await;
        Ok(state
            .collection_index()
            .iter()
            .find(|c| c.alias.as_deref() == Some(name.as_str()))
            .map(|c| collection_path(c.id))
            .unwrap_or_else(null_path))
    }

    async fn set_alias(&self, name: String, collection: OwnedObjectPath) -> fdo::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state.vault_mut().map_err(fdo::Error::from)?;
        let target = parse_collection_path(collection.as_str());

        for c in &mut vault.data_mut().collections {
            if c.alias.as_deref() == Some(name.as_str()) {
                c.alias = None;
            }
            if Some(c.id) == target {
                c.alias = Some(name.clone());
            }
        }
        state.persist();
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        // Listed while locked too, for the same reason as ReadAlias.
        let state = self.state.lock().await;
        state
            .collection_index()
            .iter()
            .map(|c| collection_path(c.id))
            .collect()
    }

    #[zbus(signal)]
    async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// org.freedesktop.Secret.Collection
// ---------------------------------------------------------------------------

pub struct CollectionIface {
    pub state: SharedState,
    pub id: Uuid,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionIface {
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        let item_paths = {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut().map_err(fdo::Error::from)?;
            let data = vault.data_mut();

            let Some(pos) = data.collections.iter().position(|c| c.id == self.id) else {
                return Err(fdo::Error::UnknownObject("no such collection".into()));
            };
            // Deleting a collection deletes every item in it — through the
            // trash, item by item, because a whole collection wiped by one
            // call is exactly the accident the trash exists to survive.
            let item_ids: Vec<Uuid> =
                data.collections[pos].items.iter().map(|i| i.id).collect();
            for id in &item_ids {
                data.trash_item(*id);
            }
            data.collections.remove(pos);
            state.persist();
            item_ids
                .iter()
                .map(|i| item_path(self.id, *i))
                .collect::<Vec<_>>()
        };

        for p in item_paths {
            let _ = server.remove::<ItemIface, _>(&p).await;
        }
        let _ = server
            .remove::<CollectionIface, _>(&collection_path(self.id))
            .await;
        Ok(null_path())
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, crate::error::SecretError> {
        ServiceState::ensure_unlocked(&self.state).await?;

        let state = self.state.lock().await;
        // If the user declined or the prompt timed out, this is a real
        // IsLocked error *name*, so libsecret knows to unlock and retry rather
        // than treating it as a hard failure or an absent secret.
        let vault = state.vault().map_err(crate::error::SecretError::from)?;
        let collection = vault.data().collection(self.id).ok_or_else(|| {
            crate::error::SecretError::NoSuchObject("no such collection".into())
        })?;

        let query: std::collections::BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(collection
            .search(&query)
            .into_iter()
            .map(|i| item_path(self.id, i.id))
            .collect())
    }

    /// Store a secret. This is the call behind `secret-tool store`,
    /// `gnome-keyring`'s Chromium integration, and every `libsecret` write.
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        // Writes prompt too. An application that is told "locked" when it tries
        // to save typically discards the secret it was holding.
        ServiceState::ensure_unlocked(&self.state)
            .await
            .map_err(fdo::Error::from)?;

        let label = take_string(&properties, prop::ITEM_LABEL).unwrap_or_default();
        let attributes = take_attributes(&properties, prop::ITEM_ATTRIBUTES);
        let schema = take_string(&properties, prop::ITEM_TYPE);

        let (path, replaced) = {
            let mut state = self.state.lock().await;

            let plaintext = {
                let session = state
                    .sessions
                    .get(&secret.session)
                    .map_err(fdo::Error::from)?;
                session
                    .decode(&secret.parameters, &secret.value)
                    .map_err(fdo::Error::from)?
            };
            // Kept as bytes: a Secret Service secret is a byte array, and a
            // lossy conversion here destroys every binary one.
            let plaintext = plaintext.to_vec();

            let vault = state.vault_mut().map_err(fdo::Error::from)?;
            let collection = vault
                .data_mut()
                .collection_mut(self.id)
                .ok_or_else(|| fdo::Error::UnknownObject("no such collection".into()))?;

            // `replace` means "overwrite the item with identical attributes",
            // which is how clients avoid piling up duplicates on every save.
            let existing = if replace && !attributes.is_empty() {
                collection
                    .items
                    .iter()
                    .position(|i| i.attributes == attributes)
            } else {
                None
            };

            let id = match existing {
                Some(pos) => {
                    let item = &mut collection.items[pos];
                    // A replace-on-store is an edit: the value it overwrites
                    // goes into the item's history first, so an application
                    // rotating a credential does not destroy the old one.
                    item.record_revision();
                    item.set_secret_bytes(&plaintext);
                    item.label = label;
                    item.content_type = secret.content_type.clone();
                    item.touch();
                    item.id
                }
                None => {
                    let mut item = Item::new(infer_kind(&attributes), label);
                    item.attributes = attributes;
                    item.set_secret_bytes(&plaintext);
                    item.content_type = secret.content_type.clone();
                    if let Some(s) = schema {
                        item.attributes.entry("xdg:schema".into()).or_insert(s);
                    }
                    let id = item.id;
                    collection.items.push(item);
                    id
                }
            };
            collection.modified = now();
            state.persist();
            (item_path(self.id, id), existing.is_some())
        };

        if !replaced {
            server
                .at(
                    path.clone(),
                    ItemIface {
                        state: self.state.clone(),
                        collection: self.id,
                        id: parse_item_path(path.as_str()).map(|(_, i)| i).unwrap_or_default(),
                    },
                )
                .await?;
            CollectionIface::item_created(&emitter, path.as_ref()).await?;
        } else {
            CollectionIface::item_changed(&emitter, path.as_ref()).await?;
        }

        Ok((path, null_path()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.data().collection(self.id))
            .map(|c| c.items.iter().map(|i| item_path(self.id, i.id)).collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        // Available while locked: the label is in the plaintext index, and a
        // nameless collection in an unlock prompt helps nobody.
        let state = self.state.lock().await;
        state
            .collection_index()
            .iter()
            .find(|c| c.id == self.id)
            .map(|c| c.label.clone())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&self, value: String) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        if let Some(c) = vault.data_mut().collection_mut(self.id) {
            c.label = value;
            c.modified = now();
        }
        state.persist();
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.state.lock().await.is_locked()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.data().collection(self.id))
            .map(|c| c.created)
            .unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.data().collection(self.id))
            .map(|c| c.modified)
            .unwrap_or(0)
    }

    #[zbus(signal)]
    async fn item_created(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// org.freedesktop.Secret.Item
// ---------------------------------------------------------------------------

pub struct ItemIface {
    pub state: SharedState,
    pub collection: Uuid,
    pub id: Uuid,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemIface {
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut().map_err(fdo::Error::from)?;
            // Soft-delete. To this client — and every other one — the item is
            // gone: the trash lives outside the collections that SearchItems
            // and the properties walk, so only locket's own trash UI sees it.
            vault.trash_item(self.id);
            state.persist();
        }
        let path = item_path(self.collection, self.id);
        let _ = server.remove::<ItemIface, _>(&path).await;
        Ok(null_path())
    }

    /// Returns a 1-tuple, not a bare `SecretStruct`.
    ///
    /// zbus uses a returned struct *as* the message body, which would give
    /// this method the body signature `(oayays)` — four top-level arguments.
    /// The spec wants one argument of type `(oayays)`, i.e. body `((oayays))`,
    /// and libsecret checks. Wrapping in a 1-tuple restores the nesting.
    async fn get_secret(&self, session: OwnedObjectPath) -> fdo::Result<(SecretStruct,)> {
        ServiceState::ensure_unlocked(&self.state)
            .await
            .map_err(fdo::Error::from)?;

        let state = self.state.lock().await;
        let vault = state.vault().map_err(fdo::Error::from)?;
        let sess = state.sessions.get(&session).map_err(fdo::Error::from)?;
        let item = vault
            .item(self.id)
            .ok_or_else(|| fdo::Error::UnknownObject("no such item".into()))?;

        let (parameters, value) = sess
            .encode(&item.secret_bytes())
            .map_err(fdo::Error::from)?;
        Ok((SecretStruct {
            session,
            parameters,
            value,
            content_type: item.content_type.clone(),
        },))
    }

    async fn set_secret(&self, secret: SecretStruct) -> fdo::Result<()> {
        ServiceState::ensure_unlocked(&self.state)
            .await
            .map_err(fdo::Error::from)?;

        let mut state = self.state.lock().await;
        let plaintext = {
            let session = state
                .sessions
                .get(&secret.session)
                .map_err(fdo::Error::from)?;
            session
                .decode(&secret.parameters, &secret.value)
                .map_err(fdo::Error::from)?
        };
        let plaintext = plaintext.to_vec();

        let vault = state.vault_mut().map_err(fdo::Error::from)?;
        let item = vault
            .item_mut(self.id)
            .ok_or_else(|| fdo::Error::UnknownObject("no such item".into()))?;
        // SetSecret is an edit: file the value being overwritten.
        item.record_revision();
        item.set_secret_bytes(&plaintext);
        item.content_type = secret.content_type;
        item.touch();
        state.persist();
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.state.lock().await.is_locked()
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.item(self.id))
            .map(|i| i.attributes.clone().into_iter().collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(&self, value: HashMap<String, String>) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        if let Some(i) = vault.item_mut(self.id) {
            i.attributes = value.into_iter().collect();
            i.touch();
        }
        state.persist();
        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.item(self.id))
            .map(|i| i.label.clone())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&self, value: String) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        if let Some(i) = vault.item_mut(self.id) {
            i.label = value;
            i.touch();
        }
        state.persist();
        Ok(())
    }

    #[zbus(property, name = "Type")]
    async fn type_(&self) -> String {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.item(self.id))
            .map(|i| {
                i.attributes
                    .get("xdg:schema")
                    .cloned()
                    .unwrap_or_else(|| i.kind.xdg_schema().to_owned())
            })
            .unwrap_or_default()
    }

    #[zbus(property, name = "Type")]
    async fn set_type(&self, value: String) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        if let Some(i) = vault.item_mut(self.id) {
            i.attributes.insert("xdg:schema".into(), value);
            i.touch();
        }
        state.persist();
        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.item(self.id))
            .map(|i| i.created)
            .unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let state = self.state.lock().await;
        state
            .vault()
            .ok()
            .and_then(|v| v.item(self.id))
            .map(|i| i.modified)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// org.freedesktop.Secret.Session
// ---------------------------------------------------------------------------

pub struct SessionIface {
    pub state: SharedState,
    pub path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionIface {
    async fn close(&self, #[zbus(object_server)] server: &ObjectServer) -> fdo::Result<()> {
        self.state.lock().await.sessions.close(&self.path);
        let _ = server.remove::<SessionIface, _>(&self.path).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// org.freedesktop.Secret.Prompt
// ---------------------------------------------------------------------------

pub struct PromptIface {
    pub state: SharedState,
    pub path: OwnedObjectPath,
    pub objects: Vec<OwnedObjectPath>,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptIface {
    /// Ask the user to unlock, then report the outcome via `Completed`.
    ///
    /// `window_id` is the caller's toplevel, so the dialog can be parented to
    /// the window that triggered it rather than appearing unattached.
    async fn prompt(
        &self,
        _window_id: String,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let sender = self.state.lock().await.prompts.clone();

        let granted = match sender {
            Some(tx) => {
                let (reply, wait) = oneshot::channel();
                if tx.send(PromptRequest::Unlock { reply }).await.is_err() {
                    false
                } else {
                    wait.await.unwrap_or(false)
                }
            }
            // No UI attached: refuse rather than silently failing open.
            None => false,
        };

        let result = if granted {
            OwnedValue::try_from(Value::from(self.objects.clone()))
                .map_err(|e| fdo::Error::Failed(e.to_string()))?
        } else {
            OwnedValue::try_from(Value::from(Vec::<OwnedObjectPath>::new()))
                .map_err(|e| fdo::Error::Failed(e.to_string()))?
        };

        PromptIface::completed(&emitter, !granted, result).await?;
        let _ = server.remove::<PromptIface, _>(&self.path).await;
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let empty = OwnedValue::try_from(Value::from(Vec::<OwnedObjectPath>::new()))
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        PromptIface::completed(&emitter, true, empty).await?;
        let _ = server.remove::<PromptIface, _>(&self.path).await;
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Publish the service object plus one object per collection and item.
///
/// Called on unlock; the object tree is torn down again on lock so that a
/// locked vault does not advertise how many items it holds.
pub async fn register_objects(server: &ObjectServer, state: &SharedState) -> Result<()> {
    server
        .at(crate::SERVICE_PATH, SecretService::new(state.clone()))
        .await?;
    register_vault_objects(server, state).await
}

pub async fn register_vault_objects(server: &ObjectServer, state: &SharedState) -> Result<()> {
    // Collections are published whether or not the vault is open, from the
    // plaintext index. A client must be able to find the collection in order
    // to ask for it to be unlocked at all.
    let (index, items): (Vec<CollectionIndex>, Vec<(Uuid, Vec<Uuid>)>) = {
        let guard = state.lock().await;
        let index = guard.collection_index();
        let items = guard
            .vault()
            .map(|v| {
                v.data()
                    .collections
                    .iter()
                    .map(|c| (c.id, c.items.iter().map(|i| i.id).collect()))
                    .collect()
            })
            .unwrap_or_default();
        (index, items)
    };

    for collection in index {
        server
            .at(
                collection_path(collection.id),
                CollectionIface {
                    state: state.clone(),
                    id: collection.id,
                },
            )
            .await?;

        // Also publish under /aliases/<alias>, which is where libsecret looks.
        if let Some(path) = collection.alias.as_deref().and_then(alias_path) {
            server
                .at(
                    path,
                    CollectionIface {
                        state: state.clone(),
                        id: collection.id,
                    },
                )
                .await?;
        }
    }

    // Items only exist once the vault is open; while locked there is nothing
    // to enumerate, which is what `Locked` on the collection communicates.
    for (collection_id, item_ids) in items {
        for item_id in item_ids {
            server
                .at(
                    item_path(collection_id, item_id),
                    ItemIface {
                        state: state.clone(),
                        collection: collection_id,
                        id: item_id,
                    },
                )
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_paths_roundtrip() {
        let id = Uuid::new_v4();
        let path = collection_path(id);
        assert_eq!(parse_collection_path(path.as_str()), Some(id));
        // An item path must not parse as a collection path.
        let item = item_path(id, Uuid::new_v4());
        assert_eq!(parse_collection_path(item.as_str()), None);
    }

    #[test]
    fn item_paths_roundtrip() {
        let c = Uuid::new_v4();
        let i = Uuid::new_v4();
        let path = item_path(c, i);
        assert_eq!(parse_item_path(path.as_str()), Some((c, i)));
        assert_eq!(parse_item_path(collection_path(c).as_str()), None);
    }

    #[test]
    fn foreign_paths_are_rejected() {
        let p = OwnedObjectPath::try_from("/org/gnome/keyring/collection/login").unwrap();
        assert_eq!(parse_collection_path(p.as_str()), None);
        assert_eq!(parse_item_path(p.as_str()), None);
    }

    #[test]
    fn kind_inference_recognises_known_schemas() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("xdg:schema".to_owned(), "org.freedesktop.Secret.Note".to_owned());
        assert_eq!(infer_kind(&attrs), ItemKind::Note);

        attrs.insert(
            "xdg:schema".to_owned(),
            "org.gnome.NetworkManager.Connection".to_owned(),
        );
        assert_eq!(infer_kind(&attrs), ItemKind::WifiNetwork);

        let mut login = std::collections::BTreeMap::new();
        login.insert("username".to_owned(), "ada".to_owned());
        assert_eq!(infer_kind(&login), ItemKind::Login);

        assert_eq!(infer_kind(&std::collections::BTreeMap::new()), ItemKind::Application);
    }
}
