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

use std::collections::{HashMap, HashSet};
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

use crate::error::SecretError;
use crate::{Error, Result, SessionStore};

/// A standard D-Bus error, for the few answers the Secret Service
/// specification does not name.
fn fdo_error(error: fdo::Error) -> SecretError {
    SecretError::ZBus(zbus::Error::FDO(Box::new(error)))
}

/// Announce that an item changed or went away, on its collection's path.
async fn item_signal(
    connection: &zbus::Connection,
    collection: Uuid,
    item: Uuid,
    deleted: bool,
) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(connection, collection_path(collection))?;
    let path = item_path(collection, item);
    if deleted {
        CollectionIface::item_deleted(&emitter, path.as_ref()).await
    } else {
        CollectionIface::item_changed(&emitter, path.as_ref()).await
    }
}

/// Announce that a collection changed or went away, on the service's path.
async fn collection_signal(
    connection: &zbus::Connection,
    collection: Uuid,
    deleted: bool,
) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(connection, crate::SERVICE_PATH)?;
    let path = collection_path(collection);
    if deleted {
        SecretService::collection_deleted(&emitter, path.as_ref()).await
    } else {
        SecretService::collection_changed(&emitter, path.as_ref()).await
    }
}

/// The unique bus name a call came from.
fn caller(header: &zbus::message::Header<'_>) -> Option<String> {
    header.sender().map(|s| s.to_string())
}

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

/// A locked-vault call waiting for somebody to unlock.
///
/// The reply is whether the vault is unlocked now.
#[derive(Debug)]
pub struct PromptRequest {
    pub reply: oneshot::Sender<bool>,
}

/// How long a locked `SearchItems` holds its caller while the person unlocks.
///
/// Inside the 25 seconds GDBus, libdbus, sd-bus and QtDBus each give a method
/// call by default, with room for the reply to travel. Waiting any longer
/// answers nobody: the client has already reported "Timeout was reached".
pub const UNLOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(20);
const _: () = assert!(UNLOCK_WAIT.as_secs() < 25);

/// How long an unlock request waits for the person before it is refused.
pub const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Bus name to claim. Defaults to the development name so that starting
    /// the daemon does not silently displace a running gnome-keyring.
    pub bus_name: String,
    /// Persist to disk after every mutation. Off only in tests.
    pub autosave: bool,
    /// See [`UNLOCK_WAIT`]. Shorter only in tests.
    pub unlock_wait: std::time::Duration,
    /// See [`PROMPT_TIMEOUT`]. Shorter only in tests.
    pub prompt_timeout: std::time::Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            bus_name: crate::DEV_NAME.to_owned(),
            autosave: true,
            unlock_wait: UNLOCK_WAIT,
            prompt_timeout: PROMPT_TIMEOUT,
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
    /// Woken when the person dismisses the unlock dialog, so the waiting
    /// request is refused now rather than when it times out.
    pub unlock_refused: Arc<tokio::sync::Notify>,
    /// Where to tell the person about a write that did not land. `None`
    /// sends nothing — tests, and a daemon with no session bus to reach.
    pub notifications: Option<zbus::Connection>,
    prompt_counter: AtomicU64,
    observers: Vec<Arc<dyn VaultObserver>>,
    /// What is published on the bus. Kept outside this state's own lock so
    /// the tree can be brought in step without holding it; see
    /// [`sync_objects`].
    tree: Arc<ObjectTree>,
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
            unlock_refused: Arc::default(),
            notifications: None,
            prompt_counter: AtomicU64::new(0),
            observers: Vec::new(),
            tree: Arc::default(),
            auto_lock_seconds: AtomicU64::new(0),
            last_activity: AtomicU64::new(now()),
        }
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

    /// Install a vault an unlock just opened, unless one is open already.
    ///
    /// Unlocks derive their key with the state released — Argon2id takes a
    /// while — so two can race: PAM at login and the GUI, say. The loser's
    /// copy is dropped here instead of replacing the vault the winner put in
    /// place, and with it anything written to that one since. Returns whether
    /// this vault was the one installed.
    ///
    /// A file in an older format is upgraded on the way in, so the next
    /// locked start has a collection index to answer `ReadAlias` from.
    pub fn install_unlocked(&mut self, mut vault: Vault) -> bool {
        if !self.is_locked() {
            return false;
        }
        if vault.format() < locket_core::vault::FORMAT_VERSION
            && let Err(e) = vault.save()
        {
            tracing::warn!("could not upgrade the vault format: {e}");
        }
        self.index = vault
            .data()
            .collections
            .iter()
            .map(|c| CollectionIndex {
                id: c.id,
                label: c.label.clone(),
                alias: c.alias.clone(),
            })
            .collect();
        self.open_vault(vault);
        true
    }

    /// Drop the vault — and with it the DEK — and tell everyone watching.
    ///
    /// The item objects come off the bus with it, by way of the object tree's
    /// upkeep task: a locked vault does not advertise how many items it holds.
    pub fn close_vault(&mut self) {
        self.vault = None;
        for observer in &self.observers {
            observer.vault_closed();
        }
        self.tree.changed.notify_one();
    }

    /// Re-announce the current vault, after its contents changed underneath.
    pub fn notify_opened(&self) {
        if let Some(vault) = self.vault.as_ref() {
            for observer in &self.observers {
                observer.vault_opened(vault);
            }
        }
        self.tree.changed.notify_one();
    }

    /// Ask for the published objects to be brought in step with the vault,
    /// after a change made outside the D-Bus methods that do it themselves.
    pub fn objects_changed(&self) {
        self.tree.changed.notify_one();
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
    pub(crate) fn vault_mut(&mut self) -> Result<&mut Vault> {
        self.touch();
        let vault = self.vault.as_mut().ok_or(Error::Locked)?;
        if self.config.autosave && !vault.is_dirty() && vault.changed_on_disk() {
            match vault.reload() {
                Ok(()) => {
                    tracing::info!("vault changed on disk; reloaded before writing");
                    // The SSH agent and the object tree follow the new
                    // contents, not the ones they were built from.
                    self.notify_opened();
                }
                // Most likely the key material changed — a passphrase change
                // from another process. Carry on with what we have; the save
                // will refuse and say so rather than clobbering it.
                Err(e) => tracing::warn!("could not reload the changed vault: {e}"),
            }
        }
        self.vault.as_mut().ok_or(Error::Locked)
    }

    /// Persist a change, unless autosave is off.
    ///
    /// A change that did not reach the disk is an error for the caller to
    /// return: a client told "stored" would stop holding the secret it gave
    /// us. The change is dropped, not kept in memory — a copy that differs
    /// from the file every other reader sees, which each later save would
    /// refuse over again, until one of them is reloaded away. The person is
    /// told as well, since the client that sees the error may say nothing.
    fn persist(&mut self) -> Result<()> {
        if !self.config.autosave {
            return Ok(());
        }
        let Some(vault) = self.vault.as_mut() else {
            return Ok(());
        };
        if !vault.is_dirty() {
            return Ok(());
        }
        let Err(e) = vault.save() else {
            return Ok(());
        };
        tracing::error!("a change was not saved, and has been dropped: {e}");
        match vault.reload() {
            Ok(()) => self.notify_opened(),
            Err(reload) => {
                // The file no longer opens with the key we hold — a passphrase
                // changed elsewhere. Nothing trustworthy is left to serve.
                tracing::error!("could not reload the vault either ({reload}); locking it");
                self.close_vault();
            }
        }
        self.report_unsaved(&e);
        Err(Error::Vault(e))
    }

    /// Tell the desktop a change did not land.
    fn report_unsaved(&self, error: &locket_core::Error) {
        let Some(connection) = self.notifications.clone() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let body = match error {
            locket_core::Error::ChangedOnDisk { .. } => {
                "Another program wrote the vault at the same moment, so an application's \
                 change was not saved. Nothing already saved was lost."
                    .to_owned()
            }
            other => format!("An application's change could not be saved: {other}"),
        };
        runtime.spawn(async move {
            crate::notify::send(&connection, "Vault change not saved", &body).await;
        });
    }

    /// Lock: persist what is pending, then drop the DEK.
    ///
    /// Every lock goes through here — a client's `Lock`, the idle timer, the
    /// session locking, suspend, shutdown — so none of them can drop a change
    /// another would have saved.
    pub fn lock_vault(&mut self) {
        if let Err(e) = self.persist() {
            tracing::error!("locking without the last change: {e}");
        }
        self.close_vault();
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
        if tx.send(PromptRequest { reply }).await.is_err() {
            return false;
        }
        wait.await.unwrap_or(false)
    }

    /// Ask the frontend to unlock, and hold this call while the person
    /// answers — for [`ServiceConfig::unlock_wait`] at most.
    ///
    /// For `SearchItems` alone. A locked locket vault cannot say which items
    /// match: labels and attributes are inside the sealed body. The
    /// specification's answer to a locked search is the list of locked items,
    /// which the client then unlocks through a `Prompt`; there is no such list
    /// to give, and an empty one is a lie clients believe — Chromium and
    /// Electron's `safeStorage` treat "no such item" as "no key yet" and
    /// generate a *new* one, which silently orphans everything they had
    /// already encrypted. So the search raises the dialog itself and waits.
    ///
    /// The wait ends before the caller's own deadline does. A call still
    /// waiting here when the client gives up — 25 seconds, for every common
    /// D-Bus binding — is answered to nobody, and the client reports a
    /// transport timeout instead of the truth, which is `IsLocked`. The dialog
    /// stays up either way: a person who takes longer still unlocks the vault,
    /// and the application's next attempt finds it open.
    ///
    /// Every other call answers `IsLocked` at once, which sends a client
    /// through `Unlock` and a `Prompt` — whose `Completed` signal has no
    /// deadline. Property reads never prompt: D-Bus property traffic is
    /// constant and background, and a passphrase dialog raised by a property
    /// get would be unattributable to any user action.
    pub async fn ensure_unlocked(state: &SharedState) -> Result<()> {
        let patience = {
            let guard = state.lock().await;
            if !guard.is_locked() {
                return Ok(());
            }
            guard.config.unlock_wait
        };
        match tokio::time::timeout(patience, Self::request_unlock(state)).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::Locked),
            Err(_) => {
                tracing::info!("nobody unlocked within {patience:?}; answering that it is locked");
                Err(Error::Locked)
            }
        }
    }

    fn next_prompt_path(&self) -> Result<OwnedObjectPath> {
        let n = self.prompt_counter.fetch_add(1, Ordering::Relaxed);
        OwnedObjectPath::try_from(format!("{}/p{n}", crate::PROMPT_PREFIX))
            .map_err(|e| Error::Other(e.to_string()))
    }
}

pub type SharedState = Arc<Mutex<ServiceState>>;

/// Refuse to change an item locket keeps for itself (see
/// [`locket_core::model::internal`]): a bus peer deleting or rewriting the
/// portal master would re-key every sandboxed application at once.
fn refuse_internal(item: Option<&Item>) -> fdo::Result<()> {
    match item {
        Some(item) if item.is_internal() => Err(fdo::Error::AccessDenied(
            "locket keeps this item for its own use".into(),
        )),
        _ => Ok(()),
    }
}

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
    if alias.is_empty() || !alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
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
    let rest = s
        .strip_prefix(crate::COLLECTION_PREFIX)?
        .strip_prefix('/')?;
    if rest.contains('/') {
        return None;
    }
    uuid_from_element(rest, 'c')
}

/// Parse an item path into `(collection, item)`.
pub fn parse_item_path(path: &str) -> Option<(Uuid, Uuid)> {
    let s = path;
    let rest = s
        .strip_prefix(crate::COLLECTION_PREFIX)?
        .strip_prefix('/')?;
    let (c, i) = rest.split_once('/')?;
    Some((uuid_from_element(c, 'c')?, uuid_from_element(i, 'i')?))
}

// ---------------------------------------------------------------------------
// Property extraction
// ---------------------------------------------------------------------------

fn take_string(props: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    props
        .get(key)
        .and_then(|v| String::try_from(v.clone()).ok())
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

/// Every method of the Secret Service interfaces returns [`SecretError`], whose
/// variants carry the specification's own error names —
/// `org.freedesktop.Secret.Error.IsLocked`, `NoSession`, `NoSuchObject`.
/// libsecret branches on those names; a `Failed` with the name in its message
/// is invisible to every client.
#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    /// Negotiate a transport. `libsecret` calls this before anything else.
    async fn open_session(
        &self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath), SecretError> {
        // For `plain` the input is an empty string, so a failed byte-array
        // conversion is expected rather than an error.
        let peer_public: Option<Vec<u8>> = Vec::<u8>::try_from(input).ok();
        let owner = header.sender().map(|s| s.to_string());

        let (session, output) = {
            let mut state = self.state.lock().await;
            state
                .sessions
                .open(&algorithm, peer_public.as_deref(), owner)?
        };

        let output = if output.is_empty() {
            OwnedValue::try_from(Value::from(String::new()))
        } else {
            OwnedValue::try_from(Value::from(output))
        }
        .map_err(zbus::Error::from)?;

        sync_objects(server, &self.state).await?;
        Ok((output, session.path))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let label = take_string(&properties, prop::COLLECTION_LABEL)
            .unwrap_or_else(|| "Unnamed".to_owned());

        let path = {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut()?;

            // The spec: a collection created for a well-known alias that
            // already has one is that collection, not a second one sharing it.
            if !alias.is_empty()
                && let Some(existing) = vault
                    .data()
                    .collections
                    .iter()
                    .find(|c| c.alias.as_deref() == Some(alias.as_str()))
            {
                return Ok((collection_path(existing.id), null_path()));
            }

            let mut collection = locket_core::Collection::new(label);
            if !alias.is_empty() {
                collection.alias = Some(alias);
            }
            let id = collection.id;
            vault.add_collection(collection);
            state.persist()?;
            collection_path(id)
        };

        sync_objects(server, &self.state).await?;
        SecretService::collection_created(&emitter, path.as_ref()).await?;

        Ok((path, null_path()))
    }

    /// Attribute search across every collection.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), SecretError> {
        // A locked locket vault cannot be enumerated at all: labels and
        // attributes live inside the sealed body, which is the point — nothing
        // about your secrets leaks at rest. gnome-keyring can list locked items
        // because its metadata is plaintext.
        //
        // The consequence is that returning "no matches" here would be a lie
        // that clients believe: libsecret would report the secret as missing
        // rather than prompting. So ask for an unlock and wait — though not
        // past the caller's own deadline; see `ensure_unlocked`.
        ServiceState::ensure_unlocked(&self.state).await?;

        let state = self.state.lock().await;
        let vault = state.vault()?;

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
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), SecretError> {
        let state = self.state.lock().await;
        if !state.is_locked() {
            return Ok((objects, null_path()));
        }

        // Locked: hand back a Prompt the client must call `Prompt()` on. That
        // is what lets the unlock dialog be raised by *our* UI at a moment the
        // user is expecting it, rather than from a background D-Bus call.
        let path = state.next_prompt_path()?;
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
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), SecretError> {
        {
            let mut state = self.state.lock().await;
            state.lock_vault();
        }
        sync_objects(server, &self.state).await?;
        Ok((objects, null_path()))
    }

    /// Drop the DEK and every session. The vault must be reopened from the
    /// passphrase after this.
    async fn lock_service(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(), SecretError> {
        {
            let mut state = self.state.lock().await;
            state.lock_vault();
            state.sessions = SessionStore::new();
        }
        sync_objects(server, &self.state).await?;
        Ok(())
    }

    async fn change_lock(
        &self,
        _collection: OwnedObjectPath,
    ) -> Result<OwnedObjectPath, SecretError> {
        // Changing the passphrase is a first-class UI flow, not something a
        // random bus peer gets to trigger headlessly.
        Err(fdo_error(fdo::Error::NotSupported(
            "change the passphrase from the locket application".into(),
        )))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>, SecretError> {
        let state = self.state.lock().await;
        let vault = state.vault()?;
        let sess = state.sessions.get(&session, caller(&header).as_deref())?;

        let mut out = HashMap::new();
        for path in items {
            let Some((_, item_id)) = parse_item_path(path.as_str()) else {
                continue;
            };
            let Some(item) = vault.item(item_id) else {
                continue;
            };
            let (parameters, value) = sess.encode(&item.secret_bytes())?;
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

    async fn read_alias(&self, name: String) -> Result<OwnedObjectPath, SecretError> {
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

    async fn set_alias(
        &self,
        name: String,
        collection: OwnedObjectPath,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(), SecretError> {
        {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut()?;
            let target = parse_collection_path(collection.as_str());

            for c in &mut vault.data_mut().collections {
                if c.alias.as_deref() == Some(name.as_str()) {
                    c.alias = None;
                }
                if Some(c.id) == target {
                    c.alias = Some(name.clone());
                }
            }
            state.persist()?;
        }
        // `/aliases/<name>` has to follow: libsecret addresses it directly.
        sync_objects(server, &self.state).await?;
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
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut()?;
            let data = vault.data_mut();

            let Some(pos) = data.collections.iter().position(|c| c.id == self.id) else {
                return Err(SecretError::NoSuchObject("no such collection".into()));
            };
            // Deleting a collection deletes every item in it — through the
            // trash, item by item, because a whole collection wiped by one
            // call is exactly the accident the trash exists to survive.
            if data.collections[pos].items.iter().any(Item::is_internal) {
                return Err(fdo_error(fdo::Error::AccessDenied(
                    "this collection holds an item locket keeps for its own use".into(),
                )));
            }
            let item_ids: Vec<Uuid> = data.collections[pos].items.iter().map(|i| i.id).collect();
            for id in &item_ids {
                data.trash_item(*id);
            }
            data.collections.remove(pos);
            state.persist()?;
        }

        // Its items, its own path and any alias it held all come off.
        sync_objects(server, &self.state).await?;
        collection_signal(connection, self.id, true).await?;
        Ok(null_path())
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, SecretError> {
        ServiceState::ensure_unlocked(&self.state).await?;

        let state = self.state.lock().await;
        let vault = state.vault()?;
        let collection = vault
            .data()
            .collection(self.id)
            .ok_or_else(|| SecretError::NoSuchObject("no such collection".into()))?;

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
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        // A locked vault answers `IsLocked` at once, below, and does not hold
        // the call while it asks: that is the answer libsecret acts on. It
        // calls `Unlock` for this collection, waits on the `Prompt` for as
        // long as the person takes, and stores again. Holding the call gave
        // the person the 25 seconds of a D-Bus call timeout instead, after
        // which `secret-tool store` and `git credential` reported "Timeout
        // was reached" and dropped the secret.
        let label = take_string(&properties, prop::ITEM_LABEL).unwrap_or_default();
        let attributes = take_attributes(&properties, prop::ITEM_ATTRIBUTES);
        let schema = take_string(&properties, prop::ITEM_TYPE);

        let (path, replaced) = {
            let mut state = self.state.lock().await;

            let plaintext = {
                let session = state
                    .sessions
                    .get(&secret.session, caller(&header).as_deref())?;
                session.decode(&secret.parameters, &secret.value)?
            };
            // Kept as bytes: a Secret Service secret is a byte array, and a
            // lossy conversion here destroys every binary one.
            let plaintext = plaintext.to_vec();

            let vault = state.vault_mut()?;
            let collection = vault
                .data_mut()
                .collection_mut(self.id)
                .ok_or_else(|| SecretError::NoSuchObject("no such collection".into()))?;

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
            state.persist()?;
            (item_path(self.id, id), existing.is_some())
        };

        if !replaced {
            sync_objects(server, &self.state).await?;
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
    async fn set_label(
        &self,
        value: String,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::Result<()> {
        {
            let mut state = self.state.lock().await;
            let vault = state
                .vault_mut()
                .map_err(|e| zbus::Error::Failure(e.to_string()))?;
            if let Some(c) = vault.data_mut().collection_mut(self.id) {
                c.label = value;
                c.modified = now();
            }
            state
                .persist()
                .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        }
        collection_signal(connection, self.id, false).await
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
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<OwnedObjectPath, SecretError> {
        {
            let mut state = self.state.lock().await;
            let vault = state.vault_mut()?;
            refuse_internal(vault.item(self.id)).map_err(fdo_error)?;
            // Soft-delete. To this client — and every other one — the item is
            // gone: the trash lives outside the collections that SearchItems
            // and the properties walk, so only locket's own trash UI sees it.
            // Checked first: a miss must not leave the vault marked dirty.
            if vault.item(self.id).is_none() {
                return Err(SecretError::NoSuchObject("no such item".into()));
            }
            vault.trash_item(self.id);
            state.persist()?;
        }
        sync_objects(server, &self.state).await?;
        item_signal(connection, self.collection, self.id, true).await?;
        Ok(null_path())
    }

    /// Returns a 1-tuple, not a bare `SecretStruct`.
    ///
    /// zbus uses a returned struct *as* the message body, which would give
    /// this method the body signature `(oayays)` — four top-level arguments.
    /// The spec wants one argument of type `(oayays)`, i.e. body `((oayays))`,
    /// and libsecret checks. Wrapping in a 1-tuple restores the nesting.
    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(SecretStruct,), SecretError> {
        let state = self.state.lock().await;
        let vault = state.vault()?;
        let sess = state.sessions.get(&session, caller(&header).as_deref())?;
        let item = vault
            .item(self.id)
            .ok_or_else(|| SecretError::NoSuchObject("no such item".into()))?;

        let (parameters, value) = sess.encode(&item.secret_bytes())?;
        Ok((SecretStruct {
            session,
            parameters,
            value,
            content_type: item.content_type.clone(),
        },))
    }

    async fn set_secret(
        &self,
        secret: SecretStruct,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SecretError> {
        let mut state = self.state.lock().await;
        let plaintext = {
            let session = state
                .sessions
                .get(&secret.session, caller(&header).as_deref())?;
            session.decode(&secret.parameters, &secret.value)?
        };
        let plaintext = plaintext.to_vec();

        let vault = state.vault_mut()?;
        refuse_internal(vault.item(self.id)).map_err(fdo_error)?;
        let item = vault
            .item_mut(self.id)
            .ok_or_else(|| SecretError::NoSuchObject("no such item".into()))?;
        // SetSecret is an edit: file the value being overwritten.
        item.record_revision();
        item.set_secret_bytes(&plaintext);
        item.content_type = secret.content_type;
        item.touch();
        state.persist()?;
        drop(state);
        item_signal(connection, self.collection, self.id, false).await?;
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
    async fn set_attributes(
        &self,
        value: HashMap<String, String>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        refuse_internal(vault.item(self.id)).map_err(zbus::Error::from)?;
        if let Some(i) = vault.item_mut(self.id) {
            i.attributes = value.into_iter().collect();
            i.touch();
        }
        state
            .persist()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        drop(state);
        item_signal(connection, self.collection, self.id, false).await
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
    async fn set_label(
        &self,
        value: String,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        if let Some(i) = vault.item_mut(self.id) {
            i.label = value;
            i.touch();
        }
        state
            .persist()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        drop(state);
        item_signal(connection, self.collection, self.id, false).await
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
    async fn set_type(
        &self,
        value: String,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::Result<()> {
        let mut state = self.state.lock().await;
        let vault = state
            .vault_mut()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        if let Some(i) = vault.item_mut(self.id) {
            i.attributes.insert("xdg:schema".into(), value);
            i.touch();
        }
        state
            .persist()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        drop(state);
        item_signal(connection, self.collection, self.id, false).await
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
    async fn close(&self, #[zbus(object_server)] server: &ObjectServer) -> Result<(), SecretError> {
        self.state.lock().await.sessions.close(&self.path);
        sync_objects(server, &self.state).await?;
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
    /// Ask the user to unlock, and report the outcome through `Completed`.
    ///
    /// Returns at once, as the specification has it: the answer comes by the
    /// signal, not the reply. Waiting here put a person's whole unlock inside
    /// one method call, and GDBus clients — libsecret among them — give up on
    /// a call after 25 seconds by default, so an unlock that took longer
    /// than that failed on the client's side even though it succeeded.
    ///
    /// `window_id` is the caller's toplevel, so the dialog can be parented to
    /// the window that triggered it rather than appearing unattached.
    async fn prompt(
        &self,
        _window_id: String,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(), SecretError> {
        let sender = self.state.lock().await.prompts.clone();
        let objects = self.objects.clone();
        let path = self.path.clone();
        let server = server.clone();
        let emitter = emitter.to_owned();

        tokio::spawn(async move {
            let granted = match sender {
                Some(tx) => {
                    let (reply, wait) = oneshot::channel();
                    if tx.send(PromptRequest { reply }).await.is_err() {
                        false
                    } else {
                        wait.await.unwrap_or(false)
                    }
                }
                // No UI attached: refuse rather than silently failing open.
                None => false,
            };
            let result = if granted { objects } else { Vec::new() };
            match OwnedValue::try_from(Value::from(result)) {
                Ok(result) => {
                    if let Err(e) = PromptIface::completed(&emitter, !granted, result).await {
                        tracing::warn!("could not report a prompt's outcome: {e}");
                    }
                }
                Err(e) => tracing::warn!("could not encode a prompt's outcome: {e}"),
            }
            if let Err(e) = unpublish::<PromptIface>(&server, &path).await {
                tracing::warn!("could not take down a finished prompt: {e}");
            }
        });
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(), SecretError> {
        let empty = OwnedValue::try_from(Value::from(Vec::<OwnedObjectPath>::new()))
            .map_err(zbus::Error::from)?;
        PromptIface::completed(&emitter, true, empty).await?;
        unpublish::<PromptIface>(server, &self.path).await?;
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

/// Publish the service object, and the collection and item objects the vault
/// currently calls for.
pub async fn register_objects(server: &ObjectServer, state: &SharedState) -> Result<()> {
    server
        .at(crate::SERVICE_PATH, SecretService::new(state.clone()))
        .await?;
    sync_objects(server, state).await
}

/// Keep the object tree in step with the vault for as long as the daemon runs.
///
/// Every D-Bus method that changes what exists brings the tree in step itself
/// before it returns, so its caller sees the result. This covers the changes
/// that arrive any other way: the idle timer and the session locking the
/// vault, a reload picked up on the way into a write — which [`ServiceState`]
/// announces through [`ObjectTree::changed`] — and clients leaving the bus,
/// whose sessions (and their DH keys) are closed with them.
pub fn spawn_upkeep(connection: &zbus::Connection, state: &SharedState) {
    let server = connection.object_server().clone();
    let watched = state.clone();
    tokio::spawn(async move {
        let tree = watched.lock().await.tree.clone();
        loop {
            tree.changed.notified().await;
            if let Err(e) = sync_objects(&server, &watched).await {
                tracing::error!("could not bring the published objects in step: {e}");
            }
        }
    });

    let connection = connection.clone();
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = reap_sessions(&connection, &state).await {
            tracing::error!("not closing the sessions of clients that leave the bus: {e}");
        }
    });
}

/// Close each session when the client that opened it leaves the bus.
async fn reap_sessions(connection: &zbus::Connection, state: &SharedState) -> Result<()> {
    use futures_util::StreamExt as _;

    let bus = fdo::DBusProxy::new(connection).await?;
    let mut changes = bus.receive_name_owner_changed().await?;
    while let Some(change) = changes.next().await {
        let Ok(args) = change.args() else {
            continue;
        };
        // A unique name losing its owner is a connection that has gone.
        if args.new_owner().is_some() || !args.name().starts_with(':') {
            continue;
        }
        let mut guard = state.lock().await;
        if !guard.sessions.close_for_owner(args.name()).is_empty() {
            guard.tree.changed.notify_one();
        }
    }
    Ok(())
}

/// What is published on the bus, and the signal that it may be stale.
#[derive(Default)]
pub struct ObjectTree {
    published: Mutex<Published>,
    changed: tokio::sync::Notify,
}

/// One snapshot of the objects that exist.
#[derive(Default)]
struct Published {
    collections: HashSet<Uuid>,
    /// Alias name to the collection it is currently published for.
    aliases: HashMap<String, Uuid>,
    /// `(collection, item)`.
    items: HashSet<(Uuid, Uuid)>,
    sessions: HashSet<OwnedObjectPath>,
}

impl Published {
    /// What the vault calls for now.
    ///
    /// Collections come from the plaintext index while locked, because a
    /// client must be able to find a collection to ask for it to be unlocked
    /// at all. Items exist only while the vault is open.
    fn wanted(state: &ServiceState) -> Self {
        let index = state.collection_index();
        let aliases = index
            .iter()
            .filter_map(|c| {
                let alias = c.alias.as_deref()?;
                alias_path(alias).map(|_| (alias.to_owned(), c.id))
            })
            .collect();
        let items = state
            .vault
            .as_ref()
            .map(|v| {
                v.data()
                    .collections
                    .iter()
                    .flat_map(|c| c.items.iter().map(move |i| (c.id, i.id)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            collections: index.iter().map(|c| c.id).collect(),
            aliases,
            items,
            sessions: state.sessions.paths().cloned().collect(),
        }
    }
}

/// Bring the published objects in step with the vault: publish what is new,
/// take down what has gone, and move each `/aliases/<name>` to the collection
/// that holds the alias now.
///
/// The only place objects are published or removed, so the tree cannot drift
/// from the vault by one path forgetting to. Serialised on the tree's own
/// lock, and never holds the state lock while it talks to the object server.
pub async fn sync_objects(server: &ObjectServer, state: &SharedState) -> Result<()> {
    let tree = state.lock().await.tree.clone();
    let mut published = tree.published.lock().await;
    let wanted = Published::wanted(&*state.lock().await);

    for &(collection, item) in published.items.difference(&wanted.items) {
        unpublish::<ItemIface>(server, &item_path(collection, item)).await?;
    }
    for (alias, id) in &published.aliases {
        if wanted.aliases.get(alias) != Some(id)
            && let Some(path) = alias_path(alias)
        {
            unpublish::<CollectionIface>(server, &path).await?;
        }
    }
    for &id in published.collections.difference(&wanted.collections) {
        unpublish::<CollectionIface>(server, &collection_path(id)).await?;
    }
    for path in published.sessions.difference(&wanted.sessions) {
        unpublish::<SessionIface>(server, path).await?;
    }

    for &id in wanted.collections.difference(&published.collections) {
        server
            .at(
                collection_path(id),
                CollectionIface {
                    state: state.clone(),
                    id,
                },
            )
            .await?;
    }
    for (alias, &id) in &wanted.aliases {
        if published.aliases.get(alias) != Some(&id)
            && let Some(path) = alias_path(alias)
        {
            server
                .at(
                    path,
                    CollectionIface {
                        state: state.clone(),
                        id,
                    },
                )
                .await?;
        }
    }
    for &(collection, id) in wanted.items.difference(&published.items) {
        server
            .at(
                item_path(collection, id),
                ItemIface {
                    state: state.clone(),
                    collection,
                    id,
                },
            )
            .await?;
    }

    for path in wanted.sessions.difference(&published.sessions) {
        server
            .at(
                path.clone(),
                SessionIface {
                    state: state.clone(),
                    path: path.clone(),
                },
            )
            .await?;
    }

    *published = wanted;
    Ok(())
}

/// Take one interface off a path. Already gone is fine: that is the state
/// being asked for.
async fn unpublish<I: zbus::object_server::Interface>(
    server: &ObjectServer,
    path: &OwnedObjectPath,
) -> Result<()> {
    match server.remove::<I, _>(path).await {
        Ok(_) | Err(zbus::Error::InterfaceNotFound) => Ok(()),
        Err(e) => Err(e.into()),
    }
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
        attrs.insert(
            "xdg:schema".to_owned(),
            "org.freedesktop.Secret.Note".to_owned(),
        );
        assert_eq!(infer_kind(&attrs), ItemKind::Note);

        attrs.insert(
            "xdg:schema".to_owned(),
            "org.gnome.NetworkManager.Connection".to_owned(),
        );
        assert_eq!(infer_kind(&attrs), ItemKind::WifiNetwork);

        let mut login = std::collections::BTreeMap::new();
        login.insert("username".to_owned(), "ada".to_owned());
        assert_eq!(infer_kind(&login), ItemKind::Login);

        assert_eq!(
            infer_kind(&std::collections::BTreeMap::new()),
            ItemKind::Application
        );
    }
}
