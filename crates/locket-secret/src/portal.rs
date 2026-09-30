//! `org.freedesktop.impl.portal.Secret` — per-application master secrets for
//! sandboxed apps.
//!
//! This is the interface that lets a Flatpak application encrypt its own
//! credentials without being handed the run of the user's keyring. The app
//! asks `xdg-desktop-portal` for "my secret", the portal forwards to a
//! backend, and the backend writes the key into a pipe the app supplied.
//!
//! On a stock COSMIC session `gnome-keyring` is the **only** installed backend
//! providing this — `xdg-desktop-portal-cosmic` does not implement it — so
//! this is the piece that lets a COSMIC user drop gnome-keyring entirely.
//!
//! # Derivation
//!
//! Secrets are *derived*, not stored per app:
//!
//! ```text
//! app_secret = HKDF-SHA256(ikm = portal_master, salt = none,
//!                          info = "org.freedesktop.portal.Secret\0" || app_id)
//! ```
//!
//! The master lives in the vault, so every app secret is reproducible from a
//! vault backup and the set of secrets does not grow without bound. Because
//! `app_id` is bound into `info`, two applications can never derive each
//! other's key, and an app's key is stable across reinstalls.

use std::collections::HashMap;
use std::io::Write as _;

use hkdf::Hkdf;
use locket_core::{
    Vault,
    model::{
        Item, ItemKind, VaultData, field_names,
        internal::{
            ATTRIBUTE as INTERNAL_ATTRIBUTE, LEGACY_ATTRIBUTE as LEGACY_INTERNAL_ATTRIBUTE,
            PORTAL_MASTER,
        },
    },
};
use sha2::Sha256;
use uuid::Uuid;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{fdo, interface};
use zeroize::Zeroizing;

use crate::service::{ServiceState, SharedState};

/// The name `xdg-desktop-portal` owns. It alone may ask a backend for an
/// application's secret: it is what vouches for the `app_id`.
pub const PORTAL_FRONTEND: &str = "org.freedesktop.portal.Desktop";

/// Length of a derived application secret.
pub const APP_SECRET_LEN: usize = 64;

/// Length of the vault-held master the app secrets derive from.
const MASTER_LEN: usize = 32;

/// Label the portal master secret is created under. Only a label: see
/// [`master_secret`] for how the item is found.
const MASTER_ITEM_LABEL: &str = "XDG Secret portal master key";

/// Domain separator, so this master can never collide with another use.
const HKDF_DOMAIN: &[u8] = b"org.freedesktop.portal.Secret\0";

/// Derive one application's secret.
pub fn derive_app_secret(master: &[u8], app_id: &str) -> Zeroizing<Vec<u8>> {
    let mut info = Vec::with_capacity(HKDF_DOMAIN.len() + app_id.len());
    info.extend_from_slice(HKDF_DOMAIN);
    info.extend_from_slice(app_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = Zeroizing::new(vec![0u8; APP_SECRET_LEN]);
    hk.expand(&info, out.as_mut_slice())
        .expect("64 bytes is well within HKDF-SHA256's output limit");
    out
}

/// Fetch the portal master from the vault, creating it on first use.
///
/// # Which item is the master
///
/// The item carrying [`INTERNAL_ATTRIBUTE`]` = `[`PORTAL_MASTER`]. Its label is
/// only a label: the person can rename it and every application keeps its key.
///
/// Vaults written before that rule identified the master by its label and
/// kind alone, and may hold several candidates — a master renamed away (after
/// which a second one was minted under the old label), a master from before
/// the project's rename carrying `passman:internal` instead, an unrelated item
/// that happens to share the label. [`find_master`] settles which one is in
/// use the way the old lookup did, so no application is re-keyed by the
/// migration, and [`master_secret`] then writes the tag back onto that one
/// item alone.
///
/// A tagged item whose key is missing or malformed is an error, never a
/// reason to mint: a fresh master would silently re-key every application.
fn master_secret(vault: &mut Vault) -> crate::Result<Zeroizing<Vec<u8>>> {
    match find_master(vault.data())? {
        Master::Tagged(key) => Ok(key),
        Master::Migrate { id, key } => {
            tag_master(vault, id);
            if let Err(e) = vault.save() {
                // The key itself is already on disk; only the tag did not
                // land. Drop the unsaved change and hand the key out: the next
                // request settles on the same item and tries the write again.
                tracing::warn!("could not record the portal master's tag: {e}");
                if let Err(e) = vault.reload() {
                    tracing::warn!("and could not reload the vault: {e}");
                }
            } else {
                tracing::info!("the portal master key is now identified by its tag");
            }
            Ok(key)
        }
        Master::None => mint_master(vault),
    }
}

/// What [`find_master`] found.
enum Master {
    /// Exactly one item carries the tag, with a well-formed key.
    Tagged(Zeroizing<Vec<u8>>),
    /// A master identified the old way; `id` should be tagged, alone.
    Migrate { id: Uuid, key: Zeroizing<Vec<u8>> },
    /// No master anywhere: this is the first request.
    None,
}

/// Settle which item holds the portal master. See [`master_secret`].
fn find_master(data: &VaultData) -> crate::Result<Master> {
    let tagged: Vec<&Item> = data
        .all_items()
        .map(|(_, item)| item)
        .filter(|item| {
            item.attributes.get(INTERNAL_ATTRIBUTE).map(String::as_str) == Some(PORTAL_MASTER)
        })
        .collect();

    if let [only] = tagged.as_slice() {
        return master_key(only).map(Master::Tagged).ok_or_else(damaged);
    }

    // No tag, or more than one. What the label lookup used to return is the
    // key applications have been using since, so that settles it: the first
    // item of the right kind under the old label — provided it holds a key,
    // since when it did not the old lookup minted a new master on every call
    // and no application held on to any of them.
    if let Some((id, key)) = data
        .all_items()
        .map(|(_, item)| item)
        .find(|item| item.kind == ItemKind::Application && item.label == MASTER_ITEM_LABEL)
        .and_then(|item| Some((item.id, master_key(item)?)))
    {
        return Ok(Master::Migrate { id, key });
    }

    // Renamed away from the label: the first tagged item, current tag before
    // the pre-rename one, that holds a key.
    for attribute in [INTERNAL_ATTRIBUTE, LEGACY_INTERNAL_ATTRIBUTE] {
        if let Some((id, key)) = data
            .all_items()
            .map(|(_, item)| item)
            .filter(|item| {
                item.attributes.get(attribute).map(String::as_str) == Some(PORTAL_MASTER)
            })
            .find_map(|item| Some((item.id, master_key(item)?)))
        {
            return Ok(Master::Migrate { id, key });
        }
    }

    if tagged.is_empty() {
        Ok(Master::None)
    } else {
        Err(damaged())
    }
}

fn damaged() -> crate::Error {
    crate::Error::Other(
        "the portal master key item is damaged; refusing to create a new one, \
         which would change every sandboxed application's key"
            .into(),
    )
}

/// The key an item holds, if it is a well-formed master.
fn master_key(item: &Item) -> Option<Zeroizing<Vec<u8>>> {
    let raw = decode_hex(item.field_value(field_names::PRIVATE_KEY)?)?;
    (raw.len() == MASTER_LEN).then(|| Zeroizing::new(raw))
}

/// Make `id` the one item carrying the master's tag.
fn tag_master(vault: &mut Vault, id: Uuid) {
    for collection in &mut vault.data_mut().collections {
        for item in &mut collection.items {
            if item.id == id {
                item.attributes
                    .insert(INTERNAL_ATTRIBUTE.to_owned(), PORTAL_MASTER.to_owned());
                item.attributes.remove(LEGACY_INTERNAL_ATTRIBUTE);
            } else if item.attributes.get(INTERNAL_ATTRIBUTE).map(String::as_str)
                == Some(PORTAL_MASTER)
            {
                // A superseded master keeps its key — it is the person's data,
                // and some application may still hold a copy — but it no
                // longer answers for the portal.
                item.attributes.remove(INTERNAL_ATTRIBUTE);
            }
        }
    }
}

/// Create the master on first use.
fn mint_master(vault: &mut Vault) -> crate::Result<Zeroizing<Vec<u8>>> {
    let mut raw = Zeroizing::new(vec![0u8; MASTER_LEN]);
    getrandom::fill(&mut raw).map_err(|e| crate::Error::Crypto(e.to_string()))?;

    let item = Item::new(ItemKind::Application, MASTER_ITEM_LABEL)
        .with_field(locket_core::Field::new(
            field_names::PRIVATE_KEY,
            locket_core::FieldKind::PrivateKey,
            encode_hex(&raw),
        ))
        .with_attribute(INTERNAL_ATTRIBUTE, PORTAL_MASTER);
    let id = vault.add_item_default(item);
    if let Err(e) = vault.save() {
        // Never leave an unsaved master behind to be found by the next
        // request: the reload the GUI triggers after its next save would drop
        // it, and the request after that would mint a different one — under
        // an application that had already encrypted its data with the first.
        if vault.reload().is_err() {
            vault.remove_item(id);
        }
        return Err(crate::Error::Vault(e));
    }

    tracing::info!("generated a new XDG Secret portal master key");
    Ok(raw)
}

/// The calling application's secret.
///
/// Goes through [`ServiceState::vault_mut`] like every other write, so a copy
/// that another process has rewritten is reloaded before a master is minted
/// into it, rather than the save refusing for a conflict.
fn app_secret(state: &mut ServiceState, app_id: &str) -> crate::Result<Zeroizing<Vec<u8>>> {
    let master = master_secret(state.vault_mut()?)?;
    // A first master is a new item, perhaps in a new default collection.
    state.objects_changed();
    Ok(derive_app_secret(&master, app_id))
}

/// Whether a call came from the connection that owns [`PORTAL_FRONTEND`].
async fn from_portal_frontend(
    connection: &zbus::Connection,
    header: &zbus::message::Header<'_>,
) -> bool {
    let Some(sender) = header.sender() else {
        return false;
    };
    let Ok(bus) = fdo::DBusProxy::new(connection).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(PORTAL_FRONTEND) else {
        return false;
    };
    matches!(bus.get_name_owner(name).await, Ok(owner) if owner.as_str() == sender.as_str())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The portal backend object, served at `/org/freedesktop/portal/desktop`.
pub struct SecretPortal {
    pub state: SharedState,
}

impl SecretPortal {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.impl.portal.Secret")]
impl SecretPortal {
    /// Write the calling application's master secret into `fd`.
    ///
    /// The response code follows the portal convention: 0 success, 1 cancelled,
    /// 2 other error.
    async fn retrieve_secret(
        &self,
        _handle: OwnedObjectPath,
        app_id: String,
        fd: zbus::zvariant::OwnedFd,
        _options: HashMap<String, OwnedValue>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<(u32, HashMap<String, OwnedValue>)> {
        // The app id is only as good as whoever names it. The daemon shares
        // one connection between this backend and the Secret Service, so any
        // peer that can reach the one can call the other; only the portal
        // frontend, which looks the id up from the caller's sandbox, may.
        if !from_portal_frontend(connection, &header).await {
            tracing::warn!(
                "portal secret for `{app_id}` requested by something other than xdg-desktop-portal; refusing"
            );
            return Ok((2, HashMap::new()));
        }
        if app_id.is_empty() {
            tracing::warn!("portal secret requested with an empty app id; refusing");
            return Ok((2, HashMap::new()));
        }

        // Prompt rather than refuse, the same as every libsecret path. An
        // application told "no" here does not come back later and ask again:
        // it starts up concluding it has no keyring, which for something like
        // Authenticator means its existing database is simply unreadable.
        if crate::service::ServiceState::ensure_unlocked(&self.state)
            .await
            .is_err()
        {
            tracing::info!("portal secret for `{app_id}` refused: still locked");
            return Ok((2, HashMap::new()));
        }

        // Still locked is possible here — the lock is released in between —
        // and answers like every other failure: code 2, not a bus error.
        let secret = match app_secret(&mut *self.state.lock().await, &app_id) {
            Ok(secret) => secret,
            Err(e) => {
                tracing::warn!("could not serve a portal secret to `{app_id}`: {e}");
                return Ok((2, HashMap::new()));
            }
        };

        // The portal contract is to write the secret into the pipe and close
        // it; the application reads until EOF. Taking the descriptor by value
        // means it is closed exactly once, when `file` drops.
        let owned: std::os::fd::OwnedFd = fd.into();
        let mut file = std::fs::File::from(owned);

        if let Err(e) = file.write_all(&secret) {
            tracing::error!("could not write portal secret for `{app_id}`: {e}");
            return Ok((2, HashMap::new()));
        }
        drop(file);

        tracing::info!("served an XDG portal secret to `{app_id}`");
        Ok((0, HashMap::new()))
    }

    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_app_scoped() {
        let master = [7u8; MASTER_LEN];
        let a1 = derive_app_secret(&master, "org.example.App");
        let a2 = derive_app_secret(&master, "org.example.App");
        let b = derive_app_secret(&master, "org.example.Other");

        assert_eq!(a1.as_slice(), a2.as_slice(), "not reproducible");
        assert_ne!(a1.as_slice(), b.as_slice(), "two apps derived the same key");
        assert_eq!(a1.len(), APP_SECRET_LEN);
    }

    #[test]
    fn different_masters_give_different_app_secrets() {
        let a = derive_app_secret(&[1u8; MASTER_LEN], "org.example.App");
        let b = derive_app_secret(&[2u8; MASTER_LEN], "org.example.App");
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn app_id_boundary_cannot_be_confused() {
        // A naive `master || app_id` concatenation would let these collide.
        let master = [3u8; MASTER_LEN];
        assert_ne!(
            derive_app_secret(&master, "org.a").as_slice(),
            derive_app_secret(&master, "org.a\0extra").as_slice()
        );
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = vec![0x00, 0x0f, 0xff, 0xa5];
        assert_eq!(encode_hex(&bytes), "000fffa5");
        assert_eq!(decode_hex("000fffa5"), Some(bytes));
        assert_eq!(decode_hex("odd"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    /// The GUI writes the vault file directly and then has the daemon
    /// reload. A master minted into the daemon's stale copy used to fail to
    /// save, stay in memory, be handed out by the next request — and vanish
    /// at that reload, so the request after it got a different key.
    #[test]
    fn a_key_handed_out_survives_the_reload_after_another_writer() {
        use crate::service::ServiceConfig;
        use locket_core::crypto::KdfParams;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let daemon = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let mut state = ServiceState::new(ServiceConfig {
            bus_name: "org.locket.test".into(),
            autosave: true,
            ..ServiceConfig::default()
        });
        state.vault = Some(daemon);

        // The GUI saves behind the daemon's back.
        let mut gui = Vault::open(&path, "pw").unwrap();
        gui.add_item_default(Item::new(ItemKind::Note, "written by the GUI"));
        gui.save().unwrap();

        // An application asks until it gets an answer, as a retrying client
        // would.
        let first = (0..2)
            .find_map(|_| app_secret(&mut state, "org.example.App").ok())
            .expect("no secret at all");
        // What `Manager1.Reload` does after the GUI's next save.
        state.vault.as_mut().unwrap().reload().unwrap();
        let second = app_secret(&mut state, "org.example.App").unwrap();

        assert_eq!(
            first.as_slice(),
            second.as_slice(),
            "the application was given a key that did not survive a reload"
        );
    }

    #[test]
    fn master_is_created_once_and_then_reused() {
        use locket_core::crypto::KdfParams;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let first = master_secret(&mut vault).unwrap();
        let count_after_first = vault.data().item_count();
        let second = master_secret(&mut vault).unwrap();

        assert_eq!(first.as_slice(), second.as_slice(), "master key rotated");
        assert_eq!(
            vault.data().item_count(),
            count_after_first,
            "a second call created another master item"
        );
    }

    /// A master item as some version of locket left it.
    fn master_item(label: &str, key: &[u8], tag: Option<&str>) -> Item {
        let item = Item::new(ItemKind::Application, label).with_field(locket_core::Field::new(
            field_names::PRIVATE_KEY,
            locket_core::FieldKind::PrivateKey,
            encode_hex(key),
        ));
        match tag {
            Some(attribute) => item.with_attribute(attribute, PORTAL_MASTER),
            None => item,
        }
    }

    fn vault() -> (tempfile::TempDir, Vault) {
        use locket_core::crypto::KdfParams;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        (dir, vault)
    }

    fn tagged(vault: &Vault) -> Vec<Uuid> {
        vault
            .data()
            .all_items()
            .filter(|(_, i)| {
                i.attributes.get(INTERNAL_ATTRIBUTE).map(String::as_str) == Some(PORTAL_MASTER)
            })
            .map(|(_, i)| i.id)
            .collect()
    }

    /// The master's label is only a label. Found by it, a rename used to
    /// mint a new master on the next request — re-keying every sandboxed
    /// application at once.
    #[test]
    fn renaming_the_master_keeps_every_applications_key() {
        let (_dir, mut vault) = vault();
        let before = master_secret(&mut vault).unwrap();
        let id = tagged(&vault)[0];
        vault.item_mut(id).unwrap().label = "Flatpak keys".into();
        vault.save().unwrap();

        let after = master_secret(&mut vault).unwrap();
        assert_eq!(
            before.as_slice(),
            after.as_slice(),
            "a rename re-keyed the portal"
        );
        assert_eq!(vault.data().item_count(), 1, "a second master was minted");
    }

    /// A vault from before the project's rename: the master carries
    /// `passman:internal`. It is the master, and is re-tagged the current way.
    #[test]
    fn a_master_from_before_the_rename_is_adopted() {
        let (_dir, mut vault) = vault();
        let key = [9u8; MASTER_LEN];
        vault.add_item_default(master_item(
            MASTER_ITEM_LABEL,
            &key,
            Some(LEGACY_INTERNAL_ATTRIBUTE),
        ));
        vault.save().unwrap();

        assert_eq!(master_secret(&mut vault).unwrap().as_slice(), key);
        let ids = tagged(&vault);
        assert_eq!(ids.len(), 1);
        let item = vault.item(ids[0]).unwrap();
        assert!(!item.attributes.contains_key(LEGACY_INTERNAL_ATTRIBUTE));
        assert!(!vault.is_dirty(), "the migration was not saved");
    }

    /// Renamed under the old lookup, a master was replaced by a new one
    /// under the old label, and applications have used that one since. The
    /// migration keeps it, and the orphan stops answering for the portal.
    #[test]
    fn with_two_masters_the_one_in_use_wins() {
        let (_dir, mut vault) = vault();
        let orphan = vault.add_item_default(master_item(
            "renamed long ago",
            &[1u8; MASTER_LEN],
            Some(INTERNAL_ATTRIBUTE),
        ));
        let in_use = [2u8; MASTER_LEN];
        vault.add_item_default(master_item(
            MASTER_ITEM_LABEL,
            &in_use,
            Some(INTERNAL_ATTRIBUTE),
        ));
        vault.save().unwrap();

        assert_eq!(master_secret(&mut vault).unwrap().as_slice(), in_use);
        let ids = tagged(&vault);
        assert_eq!(ids.len(), 1);
        assert_ne!(ids[0], orphan);
        assert!(vault.item(orphan).is_some(), "the orphaned key was deleted");
        // And from now on the label no longer matters.
        vault.item_mut(ids[0]).unwrap().label = "portal".into();
        assert_eq!(master_secret(&mut vault).unwrap().as_slice(), in_use);
    }

    /// Something else stored under the master's label, without a key — a
    /// `secret-tool store --label=…`. The old lookup found it first, got no
    /// key, and minted a new master on every request.
    #[test]
    fn a_keyless_item_under_the_label_does_not_rotate_the_master() {
        let (_dir, mut vault) = vault();
        vault.add_item_default(Item::new(ItemKind::Application, MASTER_ITEM_LABEL));
        vault.save().unwrap();

        let first = master_secret(&mut vault).unwrap();
        let second = master_secret(&mut vault).unwrap();
        assert_eq!(first.as_slice(), second.as_slice(), "the master rotated");
    }

    /// A damaged master is an error. Minting a replacement would change
    /// every application's key without a word.
    #[test]
    fn a_damaged_master_is_refused_not_replaced() {
        let (_dir, mut vault) = vault();
        vault.add_item_default(
            Item::new(ItemKind::Application, MASTER_ITEM_LABEL)
                .with_field(locket_core::Field::new(
                    field_names::PRIVATE_KEY,
                    locket_core::FieldKind::PrivateKey,
                    "not hex",
                ))
                .with_attribute(INTERNAL_ATTRIBUTE, PORTAL_MASTER),
        );
        vault.save().unwrap();

        assert!(master_secret(&mut vault).is_err());
        assert_eq!(vault.data().item_count(), 1, "a replacement was minted");
    }
}
