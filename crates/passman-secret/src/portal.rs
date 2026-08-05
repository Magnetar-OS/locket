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
use passman_core::{
    Vault,
    model::{Item, ItemKind, field_names},
};
use sha2::Sha256;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{fdo, interface};
use zeroize::Zeroizing;

use crate::service::SharedState;

/// Length of a derived application secret.
pub const APP_SECRET_LEN: usize = 64;

/// Length of the vault-held master the app secrets derive from.
const MASTER_LEN: usize = 32;

/// Label of the vault item holding the portal master secret.
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
fn master_secret(vault: &mut Vault) -> crate::Result<Zeroizing<Vec<u8>>> {
    let existing = vault
        .data()
        .all_items()
        .find(|(_, i)| i.kind == ItemKind::Application && i.label == MASTER_ITEM_LABEL)
        .and_then(|(_, i)| i.field_value(field_names::PRIVATE_KEY).map(str::to_owned));

    if let Some(hex) = existing {
        let raw = decode_hex(&hex)
            .ok_or_else(|| crate::Error::Other("portal master key is malformed".into()))?;
        return Ok(Zeroizing::new(raw));
    }

    let mut raw = Zeroizing::new(vec![0u8; MASTER_LEN]);
    getrandom::fill(&mut raw).map_err(|e| crate::Error::Crypto(e.to_string()))?;

    let item = Item::new(ItemKind::Application, MASTER_ITEM_LABEL)
        .with_field(passman_core::Field::new(
            field_names::PRIVATE_KEY,
            passman_core::FieldKind::PrivateKey,
            encode_hex(&raw),
        ))
        .with_attribute("passman:internal", "portal-master");
    vault.add_item_default(item);
    vault.save().map_err(crate::Error::Vault)?;

    tracing::info!("generated a new XDG Secret portal master key");
    Ok(raw)
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
    ) -> fdo::Result<(u32, HashMap<String, OwnedValue>)> {
        if app_id.is_empty() {
            tracing::warn!("portal secret requested with an empty app id; refusing");
            return Ok((2, HashMap::new()));
        }

        let secret = {
            let mut guard = self.state.lock().await;
            let Some(vault) = guard.vault.as_mut() else {
                tracing::info!("portal secret requested for `{app_id}` while locked");
                return Ok((2, HashMap::new()));
            };
            let master = master_secret(vault).map_err(fdo::Error::from)?;
            derive_app_secret(&master, &app_id)
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

    #[test]
    fn master_is_created_once_and_then_reused() {
        use passman_core::crypto::KdfParams;

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
}
