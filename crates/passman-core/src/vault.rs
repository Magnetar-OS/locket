//! The on-disk vault file: envelope format, open/create, atomic save.
//!
//! # File layout (format 2)
//!
//! JSON with base64 fields — inspectable on purpose, so a recovery tool never
//! has to reverse a binary format.
//!
//! ```json
//! {
//!   "magic": "passman-vault",
//!   "format": 2,
//!   "slots": [ { "id": "...", "label": "Passphrase", "factor": {...},
//!                "wrapped_key": { "nonce": "b64", "ciphertext": "b64" } } ],
//!   "body": { "nonce": "b64", "ciphertext": "b64" }
//! }
//! ```
//!
//! The body is encrypted once, under a random data-encryption key. Every slot
//! stores that same DEK wrapped under a different factor (see [`crate::slots`]),
//! so enrolling a TPM or a security key *adds* a way in rather than replacing
//! the passphrase.
//!
//! Format 1 — a single inline `kdf` + `wrapped_key` — is still readable and is
//! converted to a one-slot format 2 file the next time the vault is saved.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, Result,
    crypto::{KdfParams, NONCE_LEN, SALT_LEN, SymKey},
    model::{Collection, Item, VaultData},
    slots::{PassphraseOpener, Slot, SlotFactor, SlotKind, SlotOpener},
};

pub const MAGIC: &str = "passman-vault";
pub const FORMAT_VERSION: u16 = 2;

/// A base64-encoded (nonce, ciphertext) pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedBlob {
    pub(crate) fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self {
            nonce: Base64::encode_string(&nonce),
            ciphertext: Base64::encode_string(&ciphertext),
        }
    }

    pub(crate) fn nonce_bytes(&self, field: &'static str) -> Result<[u8; NONCE_LEN]> {
        let raw = Base64::decode_vec(&self.nonce).map_err(|_| Error::Base64 { field })?;
        raw.as_slice().try_into().map_err(|_| Error::FieldLength {
            field,
            found: raw.len(),
            expected: NONCE_LEN,
        })
    }

    pub(crate) fn ciphertext_bytes(&self, field: &'static str) -> Result<Vec<u8>> {
        Base64::decode_vec(&self.ciphertext).map_err(|_| Error::Base64 { field })
    }
}

/// Format 1's inline KDF descriptor. Retained only to read old files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfDescriptor {
    pub algorithm: String,
    #[serde(flatten)]
    pub params: KdfParams,
    pub salt: String,
}

/// The complete file, as it appears on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub magic: String,
    pub format: u16,

    /// Format 2 and later.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<Slot>,

    /// Format 1 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfDescriptor>,
    /// Format 1 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<SealedBlob>,

    pub body: SealedBlob,
}

impl VaultFile {
    fn validate(&self, path: &Path) -> Result<()> {
        if self.magic != MAGIC {
            return Err(Error::NotAVault {
                path: path.to_path_buf(),
            });
        }
        if self.format > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: self.format,
                supported: FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// Associated data for the body: the whole slot table, so a slot cannot be
    /// added, removed or edited without invalidating the body.
    fn body_aad(&self) -> Vec<u8> {
        match self.format {
            0 | 1 => {
                // Format 1's original computation, preserved byte for byte so
                // existing vaults still authenticate.
                serde_json::to_vec(&(&self.magic, self.format, &self.kdf, &self.wrapped_key))
                    .unwrap_or_default()
            }
            _ => serde_json::to_vec(&(&self.magic, self.format, &self.slots)).unwrap_or_default(),
        }
    }

    /// Format 1's key AAD.
    fn legacy_key_aad(&self) -> Vec<u8> {
        serde_json::to_vec(&(&self.magic, self.format, &self.kdf)).unwrap_or_default()
    }
}

/// An open, decrypted vault.
///
/// Holds the DEK but not the passphrase or any KEK: those are dropped (and
/// zeroized) as soon as unwrapping finishes.
pub struct Vault {
    path: PathBuf,
    file: VaultFile,
    dek: SymKey,
    data: VaultData,
    dirty: bool,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("slots", &self.file.slots.len())
            .field("collections", &self.data.collections.len())
            .field("items", &self.data.item_count())
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The default vault location: `$XDG_DATA_HOME/passman/default.vault`.
    pub fn default_path() -> Result<PathBuf> {
        let dir = dirs::data_dir().ok_or(Error::NoDataDir)?;
        Ok(dir.join("passman").join("default.vault"))
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Create a brand-new vault with a single passphrase slot.
    pub fn create(path: impl Into<PathBuf>, passphrase: &str, params: KdfParams) -> Result<Self> {
        let path = path.into();
        let dek = SymKey::random()?;

        let slot = Slot::new_passphrase("Passphrase", passphrase, params, &dek, MAGIC, FORMAT_VERSION)?;

        let file = VaultFile {
            magic: MAGIC.to_owned(),
            format: FORMAT_VERSION,
            slots: vec![slot],
            kdf: None,
            wrapped_key: None,
            body: SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
        };

        let mut vault = Self {
            path,
            file,
            dek,
            data: VaultData::default(),
            dirty: true,
        };
        vault.save()?;
        Ok(vault)
    }

    fn read_file(path: &Path) -> Result<VaultFile> {
        let raw = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        let file: VaultFile = serde_json::from_slice(&raw).map_err(|e| {
            // A file that is not JSON at all is much more likely to be "wrong
            // path" than "corrupt vault", so report it as such.
            if raw.starts_with(b"{") {
                Error::Json(e)
            } else {
                Error::NotAVault {
                    path: path.to_path_buf(),
                }
            }
        })?;
        file.validate(path)?;
        Ok(file)
    }

    /// Open with a passphrase. Upgrades a format 1 file in memory; the upgrade
    /// reaches disk on the next [`Vault::save`].
    pub fn open(path: impl Into<PathBuf>, passphrase: &str) -> Result<Self> {
        let path = path.into();
        let mut file = Self::read_file(&path)?;

        let dek = if file.format <= 1 {
            let dek = Self::unwrap_legacy(&file, passphrase)?;
            // Rebuild as a one-slot format 2 file.
            let slot = Slot::new_passphrase(
                "Passphrase",
                passphrase,
                file.kdf
                    .as_ref()
                    .map(|k| k.params)
                    .unwrap_or_else(KdfParams::default),
                &dek,
                MAGIC,
                FORMAT_VERSION,
            )?;
            // Decrypt the body under the *old* AAD before switching format.
            let plaintext = dek.open(
                &file.body.nonce_bytes("body.nonce")?,
                &file.body.ciphertext_bytes("body.ciphertext")?,
                &file.body_aad(),
            )?;
            let data: VaultData = serde_json::from_slice(&plaintext)?;

            file.format = FORMAT_VERSION;
            file.slots = vec![slot];
            file.kdf = None;
            file.wrapped_key = None;

            tracing::info!("upgrading vault from format 1 to {FORMAT_VERSION}");
            return Ok(Self {
                path,
                file,
                dek,
                data,
                // Dirty, so the upgraded layout is written on the next save.
                dirty: true,
            });
        } else {
            Self::unwrap_with(&file, &PassphraseOpener::new(passphrase))?
        };

        Self::finish_open(path, file, dek)
    }

    /// Open using any unlock factor — a TPM, a security key, or a passphrase.
    pub fn open_with(path: impl Into<PathBuf>, opener: &dyn SlotOpener) -> Result<Self> {
        let path = path.into();
        let file = Self::read_file(&path)?;
        if file.format <= 1 {
            return Err(Error::Other(
                "this vault predates key slots; open it once with its passphrase to upgrade".into(),
            ));
        }
        let dek = Self::unwrap_with(&file, opener)?;
        Self::finish_open(path, file, dek)
    }

    fn finish_open(path: PathBuf, file: VaultFile, dek: SymKey) -> Result<Self> {
        let plaintext = dek.open(
            &file.body.nonce_bytes("body.nonce")?,
            &file.body.ciphertext_bytes("body.ciphertext")?,
            &file.body_aad(),
        )?;
        let data: VaultData = serde_json::from_slice(&plaintext)?;
        Ok(Self {
            path,
            file,
            dek,
            data,
            dirty: false,
        })
    }

    /// Try every slot this opener recognises.
    ///
    /// Reports [`Error::Unauthenticated`] whether the factor was wrong or no
    /// slot matched at all: distinguishing them would tell an attacker which
    /// factors a vault is enrolled with.
    fn unwrap_with(file: &VaultFile, opener: &dyn SlotOpener) -> Result<SymKey> {
        for slot in &file.slots {
            let Some(kek) = opener.kek_for(&slot.factor)? else {
                continue;
            };
            if let Ok(dek) = slot.unwrap_dek(&kek, &file.magic, file.format) {
                return Ok(dek);
            }
        }
        Err(Error::Unauthenticated)
    }

    fn unwrap_legacy(file: &VaultFile, passphrase: &str) -> Result<SymKey> {
        let kdf = file
            .kdf
            .as_ref()
            .ok_or(Error::Other("format 1 vault has no kdf section".into()))?;
        let wrapped = file
            .wrapped_key
            .as_ref()
            .ok_or(Error::Other("format 1 vault has no wrapped key".into()))?;

        let salt = Base64::decode_vec(&kdf.salt).map_err(|_| Error::Base64 { field: "salt" })?;
        let salt: [u8; SALT_LEN] = salt.as_slice().try_into().map_err(|_| Error::FieldLength {
            field: "salt",
            found: salt.len(),
            expected: SALT_LEN,
        })?;

        let kek = SymKey::derive(passphrase, &salt, kdf.params)?;
        kek.unwrap_key(
            &wrapped.nonce_bytes("wrapped_key.nonce")?,
            &wrapped.ciphertext_bytes("wrapped_key.ciphertext")?,
            &file.legacy_key_aad(),
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn data(&self) -> &VaultData {
        &self.data
    }

    /// Mutable access. Marks the vault dirty; call [`Vault::save`] to persist.
    pub fn data_mut(&mut self) -> &mut VaultData {
        self.dirty = true;
        &mut self.data
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn format(&self) -> u16 {
        self.file.format
    }

    // -- slots --------------------------------------------------------------

    pub fn slots(&self) -> &[Slot] {
        &self.file.slots
    }

    /// KDF parameters of the first passphrase slot.
    pub fn kdf_params(&self) -> KdfParams {
        self.file
            .slots
            .iter()
            .find_map(|s| match &s.factor {
                SlotFactor::Passphrase { params, .. } => Some(*params),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Enrol a hardware factor, wrapping the existing DEK under `kek`.
    ///
    /// The caller obtains `kek` from the device — 32 bytes unsealed by a TPM,
    /// or a token's `hmac-secret` output.
    pub fn add_slot(
        &mut self,
        label: impl Into<String>,
        factor: SlotFactor,
        kek: &SymKey,
    ) -> Result<Uuid> {
        let slot = Slot::new_with_kek(label, factor, kek, &self.dek, MAGIC, self.file.format)?;
        let id = slot.id;
        self.file.slots.push(slot);
        self.dirty = true;
        // The body's AAD covers the slot table, so it must be resealed.
        self.save()?;
        Ok(id)
    }

    /// Remove a slot, refusing to remove the last one.
    ///
    /// A vault with no slots is unopenable, so this is a footgun worth an
    /// explicit error rather than a silent brick.
    pub fn remove_slot(&mut self, id: Uuid) -> Result<()> {
        if self.file.slots.len() <= 1 {
            return Err(Error::Other(
                "refusing to remove the only remaining unlock factor".into(),
            ));
        }
        let before = self.file.slots.len();
        self.file.slots.retain(|s| s.id != id);
        if self.file.slots.len() == before {
            return Err(Error::Other(format!("no slot {id}")));
        }
        self.dirty = true;
        self.save()
    }

    /// Replace the passphrase slot(s) with one derived from a new passphrase.
    pub fn change_passphrase(&mut self, new_passphrase: &str, params: KdfParams) -> Result<()> {
        let slot = Slot::new_passphrase(
            "Passphrase",
            new_passphrase,
            params,
            &self.dek,
            MAGIC,
            self.file.format,
        )?;
        self.file
            .slots
            .retain(|s| s.factor.kind() != SlotKind::Passphrase);
        self.file.slots.push(slot);
        self.dirty = true;
        self.save()
    }

    /// Encrypt and write the vault, atomically.
    ///
    /// Writes to a sibling temp file, fsyncs it, then renames over the target,
    /// so a crash mid-write can never leave a truncated vault. The temp file is
    /// created 0600 before any ciphertext reaches it.
    pub fn save(&mut self) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.data)?;
        let (body_nonce, body_ct) = self.dek.seal(&plaintext, &self.file.body_aad())?;
        self.file.body = SealedBlob::new(body_nonce, body_ct);

        let serialized = serde_json::to_vec_pretty(&self.file)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }

        let tmp = self.path.with_extension("vault.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(|e| Error::io(&tmp, e))?;
            f.write_all(&serialized).map_err(|e| Error::io(&tmp, e))?;
            f.sync_all().map_err(|e| Error::io(&tmp, e))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| Error::io(&self.path, e))?;

        self.dirty = false;
        Ok(())
    }

    // -- convenience wrappers over VaultData --------------------------------

    pub fn add_item(&mut self, collection: Uuid, item: Item) -> Result<Uuid> {
        let id = item.id;
        let c = self
            .data_mut()
            .collection_mut(collection)
            .ok_or_else(|| Error::Other(format!("no collection {collection}")))?;
        c.items.push(item);
        c.modified = crate::model::now();
        Ok(id)
    }

    /// Add to whichever collection is aliased `default`.
    pub fn add_item_default(&mut self, item: Item) -> Uuid {
        let id = item.id;
        let c = self.data_mut().default_collection_mut();
        c.items.push(item);
        c.modified = crate::model::now();
        id
    }

    pub fn item(&self, id: Uuid) -> Option<&Item> {
        self.data.find_item(id).map(|(_, i)| i)
    }

    pub fn item_mut(&mut self, id: Uuid) -> Option<&mut Item> {
        self.data_mut()
            .collections
            .iter_mut()
            .find_map(|c| c.items.iter_mut().find(|i| i.id == id))
    }

    pub fn remove_item(&mut self, id: Uuid) -> Option<Item> {
        self.data_mut().remove_item(id)
    }

    pub fn add_collection(&mut self, collection: Collection) -> Uuid {
        let id = collection.id;
        self.data_mut().collections.push(collection);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, Item, ItemKind, field_names};
    use crate::slots::{RawKeyOpener, base64_encode};

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        (dir, path)
    }

    #[test]
    fn create_open_roundtrip() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "correct horse battery staple", KdfParams::insecure_fast())
            .unwrap();
        let id = v.add_item_default(
            Item::new(ItemKind::Login, "GitHub")
                .with_secret("hunter2")
                .with_field(Field::text(field_names::USERNAME, "ada")),
        );
        v.save().unwrap();
        drop(v);

        let v2 = Vault::open(&path, "correct horse battery staple").unwrap();
        let item = v2.item(id).expect("item survived the roundtrip");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(v2.format(), FORMAT_VERSION);
        assert_eq!(v2.slots().len(), 1);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let (_d, path) = tmp();
        Vault::create(&path, "right", KdfParams::insecure_fast()).unwrap();
        assert!(matches!(
            Vault::open(&path, "wrong"),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn no_plaintext_secret_hits_the_disk() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        v.add_item_default(Item::new(ItemKind::Login, "Bank").with_secret("s3kr1t-canary-value"));
        v.save().unwrap();

        let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        assert!(!raw.contains("s3kr1t-canary-value"), "secret leaked in the clear");
        assert!(!raw.contains("Bank"), "label leaked in the clear");
    }

    #[test]
    fn passphrase_change_preserves_contents_and_slot_count() {
        let (_d, path) = tmp();
        let params = KdfParams::insecure_fast();
        let mut v = Vault::create(&path, "old", params).unwrap();
        let id = v.add_item_default(Item::new(ItemKind::Note, "Note").with_secret("body"));
        v.save().unwrap();
        v.change_passphrase("new", params).unwrap();
        drop(v);

        assert!(matches!(Vault::open(&path, "old"), Err(Error::Unauthenticated)));
        let v2 = Vault::open(&path, "new").unwrap();
        assert_eq!(v2.item(id).unwrap().secret.expose(), "body");
        assert_eq!(v2.slots().len(), 1, "passphrase change left a stale slot");
    }

    #[test]
    fn a_hardware_slot_opens_the_same_vault_as_the_passphrase() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let id = v.add_item_default(Item::new(ItemKind::Login, "X").with_secret("shared"));
        v.save().unwrap();

        // Stand in for a TPM handing back 32 unsealed bytes.
        let device_key = SymKey::random().unwrap();
        v.add_slot(
            "TPM 2.0",
            SlotFactor::Tpm2 {
                sealed: base64_encode(b"opaque"),
                parent: Default::default(),
                pcrs: vec![],
                with_pin: true,
            },
            &device_key,
        )
        .unwrap();
        drop(v);

        // Both factors reach the same data.
        let by_passphrase = Vault::open(&path, "pw").unwrap();
        assert_eq!(by_passphrase.item(id).unwrap().secret.expose(), "shared");
        assert_eq!(by_passphrase.slots().len(), 2);

        let by_device = Vault::open_with(
            &path,
            &RawKeyOpener {
                kind: SlotKind::Tpm2,
                key: device_key,
            },
        )
        .unwrap();
        assert_eq!(by_device.item(id).unwrap().secret.expose(), "shared");
    }

    #[test]
    fn a_wrong_device_key_does_not_open_the_vault() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        v.add_slot(
            "TPM 2.0",
            SlotFactor::Tpm2 {
                sealed: base64_encode(b"opaque"),
                parent: Default::default(),
                pcrs: vec![],
                with_pin: false,
            },
            &SymKey::random().unwrap(),
        )
        .unwrap();
        drop(v);

        assert!(matches!(
            Vault::open_with(
                &path,
                &RawKeyOpener {
                    kind: SlotKind::Tpm2,
                    key: SymKey::random().unwrap(),
                }
            ),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn removing_a_slot_keeps_the_others_working() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let device_key = SymKey::random().unwrap();
        let slot_id = v
            .add_slot(
                "TPM 2.0",
                SlotFactor::Tpm2 {
                    sealed: base64_encode(b"o"),
                    parent: Default::default(),
                    pcrs: vec![],
                    with_pin: false,
                },
                &device_key,
            )
            .unwrap();

        v.remove_slot(slot_id).unwrap();
        drop(v);

        assert!(Vault::open(&path, "pw").is_ok());
        assert!(matches!(
            Vault::open_with(
                &path,
                &RawKeyOpener {
                    kind: SlotKind::Tpm2,
                    key: device_key
                }
            ),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn the_last_slot_cannot_be_removed() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let only = v.slots()[0].id;
        assert!(v.remove_slot(only).is_err(), "bricked the vault");
        assert_eq!(v.slots().len(), 1);
    }

    #[test]
    fn tampering_with_the_slot_table_invalidates_the_body() {
        let (_d, path) = tmp();
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let mut file: VaultFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file.slots[0].label = "Tampered".into();
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(Vault::open(&path, "pw"), Err(Error::Unauthenticated)));
    }

    #[test]
    fn opening_a_non_vault_file_is_diagnosable() {
        let (_d, path) = tmp();
        std::fs::write(&path, b"this is not a vault").unwrap();
        assert!(matches!(Vault::open(&path, "pw"), Err(Error::NotAVault { .. })));
    }

    #[test]
    fn a_future_format_is_refused_rather_than_guessed_at() {
        let (_d, path) = tmp();
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let mut file: VaultFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file.format = FORMAT_VERSION + 1;
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(
            Vault::open(&path, "pw"),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, path) = tmp();
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "vault is readable by group or other");
    }

    /// Format 1 files must keep opening, and become format 2 on save.
    #[test]
    fn format_1_vaults_are_read_and_upgraded() {
        let (_d, path) = tmp();

        // Build a format 1 file exactly as the old code did.
        let params = KdfParams::insecure_fast();
        let salt = crate::crypto::random_salt().unwrap();
        let kek = SymKey::derive("legacy-pw", &salt, params).unwrap();
        let dek = SymKey::random().unwrap();

        let mut file = VaultFile {
            magic: MAGIC.to_owned(),
            format: 1,
            slots: Vec::new(),
            kdf: Some(KdfDescriptor {
                algorithm: "argon2id".to_owned(),
                params,
                salt: Base64::encode_string(&salt),
            }),
            wrapped_key: Some(SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            }),
            body: SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
        };
        let (n, ct) = kek.wrap(&dek, &file.legacy_key_aad()).unwrap();
        file.wrapped_key = Some(SealedBlob::new(n, ct));

        let mut data = VaultData::default();
        data.default_collection_mut()
            .items
            .push(Item::new(ItemKind::Login, "Legacy").with_secret("old-secret"));
        let (bn, bct) = dek
            .seal(&serde_json::to_vec(&data).unwrap(), &file.body_aad())
            .unwrap();
        file.body = SealedBlob::new(bn, bct);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        // It opens, and the contents survive.
        let mut v = Vault::open(&path, "legacy-pw").unwrap();
        assert_eq!(v.data().item_count(), 1);
        assert_eq!(
            v.data().all_items().next().unwrap().1.secret.expose(),
            "old-secret"
        );
        assert_eq!(v.format(), FORMAT_VERSION, "format was not upgraded");

        // After saving it is a real format 2 file that still opens.
        v.save().unwrap();
        drop(v);

        // Check the top-level shape, not a substring: every *slot* legitimately
        // carries its own `wrapped_key`, so only the legacy top-level copies of
        // `kdf` and `wrapped_key` should be gone.
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let top = json.as_object().unwrap();
        assert_eq!(top["format"], 2);
        assert!(!top.contains_key("kdf"), "legacy kdf was kept");
        assert!(
            !top.contains_key("wrapped_key"),
            "legacy top-level wrapped_key was kept"
        );
        assert_eq!(top["slots"].as_array().unwrap().len(), 1);

        let reopened = Vault::open(&path, "legacy-pw").unwrap();
        assert_eq!(reopened.data().item_count(), 1);
        assert_eq!(reopened.slots().len(), 1);
    }
}
