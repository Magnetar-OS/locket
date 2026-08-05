//! The on-disk vault file: envelope format, open/create, atomic save.
//!
//! # File layout
//!
//! The file is JSON with base64 fields. Being inspectable matters more than
//! being compact here — a user who loses the app should still be able to see
//! what algorithm and cost parameters their data is under, and recovery tools
//! should not need to reverse a binary format.
//!
//! ```json
//! {
//!   "magic": "passman-vault",
//!   "format": 1,
//!   "kdf": { "algorithm": "argon2id", "m_cost": 65536, ..., "salt": "b64" },
//!   "wrapped_key": { "nonce": "b64", "ciphertext": "b64" },
//!   "body":        { "nonce": "b64", "ciphertext": "b64" }
//! }
//! ```
//!
//! The header is fed to both AEADs as associated data, so downgrading the KDF
//! cost or swapping a wrapped key between vaults fails authentication rather
//! than silently weakening the file.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, Result,
    crypto::{KdfParams, NONCE_LEN, SALT_LEN, SymKey, random_salt},
    model::{Collection, Item, VaultData},
};

pub const MAGIC: &str = "passman-vault";
pub const FORMAT_VERSION: u16 = 1;

/// A base64-encoded (nonce, ciphertext) pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedBlob {
    fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self {
            nonce: Base64::encode_string(&nonce),
            ciphertext: Base64::encode_string(&ciphertext),
        }
    }

    fn nonce_bytes(&self, field: &'static str) -> Result<[u8; NONCE_LEN]> {
        let raw = Base64::decode_vec(&self.nonce).map_err(|_| Error::Base64 { field })?;
        raw.as_slice().try_into().map_err(|_| Error::FieldLength {
            field,
            found: raw.len(),
            expected: NONCE_LEN,
        })
    }

    fn ciphertext_bytes(&self, field: &'static str) -> Result<Vec<u8>> {
        Base64::decode_vec(&self.ciphertext).map_err(|_| Error::Base64 { field })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfDescriptor {
    pub algorithm: String,
    #[serde(flatten)]
    pub params: KdfParams,
    pub salt: String,
}

impl KdfDescriptor {
    fn salt_bytes(&self) -> Result<[u8; SALT_LEN]> {
        let raw = Base64::decode_vec(&self.salt).map_err(|_| Error::Base64 { field: "salt" })?;
        raw.as_slice().try_into().map_err(|_| Error::FieldLength {
            field: "salt",
            found: raw.len(),
            expected: SALT_LEN,
        })
    }
}

/// The complete file, as it appears on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub magic: String,
    pub format: u16,
    pub kdf: KdfDescriptor,
    pub wrapped_key: SealedBlob,
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
        if self.kdf.algorithm != "argon2id" {
            return Err(Error::KdfParams(format!(
                "unsupported KDF `{}`",
                self.kdf.algorithm
            )));
        }
        Ok(())
    }

    /// Associated data binding the wrapped DEK to this file's KDF parameters.
    fn key_aad(&self) -> Vec<u8> {
        // serde_json preserves declaration order for structs, so this is
        // deterministic across runs and machines.
        serde_json::to_vec(&(&self.magic, self.format, &self.kdf)).unwrap_or_default()
    }

    /// Associated data binding the body to the whole header, wrapped key
    /// included — so an attacker cannot graft a body from another vault.
    fn body_aad(&self) -> Vec<u8> {
        serde_json::to_vec(&(&self.magic, self.format, &self.kdf, &self.wrapped_key))
            .unwrap_or_default()
    }
}

/// An open, decrypted vault.
///
/// Holds the DEK but *not* the passphrase or the KEK: both are dropped (and
/// zeroized) as soon as [`Vault::open`] finishes unwrapping.
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

    /// Create a brand-new vault and write it to disk.
    pub fn create(
        path: impl Into<PathBuf>,
        passphrase: &str,
        params: KdfParams,
    ) -> Result<Self> {
        let path = path.into();
        let salt = random_salt()?;
        let kek = SymKey::derive(passphrase, &salt, params)?;
        let dek = SymKey::random()?;

        // Build the header first so the wrapped key can be bound to it.
        let mut file = VaultFile {
            magic: MAGIC.to_owned(),
            format: FORMAT_VERSION,
            kdf: KdfDescriptor {
                algorithm: "argon2id".to_owned(),
                params,
                salt: Base64::encode_string(&salt),
            },
            wrapped_key: SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
            body: SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
        };

        let (nonce, ct) = kek.wrap(&dek, &file.key_aad())?;
        file.wrapped_key = SealedBlob::new(nonce, ct);

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

    /// Open an existing vault.
    ///
    /// Returns [`Error::Unauthenticated`] for both a wrong passphrase and a
    /// corrupted file: distinguishing them would tell an attacker which of the
    /// two they achieved.
    pub fn open(path: impl Into<PathBuf>, passphrase: &str) -> Result<Self> {
        let path = path.into();
        let raw = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
        let file: VaultFile = serde_json::from_slice(&raw).map_err(|e| {
            // A file that is not JSON at all is much more likely to be "wrong
            // path" than "corrupt vault", so report it as such.
            if raw.starts_with(b"{") {
                Error::Json(e)
            } else {
                Error::NotAVault { path: path.clone() }
            }
        })?;
        file.validate(&path)?;

        let salt = file.kdf.salt_bytes()?;
        let kek = SymKey::derive(passphrase, &salt, file.kdf.params)?;
        let dek = kek.unwrap_key(
            &file.wrapped_key.nonce_bytes("wrapped_key.nonce")?,
            &file.wrapped_key.ciphertext_bytes("wrapped_key.ciphertext")?,
            &file.key_aad(),
        )?;
        // `kek` and `passphrase`'s derived material die here.
        drop(kek);

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

    pub fn kdf_params(&self) -> KdfParams {
        self.file.kdf.params
    }

    /// Re-derive the KEK from a new passphrase and rewrap the DEK.
    ///
    /// The body is untouched: only 32 bytes are re-encrypted.
    pub fn change_passphrase(&mut self, new_passphrase: &str, params: KdfParams) -> Result<()> {
        let salt = random_salt()?;
        self.file.kdf = KdfDescriptor {
            algorithm: "argon2id".to_owned(),
            params,
            salt: Base64::encode_string(&salt),
        };
        let kek = SymKey::derive(new_passphrase, &salt, params)?;
        let (nonce, ct) = kek.wrap(&self.dek, &self.file.key_aad())?;
        self.file.wrapped_key = SealedBlob::new(nonce, ct);
        self.dirty = true;
        // The body's AAD covers wrapped_key, so it must be resealed too.
        self.save()
    }

    /// Encrypt and write the vault, atomically.
    ///
    /// Writes to a sibling temp file, fsyncs it, then renames over the target,
    /// so a crash mid-write can never leave a truncated vault. The temp file is
    /// created 0600 *before* any plaintext-derived bytes reach it.
    pub fn save(&mut self) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.data)?;

        // Reseal the body under the current header.
        let (body_nonce, body_ct) = {
            // wrapped_key is already final; body_aad reads it.
            self.dek.seal(&plaintext, &self.file.body_aad())?
        };
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

    // ---- convenience wrappers over VaultData ------------------------------

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

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        (dir, path)
    }

    #[test]
    fn create_open_roundtrip() {
        let (_d, path) = tmp();
        let params = KdfParams::insecure_fast();

        let mut v = Vault::create(&path, "correct horse battery staple", params).unwrap();
        let id = v.add_item_default(
            Item::new(ItemKind::Login, "GitHub")
                .with_secret("hunter2")
                .with_field(Field::text(field_names::USERNAME, "ada")),
        );
        v.save().unwrap();
        drop(v);

        let v2 = Vault::open(&path, "correct horse battery staple").unwrap();
        let item = v2.item(id).expect("item survived the roundtrip");
        assert_eq!(item.label, "GitHub");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
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
        v.add_item_default(
            Item::new(ItemKind::Login, "Bank").with_secret("s3kr1t-canary-value"),
        );
        v.save().unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("s3kr1t-canary-value"),
            "secret leaked into the vault file in the clear"
        );
        // The label is a secret too — it is inside the sealed body.
        assert!(!String::from_utf8_lossy(&raw).contains("Bank"));
    }

    #[test]
    fn downgrading_kdf_cost_invalidates_the_file() {
        let (_d, path) = tmp();
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let mut file: VaultFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file.kdf.params.t_cost += 1; // tamper with the header
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        // The KEK now derives differently *and* the AAD no longer matches, so
        // this must fail authentication rather than open with weaker params.
        assert!(matches!(Vault::open(&path, "pw"), Err(Error::Unauthenticated)));
    }

    #[test]
    fn passphrase_change_preserves_contents() {
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
    }

    #[test]
    fn opening_a_non_vault_file_is_diagnosable() {
        let (_d, path) = tmp();
        std::fs::write(&path, b"this is not a vault").unwrap();
        assert!(matches!(Vault::open(&path, "pw"), Err(Error::NotAVault { .. })));
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
}
