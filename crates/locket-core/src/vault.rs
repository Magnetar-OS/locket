//! The on-disk vault file: envelope format, open/create, atomic save.
//!
//! # File layout (format 4)
//!
//! JSON with base64 fields — inspectable on purpose, so a recovery tool never
//! has to reverse a binary format.
//!
//! ```json
//! {
//!   "magic": "locket-vault",
//!   "format": 4,
//!   "slots": [ { "id": "...", "label": "Passphrase", "factor": {...},
//!                "wrapped_key": { "nonce": "b64", "ciphertext": "b64" } } ],
//!   "collections": [ { "id": "...", "label": "Login", "alias": "default" } ],
//!   "body": { "nonce": "b64", "ciphertext": "b64" }
//! }
//! ```
//!
//! The body is encrypted once, under a random data-encryption key. Every slot
//! stores that same DEK wrapped under a different factor (see [`crate::slots`]),
//! so enrolling a TPM or a security key *adds* a way in rather than replacing
//! the passphrase.
//!
//! `collections` is the only plaintext part, and it holds collection ids,
//! labels and aliases — nothing about any item. See [`CollectionIndex`] for
//! why a locked Secret Service has to be able to answer that.
//!
//! Older files are read and upgraded in place on the next save: format 1 — a
//! single inline `kdf` + `wrapped_key` — becomes a one-slot format 2 file,
//! format 2 gains the collection index, and format 3 becomes format 4. The
//! envelope did not change between 3 and 4; the version exists so a build
//! that predates trash, history and attachments refuses the file instead of
//! opening it and silently stripping data it does not know about on save.

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

pub const MAGIC: &str = "locket-vault";
/// The magic the project wrote before it was renamed. It is bound into every
/// slot's and the body's AEAD context, so a vault created under it keeps it
/// for life: rewriting the string would lock every existing slot out of the
/// key, and re-sealing them needs every factor the vault is enrolled with.
pub const LEGACY_MAGIC: &str = "passman-vault";
pub const FORMAT_VERSION: u16 = 4;

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

/// A collection, as visible *without* unlocking the vault.
///
/// This is the one thing locket keeps in the clear, and it is a deliberate
/// concession to the Secret Service protocol rather than an oversight.
///
/// A locked service must still be able to answer "which collections exist?" —
/// `ReadAlias`, the `Collections` property and the `Unlock` method are all
/// meaningless otherwise. Answering "none" instead does not read as *locked*
/// to a client, it reads as *there is no keyring here*, which is how
/// `libsecret` applications end up reporting that no keyring is installed.
///
/// So collection ids, labels and aliases are plaintext. Item labels,
/// usernames, attributes and secrets all stay inside the sealed body. This is
/// the same line gnome-keyring draws — keyring names are in the clear there
/// too — and the index is covered by the body's AEAD, so it cannot be edited
/// without invalidating the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionIndex {
    pub id: Uuid,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
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

    /// Format 3 and later: which collections exist, readable while locked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<CollectionIndex>,

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
        if self.magic != MAGIC && self.magic != LEGACY_MAGIC {
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
            2 => serde_json::to_vec(&(&self.magic, self.format, &self.slots)).unwrap_or_default(),
            // Format 3 binds the plaintext collection index into the body's
            // AEAD, so relabelling a collection on disk breaks authentication
            // rather than silently succeeding.
            _ => serde_json::to_vec(&(&self.magic, self.format, &self.slots, &self.collections))
                .unwrap_or_default(),
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
    /// What the file looked like when we last read or wrote it.
    ///
    /// locket is routinely two processes deep — the daemon holds the vault
    /// and the GUI opens the same file directly when no daemon is on the bus —
    /// so "the file changed since I read it" is a normal condition, not a
    /// corner case, and overwriting blindly loses whichever edit came second.
    stamp: Option<Stamp>,
}

/// Enough of a file's metadata to notice it was replaced.
///
/// Modification time and length rather than a hash: a save rewrites the whole
/// file through a rename, so the inode changes wholesale and there is nothing
/// subtle to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: std::time::SystemTime,
    len: u64,
}

impl Stamp {
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Self {
            modified: meta.modified().ok()?,
            len: meta.len(),
        })
    }
}

/// Take the advisory lock guarding a vault file.
///
/// The lock lives on a sibling `.lock` file rather than the vault itself,
/// because a save renames a new file over the old one: a lock held on the
/// vault's own inode would be released the moment it stopped being the vault.
fn lock_file(path: &Path, exclusive: bool) -> Result<std::fs::File> {
    let lock_path = path.with_extension("vault.lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts
        .open(&lock_path)
        .map_err(|e| Error::io(&lock_path, e))?;
    let locked = if exclusive {
        file.lock()
    } else {
        file.lock_shared()
    };
    locked.map_err(|e| Error::io(&lock_path, e))?;
    Ok(file)
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
    /// The default vault location: `$XDG_DATA_HOME/locket/default.vault`.
    pub fn default_path() -> Result<PathBuf> {
        let dir = dirs::data_dir().ok_or(Error::NoDataDir)?;
        let current = dir.join("locket").join("default.vault");

        // The project used to be called passman. A vault written under that
        // name keeps being used where it is: moving somebody's only copy of
        // every secret they own, silently, because a program was renamed, is
        // not a trade anyone would agree to if asked. Copy it across yourself
        // if you want the tidier path.
        if !current.exists() {
            let legacy = dir.join("passman").join("default.vault");
            if legacy.is_file() {
                tracing::info!(
                    path = %legacy.display(),
                    "using the vault from the previous name; move it to {} when convenient",
                    current.display()
                );
                return Ok(legacy);
            }
        }
        Ok(current)
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Read the collection index without unlocking anything.
    ///
    /// This is what lets a locked daemon answer `ReadAlias` and `Collections`
    /// honestly — "these exist, and they are locked" — instead of claiming no
    /// keyring is present.
    pub fn read_index(path: &Path) -> Result<Vec<CollectionIndex>> {
        Ok(Self::read_file(path)?.collections)
    }

    /// Create a brand-new vault with a single passphrase slot.
    pub fn create(path: impl Into<PathBuf>, passphrase: &str, params: KdfParams) -> Result<Self> {
        Self::create_with_magic(path, passphrase, params, MAGIC)
    }

    /// [`Vault::create`] under a given magic; only tests want anything but [`MAGIC`].
    fn create_with_magic(
        path: impl Into<PathBuf>,
        passphrase: &str,
        params: KdfParams,
        magic: &str,
    ) -> Result<Self> {
        let path = path.into();
        let dek = SymKey::random()?;

        let slot = Slot::new_passphrase(
            "Passphrase",
            passphrase,
            params,
            &dek,
            magic,
            FORMAT_VERSION,
        )?;

        let file = VaultFile {
            magic: magic.to_owned(),
            format: FORMAT_VERSION,
            slots: vec![slot],
            collections: Vec::new(),
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
            // Nothing on disk yet, so nothing to be stale against.
            stamp: None,
        };

        // Check and write under one lock. A caller that looked before calling
        // is racing anything else that might be creating the same vault, and
        // the loser of that race would otherwise silently replace a vault that
        // already had secrets in it.
        let guard = lock_file(&vault.path, true)?;
        if vault.path.exists() {
            return Err(Error::AlreadyExists { path: vault.path });
        }
        vault.write_locked()?;
        drop(guard);
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
                &file.magic,
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
            let stamp = Stamp::of(&path);
            return Ok(Self {
                path,
                file,
                dek,
                data,
                // Dirty, so the upgraded layout is written on the next save.
                dirty: true,
                stamp,
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
        let mut data: VaultData = serde_json::from_slice(&plaintext)?;
        // Unlock is where the trash retention window is enforced: every
        // frontend opens through here, so "30 days" means 30 days no matter
        // which process gets to the vault first.
        let purged = data.purge_expired_trash(crate::model::now());
        if purged > 0 {
            tracing::info!(purged, "purged trashed items past the retention window");
        }
        let stamp = Stamp::of(&path);
        Ok(Self {
            path,
            file,
            dek,
            data,
            dirty: purged > 0,
            stamp,
        })
    }

    /// Try every slot this opener recognises.
    ///
    /// Reports [`Error::WrongPassphrase`] whether the factor was wrong or no
    /// slot matched at all: distinguishing them would tell an attacker which
    /// factors a vault is enrolled with.
    fn unwrap_with(file: &VaultFile, opener: &dyn SlotOpener) -> Result<SymKey> {
        for slot in &file.slots {
            let Some(kek) = opener.kek_for(&slot.factor)? else {
                continue;
            };
            // A slot's AAD binds the format version that was current when the
            // slot was *sealed*, which is not necessarily the file's format
            // today: raising FORMAT_VERSION rewrites the header on the next
            // save, but re-wrapping a slot needs the passphrase, which `save`
            // does not have. So try the current version and then older ones.
            //
            // This is what stops a format bump from locking every existing
            // vault out of its own key — which is exactly what happened when
            // format 3 landed. Only the AEAD open repeats here; the expensive
            // part, deriving the KEK, has already been done once above.
            for format in (1..=file.format).rev() {
                if let Ok(dek) = slot.unwrap_dek(&kek, &file.magic, format) {
                    return Ok(dek);
                }
            }
        }
        Err(Error::WrongPassphrase)
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
        let slot = Slot::new_with_kek(
            label,
            factor,
            kek,
            &self.dek,
            &self.file.magic,
            self.file.format,
        )?;
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
            &self.file.magic,
            self.file.format,
        )?;
        self.file
            .slots
            .retain(|s| s.factor.kind() != SlotKind::Passphrase);
        self.file.slots.push(slot);
        self.dirty = true;
        self.save()
    }

    /// Encrypt and write the vault, atomically, refusing to clobber another
    /// writer.
    ///
    /// Writes to a sibling temp file, fsyncs it, then renames over the target,
    /// so a crash mid-write can never leave a truncated vault. The temp file is
    /// created 0600 before any ciphertext reaches it.
    ///
    /// Two processes editing the same vault is the normal arrangement here,
    /// not an exotic one, so the whole read-check-write is done under an
    /// exclusive lock and a file that changed since we read it produces
    /// [`Error::ChangedOnDisk`] rather than silently discarding the other
    /// side's edits. Recover with [`Vault::reload`].
    pub fn save(&mut self) -> Result<()> {
        let _guard = lock_file(&self.path, true)?;
        let on_disk = Stamp::of(&self.path);
        // `None` on both sides means the file does not exist yet, which is the
        // create path, not a conflict.
        if on_disk.is_some() && on_disk != self.stamp {
            return Err(Error::ChangedOnDisk {
                path: self.path.clone(),
            });
        }
        self.write_locked()
    }

    /// Write unconditionally, discarding whatever is on disk.
    ///
    /// For the one case where that is right: the caller has already reconciled
    /// with the other writer, or is deliberately restoring.
    pub fn save_force(&mut self) -> Result<()> {
        let _guard = lock_file(&self.path, true)?;
        self.write_locked()
    }

    fn write_locked(&mut self) -> Result<()> {
        // Regenerate the plaintext index from the real data every time, so it
        // cannot drift from what the body actually contains.
        self.file.collections = self
            .data
            .collections
            .iter()
            .map(|c| CollectionIndex {
                id: c.id,
                label: c.label.clone(),
                alias: c.alias.clone(),
            })
            .collect();
        // An older file gains the index the first time it is written.
        self.file.format = FORMAT_VERSION;

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

        self.stamp = Stamp::of(&self.path);
        self.dirty = false;
        Ok(())
    }

    /// Re-read the vault from disk, keeping the key we already hold.
    ///
    /// This is how a process recovers from [`Error::ChangedOnDisk`], and how
    /// the daemon picks up an edit the GUI made directly to the file. The DEK
    /// survives a normal save — only re-wrapping it does not — so a reload
    /// needs no passphrase. If it fails to decrypt, the other writer changed
    /// the key material, and the honest answer is to lock and ask again.
    ///
    /// In-memory edits that were never saved are discarded, which is why this
    /// reports how many there were rather than deciding for the caller.
    pub fn reload(&mut self) -> Result<()> {
        let _guard = lock_file(&self.path, false)?;
        let file = Self::read_file(&self.path)?;
        let plaintext = self.dek.open(
            &file.body.nonce_bytes("body.nonce")?,
            &file.body.ciphertext_bytes("body.ciphertext")?,
            &file.body_aad(),
        )?;
        self.data = serde_json::from_slice(&plaintext)?;
        self.file = file;
        self.stamp = Stamp::of(&self.path);
        self.dirty = false;
        Ok(())
    }

    /// Whether the file on disk has been replaced since this vault read it.
    pub fn changed_on_disk(&self) -> bool {
        match Stamp::of(&self.path) {
            Some(current) => Some(current) != self.stamp,
            // A vault whose file has vanished is not "changed"; saving will
            // recreate it, which is better than refusing to write at all.
            None => false,
        }
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

    /// Soft-delete into the trash. See [`VaultData::trash_item`].
    pub fn trash_item(&mut self, id: Uuid) -> Option<Uuid> {
        self.data_mut().trash_item(id)
    }

    /// Restore from the trash. See [`VaultData::restore_item`].
    pub fn restore_item(&mut self, id: Uuid) -> Option<Uuid> {
        self.data_mut().restore_item(id)
    }

    /// Permanently delete a trashed item. See [`VaultData::purge_item`].
    pub fn purge_item(&mut self, id: Uuid) -> Option<Item> {
        self.data_mut().purge_item(id)
    }

    /// Edit an item with its prior state captured into history first.
    ///
    /// This is the mutation path for anything a person would call "editing" —
    /// the GUI editor, `locket edit`, a Secret Service replace-on-store. Raw
    /// [`Vault::item_mut`] stays available for changes that are not edits of
    /// the item's content (bookkeeping like `favorite`).
    pub fn edit_item<R>(&mut self, id: Uuid, f: impl FnOnce(&mut Item) -> R) -> Result<R> {
        let item = self.item_mut(id).ok_or(Error::NoSuchItem(id))?;
        item.record_revision();
        let out = f(item);
        item.touch();
        Ok(out)
    }

    pub fn add_collection(&mut self, collection: Collection) -> Uuid {
        let id = collection.id;
        self.data_mut().collections.push(collection);
        id
    }

    /// Merge another vault's decrypted contents into this one.
    ///
    /// See [`crate::merge`] for the rules. The other side is consumed: merge
    /// is for reconciling two copies of the *same* vault after file sync
    /// forked them, not for importing between unrelated vaults.
    pub fn merge_from(&mut self, other: VaultData) -> crate::merge::MergeReport {
        crate::merge::merge(self.data_mut(), other)
    }

    /// Decrypt another copy of *this* vault with the key already held.
    ///
    /// Two forks of one vault share a DEK — a passphrase change only rewraps
    /// it — so the sibling a file synchroniser left behind opens without
    /// asking for anything. A file sealed under a different key (a genuinely
    /// unrelated vault) fails to authenticate, which is the correct answer:
    /// merge is for forks, not for imports.
    pub fn open_sibling(&self, path: &Path) -> Result<VaultData> {
        let file = Self::read_file(path)?;
        let plaintext = self.dek.open(
            &file.body.nonce_bytes("body.nonce")?,
            &file.body.ciphertext_bytes("body.ciphertext")?,
            &file.body_aad(),
        )?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Files beside this vault that look like a synchroniser's fork of it —
    /// Syncthing's `name.sync-conflict-….vault` naming, matched on the stem.
    pub fn sync_conflict_siblings(&self) -> Vec<PathBuf> {
        let Some(dir) = self.path.parent() else {
            return Vec::new();
        };
        let Some(stem) = self.path.file_stem().and_then(|s| s.to_str()) else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
                        name.starts_with(stem)
                            && name.contains(".sync-conflict")
                            && name.ends_with(".vault")
                    })
            })
            .collect();
        found.sort();
        found
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
        let mut v = Vault::create(
            &path,
            "correct horse battery staple",
            KdfParams::insecure_fast(),
        )
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
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn no_plaintext_secret_hits_the_disk() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        v.add_item_default(Item::new(ItemKind::Login, "Bank").with_secret("s3kr1t-canary-value"));
        v.save().unwrap();

        let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        assert!(
            !raw.contains("s3kr1t-canary-value"),
            "secret leaked in the clear"
        );
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

        assert!(matches!(
            Vault::open(&path, "old"),
            Err(Error::WrongPassphrase)
        ));
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

    /// The project used to be called passman, and that name is bound into the
    /// AEAD context of every slot and of the body. A vault written under it
    /// must open, keep its magic across a save, and seal anything new under
    /// that magic rather than the current one — or a passphrase change or a
    /// hardware enrolment would lock it out of its own key.
    #[test]
    fn a_vault_from_before_the_rename_opens_and_keeps_its_magic() {
        let (_d, path) = tmp();
        let params = KdfParams::insecure_fast();
        let mut v = Vault::create_with_magic(&path, "pw", params, LEGACY_MAGIC).unwrap();
        let id = v.add_item_default(Item::new(ItemKind::Login, "GitHub").with_secret("hunter2"));
        v.save().unwrap();
        drop(v);

        let mut v = Vault::open(&path, "pw").unwrap();
        assert_eq!(v.item(id).unwrap().secret.expose(), "hunter2");
        v.change_passphrase("new", params).unwrap();
        let device_key = SymKey::random().unwrap();
        v.add_slot(
            "TPM 2.0",
            SlotFactor::Tpm2 {
                sealed: base64_encode(b"opaque"),
                parent: Default::default(),
                pcrs: vec![],
                with_pin: false,
            },
            &device_key,
        )
        .unwrap();
        drop(v);

        let on_disk: VaultFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk.magic, LEGACY_MAGIC, "save rewrote the magic");
        assert_eq!(on_disk.format, FORMAT_VERSION);

        let by_passphrase = Vault::open(&path, "new").unwrap();
        assert_eq!(by_passphrase.item(id).unwrap().secret.expose(), "hunter2");
        let by_device = Vault::open_with(
            &path,
            &RawKeyOpener {
                kind: SlotKind::Tpm2,
                key: device_key,
            },
        )
        .unwrap();
        assert_eq!(by_device.item(id).unwrap().secret.expose(), "hunter2");
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
            Err(Error::WrongPassphrase)
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
            Err(Error::WrongPassphrase)
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

        // Surfaces as a rejected factor: a slot whose AAD no longer matches is
        // indistinguishable from one the supplied passphrase never fitted.
        assert!(matches!(
            Vault::open(&path, "pw"),
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn opening_a_non_vault_file_is_diagnosable() {
        let (_d, path) = tmp();
        std::fs::write(&path, b"this is not a vault").unwrap();
        assert!(matches!(
            Vault::open(&path, "pw"),
            Err(Error::NotAVault { .. })
        ));
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

    #[test]
    fn collections_are_listable_without_unlocking() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        v.add_collection(Collection::new("Work").with_alias("work"));
        v.add_item_default(Item::new(ItemKind::Login, "Secret Label").with_secret("s"));
        v.save().unwrap();
        drop(v);

        // No passphrase involved: this is what a locked daemon can answer.
        let index = Vault::read_index(&path).unwrap();
        let labels: Vec<&str> = index.iter().map(|c| c.label.as_str()).collect();
        assert!(
            labels.contains(&"Login"),
            "default collection missing from the index"
        );
        assert!(labels.contains(&"Work"));
        assert_eq!(
            index
                .iter()
                .find(|c| c.alias.as_deref() == Some("default"))
                .map(|c| &c.label),
            Some(&"Login".to_owned()),
            "the default alias must be resolvable while locked"
        );

        // Item-level data must NOT be in the clear, only collection names.
        let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        assert!(
            raw.contains("Work"),
            "collection labels are deliberately plaintext"
        );
        assert!(
            !raw.contains("Secret Label"),
            "an item label leaked into the plaintext index"
        );
    }

    #[test]
    fn tampering_with_the_collection_index_invalidates_the_body() {
        let (_d, path) = tmp();
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let mut file: VaultFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file.collections[0].label = "Renamed".into();
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(
            Vault::open(&path, "pw"),
            Err(Error::Unauthenticated)
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

    #[test]
    fn creating_over_an_existing_vault_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut first = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        first.add_item_default(Item::new(ItemKind::Login, "precious"));
        first.save().unwrap();

        let err = Vault::create(&path, "other", KdfParams::insecure_fast()).unwrap_err();
        assert!(
            matches!(err, Error::AlreadyExists { .. }),
            "a second create replaced a vault with secrets in it: {err:?}"
        );

        // Untouched: still opens with the original passphrase, still has the item.
        let disk = Vault::open(&path, "pw").unwrap();
        assert_eq!(disk.data().item_count(), 1);
    }

    #[test]
    fn saving_over_another_writer_is_refused_rather_than_silently_winning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        // Two processes, both with the vault open: the daemon and the GUI.
        let mut first = Vault::open(&path, "pw").unwrap();
        let mut second = Vault::open(&path, "pw").unwrap();

        first.add_item_default(Item::new(ItemKind::Login, "from the daemon"));
        first.save().unwrap();

        second.add_item_default(Item::new(ItemKind::Login, "from the GUI"));
        let err = second.save().unwrap_err();
        assert!(
            matches!(err, Error::ChangedOnDisk { .. }),
            "second writer clobbered the first: {err:?}"
        );

        // The first writer's item is still there.
        let disk = Vault::open(&path, "pw").unwrap();
        assert_eq!(disk.data().item_count(), 1);
        assert!(
            disk.data()
                .all_items()
                .any(|(_, i)| i.label == "from the daemon")
        );
    }

    #[test]
    fn reloading_picks_up_the_other_writer_and_lets_the_save_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let mut first = Vault::open(&path, "pw").unwrap();
        let mut second = Vault::open(&path, "pw").unwrap();

        first.add_item_default(Item::new(ItemKind::Login, "first"));
        first.save().unwrap();

        assert!(second.changed_on_disk());
        second.reload().unwrap();
        assert!(!second.changed_on_disk());
        assert_eq!(
            second.data().item_count(),
            1,
            "reload did not pick up the write"
        );

        second.add_item_default(Item::new(ItemKind::Login, "second"));
        second.save().expect("save after reload should succeed");

        let disk = Vault::open(&path, "pw").unwrap();
        assert_eq!(disk.data().item_count(), 2);
    }

    #[test]
    fn a_forced_save_is_the_way_to_overwrite_on_purpose() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let mut first = Vault::open(&path, "pw").unwrap();
        let mut second = Vault::open(&path, "pw").unwrap();
        first.add_item_default(Item::new(ItemKind::Login, "first"));
        first.save().unwrap();

        second.add_item_default(Item::new(ItemKind::Login, "second"));
        second.save_force().expect("forced save should not check");

        let disk = Vault::open(&path, "pw").unwrap();
        assert_eq!(disk.data().item_count(), 1);
        assert!(disk.data().all_items().any(|(_, i)| i.label == "second"));
    }

    #[test]
    fn repeated_saves_from_one_writer_are_not_mistaken_for_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        for n in 0..3 {
            vault.add_item_default(Item::new(ItemKind::Login, format!("item {n}")));
            vault
                .save()
                .expect("own writes must not look like someone else's");
        }
        assert_eq!(Vault::open(&path, "pw").unwrap().data().item_count(), 3);
    }

    /// Raising FORMAT_VERSION must not lock an existing vault out of its key.
    ///
    /// The exact format 2 -> 3 regression: `save` rewrites the header with the
    /// new version, but re-wrapping a key slot needs the passphrase, which
    /// `save` does not have. The slot therefore keeps the *old* version in its
    /// AAD, and unwrapping it against the file's current version fails — on a
    /// vault that is perfectly intact, reported as "incorrect passphrase, or
    /// the vault has been tampered with".
    #[test]
    fn a_format_bump_does_not_invalidate_existing_key_slots() {
        let (_d, path) = tmp();
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        vault.add_collection(crate::model::Collection::new("Login"));

        // Put the slot back the way an older build sealed it — AAD bound to
        // format 2 — and only then save, so the body is sealed over these
        // slots at the current format. That is the on-disk shape a real
        // upgraded vault has: new header and body, old slot.
        let dek =
            Vault::unwrap_with(&vault.file, &crate::slots::PassphraseOpener::new("pw")).unwrap();
        vault.file.slots = vec![
            crate::slots::Slot::new_passphrase(
                "Passphrase",
                "pw",
                KdfParams::insecure_fast(),
                &dek,
                MAGIC,
                2,
            )
            .unwrap(),
        ];
        vault.save().unwrap();

        let on_disk = Vault::read_file(&path).unwrap();
        assert!(
            on_disk.format > 2,
            "this test needs a format newer than the slot was sealed with"
        );

        let reopened = Vault::open(&path, "pw")
            .expect("a format bump locked the passphrase slot out of its own key");
        assert!(
            reopened
                .data()
                .collections
                .iter()
                .any(|c| c.label == "Login"),
            "the vault opened but lost its contents"
        );
    }

    /// Format 2's AAD must never change: it is the only thing standing between
    /// an existing on-disk vault and an authentication failure. Adding the
    /// collection index in format 3 was safe precisely because it went into a
    /// new branch rather than the existing one.
    #[test]
    fn the_format_2_body_aad_is_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let mut file = vault.file.clone();
        file.format = 2;
        let expected = serde_json::to_vec(&(&file.magic, 2u16, &file.slots)).unwrap();
        assert_eq!(
            file.body_aad(),
            expected,
            "format 2's AAD changed; every existing vault would fail to open"
        );
    }

    /// A format 3 file — written by the last release — must open with the
    /// current build and leave disk as a format 4 file on the next save.
    #[test]
    fn format_3_vaults_are_read_and_upgraded() {
        let (_d, path) = tmp();

        // Build a format 3 file the way the previous release did: slot AAD
        // and body AAD both bound to format 3.
        let dek = SymKey::random().unwrap();
        let slot = crate::slots::Slot::new_passphrase(
            "Passphrase",
            "pw",
            KdfParams::insecure_fast(),
            &dek,
            MAGIC,
            3,
        )
        .unwrap();
        let mut data = VaultData::default();
        data.default_collection_mut()
            .items
            .push(Item::new(ItemKind::Login, "From format 3").with_secret("survives"));
        let mut file = VaultFile {
            magic: MAGIC.to_owned(),
            format: 3,
            slots: vec![slot],
            collections: data
                .collections
                .iter()
                .map(|c| CollectionIndex {
                    id: c.id,
                    label: c.label.clone(),
                    alias: c.alias.clone(),
                })
                .collect(),
            kdf: None,
            wrapped_key: None,
            body: SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
        };
        let (bn, bct) = dek
            .seal(&serde_json::to_vec(&data).unwrap(), &file.body_aad())
            .unwrap();
        file.body = SealedBlob::new(bn, bct);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let mut v = Vault::open(&path, "pw").expect("a format 3 vault failed to open");
        assert_eq!(v.data().item_count(), 1);
        v.save().unwrap();
        drop(v);

        let on_disk = Vault::read_file(&path).unwrap();
        assert_eq!(
            on_disk.format, FORMAT_VERSION,
            "save did not upgrade the format"
        );
        let reopened = Vault::open(&path, "pw").unwrap();
        assert_eq!(
            reopened
                .data()
                .all_items()
                .next()
                .unwrap()
                .1
                .secret
                .expose(),
            "survives"
        );
    }

    #[test]
    fn a_trashed_item_survives_the_roundtrip_and_restores() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let id = v.add_item_default(Item::new(ItemKind::Login, "Doomed").with_secret("s"));
        v.trash_item(id).expect("live item went to the trash");
        assert!(v.item(id).is_none(), "trashed item still visible as live");
        v.save().unwrap();
        drop(v);

        let mut v2 = Vault::open(&path, "pw").unwrap();
        assert!(v2.item(id).is_none());
        assert!(
            v2.data().trashed(id).is_some(),
            "trash was lost on the roundtrip"
        );
        v2.restore_item(id).expect("restore failed");
        assert_eq!(v2.item(id).unwrap().secret.expose(), "s");
        assert!(v2.data().trashed(id).is_none());
    }

    #[test]
    fn trash_past_the_retention_window_is_purged_on_open() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let old = v.add_item_default(Item::new(ItemKind::Login, "Old"));
        let recent = v.add_item_default(Item::new(ItemKind::Login, "Recent"));
        v.trash_item(old);
        v.trash_item(recent);
        // Backdate one deletion past the 30-day default window.
        v.data_mut()
            .trash
            .iter_mut()
            .find(|t| t.item.id == old)
            .unwrap()
            .deleted = crate::model::now() - 31 * 86_400;
        v.save().unwrap();
        drop(v);

        let v2 = Vault::open(&path, "pw").unwrap();
        assert!(
            v2.data().trashed(old).is_none(),
            "expired trash survived unlock"
        );
        assert!(
            v2.data().trashed(recent).is_some(),
            "fresh trash was purged"
        );
        assert!(v2.is_dirty(), "a purge must reach disk on the next save");
    }

    #[test]
    fn editing_through_edit_item_records_history_and_restores() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let id = v.add_item_default(Item::new(ItemKind::Login, "Site").with_secret("first"));

        v.edit_item(id, |item| item.secret = "second".into())
            .unwrap();
        v.edit_item(id, |item| item.secret = "third".into())
            .unwrap();
        v.save().unwrap();
        drop(v);

        let mut v2 = Vault::open(&path, "pw").unwrap();
        let item = v2.item(id).unwrap();
        assert_eq!(item.secret.expose(), "third");
        assert_eq!(item.history.len(), 2, "history was lost on the roundtrip");
        assert_eq!(item.history[0].item.secret.expose(), "first");
        assert_eq!(item.history[1].item.secret.expose(), "second");

        v2.edit_item(id, |item| item.restore_revision(0).unwrap())
            .unwrap();
        let item = v2.item(id).unwrap();
        assert_eq!(item.secret.expose(), "first", "restore did not take");
        assert!(
            item.history
                .iter()
                .any(|r| r.item.secret.expose() == "third"),
            "the state a restore replaced must itself be recoverable"
        );
    }

    #[test]
    fn an_attachment_survives_the_roundtrip_and_never_hits_disk_in_the_clear() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let id = v.add_item_default(Item::new(ItemKind::Login, "Bank"));
        // Recognisable, non-UTF-8-safe bytes: a fake PDF header plus a canary.
        let blob = b"%PDF-1.7 recovery-codes-canary \xff\xfe\x00".to_vec();
        let attachment_id = v
            .item_mut(id)
            .unwrap()
            .add_attachment("recovery.pdf", "application/pdf", blob.clone())
            .unwrap();
        v.save().unwrap();
        drop(v);

        let raw = std::fs::read(&path).unwrap();
        let raw_text = String::from_utf8_lossy(&raw);
        assert!(
            !raw_text.contains("recovery-codes-canary"),
            "attachment bytes leaked"
        );
        assert!(!raw_text.contains("recovery.pdf"), "attachment name leaked");

        let v2 = Vault::open(&path, "pw").unwrap();
        let attachment = v2.item(id).unwrap().attachment(attachment_id).unwrap();
        assert_eq!(attachment.data.expose(), blob.as_slice());
        assert_eq!(attachment.name, "recovery.pdf");
    }

    #[test]
    fn an_oversized_attachment_is_refused_with_the_limit_stated() {
        let mut item = Item::new(ItemKind::Login, "X");
        let err = item
            .add_attachment(
                "huge.bin",
                "application/octet-stream",
                vec![0u8; crate::model::MAX_ATTACHMENT_BYTES + 1],
            )
            .unwrap_err();
        assert!(matches!(err, Error::AttachmentTooLarge { .. }), "{err:?}");
        assert!(item.attachments.is_empty());
    }

    #[test]
    fn an_expired_item_knows_it_and_an_unexpiring_one_does_not() {
        let now = crate::model::now();
        let mut item = Item::new(ItemKind::Certificate, "TLS cert");
        assert!(!item.is_expired(now));
        item.expires = Some(now - 1);
        assert!(item.is_expired(now));
        item.expires = Some(now + 100);
        assert!(!item.is_expired(now));
        assert!(item.expires_within(now, 200));
        assert!(!item.expires_within(now, 50));
    }

    #[test]
    fn a_sync_conflict_sibling_opens_with_the_held_key_and_merges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.vault");
        let mut v = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        v.add_item_default(Item::new(ItemKind::Login, "Shared").with_secret("s"));
        v.save().unwrap();

        // The synchroniser's fork: a byte copy under its conflict name.
        let fork = dir
            .path()
            .join("default.sync-conflict-20260827-101010-ABCDEF.vault");
        std::fs::copy(&path, &fork).unwrap();

        assert_eq!(v.sync_conflict_siblings(), vec![fork.clone()]);

        // Edit the fork through its own handle, as the other machine would.
        let mut forked = Vault::open(&fork, "pw").unwrap();
        forked.add_item_default(Item::new(ItemKind::Login, "From the fork").with_secret("f"));
        forked.save().unwrap();
        drop(forked);

        // No passphrase involved: the held DEK opens the sibling.
        let other = v
            .open_sibling(&fork)
            .expect("sibling did not open with the held key");
        let report = v.merge_from(other);
        assert_eq!(report.added, 1);
        assert!(
            v.data()
                .all_items()
                .any(|(_, i)| i.label == "From the fork")
        );

        // An unrelated vault is not a sibling, and must not decrypt.
        let stranger_path = dir.path().join("other.vault");
        let mut stranger = Vault::create(&stranger_path, "pw", KdfParams::insecure_fast()).unwrap();
        stranger.save().unwrap();
        assert!(
            v.open_sibling(&stranger_path).is_err(),
            "a foreign vault decrypted"
        );
    }

    /// Format 1 files must keep opening, and be upgraded on save.
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
            collections: Vec::new(),
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
        assert_eq!(top["format"], FORMAT_VERSION);
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
