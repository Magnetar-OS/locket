//! Importers for other password managers.
//!
//! Each importer maps a foreign format onto locket's item model and hands the
//! result to a vault. They share two rules:
//!
//! * **Read-only against the source.** Nothing here writes to a password-store
//!   or a `.kdbx`; a failed import must leave you exactly where you started.
//! * **Idempotent against the target.** An item whose attribute set already
//!   exists is skipped, so re-running after adding a few secrets does not
//!   duplicate anything.
//!
//! Importing from a running Secret Service (gnome-keyring, KWallet) lives in
//! `locket-secret` instead, because it needs D-Bus rather than a file format.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use locket_core::{Vault, model::Collection};
use uuid::Uuid;

pub mod bitwarden;
pub mod cloud;
pub mod csv;
pub mod dotenv;
pub mod export;
pub mod keepass;
pub mod onepassword;
pub mod pass;
pub mod protonpass;
pub mod ssh;
pub mod totp;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} does not exist, or is not a directory")]
    NotFound(PathBuf),

    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not run an external tool: {0}")]
    Tool(String),

    #[error("decryption failed: {0}")]
    Decrypt(String),

    #[error("could not open the database: {0}")]
    Database(String),

    #[error("vault error: {0}")]
    Vault(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub collections: usize,
    pub imported: usize,
    /// Already present in the target, matched by attribute set.
    pub skipped_duplicate: usize,
    /// Could not be read or decrypted.
    pub skipped_unreadable: usize,
    /// Things the person who ran this needs to know about what just landed —
    /// not errors, and not derivable from the counts. Shown by both frontends.
    pub notes: Vec<String>,
}

impl std::fmt::Display for ImportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} item(s); {} already present, {} unreadable",
            self.imported, self.skipped_duplicate, self.skipped_unreadable
        )
    }
}

/// Find or create the collection an import should land in.
pub(crate) fn target_collection(vault: &mut Vault, label: &str) -> Uuid {
    if let Some(c) = vault.data().collections.iter().find(|c| c.label == label) {
        return c.id;
    }
    vault.add_collection(Collection::new(label))
}

/// Whether the vault already holds an item with exactly these attributes.
///
/// Importers stamp a source-specific path attribute, so this recognises "the
/// same entry from the same store" without needing the two formats to agree on
/// anything else.
pub(crate) fn already_present(vault: &Vault, attributes: &BTreeMap<String, String>) -> bool {
    if attributes.is_empty() {
        return false;
    }
    vault
        .data()
        .all_items()
        .any(|(_, i)| &i.attributes == attributes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::{
        crypto::KdfParams,
        model::{Item, ItemKind},
    };

    #[test]
    fn target_collection_is_reused_not_duplicated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let before = vault.data().collections.len();
        let a = target_collection(&mut vault, "pass");
        let b = target_collection(&mut vault, "pass");
        assert_eq!(a, b);
        assert_eq!(vault.data().collections.len(), before + 1);
    }

    #[test]
    fn duplicate_detection_needs_an_exact_attribute_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let item = Item::new(ItemKind::Login, "X")
            .with_attribute("pass:path", "web/github.com")
            .with_attribute("locket:source", "pass");
        let attrs = item.attributes.clone();
        vault.add_item_default(item);

        assert!(already_present(&vault, &attrs));

        let mut different = attrs.clone();
        different.insert("pass:path".into(), "web/gitlab.com".into());
        assert!(!already_present(&vault, &different));
        assert!(!already_present(&vault, &BTreeMap::new()));
    }
}
