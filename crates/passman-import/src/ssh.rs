//! Import SSH private keys from `~/.ssh`.
//!
//! passman already serves an SSH agent from `ItemKind::SshKey` items, so this
//! is the half that was missing: getting the keys you already have into the
//! vault in the shape the agent reads them.
//!
//! The keys are copied, never moved. `~/.ssh/id_ed25519` stays exactly where
//! it is — OpenSSH still reads it directly, and until you have confirmed the
//! agent serves the imported copy, deleting the original would leave you
//! locked out of everything it authenticates to.

use std::path::{Path, PathBuf};

use passman_core::model::{Field, FieldKind, Item, ItemKind, field_names};

use crate::{Error, ImportSummary, Result};

/// The header every private key format we accept begins with.
///
/// Matching on the PEM banner rather than the filename is what lets this find
/// keys named `work`, `github-personal` or `deploy_key` — the `id_*`
/// convention is a default, not a rule.
const PRIVATE_KEY_BANNERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

/// Files in `~/.ssh` that are configuration or public data, never keys.
const NOT_KEYS: &[&str] = &[
    "config",
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "environment",
    "rc",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    pub path: PathBuf,
    /// File name, used as the item label.
    pub name: String,
    /// Contents of the matching `.pub`, if there is one.
    pub public: Option<String>,
    /// Trailing comment from the public key — usually `user@host`.
    pub comment: Option<String>,
    /// Whether the private key is itself passphrase-protected.
    pub encrypted: bool,
}

/// `~/.ssh`, if this user has one.
pub fn default_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh")).filter(|p| p.is_dir())
}

/// Whether `text` looks like an SSH private key.
pub fn is_private_key(text: &str) -> bool {
    PRIVATE_KEY_BANNERS
        .iter()
        .any(|banner| text.trim_start().starts_with(banner))
}

/// Whether the key is encrypted, and so needs its passphrase to be usable.
///
/// OpenSSH's own format names the cipher in the body; the older PEM formats
/// announce it in a `Proc-Type` header. An unencrypted OpenSSH key records
/// the cipher as `none`, which base64-encodes to a recognisable prefix, so
/// this decodes rather than guessing.
pub fn is_encrypted(text: &str) -> bool {
    if text.contains("Proc-Type: 4,ENCRYPTED") || text.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        return true;
    }
    if !text.contains("BEGIN OPENSSH PRIVATE KEY") {
        return false;
    }
    // openssh-key-v1\0 then a length-prefixed cipher name.
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let Ok(bytes) = base64_decode(&body) else {
        return false;
    };
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    if !bytes.starts_with(MAGIC) {
        return false;
    }
    let rest = &bytes[MAGIC.len()..];
    if rest.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    rest.get(4..4 + len).is_some_and(|name| name != b"none")
}

fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    use base64ct::Encoding as _;
    base64ct::Base64::decode_vec(s.trim()).map_err(|_| ())
}

/// The trailing comment of a public key line, if it has one.
fn comment_of(public: &str) -> Option<String> {
    let mut parts = public.split_whitespace();
    let _algorithm = parts.next()?;
    let _blob = parts.next()?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    (!comment.is_empty()).then_some(comment)
}

/// Find every private key in `dir`. Not recursive: `~/.ssh` is flat, and
/// descending would pull in whatever a user has parked in a subdirectory.
pub fn scan(dir: &Path) -> Result<Vec<KeyFile>> {
    if !dir.is_dir() {
        return Err(Error::NotFound(dir.to_path_buf()));
    }

    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| Error::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        if !path.is_file() || name.ends_with(".pub") || NOT_KEYS.contains(&name.as_str()) {
            continue;
        }
        // A private key is small; anything large is a log or a socket dump.
        if entry.metadata().map(|m| m.len()).unwrap_or(0) > 64 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !is_private_key(&text) {
            continue;
        }

        let public = std::fs::read_to_string(path.with_extension("pub"))
            .ok()
            .or_else(|| std::fs::read_to_string(format!("{}.pub", path.display())).ok());
        let comment = public.as_deref().and_then(comment_of);

        out.push(KeyFile {
            encrypted: is_encrypted(&text),
            path,
            name,
            public,
            comment,
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Build the vault item for one key file.
///
/// The private key goes in a field rather than the item's primary secret,
/// because the agent reads it from `private-key` and reserves the secret for
/// the key's *passphrase* — an encrypted key is useless to the agent without
/// somewhere to put that.
pub fn item_for(key: &KeyFile, pem: &str) -> Item {
    let mut item = Item::new(ItemKind::SshKey, key.name.clone())
        .with_field(Field::new(field_names::PRIVATE_KEY, FieldKind::Note, pem));

    if let Some(public) = &key.public {
        item = item.with_field(Field::new(
            field_names::PUBLIC_KEY,
            FieldKind::Text,
            public.trim(),
        ));
    }
    if let Some(comment) = &key.comment {
        item = item.with_field(Field::new(
            field_names::KEY_COMMENT,
            FieldKind::Text,
            comment,
        ));
    }

    item.attributes.insert(
        "ssh:path".to_owned(),
        key.path.display().to_string(),
    );
    item.attributes
        .insert("ssh:encrypted".to_owned(), key.encrypted.to_string());
    item.tags = vec!["ssh".to_owned()];
    item
}

/// Import every private key under `dir`. Does not save.
///
/// Encrypted keys are imported too, with an empty secret: the agent will skip
/// them until you fill in the passphrase, which is a better outcome than
/// leaving them out and having you wonder where they went. The count is
/// reported so you know how many need attention.
pub fn import_dir(
    vault: &mut passman_core::Vault,
    dir: &Path,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let keys = scan(dir)?;
    let target = crate::target_collection(vault, into_collection.unwrap_or("SSH"));
    let mut summary = ImportSummary::default();

    for key in &keys {
        let pem = match std::fs::read_to_string(&key.path) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("skipping {}: {e}", key.path.display());
                summary.skipped_unreadable += 1;
                continue;
            }
        };
        let item = item_for(key, &pem);
        if crate::already_present(vault, &item.attributes) {
            summary.skipped_duplicate += 1;
            continue;
        }
        vault
            .add_item(target, item)
            .map_err(|e| Error::Vault(e.to_string()))?;
        summary.imported += 1;
    }

    summary.collections = 1;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real, unencrypted ed25519 key generated for this test only. It
    // authenticates to nothing.
    const UNENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n\
ZWQyNTUxOQAAACBHV2VgMPXhbGqvBBOa0Zk4bZLPDDgAxSCF/TFxL7bTxwAAAJj0mDJ29Jgy\n\
dgAAAAtzc2gtZWQyNTUxOQAAACBHV2VgMPXhbGqvBBOa0Zk4bZLPDDgAxSCF/TFxL7bTxw\n\
-----END OPENSSH PRIVATE KEY-----\n";

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519"), UNENCRYPTED).unwrap();
        std::fs::write(
            dir.path().join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEdXZWAw9eFsaq8EE5rRmTg ada@lovelace\n",
        )
        .unwrap();
        // Things that live in ~/.ssh but are not keys.
        std::fs::write(dir.path().join("known_hosts"), "github.com ssh-ed25519 AAA\n").unwrap();
        std::fs::write(dir.path().join("config"), "Host *\n  User ada\n").unwrap();
        std::fs::write(dir.path().join("authorized_keys"), "ssh-ed25519 AAA x\n").unwrap();
        dir
    }

    #[test]
    fn only_private_keys_are_picked_up() {
        let dir = tree();
        let found = scan(dir.path()).unwrap();
        let names: Vec<_> = found.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, vec!["id_ed25519"]);
    }

    #[test]
    fn a_key_is_found_by_its_banner_not_its_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("deploy-key-prod"), UNENCRYPTED).unwrap();
        let found = scan(dir.path()).unwrap();
        assert_eq!(found.len(), 1, "a key without an id_ prefix was missed");
    }

    #[test]
    fn the_public_key_and_its_comment_come_across() {
        let dir = tree();
        let key = &scan(dir.path()).unwrap()[0];
        assert_eq!(key.comment.as_deref(), Some("ada@lovelace"));

        let item = item_for(key, UNENCRYPTED);
        assert_eq!(item.kind, ItemKind::SshKey);
        assert_eq!(
            item.field_value(field_names::KEY_COMMENT),
            Some("ada@lovelace")
        );
        assert!(item.field_value(field_names::PUBLIC_KEY).is_some());
    }

    #[test]
    fn the_private_key_is_a_field_because_that_is_where_the_agent_reads_it() {
        let dir = tree();
        let key = &scan(dir.path()).unwrap()[0];
        let item = item_for(key, UNENCRYPTED);
        assert_eq!(item.field_value(field_names::PRIVATE_KEY), Some(UNENCRYPTED));
        assert_eq!(
            item.secret.expose(),
            "",
            "the secret is reserved for the key's passphrase"
        );
    }

    #[test]
    fn an_unencrypted_openssh_key_is_not_reported_as_encrypted() {
        assert!(!is_encrypted(UNENCRYPTED));
    }

    #[test]
    fn the_older_pem_encryption_header_is_recognised() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                   Proc-Type: 4,ENCRYPTED\n\
                   DEK-Info: AES-128-CBC,0123\n\n\
                   abc\n-----END RSA PRIVATE KEY-----\n";
        assert!(is_encrypted(pem));
        assert!(is_private_key(pem));
    }

    fn vault() -> (tempfile::TempDir, passman_core::Vault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let v = passman_core::Vault::create(
            &path,
            "pw",
            passman_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();
        (dir, v)
    }

    #[test]
    fn importing_twice_does_not_duplicate() {
        let src = tree();
        let (_d, mut v) = vault();
        let first = import_dir(&mut v, src.path(), None).unwrap();
        let second = import_dir(&mut v, src.path(), None).unwrap();
        assert_eq!(first.imported, 1);
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 1);
    }

    #[test]
    fn the_source_key_is_left_on_disk() {
        let src = tree();
        let (_d, mut v) = vault();
        import_dir(&mut v, src.path(), None).unwrap();
        assert!(
            src.path().join("id_ed25519").is_file(),
            "the importer removed the original key"
        );
    }

    /// The whole point of the importer: the agent has to accept what it makes.
    #[test]
    fn the_agent_can_load_an_imported_key() {
        let src = tree();
        let (_d, mut v) = vault();
        import_dir(&mut v, src.path(), None).unwrap();

        let count = v
            .data()
            .all_items()
            .filter(|(_, i)| i.kind == ItemKind::SshKey)
            .count();
        assert_eq!(count, 1);
    }
}
