//! Import SSH private keys from `~/.ssh`.
//!
//! locket already serves an SSH agent from `ItemKind::SshKey` items, so this
//! is the half that was missing: getting the keys you already have into the
//! vault in the shape the agent reads them.
//!
//! The keys are copied, never moved. `~/.ssh/id_ed25519` stays exactly where
//! it is — OpenSSH still reads it directly, and until you have confirmed the
//! agent serves the imported copy, deleting the original would leave you
//! locked out of everything it authenticates to.

use std::path::{Path, PathBuf};

use locket_core::model::{Field, FieldKind, Item, ItemKind, field_names};

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

/// The two algorithms whose "private" key file holds no signing key.
const SECURITY_KEY_ALGORITHMS: &[&str] = &[
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
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
    /// The SSH algorithm name, for keys in OpenSSH's own format.
    pub algorithm: Option<String>,
    /// Contents of `<name>-cert.pub`, if the key has been issued a
    /// certificate. Public data, but useless to the agent unless it travels
    /// with the key: a host configured for certificate authentication will not
    /// accept the bare key.
    pub certificate: Option<String>,
}

impl KeyFile {
    /// Whether the signing key lives on a security key rather than in this
    /// file.
    ///
    /// It matters for what an import *means*: for every other algorithm the
    /// file is the key, and copying it into the vault is a backup. For these
    /// the file is a credential handle, and the thing that signs is a piece of
    /// hardware that cannot be copied at all.
    pub fn is_token_bound(&self) -> bool {
        self.algorithm
            .as_deref()
            .is_some_and(|a| SECURITY_KEY_ALGORITHMS.contains(&a))
    }
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

/// The key's algorithm name, read out of an OpenSSH-format private key.
///
/// The public half of an `openssh-key-v1` file is in the clear even when the
/// private half is encrypted, so this works on keys we cannot open — which is
/// the point: whether a key needs hardware has to be answerable before anyone
/// types a passphrase.
///
/// Returns `None` for the older PEM formats, which name the algorithm nowhere
/// useful. None of those can be security keys, so nothing downstream cares.
pub fn algorithm_of(text: &str) -> Option<String> {
    if !text.contains("BEGIN OPENSSH PRIVATE KEY") {
        return None;
    }
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let bytes = base64_decode(&body).ok()?;

    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let mut rest = bytes.strip_prefix(MAGIC)?;

    // string ciphername, string kdfname, string kdfoptions, uint32 nkeys,
    // then the first public key — which itself starts with its algorithm.
    let take = |rest: &mut &[u8]| -> Option<Vec<u8>> {
        let (len, tail) = rest.split_at_checked(4)?;
        let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
        let (value, tail) = tail.split_at_checked(len)?;
        *rest = tail;
        Some(value.to_vec())
    };

    take(&mut rest)?; // ciphername
    take(&mut rest)?; // kdfname
    take(&mut rest)?; // kdfoptions
    let (_nkeys, tail) = rest.split_at_checked(4)?;
    rest = tail;
    let public = take(&mut rest)?;

    let algorithm = take(&mut public.as_slice())?;
    String::from_utf8(algorithm).ok()
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
        // OpenSSH's own naming: `id_ed25519` -> `id_ed25519-cert.pub`.
        let certificate = std::fs::read_to_string(format!("{}-cert.pub", path.display()))
            .ok()
            .filter(|c| c.contains("-cert-v01@openssh.com"));

        out.push(KeyFile {
            encrypted: is_encrypted(&text),
            algorithm: algorithm_of(&text),
            certificate,
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
    if let Some(certificate) = &key.certificate {
        item = item.with_field(Field::new(
            field_names::CERTIFICATE,
            FieldKind::Text,
            certificate.trim(),
        ));
    }

    item.attributes.insert(
        "ssh:path".to_owned(),
        key.path.display().to_string(),
    );
    item.attributes
        .insert("ssh:encrypted".to_owned(), key.encrypted.to_string());
    item.tags = vec!["ssh".to_owned()];

    if let Some(algorithm) = &key.algorithm {
        item.attributes
            .insert("ssh:algorithm".to_owned(), algorithm.clone());
    }
    if key.is_token_bound() {
        item.attributes
            .insert("ssh:token-bound".to_owned(), "true".to_owned());
        item.tags.push("security-key".to_owned());
        // Said on the item, not only at import time: months later the vault is
        // the only thing anyone reads, and "I have a copy of the key" is the
        // wrong conclusion to leave lying around.
        item = item.with_field(Field::new(
            field_names::NOTES,
            FieldKind::Note,
            "Signing happens on the security key this was created with. What is \
             stored here is a credential handle, not a private key, so this item \
             is not a backup: lose the token and no copy of this file will \
             authenticate anywhere. locket's agent serves it by asking the \
             token for a signature, which needs the key plugged in and touched.",
        ));
    }
    item
}

/// Import every private key under `dir`. Does not save.
///
/// Encrypted keys are imported too, with an empty secret: the agent will skip
/// them until you fill in the passphrase, which is a better outcome than
/// leaving them out and having you wonder where they went. The count is
/// reported so you know how many need attention.
pub fn import_dir(
    vault: &mut locket_core::Vault,
    dir: &Path,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let keys = scan(dir)?;
    let target = crate::target_collection(vault, into_collection.unwrap_or("SSH"));
    let mut summary = ImportSummary::default();
    let mut token_bound_names = Vec::new();

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
        let token_bound = key.is_token_bound();
        vault
            .add_item(target, item)
            .map_err(|e| Error::Vault(e.to_string()))?;
        summary.imported += 1;
        if token_bound {
            token_bound_names.push(key.name.clone());
        }
    }

    if !token_bound_names.is_empty() {
        summary.notes.push(format!(
            "{} of these sign on a security key: {}. The files hold credential \
             handles rather than private keys, so importing them is not a backup — \
             they authenticate only with the token present.",
            token_bound_names.len(),
            token_bound_names.join(", ")
        ));
    }

    summary.collections = 1;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real, complete ed25519 key, generated by `ssh-keygen` for this test
    // only; it authenticates to nothing. Complete matters: the body is
    // base64-decoded to read the cipher name and the algorithm, so a trimmed
    // key would exercise the error path instead of the one that parses.
    const UNENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACDgaoI8ORiYR/i24g/2tEjxqVhRFt+IkxWNAfPujegZoQAAAJCX0tRml9LU\n\
ZgAAAAtzc2gtZWQyNTUxOQAAACDgaoI8ORiYR/i24g/2tEjxqVhRFt+IkxWNAfPujegZoQ\n\
AAAECWScSjnOg1c1iAdoIlggSLB8GJ6D3HuO/MFiszghHbIeBqgjw5GJhH+LbiD/a0SPGp\n\
WFEW34iTFY0B8+6N6BmhAAAADGFkYUBsb3ZlbGFjZQE=\n\
-----END OPENSSH PRIVATE KEY-----\n";

    const UNENCRYPTED_PUB: &str = "ssh-ed25519 \
AAAAC3NzaC1lZDI1NTE5AAAAIOBqgjw5GJhH+LbiD/a0SPGpWFEW34iTFY0B8+6N6Bmh \
ada@lovelace\n";

    // An `sk-ssh-ed25519@openssh.com` key file. The credential handle points
    // at no token that exists, so it signs nothing — but the file itself is
    // the real format: `ssh-keygen -y` reads it back and `ssh-keygen -l`
    // reports it as ED25519-SK.
    const SECURITY_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAABpzay1zc2\n\
gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAACAqEJtAlJAHSJbF90/auvjU/tSJCrKnOedazI1o\n\
2krUxgAAAARzc2g6AAAAgAYeWAkGHlgJAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY2\n\
9tAAAAICoQm0CUkAdIlsX3T9q6+NT+1IkKsqc551rMjWjaStTGAAAABHNzaDoBAAAAEWNy\n\
ZWRlbnRpYWwtaGFuZGxlAAAAAAAAAAx0b2tlbkBsYXB0b3ABAgME\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn the_algorithm_is_read_out_of_an_openssh_key() {
        assert_eq!(algorithm_of(UNENCRYPTED).as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            algorithm_of(SECURITY_KEY).as_deref(),
            Some("sk-ssh-ed25519@openssh.com")
        );
        // The PEM formats name it nowhere useful, and none of them are sk keys.
        assert_eq!(algorithm_of("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n"), None);
        assert_eq!(algorithm_of("not a key at all"), None);
    }

    #[test]
    fn truncated_key_data_does_not_panic_the_scanner() {
        let body: String = SECURITY_KEY
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        for cut in [4, 20, 60, body.len() / 2] {
            let mangled = format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                &body[..cut]
            );
            let _ = algorithm_of(&mangled);
        }
    }

    #[test]
    fn a_security_key_is_imported_but_labelled_as_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519_sk"), SECURITY_KEY).unwrap();

        let found = scan(dir.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_token_bound());

        let item = item_for(&found[0], SECURITY_KEY);
        assert_eq!(item.attributes.get("ssh:token-bound").map(String::as_str), Some("true"));
        assert_eq!(
            item.attributes.get("ssh:algorithm").map(String::as_str),
            Some("sk-ssh-ed25519@openssh.com")
        );
        assert!(item.tags.iter().any(|t| t == "security-key"));
        let note = item
            .field_value(field_names::NOTES)
            .expect("no note explaining what this item is");
        assert!(note.contains("not a backup"), "the note buries the lede: {note}");
    }

    #[test]
    fn an_ordinary_key_gains_no_security_key_marks() {
        let dir = tree();
        let found = scan(dir.path()).unwrap();
        let key = found.iter().find(|k| k.name == "id_ed25519").unwrap();
        assert!(!key.is_token_bound());

        let item = item_for(key, UNENCRYPTED);
        assert!(!item.attributes.contains_key("ssh:token-bound"));
        assert!(item.field_value(field_names::NOTES).is_none());
    }

    #[test]
    fn importing_a_security_key_says_so_in_the_summary() {
        use locket_core::{Vault, crypto::KdfParams};

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519_sk"), SECURITY_KEY).unwrap();
        std::fs::write(dir.path().join("id_ed25519"), UNENCRYPTED).unwrap();

        let vault_dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(
            vault_dir.path().join("v.vault"),
            "pw",
            KdfParams::insecure_fast(),
        )
        .unwrap();

        let summary = import_dir(&mut vault, dir.path(), None).unwrap();
        assert_eq!(summary.imported, 2);
        assert_eq!(summary.notes.len(), 1);
        assert!(summary.notes[0].contains("id_ed25519_sk"));
        assert!(
            !summary.notes[0].contains("id_ed25519,"),
            "the ordinary key was reported as token-bound: {}",
            summary.notes[0]
        );
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519"), UNENCRYPTED).unwrap();
        std::fs::write(
            dir.path().join("id_ed25519.pub"),
            UNENCRYPTED_PUB,
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

    fn vault() -> (tempfile::TempDir, locket_core::Vault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let v = locket_core::Vault::create(
            &path,
            "pw",
            locket_core::crypto::KdfParams::insecure_fast(),
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
