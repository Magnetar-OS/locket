//! Importing a `pass` (password-store) tree.
//!
//! `pass` stores one GPG-encrypted file per secret, laid out as a directory
//! tree: `~/.password-store/web/github.com.gpg`. The convention inside each
//! file — first line is the password, later lines are `key: value` pairs, an
//! `otpauth://` URI is the TOTP seed — is `pass`'s own, not a format, so the
//! parser here is tolerant: anything it does not recognise ends up in notes
//! rather than being dropped.
//!
//! Decryption shells out to `gpg` rather than linking an OpenPGP library. The
//! secrets are encrypted to *the user's own key*, which lives in their
//! `gpg-agent` with its own pinentry and possibly on a smartcard — reproducing
//! that relationship in-process would mean reimplementing agent negotiation to
//! no benefit.

use std::path::{Path, PathBuf};
use std::process::Command;

use locket_core::{
    Field, FieldKind, Item, ItemKind, Vault,
    model::field_names,
};

use crate::{Error, ImportSummary, Result};

/// Parse one decrypted `pass` entry.
///
/// `name` is the store-relative path without `.gpg`, e.g. `web/github.com`.
pub fn parse_entry(name: &str, plaintext: &str) -> Item {
    // The label is the leaf; the parent directories become tags so the tree
    // structure survives in a form the UI can filter on.
    let (parents, leaf) = match name.rsplit_once('/') {
        Some((p, l)) => (Some(p), l),
        None => (None, name),
    };

    let mut lines = plaintext.lines();
    let password = lines.next().unwrap_or_default().to_owned();

    let mut item = Item::new(ItemKind::Login, leaf).with_secret(password);
    if let Some(parents) = parents {
        item.tags = parents.split('/').map(str::to_owned).collect();
    }

    let mut notes: Vec<&str> = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("otpauth://") {
            item.set_field(Field::new(field_names::TOTP, FieldKind::Totp, trimmed));
            continue;
        }

        // `key: value`, but only when the key looks like a key — a colon in
        // prose ("note: see below") should not silently become a field, and a
        // URL's "https://" must not be split on its colon.
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            // A URL splits on its scheme colon and would otherwise become a
            // field named "https" holding "//example.org". Two signals rule
            // that out: a scheme-relative value, or a key that *is* a scheme.
            const URL_SCHEMES: &[&str] = &[
                "http", "https", "ftp", "ftps", "file", "mailto", "ssh", "sftp", "otpauth",
            ];
            let looks_like_a_url = value.starts_with("//")
                || URL_SCHEMES.contains(&key.to_lowercase().as_str());

            let key_is_fieldlike = !key.is_empty()
                && key.len() <= 32
                && !key.contains(char::is_whitespace)
                && !looks_like_a_url
                && key.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_');

            if key_is_fieldlike && !value.is_empty() {
                let lower = key.to_lowercase();
                let (name, kind) = match lower.as_str() {
                    "user" | "username" | "login" => {
                        (field_names::USERNAME.to_owned(), FieldKind::Text)
                    }
                    "url" | "site" => (field_names::URL.to_owned(), FieldKind::Url),
                    "email" => ("email".to_owned(), FieldKind::Email),
                    // Anything that smells secret stays masked.
                    k if k.contains("pass") || k.contains("secret") || k.contains("token") => {
                        (key.to_owned(), FieldKind::Secret)
                    }
                    _ => (key.to_owned(), FieldKind::Text),
                };
                item.set_field(Field::new(name, kind, value));
                continue;
            }
        }

        notes.push(line);
    }

    if !notes.is_empty() {
        item.set_field(Field::new(
            field_names::NOTES,
            FieldKind::Note,
            notes.join("\n"),
        ));
    }

    // Give other applications something to search on, matching what a
    // libsecret client would expect.
    if let Some(user) = item.field_value(field_names::USERNAME) {
        let user = user.to_owned();
        item.attributes.insert("username".into(), user);
    }
    item.attributes.insert("locket:source".into(), "pass".into());
    item.attributes.insert("pass:path".into(), name.to_owned());
    item
}

/// The default store location, honouring `PASSWORD_STORE_DIR`.
pub fn default_store_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("PASSWORD_STORE_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::home_dir().map(|h| h.join(".password-store"))
}

/// Every `*.gpg` under `dir`, as store-relative names, sorted for stable output.
fn entry_names(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // `.git`, `.gpg-id` and friends are store bookkeeping, not secrets.
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                walk(base, &path, out)?;
            } else if path.extension().is_some_and(|e| e == "gpg")
                && let Ok(rel) = path.strip_prefix(base)
            {
                let rel = rel.with_extension("");
                out.push((rel.to_string_lossy().into_owned(), path));
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    walk(dir, dir, &mut out).map_err(|e| Error::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn decrypt(gpg: &str, path: &Path) -> Result<String> {
    let output = Command::new(gpg)
        .args(["--quiet", "--batch", "--decrypt"])
        .arg(path)
        .output()
        .map_err(|e| Error::Tool(format!("could not run `{gpg}`: {e}")))?;

    if !output.status.success() {
        return Err(Error::Decrypt(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Import a whole password-store into `vault`. Does not save.
///
/// Entries that fail to decrypt are counted and skipped: a store often holds
/// secrets encrypted to a key you no longer have, and one of those should not
/// abort the other two hundred.
pub fn import_store(
    vault: &mut Vault,
    store_dir: &Path,
    gpg_bin: &str,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    if !store_dir.is_dir() {
        return Err(Error::NotFound(store_dir.to_path_buf()));
    }

    let target = crate::target_collection(vault, into_collection.unwrap_or("pass"));
    let mut summary = ImportSummary::default();

    for (name, path) in entry_names(store_dir)? {
        let plaintext = match decrypt(gpg_bin, &path) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("skipping `{name}`: {e}");
                summary.skipped_unreadable += 1;
                continue;
            }
        };

        let item = parse_entry(&name, &plaintext);
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

    #[test]
    fn the_first_line_is_the_password() {
        let item = parse_entry("github.com", "hunter2\nuser: ada\n");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.label, "github.com");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
    }

    #[test]
    fn directories_become_tags_and_the_leaf_becomes_the_label() {
        let item = parse_entry("web/social/github.com", "pw\n");
        assert_eq!(item.label, "github.com");
        assert_eq!(item.tags, vec!["web", "social"]);
        assert_eq!(item.attributes.get("pass:path").unwrap(), "web/social/github.com");
    }

    #[test]
    fn an_otpauth_line_becomes_a_totp_field() {
        let item = parse_entry(
            "x",
            "pw\notpauth://totp/ACME:ada?secret=JBSWY3DPEHPK3PXP&issuer=ACME\n",
        );
        let totp = item.field(field_names::TOTP).expect("totp field");
        assert_eq!(totp.kind, FieldKind::Totp);
        // And it must actually parse as a TOTP seed.
        assert!(locket_core::Totp::parse(totp.value.expose()).is_ok());
    }

    #[test]
    fn a_url_is_not_split_on_its_scheme_colon() {
        // "url: https://x" must keep the whole value, and a bare URL line must
        // not be mangled into a field called "https".
        let item = parse_entry("x", "pw\nurl: https://example.org/login\n");
        assert_eq!(
            item.field_value(field_names::URL),
            Some("https://example.org/login")
        );

        // A bare URL line must not become a field called "https".
        let bare = parse_entry("x", "pw\nhttps://example.org/login\n");
        assert!(bare.field("https").is_none(), "URL scheme became a field name");
        assert_eq!(
            bare.field_value(field_names::NOTES),
            Some("https://example.org/login")
        );

        // Same for schemes with no double slash.
        let mail = parse_entry("x", "pw\nmailto:ada@example.org\n");
        assert!(mail.field("mailto").is_none());
        assert!(mail.field_value(field_names::NOTES).unwrap().contains("ada@"));
    }

    #[test]
    fn prose_with_a_colon_stays_prose() {
        let item = parse_entry("x", "pw\nnote to self: rotate this in June\n");
        assert!(
            item.field_value(field_names::NOTES).unwrap().contains("rotate this"),
            "a sentence was mistaken for a field"
        );
    }

    #[test]
    fn secret_looking_keys_are_masked() {
        let item = parse_entry("x", "pw\nrecovery-token: abc123\ncomment: hello\n");
        assert_eq!(item.field("recovery-token").unwrap().kind, FieldKind::Secret);
        assert_eq!(item.field("comment").unwrap().kind, FieldKind::Text);
    }

    #[test]
    fn a_password_only_entry_works() {
        let item = parse_entry("x", "just-a-password");
        assert_eq!(item.secret.expose(), "just-a-password");
        assert!(item.fields.is_empty());
    }

    #[test]
    fn an_empty_file_does_not_panic() {
        let item = parse_entry("x", "");
        assert_eq!(item.secret.expose(), "");
        assert_eq!(item.label, "x");
    }

    #[test]
    fn walking_a_store_finds_entries_and_ignores_bookkeeping() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("web")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("web/github.com.gpg"), b"x").unwrap();
        std::fs::write(root.join("bank.gpg"), b"x").unwrap();
        std::fs::write(root.join(".gpg-id"), b"KEYID").unwrap();
        std::fs::write(root.join("README.md"), b"not a secret").unwrap();
        std::fs::write(root.join(".git/config"), b"[core]").unwrap();

        let names: Vec<String> = entry_names(root).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["bank", "web/github.com"]);
    }
}
