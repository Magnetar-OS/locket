//! Exporting the vault — the way *out*.
//!
//! A password manager you cannot leave is a trap, so leaving is as supported
//! as arriving, in three shapes:
//!
//! - **JSON** (`locket-export-v1`): everything, losslessly — arbitrary
//!   fields, tags, expiry, attachments as base64. Plaintext.
//! - **CSV**: the lowest common denominator every manager imports. Columns
//!   follow Bitwarden's naming, which the CSV *importers* of other managers
//!   (ours included) all recognise. Loses custom structure; says so.
//! - **KDBX 4**: a real encrypted database KeePass and KeePassXC open
//!   directly. The one export that is not plaintext — it is sealed under a
//!   passphrase the caller supplies.
//!
//! The plaintext formats are the most dangerous files on the disk while they
//! exist. Writing them 0600 and telling the user to delete them is the
//! callers' contract, same as the importers' warnings in the other
//! direction.

use std::io::Write as _;
use std::path::Path;

use locket_core::{Vault, model::field_names};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Csv,
    Kdbx,
}

impl Format {
    pub fn is_plaintext(self) -> bool {
        !matches!(self, Format::Kdbx)
    }
}

/// Create `path` refusing to overwrite, 0600 before any content reaches it.
fn create_0600(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Everything, as JSON. Returns how many items were written.
pub fn to_json(vault: &Vault, path: &Path) -> Result<usize> {
    let mut items = Vec::new();
    for (collection, item) in vault.data().all_items() {
        items.push(serde_json::json!({
            "collection": collection.label,
            "id": item.id,
            "kind": item.kind,
            "label": item.label,
            "secret": item.secret.expose(),
            "attributes": item.attributes,
            "tags": item.tags,
            "favorite": item.favorite,
            "expires": item.expires.map(locket_core::model::format_date),
            "fields": item.fields.iter().map(|f| serde_json::json!({
                "name": f.name,
                "kind": f.kind,
                "value": f.value.expose(),
            })).collect::<Vec<_>>(),
            "attachments": item.attachments.iter().map(|a| serde_json::json!({
                "name": a.name,
                "mime": a.mime,
                "data_base64": locket_core::slots::base64_encode(a.data.expose()),
            })).collect::<Vec<_>>(),
        }));
    }
    let count = items.len();
    let document = serde_json::json!({
        "format": "locket-export-v1",
        "items": items,
    });

    let mut file = create_0600(path)?;
    file.write_all(&serde_json::to_vec_pretty(&document).map_err(|e| Error::Vault(e.to_string()))?)
        .map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.sync_all().map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(count)
}

/// The flat CSV, Bitwarden's column names. Returns `(written, lossy)`:
/// `lossy` counts items that had fields or attachments CSV cannot carry.
pub fn to_csv(vault: &Vault, path: &Path) -> Result<(usize, usize)> {
    let file = create_0600(path)?;
    let mut writer = csv::Writer::from_writer(file);
    writer
        .write_record([
            "folder",
            "favorite",
            "type",
            "name",
            "notes",
            "login_uri",
            "login_username",
            "login_password",
            "login_totp",
        ])
        .map_err(|e| Error::Vault(e.to_string()))?;

    let mut written = 0usize;
    let mut lossy = 0usize;
    for (collection, item) in vault.data().all_items() {
        let notes = item.field_value(field_names::NOTES).unwrap_or_default();
        let carried: &[&str] = &[
            field_names::USERNAME,
            field_names::URL,
            field_names::TOTP,
            field_names::NOTES,
        ];
        if !item.attachments.is_empty()
            || item
                .fields
                .iter()
                .any(|f| !carried.contains(&f.name.as_str()))
        {
            lossy += 1;
        }
        writer
            .write_record([
                collection.label.as_str(),
                if item.favorite { "1" } else { "" },
                "login",
                item.label.as_str(),
                notes,
                item.field_value(field_names::URL).unwrap_or_default(),
                item.field_value(field_names::USERNAME).unwrap_or_default(),
                item.secret.expose(),
                item.field_value(field_names::TOTP).unwrap_or_default(),
            ])
            .map_err(|e| Error::Vault(e.to_string()))?;
        written += 1;
    }
    writer.flush().map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok((written, lossy))
}

/// A KDBX 4 database KeePassXC opens directly, sealed under `passphrase`.
/// One top-level group per collection; tags, TOTP seeds and custom fields
/// carried; field protection mirrors locket's own masking.
pub fn to_kdbx(vault: &Vault, path: &Path, passphrase: &str) -> Result<usize> {
    use keepass::{Database, DatabaseKey};

    if passphrase.is_empty() {
        return Err(Error::Vault(
            "a KDBX export needs a passphrase; it is the whole point of the format".into(),
        ));
    }

    let mut db = Database::new();
    db.root_mut().name = "locket".to_owned();

    let mut written = 0usize;
    for collection in &vault.data().collections {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = collection.label.clone();
        for item in &collection.items {
            let mut entry = group.add_entry();
            entry.set_unprotected("Title", item.label.clone());
            entry.set_protected("Password", item.secret.expose());
            if let Some(username) = item.field_value(field_names::USERNAME) {
                entry.set_unprotected("UserName", username);
            }
            if let Some(url) = item.field_value(field_names::URL) {
                entry.set_unprotected("URL", url);
            }
            if let Some(notes) = item.field_value(field_names::NOTES) {
                entry.set_unprotected("Notes", notes);
            }
            if let Some(totp) = item.field_value(field_names::TOTP) {
                // The field KeePassXC reads its TOTP configuration from.
                entry.set_protected("otp", totp);
            }
            let standard = [
                field_names::USERNAME,
                field_names::URL,
                field_names::NOTES,
                field_names::TOTP,
            ];
            for field in &item.fields {
                if standard.contains(&field.name.as_str()) {
                    continue;
                }
                // Mirror locket's own masking onto kdbx's protection flag.
                if field.kind.is_sensitive() {
                    entry.set_protected(field.name.clone(), field.value.expose());
                } else {
                    entry.set_unprotected(field.name.clone(), field.value.expose());
                }
            }
            entry.tags = item.tags.clone();
            written += 1;
        }
    }

    let mut file = create_0600(path)?;
    db.save(&mut file, DatabaseKey::new().with_password(passphrase))
        .map_err(|e| Error::Database(format!("could not write the kdbx: {e}")))?;
    file.sync_all().map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::{Field, FieldKind, Item, ItemKind, crypto::KdfParams};

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut v =
            Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap();
        let mut item = Item::new(ItemKind::Login, "GitHub")
            .with_secret("hunter2")
            .with_field(Field::text(field_names::USERNAME, "ada"))
            .with_field(Field::new(
                field_names::TOTP,
                FieldKind::Totp,
                "otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP",
            ))
            .with_field(Field::secret("recovery", "codes"));
        item.tags = vec!["work".into()];
        v.add_item_default(item);
        v.add_item_default(Item::new(ItemKind::Note, "Plain note").with_secret("body"));
        v
    }

    #[test]
    fn json_round_trips_and_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.json");
        assert_eq!(to_json(&v, &out).unwrap(), 2);

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(parsed["format"], "locket-export-v1");
        assert_eq!(parsed["items"].as_array().unwrap().len(), 2);

        assert!(to_json(&v, &out).is_err(), "overwrote an existing export");
    }

    #[test]
    fn csv_counts_what_it_could_not_carry() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.csv");
        let (written, lossy) = to_csv(&v, &out).unwrap();
        assert_eq!(written, 2);
        assert_eq!(lossy, 1, "the custom `recovery` field went uncounted");

        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.starts_with("folder,favorite,type,name,notes,login_uri"));
        assert!(text.contains("hunter2"));
    }

    #[test]
    fn kdbx_seals_and_reopens_with_everything_that_fits() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let out = dir.path().join("export.kdbx");
        assert_eq!(to_kdbx(&v, &out, "kdbx-pw").unwrap(), 2);

        // No plaintext on disk: it is a real encrypted database.
        let raw = std::fs::read(&out).unwrap();
        let raw_text = String::from_utf8_lossy(&raw);
        assert!(!raw_text.contains("hunter2"), "the kdbx leaked a secret");
        assert!(!raw_text.contains("GitHub"), "the kdbx leaked a title");

        // And our own importer — the same library KeePassXC's format
        // implements — reads it back whole.
        let vault2_path = dir.path().join("reimported.vault");
        let mut vault2 = Vault::create(&vault2_path, "pw", KdfParams::insecure_fast()).unwrap();
        let summary =
            crate::keepass::import_kdbx(&mut vault2, &out, "kdbx-pw", None, None).unwrap();
        assert_eq!(summary.imported, 2);
        let (_, item) = vault2
            .data()
            .all_items()
            .find(|(_, i)| i.label == "GitHub")
            .expect("the login survived the round trip");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        assert!(
            item.field(field_names::TOTP).is_some(),
            "the TOTP seed was lost"
        );
        assert_eq!(
            item.field("recovery").map(|f| f.kind),
            Some(FieldKind::Secret),
            "field protection did not survive"
        );

        assert!(
            to_kdbx(&v, &dir.path().join("x.kdbx"), "").is_err(),
            "an empty kdbx passphrase was accepted"
        );
    }
}
