//! Importing a Proton Pass export.
//!
//! Proton Pass exports a zip whose `Proton Pass/data.json` entry holds every
//! vault and item. An export made with PGP encryption enabled is a `.pgp`
//! blob instead; that is refused with directions, the same contract as the
//! other importers — export again without encryption, import, delete.
//!
//! Trashed items (`state: 2`) are skipped. Aliases — Proton's generated
//! email addresses — carry no secret at all; they import as identities so
//! the address is not lost, with a note saying the alias itself still lives
//! at Proton.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use locket_core::{Field, FieldKind, Item, ItemKind, Vault, model::field_names};
use serde::Deserialize;

use crate::{Error, ImportSummary, Result};

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    vaults: BTreeMap<String, VaultEntry>,
}

#[derive(Deserialize)]
struct VaultEntry {
    name: Option<String>,
    #[serde(default)]
    items: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "itemId")]
    item_id: Option<String>,
    /// 1 active, 2 trashed.
    state: Option<u8>,
    data: Option<EntryData>,
    #[serde(default)]
    pinned: bool,
}

#[derive(Deserialize)]
struct EntryData {
    metadata: Option<Metadata>,
    /// `login`, `note`, `creditCard`, `identity`, `alias`, `sshKey`, …
    #[serde(rename = "type")]
    kind: Option<String>,
    content: Option<Content>,
    #[serde(default, rename = "extraFields")]
    extra_fields: Vec<ExtraField>,
}

#[derive(Deserialize)]
struct Metadata {
    name: Option<String>,
    note: Option<String>,
}

#[derive(Deserialize, Default)]
struct Content {
    #[serde(rename = "itemEmail")]
    email: Option<String>,
    #[serde(rename = "itemUsername")]
    username: Option<String>,
    password: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(rename = "totpUri")]
    totp: Option<String>,
    // Credit cards.
    #[serde(rename = "cardholderName")]
    cardholder: Option<String>,
    number: Option<String>,
    #[serde(rename = "expirationDate")]
    expiration: Option<String>,
    #[serde(rename = "verificationNumber")]
    verification: Option<String>,
    pin: Option<String>,
    // SSH keys.
    #[serde(rename = "privateKey")]
    private_key: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
    // Everything a shape above did not claim (identities are a large flat
    // struct of strings) survives as fields rather than vanishing.
    #[serde(flatten)]
    rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ExtraField {
    #[serde(rename = "fieldName")]
    name: Option<String>,
    /// `text`, `hidden`, `totp`, `timestamp`.
    #[serde(rename = "type")]
    kind: Option<String>,
    data: Option<ExtraData>,
}

#[derive(Deserialize)]
struct ExtraData {
    content: Option<String>,
}

/// Parse `data.json`, without touching a vault or a zip.
pub fn parse(text: &str) -> Result<Vec<Item>> {
    let export: Export = serde_json::from_str(text)
        .map_err(|e| Error::Database(format!("not a Proton Pass export: {e}")))?;
    if export.encrypted {
        return Err(Error::Decrypt(
            "this export is PGP-encrypted; export again without encryption".into(),
        ));
    }

    let mut items = Vec::new();
    for vault in export.vaults.values() {
        for entry in &vault.items {
            if entry.state == Some(2) {
                continue;
            }
            items.push(convert(entry, vault.name.as_deref()));
        }
    }
    Ok(items)
}

fn convert(e: &Entry, vault_name: Option<&str>) -> Item {
    let data = e.data.as_ref();
    let kind_name = data.and_then(|d| d.kind.as_deref()).unwrap_or("login");
    let kind = match kind_name {
        "note" => ItemKind::Note,
        "creditCard" => ItemKind::Card,
        "identity" | "alias" => ItemKind::Identity,
        "sshKey" => ItemKind::SshKey,
        _ => ItemKind::Login,
    };
    let label = data
        .and_then(|d| d.metadata.as_ref())
        .and_then(|m| m.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Unnamed".to_owned());
    let mut item = Item::new(kind, label);

    item.attributes
        .insert("locket:source".into(), "protonpass".into());
    if let Some(id) = &e.item_id {
        item.attributes.insert("protonpass:id".into(), id.clone());
    }
    item.favorite = e.pinned;
    if let Some(vault) = vault_name.filter(|v| !v.is_empty()) {
        item.tags.push(vault.to_owned());
    }

    let Some(data) = data else { return item };

    let empty = Content::default();
    let content = data.content.as_ref().unwrap_or(&empty);

    if let Some(username) = content
        .username
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| content.email.as_deref().filter(|s| !s.is_empty()))
    {
        item.fields
            .push(Field::text(field_names::USERNAME, username));
        item.attributes.insert("username".into(), username.into());
    }
    if let Some(email) = content.email.as_deref().filter(|s| !s.is_empty())
        && content.username.as_deref().is_some_and(|u| !u.is_empty())
    {
        item.fields
            .push(Field::new("email", FieldKind::Email, email));
    }
    if let Some(password) = content.password.as_deref().filter(|s| !s.is_empty()) {
        item.secret = password.into();
    }
    if let Some(url) = content.urls.iter().find(|u| !u.is_empty()) {
        item.fields
            .push(Field::new(field_names::URL, FieldKind::Url, url.clone()));
    }
    if let Some(totp) = content.totp.as_deref().filter(|s| !s.is_empty()) {
        item.fields
            .push(Field::new(field_names::TOTP, FieldKind::Totp, totp));
    }

    // Cards: the number is the secret, the codes are masked.
    if let Some(number) = content.number.as_deref().filter(|s| !s.is_empty()) {
        item.secret = number.into();
    }
    for (name, value, sensitive) in [
        ("cardholder", content.cardholder.as_deref(), false),
        ("expiry", content.expiration.as_deref(), false),
        ("code", content.verification.as_deref(), true),
        ("pin", content.pin.as_deref(), true),
    ] {
        if let Some(v) = value.filter(|s| !s.is_empty()) {
            item.fields.push(if sensitive {
                Field::secret(name, v)
            } else {
                Field::text(name, v)
            });
        }
    }

    // SSH keys, in the shape locket's own agent reads.
    if let Some(private_key) = content.private_key.as_deref().filter(|s| !s.is_empty()) {
        item.fields.push(Field::new(
            field_names::PRIVATE_KEY,
            FieldKind::PrivateKey,
            private_key,
        ));
    }
    if let Some(public_key) = content.public_key.as_deref().filter(|s| !s.is_empty()) {
        item.fields.push(Field::new(
            field_names::PUBLIC_KEY,
            FieldKind::PublicKey,
            public_key,
        ));
    }

    // Identity exports are a flat struct of strings; keep every non-empty
    // one under its own name.
    for (name, value) in &content.rest {
        if let Some(v) = value.as_str().filter(|s| !s.is_empty()) {
            item.fields.push(Field::text(name.clone(), v));
        }
    }

    for f in &data.extra_fields {
        let Some(value) = f
            .data
            .as_ref()
            .and_then(|d| d.content.as_deref())
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let name = f.name.as_deref().unwrap_or("field");
        let kind = match f.kind.as_deref() {
            Some("hidden") => FieldKind::Secret,
            Some("totp") => FieldKind::Totp,
            _ => FieldKind::Text,
        };
        item.fields.push(Field::new(name, kind, value));
    }

    if let Some(note) = data
        .metadata
        .as_ref()
        .and_then(|m| m.note.as_deref())
        .filter(|n| !n.is_empty())
    {
        if item.kind == ItemKind::Note && item.secret.is_empty() {
            item.secret = note.into();
        } else {
            item.fields
                .push(Field::new(field_names::NOTES, FieldKind::Note, note));
        }
    }

    if kind_name == "alias" {
        item.fields.push(Field::text(
            "alias-note",
            "This is a Proton alias; the address itself still lives at Proton.",
        ));
    }

    item
}

/// Import a Proton Pass zip into the vault.
pub fn import_file(vault: &mut Vault, path: &Path, into: Option<&str>) -> Result<ImportSummary> {
    let file = std::fs::File::open(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| {
        Error::Database(format!(
            "not a zip archive (a Proton Pass export is one; a .pgp one is \
             encrypted — export again without encryption): {e}"
        ))
    })?;

    // The data file sits under a localised folder name; match the suffix.
    let entry_name = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_owned()))
        .find(|n| n.ends_with("data.json"))
        .ok_or_else(|| Error::Database("no data.json inside; not a Proton Pass export".into()))?;
    let mut text = String::new();
    archive
        .by_name(&entry_name)
        .map_err(|e| Error::Database(e.to_string()))?
        .read_to_string(&mut text)
        .map_err(|e| Error::Database(format!("could not read {entry_name}: {e}")))?;

    let items = parse(&text)?;

    let mut summary = ImportSummary::default();
    let collection = crate::target_collection(vault, into.unwrap_or("Proton Pass"));
    summary.collections = 1;
    for item in items {
        if crate::already_present(vault, &item.attributes) {
            summary.skipped_duplicate += 1;
            continue;
        }
        vault
            .add_item(collection, item)
            .map_err(|e| Error::Vault(e.to_string()))?;
        summary.imported += 1;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = r#"{
        "version": "1.21.2",
        "encrypted": false,
        "vaults": {
            "v1": {
                "name": "Personal",
                "items": [
                    {
                        "itemId": "i1", "state": 1, "pinned": true,
                        "data": {
                            "metadata": {"name": "GitHub", "note": "work"},
                            "type": "login",
                            "content": {
                                "itemEmail": "ada@example.com",
                                "itemUsername": "ada",
                                "password": "hunter2",
                                "urls": ["https://github.com"],
                                "totpUri": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
                            },
                            "extraFields": [
                                {"fieldName": "recovery", "type": "hidden",
                                 "data": {"content": "codes"}}
                            ]
                        }
                    },
                    {
                        "itemId": "i2", "state": 2,
                        "data": {"metadata": {"name": "Deleted"}, "type": "login"}
                    },
                    {
                        "itemId": "i3", "state": 1,
                        "data": {
                            "metadata": {"name": "Spam shield"},
                            "type": "alias",
                            "content": {"itemEmail": "shield.abc@passmail.net"}
                        }
                    },
                    {
                        "itemId": "i4", "state": 1,
                        "data": {
                            "metadata": {"name": "Visa"},
                            "type": "creditCard",
                            "content": {
                                "cardholderName": "Ada L",
                                "number": "4111111111111111",
                                "expirationDate": "2027-04",
                                "verificationNumber": "123"
                            }
                        }
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn a_login_arrives_whole_and_trash_stays_dead() {
        let items = parse(EXPORT).unwrap();
        assert_eq!(items.len(), 3, "the trashed item was resurrected");

        let login = items.iter().find(|i| i.label == "GitHub").unwrap();
        assert_eq!(login.secret.expose(), "hunter2");
        assert_eq!(login.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(login.field_value("email"), Some("ada@example.com"));
        assert_eq!(
            login.field(field_names::TOTP).unwrap().kind,
            FieldKind::Totp
        );
        assert_eq!(login.field("recovery").unwrap().kind, FieldKind::Secret);
        assert!(login.favorite);
        assert!(login.tags.contains(&"Personal".to_owned()));
    }

    #[test]
    fn aliases_keep_their_address_and_cards_mask_their_codes() {
        let items = parse(EXPORT).unwrap();
        let alias = items.iter().find(|i| i.label == "Spam shield").unwrap();
        assert_eq!(alias.kind, ItemKind::Identity);
        assert_eq!(
            alias.field_value(field_names::USERNAME),
            Some("shield.abc@passmail.net")
        );

        let card = items.iter().find(|i| i.label == "Visa").unwrap();
        assert_eq!(card.kind, ItemKind::Card);
        assert_eq!(card.secret.expose(), "4111111111111111");
        assert_eq!(card.field("code").unwrap().kind, FieldKind::Secret);
    }

    #[test]
    fn an_encrypted_export_is_refused_with_directions() {
        let err = parse(r#"{"encrypted": true, "vaults": {}}"#).unwrap_err();
        assert!(err.to_string().contains("without encryption"), "{err}");
    }

    #[test]
    fn a_real_zip_with_a_localised_folder_imports_and_reimport_skips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protonpass.zip");
        {
            let file = std::fs::File::create(&path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            use std::io::Write as _;
            writer
                .start_file(
                    "Proton Pass/data.json",
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            writer.write_all(EXPORT.as_bytes()).unwrap();
            writer.finish().unwrap();
        }

        let vault_path = dir.path().join("v.vault");
        let mut vault = locket_core::Vault::create(
            &vault_path,
            "pw",
            locket_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();

        let first = import_file(&mut vault, &path, None).unwrap();
        assert_eq!(first.imported, 3);
        let second = import_file(&mut vault, &path, None).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 3);
    }
}
