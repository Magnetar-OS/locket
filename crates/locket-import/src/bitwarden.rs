//! Importing a Bitwarden JSON export.
//!
//! Bitwarden's Tools → Export offers CSV and JSON; the JSON is the one that
//! carries everything — custom fields, TOTP seeds, cards, identities and the
//! folder tree — so it is the format worth first-class treatment (the CSV
//! already imports through the generic CSV path, minus what CSV cannot say).
//!
//! A *password-protected* export is an encrypted envelope. It is refused
//! outright rather than half-read: export again without a password, import,
//! then delete the file — the same contract every other importer here has.

use std::collections::BTreeMap;
use std::path::Path;

use locket_core::{Field, FieldKind, Item, ItemKind, Vault, model::field_names};
use serde::Deserialize;

use crate::{Error, ImportSummary, Result};

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<Folder>,
    /// Organisation exports say `collections` where personal ones say
    /// `folders`; both are just named groups here.
    #[serde(default)]
    collections: Vec<Folder>,
    #[serde(default)]
    items: Vec<Entry>,
}

#[derive(Deserialize)]
struct Folder {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    id: Option<String>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(default, rename = "collectionIds")]
    collection_ids: Vec<String>,
    /// 1 login, 2 secure note, 3 card, 4 identity.
    #[serde(rename = "type")]
    kind: Option<u8>,
    name: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    #[serde(default)]
    fields: Vec<CustomField>,
}

#[derive(Deserialize)]
struct Login {
    #[serde(default)]
    uris: Vec<Uri>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(Deserialize)]
struct Uri {
    uri: Option<String>,
}

#[derive(Deserialize)]
struct Card {
    #[serde(rename = "cardholderName")]
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    #[serde(rename = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "expYear")]
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize)]
struct Identity {
    #[serde(flatten)]
    fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct CustomField {
    name: Option<String>,
    value: Option<String>,
    /// 0 text, 1 hidden, 2 boolean, 3 linked (a reference, no value).
    #[serde(rename = "type", default)]
    kind: u8,
}

/// Parse the export and convert every entry, without touching a vault.
/// Public so it can be tested — and fuzzed — on bytes alone.
pub fn parse(text: &str) -> Result<Vec<Item>> {
    let export: Export =
        serde_json::from_str(text).map_err(|e| Error::Database(format!("not a Bitwarden JSON export: {e}")))?;
    if export.encrypted {
        return Err(Error::Decrypt(
            "this is a password-protected export; export again without a file password"
                .into(),
        ));
    }

    let mut folder_names: BTreeMap<String, String> = BTreeMap::new();
    for f in export.folders.iter().chain(&export.collections) {
        if let (Some(id), Some(name)) = (&f.id, &f.name) {
            folder_names.insert(id.clone(), name.clone());
        }
    }

    Ok(export
        .items
        .iter()
        .map(|e| convert(e, &folder_names))
        .collect())
}

fn convert(e: &Entry, folders: &BTreeMap<String, String>) -> Item {
    let kind = match e.kind {
        Some(2) => ItemKind::Note,
        Some(3) => ItemKind::Card,
        Some(4) => ItemKind::Identity,
        _ => ItemKind::Login,
    };
    let label = e.name.clone().unwrap_or_else(|| "Unnamed".to_owned());
    let mut item = Item::new(kind, label);

    // The idempotency anchor: same entry from the same export, recognised
    // across re-runs without the two formats agreeing on anything else.
    item.attributes
        .insert("locket:source".into(), "bitwarden".into());
    if let Some(id) = &e.id {
        item.attributes.insert("bitwarden:id".into(), id.clone());
    }

    item.favorite = e.favorite;

    // Folder (or organisation collection) names become tags, the same
    // mapping the KeePass importer uses for groups.
    for folder in e
        .folder_id
        .iter()
        .chain(&e.collection_ids)
        .filter_map(|id| folders.get(id))
    {
        if !item.tags.contains(folder) {
            item.tags.push(folder.clone());
        }
    }

    if let Some(login) = &e.login {
        if let Some(username) = login.username.as_deref().filter(|s| !s.is_empty()) {
            item.fields
                .push(Field::text(field_names::USERNAME, username));
            item.attributes.insert("username".into(), username.into());
        }
        if let Some(password) = login.password.as_deref().filter(|s| !s.is_empty()) {
            item.secret = password.into();
        }
        if let Some(uri) = login
            .uris
            .iter()
            .filter_map(|u| u.uri.as_deref())
            .find(|u| !u.is_empty())
        {
            item.fields
                .push(Field::new(field_names::URL, FieldKind::Url, uri));
        }
        if let Some(totp) = login.totp.as_deref().filter(|s| !s.is_empty()) {
            item.fields
                .push(Field::new(field_names::TOTP, FieldKind::Totp, totp));
        }
    }

    if let Some(card) = &e.card {
        // The number is the secret; the rest are ordinary fields, with the
        // code masked.
        if let Some(number) = card.number.as_deref().filter(|s| !s.is_empty()) {
            item.secret = number.into();
        }
        for (name, value) in [
            ("cardholder", card.cardholder_name.as_deref()),
            ("brand", card.brand.as_deref()),
        ] {
            if let Some(v) = value.filter(|s| !s.is_empty()) {
                item.fields.push(Field::text(name, v));
            }
        }
        if let (Some(m), Some(y)) = (card.exp_month.as_deref(), card.exp_year.as_deref()) {
            item.fields.push(Field::text("expiry", format!("{m}/{y}")));
        }
        if let Some(code) = card.code.as_deref().filter(|s| !s.is_empty()) {
            item.fields.push(Field::secret("code", code));
        }
    }

    if let Some(identity) = &e.identity {
        for (name, value) in &identity.fields {
            if let Some(v) = value.as_str().filter(|s| !s.is_empty()) {
                item.fields.push(Field::text(name.clone(), v));
            }
        }
    }

    for f in &e.fields {
        let (Some(name), Some(value)) = (f.name.as_deref(), f.value.as_deref()) else {
            continue; // a "linked" field carries a reference, not a value
        };
        let kind = if f.kind == 1 {
            FieldKind::Secret
        } else {
            FieldKind::Text
        };
        item.fields.push(Field::new(name, kind, value));
    }

    if let Some(notes) = e.notes.as_deref().filter(|s| !s.is_empty()) {
        if kind == ItemKind::Note && item.secret.is_empty() {
            item.secret = notes.into();
        } else {
            item.fields
                .push(Field::new(field_names::NOTES, FieldKind::Note, notes));
        }
    }

    item
}

/// Import a Bitwarden JSON export file into the vault.
pub fn import_file(vault: &mut Vault, path: &Path, into: Option<&str>) -> Result<ImportSummary> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let items = parse(&text)?;

    let mut summary = ImportSummary::default();
    let collection = crate::target_collection(vault, into.unwrap_or("Bitwarden"));
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

    /// A trimmed real-shaped export: one of each type, a folder, a custom
    /// hidden field, a linked field (no value), and a TOTP seed.
    const EXPORT: &str = r#"{
        "encrypted": false,
        "folders": [{"id": "f1", "name": "Work"}],
        "items": [
            {
                "id": "a1", "folderId": "f1", "type": 1, "name": "GitHub",
                "favorite": true,
                "login": {
                    "uris": [{"uri": "https://github.com"}],
                    "username": "ada", "password": "hunter2",
                    "totp": "otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
                },
                "fields": [
                    {"name": "recovery", "value": "codes-here", "type": 1},
                    {"name": "linked-username", "value": null, "type": 3}
                ]
            },
            {"id": "a2", "type": 2, "name": "Note", "notes": "the body"},
            {
                "id": "a3", "type": 3, "name": "Visa",
                "card": {"cardholderName": "Ada L", "brand": "Visa",
                         "number": "4111111111111111", "expMonth": "4",
                         "expYear": "2027", "code": "123"}
            },
            {
                "id": "a4", "type": 4, "name": "Me",
                "identity": {"firstName": "Ada", "lastName": "Lovelace"}
            }
        ]
    }"#;

    #[test]
    fn a_login_arrives_whole() {
        let items = parse(EXPORT).unwrap();
        let login = items.iter().find(|i| i.label == "GitHub").unwrap();
        assert_eq!(login.kind, ItemKind::Login);
        assert_eq!(login.secret.expose(), "hunter2");
        assert_eq!(login.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(login.field_value(field_names::URL), Some("https://github.com"));
        assert!(login.favorite);
        assert_eq!(login.tags, vec!["Work"]);
        let totp = login.field(field_names::TOTP).unwrap();
        assert_eq!(totp.kind, FieldKind::Totp);
        // The custom hidden field is masked; the linked one is dropped.
        assert_eq!(login.field("recovery").unwrap().kind, FieldKind::Secret);
        assert!(login.field("linked-username").is_none());
    }

    #[test]
    fn notes_cards_and_identities_map_to_their_kinds() {
        let items = parse(EXPORT).unwrap();
        let note = items.iter().find(|i| i.label == "Note").unwrap();
        assert_eq!(note.kind, ItemKind::Note);
        assert_eq!(note.secret.expose(), "the body");

        let card = items.iter().find(|i| i.label == "Visa").unwrap();
        assert_eq!(card.kind, ItemKind::Card);
        assert_eq!(card.secret.expose(), "4111111111111111");
        assert_eq!(card.field("code").unwrap().kind, FieldKind::Secret);
        assert_eq!(card.field_value("expiry"), Some("4/2027"));

        let me = items.iter().find(|i| i.label == "Me").unwrap();
        assert_eq!(me.kind, ItemKind::Identity);
        assert_eq!(me.field_value("firstName"), Some("Ada"));
    }

    #[test]
    fn an_encrypted_export_is_refused_with_directions() {
        let err = parse(r#"{"encrypted": true, "items": []}"#).unwrap_err();
        assert!(err.to_string().contains("without a file password"), "{err}");
    }

    #[test]
    fn not_bitwarden_at_all_is_a_clear_error() {
        assert!(parse("john,doe,hunter2").is_err());
        assert!(parse(r#"{"logins": []}"#).map(|v| v.len()).unwrap_or(1) == 0);
    }

    #[test]
    fn importing_twice_does_not_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join("bitwarden.json");
        std::fs::write(&export, EXPORT).unwrap();
        let vault_path = dir.path().join("v.vault");
        let mut vault = locket_core::Vault::create(
            &vault_path,
            "pw",
            locket_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();

        let first = import_file(&mut vault, &export, None).unwrap();
        assert_eq!(first.imported, 4);
        let second = import_file(&mut vault, &export, None).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 4);
    }
}
