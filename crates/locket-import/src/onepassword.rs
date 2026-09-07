//! Importing a 1Password `.1pux` export.
//!
//! The 1PUX format is a zip archive whose `export.data` entry is one JSON
//! document: accounts → vaults → items, each item split into an `overview`
//! (title, URLs, tags — what 1Password shows in lists) and `details` (the
//! login fields, free-form sections, and the note). Attached documents live
//! as separate files in the archive; they are counted and reported rather
//! than silently dropped.
//!
//! Items in 1Password's trash arrive marked `"trashed"` and are skipped —
//! importing what the user already deleted would resurrect it here.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use locket_core::{Field, FieldKind, Item, ItemKind, Vault, model::field_names};
use serde::Deserialize;

use crate::{Error, ImportSummary, Result};

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<VaultEntry>,
}

#[derive(Deserialize)]
struct VaultEntry {
    attrs: Option<VaultAttrs>,
    #[serde(default)]
    items: Vec<Entry>,
}

#[derive(Deserialize)]
struct VaultAttrs {
    name: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    uuid: Option<String>,
    /// `"active"`, `"archived"`, or `"trashed"`.
    state: Option<String>,
    #[serde(rename = "categoryUuid")]
    category: Option<String>,
    #[serde(default, rename = "favIndex")]
    fav_index: i64,
    overview: Option<Overview>,
    details: Option<Details>,
}

#[derive(Deserialize)]
struct Overview {
    title: Option<String>,
    url: Option<String>,
    #[serde(default)]
    urls: Vec<OverviewUrl>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct OverviewUrl {
    url: Option<String>,
}

#[derive(Deserialize)]
struct Details {
    #[serde(default, rename = "loginFields")]
    login_fields: Vec<LoginField>,
    #[serde(rename = "notesPlain")]
    notes: Option<String>,
    #[serde(default)]
    sections: Vec<Section>,
    /// The Password category keeps its one secret here.
    password: Option<String>,
}

#[derive(Deserialize)]
struct LoginField {
    value: Option<String>,
    /// `"username"` or `"password"`; everything else is web-form noise.
    designation: Option<String>,
}

#[derive(Deserialize)]
struct Section {
    title: Option<String>,
    #[serde(default)]
    fields: Vec<SectionField>,
}

#[derive(Deserialize)]
struct SectionField {
    title: Option<String>,
    id: Option<String>,
    value: Option<BTreeMap<String, serde_json::Value>>,
}

/// 1Password's category UUIDs, mapped onto locket's kinds. Anything not
/// listed — servers, routers, software licences — is credential-shaped and
/// lands as a login rather than being dropped.
fn kind_for(category: Option<&str>) -> ItemKind {
    match category {
        Some("002") => ItemKind::Card,
        Some("003") => ItemKind::Note,
        Some("004") => ItemKind::Identity,
        Some("110") => ItemKind::SshKey,
        _ => ItemKind::Login,
    }
}

/// Parse the `export.data` JSON, without touching a vault or a zip.
/// Returns the converted items and how many attached documents the export
/// mentioned (they stay in the archive; the summary says so).
pub fn parse(text: &str) -> Result<(Vec<Item>, usize)> {
    let export: Export = serde_json::from_str(text)
        .map_err(|e| Error::Database(format!("not a 1Password 1PUX export: {e}")))?;

    let mut items = Vec::new();
    let mut documents = 0usize;
    for account in &export.accounts {
        for vault in &account.vaults {
            let vault_name = vault
                .attrs
                .as_ref()
                .and_then(|a| a.name.clone());
            for entry in &vault.items {
                if entry.state.as_deref() == Some("trashed") {
                    continue;
                }
                let (item, files) = convert(entry, vault_name.as_deref());
                documents += files;
                items.push(item);
            }
        }
    }
    Ok((items, documents))
}

fn convert(e: &Entry, vault_name: Option<&str>) -> (Item, usize) {
    let overview = e.overview.as_ref();
    let label = overview
        .and_then(|o| o.title.clone())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "Unnamed".to_owned());
    let mut item = Item::new(kind_for(e.category.as_deref()), label);
    let mut documents = 0usize;

    item.attributes
        .insert("locket:source".into(), "1password".into());
    if let Some(uuid) = &e.uuid {
        item.attributes.insert("1password:uuid".into(), uuid.clone());
    }
    item.favorite = e.fav_index > 0;

    if let Some(o) = overview {
        item.tags = o.tags.clone();
        if let Some(url) = o
            .url
            .as_deref()
            .filter(|u| !u.is_empty())
            .or_else(|| o.urls.iter().filter_map(|u| u.url.as_deref()).next())
        {
            item.fields
                .push(Field::new(field_names::URL, FieldKind::Url, url));
        }
    }
    if e.state.as_deref() == Some("archived") && !item.tags.iter().any(|t| t == "archived") {
        item.tags.push("archived".into());
    }
    if let Some(vault) = vault_name.filter(|v| !v.is_empty())
        && !item.tags.contains(&vault.to_owned()) {
            item.tags.push(vault.to_owned());
        }

    let Some(details) = &e.details else {
        return (item, 0);
    };

    for f in &details.login_fields {
        let Some(value) = f.value.as_deref().filter(|v| !v.is_empty()) else {
            continue;
        };
        match f.designation.as_deref() {
            Some("username") => {
                item.fields
                    .push(Field::text(field_names::USERNAME, value));
                item.attributes.insert("username".into(), value.into());
            }
            Some("password") => item.secret = value.into(),
            _ => {} // unlabelled web-form fields carry no meaning here
        }
    }
    if let Some(password) = details.password.as_deref().filter(|p| !p.is_empty())
        && item.secret.is_empty() {
            item.secret = password.into();
        }

    for section in &details.sections {
        for f in &section.fields {
            let name = f
                .title
                .as_deref()
                .filter(|t| !t.is_empty())
                .or(f.id.as_deref())
                .unwrap_or("field")
                .to_owned();
            let name = match section.title.as_deref().filter(|t| !t.is_empty()) {
                Some(section_title) => format!("{section_title}: {name}"),
                None => name,
            };
            let Some(value) = &f.value else { continue };
            let Some((kind, raw)) = value.iter().next() else {
                continue;
            };
            let field = match (kind.as_str(), raw) {
                ("concealed", serde_json::Value::String(s)) => {
                    Some(Field::secret(name, s.clone()))
                }
                ("totp", serde_json::Value::String(s)) => {
                    Some(Field::new(name, FieldKind::Totp, s.clone()))
                }
                ("url", serde_json::Value::String(s)) => {
                    Some(Field::new(name, FieldKind::Url, s.clone()))
                }
                ("email", serde_json::Value::String(s)) => {
                    Some(Field::new(name, FieldKind::Email, s.clone()))
                }
                ("phone", serde_json::Value::String(s)) => {
                    Some(Field::new(name, FieldKind::Phone, s.clone()))
                }
                ("date", serde_json::Value::Number(n)) => n.as_u64().map(|ts| {
                    Field::new(name, FieldKind::Date, locket_core::model::format_date(ts))
                }),
                ("file", _) => {
                    // The bytes are elsewhere in the archive; count it so the
                    // summary can say documents were left behind.
                    documents += 1;
                    None
                }
                (_, serde_json::Value::String(s)) if !s.is_empty() => {
                    Some(Field::text(name, s.clone()))
                }
                _ => None,
            };
            if let Some(field) = field {
                item.fields.push(field);
            }
        }
    }

    if let Some(notes) = details.notes.as_deref().filter(|n| !n.is_empty()) {
        if item.kind == ItemKind::Note && item.secret.is_empty() {
            item.secret = notes.into();
        } else {
            item.fields
                .push(Field::new(field_names::NOTES, FieldKind::Note, notes));
        }
    }

    (item, documents)
}

/// Import a `.1pux` file into the vault.
pub fn import_file(vault: &mut Vault, path: &Path, into: Option<&str>) -> Result<ImportSummary> {
    let file = std::fs::File::open(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| Error::Database(format!("not a zip archive (a .1pux is one): {e}")))?;
    let mut text = String::new();
    archive
        .by_name("export.data")
        .map_err(|_| Error::Database("no export.data inside; not a 1PUX export".into()))?
        .read_to_string(&mut text)
        .map_err(|e| Error::Database(format!("could not read export.data: {e}")))?;

    let (items, documents) = parse(&text)?;

    let mut summary = ImportSummary::default();
    let collection = crate::target_collection(vault, into.unwrap_or("1Password"));
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
    if documents > 0 {
        summary.notes.push(format!(
            "{documents} attached document(s) were not imported; they are still \
             inside the .1pux archive"
        ));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = r#"{
        "accounts": [{
            "vaults": [{
                "attrs": {"name": "Personal"},
                "items": [
                    {
                        "uuid": "u1", "state": "active", "categoryUuid": "001",
                        "favIndex": 1,
                        "overview": {
                            "title": "GitHub",
                            "url": "https://github.com",
                            "tags": ["dev"]
                        },
                        "details": {
                            "loginFields": [
                                {"value": "ada", "designation": "username"},
                                {"value": "hunter2", "designation": "password"}
                            ],
                            "notesPlain": "work account",
                            "sections": [{
                                "title": "Extra",
                                "fields": [
                                    {"title": "recovery", "value": {"concealed": "codes"}},
                                    {"title": "2fa", "value": {"totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
                                    {"title": "scan", "value": {"file": {"documentId": "d1"}}}
                                ]
                            }]
                        }
                    },
                    {
                        "uuid": "u2", "state": "trashed", "categoryUuid": "001",
                        "overview": {"title": "Deleted thing"},
                        "details": {}
                    },
                    {
                        "uuid": "u3", "state": "active", "categoryUuid": "005",
                        "overview": {"title": "Router"},
                        "details": {"password": "only-a-password"}
                    },
                    {
                        "uuid": "u4", "state": "archived", "categoryUuid": "003",
                        "overview": {"title": "Old note"},
                        "details": {"notesPlain": "the body"}
                    }
                ]
            }]
        }]
    }"#;

    #[test]
    fn a_login_arrives_whole_and_trash_stays_dead() {
        let (items, documents) = parse(EXPORT).unwrap();
        assert_eq!(items.len(), 3, "the trashed item was resurrected");
        assert_eq!(documents, 1);

        let login = items.iter().find(|i| i.label == "GitHub").unwrap();
        assert_eq!(login.kind, ItemKind::Login);
        assert_eq!(login.secret.expose(), "hunter2");
        assert_eq!(login.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(login.field_value(field_names::URL), Some("https://github.com"));
        assert!(login.favorite);
        assert!(login.tags.contains(&"dev".to_owned()));
        assert!(login.tags.contains(&"Personal".to_owned()), "vault name lost");
        assert_eq!(
            login.field("Extra: recovery").unwrap().kind,
            FieldKind::Secret
        );
        assert_eq!(login.field("Extra: 2fa").unwrap().kind, FieldKind::Totp);
        assert!(login.field("Extra: scan").is_none(), "a file became a field");
    }

    #[test]
    fn password_and_note_categories_map_sensibly() {
        let (items, _) = parse(EXPORT).unwrap();
        let router = items.iter().find(|i| i.label == "Router").unwrap();
        assert_eq!(router.kind, ItemKind::Login);
        assert_eq!(router.secret.expose(), "only-a-password");

        let note = items.iter().find(|i| i.label == "Old note").unwrap();
        assert_eq!(note.kind, ItemKind::Note);
        assert_eq!(note.secret.expose(), "the body");
        assert!(note.tags.contains(&"archived".to_owned()));
    }

    #[test]
    fn a_real_zip_round_trips_and_reimport_skips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.1pux");
        {
            let file = std::fs::File::create(&path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            use std::io::Write as _;
            writer
                .start_file(
                    "export.data",
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
        assert_eq!(first.notes.len(), 1, "documents left behind went unmentioned");
        let second = import_file(&mut vault, &path, None).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped_duplicate, 3);
    }

    #[test]
    fn not_a_zip_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.1pux");
        std::fs::write(&path, "just text").unwrap();
        let vault_path = dir.path().join("v.vault");
        let mut vault = locket_core::Vault::create(
            &vault_path,
            "pw",
            locket_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();
        let err = import_file(&mut vault, &path, None).unwrap_err();
        assert!(err.to_string().contains("zip"), "{err}");
    }
}
