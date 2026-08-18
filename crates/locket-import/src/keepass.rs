//! Importing a KeePass `.kdbx` database (KeePassXC, KeePass2).
//!
//! Unlike `pass`, kdbx is a real format with typed fields, so the mapping is
//! mostly mechanical. The two things worth care:
//!
//! * **Group structure.** kdbx is a tree; locket's collections are flat. The
//!   full group path becomes tags, so nothing about where an entry lived is
//!   lost even though the hierarchy is flattened.
//! * **Custom fields.** KeePassXC marks fields protected or not, and that
//!   decides whether locket masks them. Guessing from the name instead would
//!   reveal a field the user deliberately protected.

use std::path::Path;

use keepass::{Database, DatabaseKey};
use locket_core::{Field, FieldKind, Item, ItemKind, Vault, model::field_names};

use crate::{Error, ImportSummary, Result};

/// Field names kdbx defines itself; everything else is a custom field.
const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes", "otp"];

/// One kdbx entry's fields, as read from the database.
#[derive(Debug, Default, Clone)]
pub struct KdbxEntry<'a> {
    pub title: Option<&'a str>,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub url: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub otp: Option<&'a str>,
    /// `(name, value, protected)` — the protection flag comes from the
    /// database, not from guessing at the name.
    pub custom: &'a [(String, String, bool)],
    /// Slash-joined group ancestry.
    pub group_path: &'a str,
}

/// Map one kdbx entry onto a locket item.
pub fn map_entry(entry: KdbxEntry<'_>) -> Item {
    let KdbxEntry {
        title,
        username,
        password,
        url,
        notes,
        otp,
        custom,
        group_path,
    } = entry;
    let title = title.filter(|t| !t.is_empty()).unwrap_or("Untitled");
    let mut item = Item::new(ItemKind::Login, title).with_secret(password.unwrap_or_default());

    if !group_path.is_empty() {
        item.tags = group_path.split('/').map(str::to_owned).collect();
    }

    if let Some(u) = username.filter(|s| !s.is_empty()) {
        item.set_field(Field::text(field_names::USERNAME, u));
        item.attributes.insert("username".into(), u.to_owned());
    }
    if let Some(u) = url.filter(|s| !s.is_empty()) {
        item.set_field(Field::new(field_names::URL, FieldKind::Url, u));
    }
    if let Some(n) = notes.filter(|s| !s.is_empty()) {
        item.set_field(Field::new(field_names::NOTES, FieldKind::Note, n));
    }
    if let Some(o) = otp.filter(|s| !s.is_empty()) {
        item.set_field(Field::new(field_names::TOTP, FieldKind::Totp, o));
    }

    for (name, value, protected) in custom {
        if STANDARD_FIELDS.contains(&name.as_str()) || value.is_empty() {
            continue;
        }
        // Honour the database's own protection flag rather than guessing from
        // the field name.
        let kind = if *protected {
            FieldKind::Secret
        } else {
            FieldKind::Text
        };
        item.set_field(Field::new(name.clone(), kind, value.clone()));
    }

    // An entry with no password but a note is a secure note, not a login.
    if password.unwrap_or_default().is_empty() && item.field(field_names::NOTES).is_some() {
        item.kind = ItemKind::Note;
    }

    item.attributes
        .insert("locket:source".into(), "keepass".into());
    item.attributes.insert(
        "keepass:path".into(),
        if group_path.is_empty() {
            title.to_owned()
        } else {
            format!("{group_path}/{title}")
        },
    );
    item
}

/// Import every entry from a `.kdbx` file. Does not save.
pub fn import_kdbx(
    vault: &mut Vault,
    path: &Path,
    password: &str,
    keyfile: Option<&Path>,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    if !path.is_file() {
        return Err(Error::NotFound(path.to_path_buf()));
    }

    let mut key = DatabaseKey::new();
    if !password.is_empty() {
        key = key.with_password(password);
    }
    if let Some(keyfile) = keyfile {
        let mut f = std::fs::File::open(keyfile).map_err(|e| Error::Io {
            path: keyfile.to_path_buf(),
            source: e,
        })?;
        key = key
            .with_keyfile(&mut f)
            .map_err(|e| Error::Database(e.to_string()))?;
    }

    let mut file = std::fs::File::open(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let db = Database::open(&mut file, key).map_err(|e| Error::Database(e.to_string()))?;

    let target = crate::target_collection(vault, into_collection.unwrap_or("KeePass"));
    let mut summary = ImportSummary::default();
    let mut items = Vec::new();
    collect(&db.root(), "", &mut items);

    for item in items {
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

/// Walk the group tree depth-first, flattening entries.
fn collect(group: &keepass::db::GroupRef<'_>, prefix: &str, out: &mut Vec<Item>) {
    for entry in group.entries() {
        let custom: Vec<(String, String, bool)> = entry
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.get().clone(), v.is_protected()))
            .collect();

        out.push(map_entry(KdbxEntry {
            title: entry.get_title(),
            username: entry.get_username(),
            password: entry.get_password(),
            url: entry.get_url(),
            notes: entry.get("Notes"),
            otp: entry.get_raw_otp_value(),
            custom: &custom,
            group_path: prefix,
        }));
    }

    for child in group.groups() {
        let name = child.name.clone();
        let next = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        collect(&child, &next, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(pairs: &[(&str, &str, bool)]) -> Vec<(String, String, bool)> {
        pairs
            .iter()
            .map(|(k, v, p)| ((*k).to_owned(), (*v).to_owned(), *p))
            .collect()
    }

    #[test]
    fn a_login_maps_across_with_its_fields() {
        let item = map_entry(KdbxEntry {
            title: Some("GitHub"),
            username: Some("ada"),
            password: Some("hunter2"),
            url: Some("https://github.com"),
            notes: Some("a note"),
            group_path: "Internet/Dev",
            ..Default::default()
        });
        assert_eq!(item.kind, ItemKind::Login);
        assert_eq!(item.label, "GitHub");
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        assert_eq!(item.field_value(field_names::URL), Some("https://github.com"));
        assert_eq!(item.field_value(field_names::NOTES), Some("a note"));
        assert_eq!(item.tags, vec!["Internet", "Dev"]);
        assert_eq!(
            item.attributes.get("keepass:path").unwrap(),
            "Internet/Dev/GitHub"
        );
    }

    #[test]
    fn the_databases_protection_flag_decides_masking() {
        let fields = custom(&[("API Key", "secret-value", true), ("Owner", "ada", false)]);
        let item = map_entry(KdbxEntry {
            title: Some("X"),
            password: Some("pw"),
            custom: &fields,
            ..Default::default()
        });
        assert_eq!(item.field("API Key").unwrap().kind, FieldKind::Secret);
        // Not guessed from the name: "Owner" is unprotected, so it stays text.
        assert_eq!(item.field("Owner").unwrap().kind, FieldKind::Text);
    }

    #[test]
    fn standard_fields_are_not_duplicated_as_custom_ones() {
        let fields = custom(&[("UserName", "ada", false), ("Password", "pw", true)]);
        let item = map_entry(KdbxEntry {
            title: Some("X"),
            username: Some("ada"),
            password: Some("pw"),
            custom: &fields,
            ..Default::default()
        });
        // Exactly one username field, from the typed accessor.
        assert_eq!(
            item.fields.iter().filter(|f| f.name == field_names::USERNAME).count(),
            1
        );
        assert!(item.field("Password").is_none());
    }

    #[test]
    fn a_passwordless_entry_with_notes_becomes_a_secure_note() {
        let item = map_entry(KdbxEntry {
            title: Some("Recovery codes"),
            password: Some(""),
            notes: Some("1234-5678"),
            ..Default::default()
        });
        assert_eq!(item.kind, ItemKind::Note);
    }

    #[test]
    fn an_otp_value_becomes_a_totp_field() {
        let item = map_entry(KdbxEntry {
            title: Some("X"),
            password: Some("pw"),
            otp: Some("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP"),
            ..Default::default()
        });
        let totp = item.field(field_names::TOTP).unwrap();
        assert_eq!(totp.kind, FieldKind::Totp);
        assert!(locket_core::Totp::parse(totp.value.expose()).is_ok());
    }

    #[test]
    fn an_untitled_entry_still_gets_a_name() {
        let item = map_entry(KdbxEntry {
            password: Some("pw"),
            ..Default::default()
        });
        assert_eq!(item.label, "Untitled");
        assert_eq!(item.attributes.get("keepass:path").unwrap(), "Untitled");
    }

    #[test]
    fn a_missing_database_is_reported_not_panicked_on() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(
            dir.path().join("v.vault"),
            "pw",
            locket_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();
        let missing = dir.path().join("nope.kdbx");
        assert!(matches!(
            import_kdbx(&mut vault, &missing, "x", None, None),
            Err(Error::NotFound(_))
        ));
    }
}
