//! Importing from another Secret Service.
//!
//! Reads every item out of a running `org.freedesktop.secrets` — normally
//! `gnome-keyring` — and writes it into a passman vault. This is the migration
//! path: replacing the keyring is only useful if what you already stored comes
//! with you.
//!
//! Deliberately a **client**, not a file parser. gnome-keyring's on-disk format
//! is undocumented and version-specific, but its D-Bus surface is a standard
//! this crate already implements the other half of. It also means the same code
//! imports from KWallet or any other conforming service.
//!
//! The import is read-only with respect to the source and idempotent with
//! respect to the target: an item whose attribute set already exists in the
//! vault is skipped, so re-running after adding a few secrets does not produce
//! duplicates.

use std::collections::HashMap;

use passman_core::{
    Vault,
    model::{Collection, Item, ItemKind},
};
use zbus::zvariant::OwnedObjectPath;

use crate::{Error, Result, service::SecretStruct};

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_path = "/org/freedesktop/secrets",
    assume_defaults = false
)]
trait SourceService {
    fn open_session(
        &self,
        algorithm: &str,
        input: &zbus::zvariant::Value<'_>,
    ) -> zbus::Result<(zbus::zvariant::OwnedValue, OwnedObjectPath)>;

    #[zbus(property)]
    fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Collection", assume_defaults = false)]
trait SourceCollection {
    #[zbus(property)]
    fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Item", assume_defaults = false)]
trait SourceItem {
    fn get_secret(&self, session: &OwnedObjectPath) -> zbus::Result<SecretStruct>;

    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<HashMap<String, String>>;

    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    #[zbus(property, name = "Type")]
    fn type_(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub collections: usize,
    pub imported: usize,
    /// Already present in the target, matched by attribute set.
    pub skipped_duplicate: usize,
    /// Could not be read — locked, or the service refused.
    pub skipped_unreadable: usize,
}

impl std::fmt::Display for ImportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} item(s) from {} collection(s); {} already present, {} unreadable",
            self.imported, self.collections, self.skipped_duplicate, self.skipped_unreadable
        )
    }
}

/// Map a foreign item onto a passman item.
///
/// Kept separate from the D-Bus plumbing so the mapping rules are testable
/// without a bus.
pub fn map_item(
    label: String,
    attributes: HashMap<String, String>,
    schema: Option<String>,
    secret: String,
    content_type: String,
) -> Item {
    let attributes: std::collections::BTreeMap<String, String> = attributes.into_iter().collect();
    let kind = infer_kind(&attributes, schema.as_deref());

    let mut item = Item::new(kind, if label.is_empty() { "Untitled" } else { &label });
    item.attributes = attributes;
    item.secret = secret.into();
    item.content_type = content_type;
    if let Some(schema) = schema {
        item.attributes.entry("xdg:schema".into()).or_insert(schema);
    }

    // Surface the username as a real field so it shows in the UI rather than
    // only in the attribute list.
    for key in ["username", "user", "UserName", "login"] {
        if let Some(v) = item.attributes.get(key) {
            let v = v.clone();
            item.set_field(passman_core::Field::text(
                passman_core::model::field_names::USERNAME,
                v,
            ));
            break;
        }
    }
    // Same for a URL-ish attribute.
    for key in ["url", "uri", "server", "host"] {
        if let Some(v) = item.attributes.get(key) {
            let v = v.clone();
            item.set_field(passman_core::Field::new(
                passman_core::model::field_names::URL,
                passman_core::FieldKind::Url,
                v,
            ));
            break;
        }
    }
    item
}

fn infer_kind(
    attributes: &std::collections::BTreeMap<String, String>,
    schema: Option<&str>,
) -> ItemKind {
    match schema {
        Some("org.freedesktop.Secret.Note") => return ItemKind::Note,
        Some("org.gnome.NetworkManager.Connection") => return ItemKind::WifiNetwork,
        Some(s) if s.contains("ssh") || s.contains("Ssh") => return ItemKind::SshKey,
        _ => {}
    }
    if attributes.contains_key("xdg:schema")
        && attributes["xdg:schema"].contains("NetworkManager")
    {
        return ItemKind::WifiNetwork;
    }
    if ["username", "user", "login", "UserName"]
        .iter()
        .any(|k| attributes.contains_key(*k))
    {
        return ItemKind::Login;
    }
    ItemKind::Application
}

/// Whether the vault already holds an item with exactly these attributes.
///
/// Attribute identity is what the Secret Service itself uses for
/// replace-on-store, so it is the right notion of "the same secret".
fn already_present(vault: &Vault, attributes: &std::collections::BTreeMap<String, String>) -> bool {
    if attributes.is_empty() {
        return false;
    }
    vault
        .data()
        .all_items()
        .any(|(_, i)| &i.attributes == attributes)
}

/// Import everything readable from `bus_name` into `vault`.
///
/// Does not save; the caller decides when to persist.
pub async fn import_from(
    vault: &mut Vault,
    bus_name: &str,
    into_collection: Option<&str>,
) -> Result<ImportSummary> {
    let connection = zbus::Connection::session().await?;
    let service = SourceServiceProxy::builder(&connection)
        .destination(bus_name.to_owned())
        .map_err(Error::Dbus)?
        .path("/org/freedesktop/secrets")
        .map_err(Error::Dbus)?
        .build()
        .await?;

    // `plain` keeps the importer simple; this is a local client on the user's
    // own session bus, and the DH transport protects against nothing extra
    // here that the bus itself does not already.
    let empty = zbus::zvariant::Value::from("");
    let (_output, session) = service
        .open_session("plain", &empty)
        .await
        .map_err(|e| Error::Other(format!("source refused a session: {e}")))?;

    let mut summary = ImportSummary::default();

    for collection_path in service.collections().await? {
        let collection = SourceCollectionProxy::builder(&connection)
            .destination(bus_name.to_owned())
            .map_err(Error::Dbus)?
            .path(collection_path.clone())
            .map_err(Error::Dbus)?
            .build()
            .await?;

        let label = collection.label().await.unwrap_or_else(|_| "Imported".into());
        if collection.locked().await.unwrap_or(false) {
            tracing::warn!("skipping locked collection `{label}`");
            continue;
        }

        let Ok(item_paths) = collection.items().await else {
            continue;
        };
        if item_paths.is_empty() {
            continue;
        }
        summary.collections += 1;

        // Route into a named collection if asked, else mirror the source's.
        let target_name = into_collection.unwrap_or(&label).to_owned();
        let target_id = match vault
            .data()
            .collections
            .iter()
            .find(|c| c.label == target_name)
        {
            Some(c) => c.id,
            None => vault.add_collection(Collection::new(target_name)),
        };

        for item_path in item_paths {
            let item_proxy = SourceItemProxy::builder(&connection)
                .destination(bus_name.to_owned())
                .map_err(Error::Dbus)?
                .path(item_path.clone())
                .map_err(Error::Dbus)?
                .build()
                .await?;

            let attributes = item_proxy.attributes().await.unwrap_or_default();
            let label = item_proxy.label().await.unwrap_or_default();
            let schema = item_proxy.type_().await.ok().filter(|s| !s.is_empty());

            let secret = match item_proxy.get_secret(&session).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("could not read `{label}`: {e}");
                    summary.skipped_unreadable += 1;
                    continue;
                }
            };

            let item = map_item(
                label,
                attributes,
                schema,
                String::from_utf8_lossy(&secret.value).into_owned(),
                secret.content_type,
            );

            if already_present(vault, &item.attributes) {
                summary.skipped_duplicate += 1;
                continue;
            }
            vault.add_item(target_id, item)?;
            summary.imported += 1;
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use passman_core::{crypto::KdfParams, model::field_names};

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_login_is_recognised_and_its_username_surfaced() {
        let item = map_item(
            "GitHub".into(),
            attrs(&[("service", "github.com"), ("username", "ada")]),
            Some("org.freedesktop.Secret.Generic".into()),
            "hunter2".into(),
            "text/plain".into(),
        );
        assert_eq!(item.kind, ItemKind::Login);
        assert_eq!(item.secret.expose(), "hunter2");
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
        // Attributes must survive verbatim, or apps stop finding the secret.
        assert_eq!(item.attributes.get("service").unwrap(), "github.com");
    }

    #[test]
    fn schema_drives_the_kind() {
        let note = map_item(
            "Note".into(),
            attrs(&[]),
            Some("org.freedesktop.Secret.Note".into()),
            "body".into(),
            "text/plain".into(),
        );
        assert_eq!(note.kind, ItemKind::Note);

        let wifi = map_item(
            "Home".into(),
            attrs(&[]),
            Some("org.gnome.NetworkManager.Connection".into()),
            "pw".into(),
            "text/plain".into(),
        );
        assert_eq!(wifi.kind, ItemKind::WifiNetwork);

        let anon = map_item(
            "Thing".into(),
            attrs(&[("app", "x")]),
            None,
            "s".into(),
            "text/plain".into(),
        );
        assert_eq!(anon.kind, ItemKind::Application);
    }

    #[test]
    fn a_url_like_attribute_becomes_a_field() {
        let item = map_item(
            "Server".into(),
            attrs(&[("server", "imap.example.org"), ("user", "ada")]),
            None,
            "pw".into(),
            "text/plain".into(),
        );
        assert_eq!(item.field_value(field_names::URL), Some("imap.example.org"));
        assert_eq!(item.field_value(field_names::USERNAME), Some("ada"));
    }

    #[test]
    fn an_empty_label_does_not_produce_a_nameless_item() {
        let item = map_item(String::new(), attrs(&[]), None, "s".into(), "text/plain".into());
        assert_eq!(item.label, "Untitled");
    }

    #[test]
    fn duplicate_detection_matches_on_the_whole_attribute_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let existing = map_item(
            "GitHub".into(),
            attrs(&[("service", "github.com"), ("username", "ada")]),
            None,
            "hunter2".into(),
            "text/plain".into(),
        );
        let same_attrs = existing.attributes.clone();
        vault.add_item_default(existing);

        assert!(already_present(&vault, &same_attrs));

        // A different username is a different secret.
        let mut other = same_attrs.clone();
        other.insert("username".into(), "grace".into());
        assert!(!already_present(&vault, &other));

        // An attribute-less item can never be matched, so it is never skipped.
        assert!(!already_present(&vault, &Default::default()));
    }

    #[test]
    fn summary_reads_sensibly() {
        let s = ImportSummary {
            collections: 2,
            imported: 5,
            skipped_duplicate: 1,
            skipped_unreadable: 0,
        };
        assert_eq!(
            s.to_string(),
            "5 item(s) from 2 collection(s); 1 already present, 0 unreadable"
        );
    }
}
