//! The vault's data model.
//!
//! The shape is chosen so a passman item can round-trip through the
//! freedesktop Secret Service without loss: every item has a *primary secret*
//! plus a flat `a{ss}` attribute map (what `libsecret` searches on), and
//! everything richer — usernames, TOTP seeds, card numbers — rides along in
//! `fields`, which the Secret Service never sees.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secret::SecretString;

/// Seconds since the Unix epoch.
pub type Timestamp = u64;

pub fn now() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What kind of thing an item is. Drives the icon, the detail layout, and
/// which fields the editor offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    /// Website or application login: username + password (+ TOTP, + URLs).
    Login,
    /// Free-form encrypted note.
    Note,
    /// Payment card.
    Card,
    /// Personal identity details.
    Identity,
    /// An SSH private key served to the agent.
    SshKey,
    /// A GPG/OpenPGP private key.
    GpgKey,
    /// A bare API token or personal access token.
    ApiToken,
    /// An OAuth 2.0 client registration and/or refresh token.
    OAuth,
    /// A TLS/X.509 certificate and its private key.
    Certificate,
    /// A named bundle of environment variables.
    Environment,
    /// A Wi-Fi network passphrase.
    WifiNetwork,
    /// Something stored by another application through the Secret Service.
    ///
    /// Items created by `libsecret` clients land here unless they carry an
    /// attribute telling us otherwise, so foreign secrets stay first-class
    /// instead of becoming untyped blobs.
    Application,
}

impl ItemKind {
    pub const ALL: &'static [ItemKind] = &[
        ItemKind::Login,
        ItemKind::Note,
        ItemKind::Card,
        ItemKind::Identity,
        ItemKind::SshKey,
        ItemKind::GpgKey,
        ItemKind::ApiToken,
        ItemKind::OAuth,
        ItemKind::Certificate,
        ItemKind::Environment,
        ItemKind::WifiNetwork,
        ItemKind::Application,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            ItemKind::Login => "Login",
            ItemKind::Note => "Secure Note",
            ItemKind::Card => "Payment Card",
            ItemKind::Identity => "Identity",
            ItemKind::SshKey => "SSH Key",
            ItemKind::GpgKey => "GPG Key",
            ItemKind::ApiToken => "API Token",
            ItemKind::OAuth => "OAuth Credential",
            ItemKind::Certificate => "Certificate",
            ItemKind::Environment => "Environment",
            ItemKind::WifiNetwork => "Wi-Fi Network",
            ItemKind::Application => "Application Secret",
        }
    }

    /// Freedesktop icon name, resolved from the COSMIC/Adwaita icon themes.
    pub const fn icon_name(self) -> &'static str {
        match self {
            ItemKind::Login => "dialog-password-symbolic",
            ItemKind::Note => "text-x-generic-symbolic",
            ItemKind::Card => "credit-card-symbolic",
            ItemKind::Identity => "avatar-default-symbolic",
            ItemKind::SshKey => "utilities-terminal-symbolic",
            ItemKind::GpgKey => "application-certificate-symbolic",
            ItemKind::ApiToken => "network-server-symbolic",
            ItemKind::OAuth => "changes-allow-symbolic",
            ItemKind::Certificate => "application-certificate-symbolic",
            ItemKind::Environment => "system-run-symbolic",
            ItemKind::WifiNetwork => "network-wireless-symbolic",
            ItemKind::Application => "application-x-executable-symbolic",
        }
    }

    /// The `org.freedesktop.Secret.Item` `Type` string to advertise.
    pub const fn xdg_schema(self) -> &'static str {
        match self {
            ItemKind::Login => "org.freedesktop.Secret.Generic",
            ItemKind::Note => "org.freedesktop.Secret.Note",
            ItemKind::WifiNetwork => "org.gnome.NetworkManager.Connection",
            _ => "org.freedesktop.Secret.Generic",
        }
    }
}

/// How a field's value should be treated by the UI and the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    /// Shown in the clear.
    Text,
    /// Masked until revealed; cleared from the clipboard after a timeout.
    Secret,
    /// Rendered as a link.
    Url,
    /// An `otpauth://` seed; the UI renders a live code.
    Totp,
    /// Multi-line text.
    Note,
    /// An email address.
    Email,
    /// A phone number.
    Phone,
    /// A date, ISO-8601.
    Date,
    /// PEM- or OpenSSH-encoded private key material.
    PrivateKey,
    /// PEM-encoded public material — not sensitive.
    PublicKey,
}

impl FieldKind {
    /// Every kind, in the order the editor offers them.
    pub const ALL: &'static [FieldKind] = &[
        FieldKind::Text,
        FieldKind::Secret,
        FieldKind::Url,
        FieldKind::Totp,
        FieldKind::Note,
        FieldKind::Email,
        FieldKind::Phone,
        FieldKind::Date,
        FieldKind::PrivateKey,
        FieldKind::PublicKey,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            FieldKind::Text => "Text",
            FieldKind::Secret => "Secret",
            FieldKind::Url => "URL",
            FieldKind::Totp => "One-time code",
            FieldKind::Note => "Note",
            FieldKind::Email => "Email",
            FieldKind::Phone => "Phone",
            FieldKind::Date => "Date",
            FieldKind::PrivateKey => "Private key",
            FieldKind::PublicKey => "Public key",
        }
    }

    /// Whether the value must be masked in the UI and redacted in logs.
    pub const fn is_sensitive(self) -> bool {
        matches!(
            self,
            FieldKind::Secret | FieldKind::Totp | FieldKind::PrivateKey
        )
    }
}

/// One named value on an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub value: SecretString,
}

impl Field {
    pub fn new(name: impl Into<String>, kind: FieldKind, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            value: SecretString::new(value.into()),
        }
    }

    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, FieldKind::Text, value)
    }

    pub fn secret(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, FieldKind::Secret, value)
    }
}

/// Well-known field names, so the GUI, the CLI and the importers agree.
pub mod field_names {
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const URL: &str = "url";
    pub const TOTP: &str = "totp";
    pub const NOTES: &str = "notes";
    pub const PRIVATE_KEY: &str = "private-key";
    pub const PUBLIC_KEY: &str = "public-key";
    pub const KEY_COMMENT: &str = "comment";
    pub const CLIENT_ID: &str = "client-id";
    pub const CLIENT_SECRET: &str = "client-secret";
    pub const REFRESH_TOKEN: &str = "refresh-token";
    pub const ACCESS_TOKEN: &str = "access-token";
    pub const TOKEN_ENDPOINT: &str = "token-endpoint";
}

/// A single stored secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub kind: ItemKind,
    /// Human-readable name; the Secret Service `Label`.
    pub label: String,
    /// The Secret Service `Attributes` map. This is the *search index* other
    /// applications use, so it is deliberately plaintext-shaped — never put a
    /// secret in here.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// The primary secret, returned by `org.freedesktop.Secret.Item.GetSecret`.
    #[serde(default)]
    pub secret: SecretString,
    /// MIME type of `secret`, per the Secret Service spec.
    #[serde(default = "default_content_type")]
    pub content_type: String,
    /// Richer structured data that the Secret Service has no room for.
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created: Timestamp,
    pub modified: Timestamp,
}

fn default_content_type() -> String {
    "text/plain".to_owned()
}

impl Item {
    pub fn new(kind: ItemKind, label: impl Into<String>) -> Self {
        let ts = now();
        Self {
            id: Uuid::new_v4(),
            kind,
            label: label.into(),
            attributes: BTreeMap::new(),
            secret: SecretString::default(),
            content_type: default_content_type(),
            fields: Vec::new(),
            favorite: false,
            tags: Vec::new(),
            created: ts,
            modified: ts,
        }
    }

    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = SecretString::new(secret.into());
        self
    }

    pub fn with_field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    pub fn with_attribute(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.attributes.insert(k.into(), v.into());
        self
    }

    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn field_value(&self, name: &str) -> Option<&str> {
        self.field(name).map(|f| f.value.expose())
    }

    /// Insert or replace a field, preserving position if it already exists.
    pub fn set_field(&mut self, field: Field) {
        match self.fields.iter_mut().find(|f| f.name == field.name) {
            Some(existing) => *existing = field,
            None => self.fields.push(field),
        }
        self.modified = now();
    }

    pub fn remove_field(&mut self, name: &str) {
        self.fields.retain(|f| f.name != name);
        self.modified = now();
    }

    /// The subtitle shown under the label in list views.
    pub fn subtitle(&self) -> &str {
        self.field_value(field_names::USERNAME)
            .or_else(|| self.field_value(field_names::URL))
            .or_else(|| self.attributes.get("service").map(String::as_str))
            .or_else(|| self.attributes.get("application").map(String::as_str))
            .unwrap_or(self.kind.label())
    }

    /// Case-insensitive match across label, subtitle, tags and attributes.
    ///
    /// Secret *values* are deliberately excluded — searching them would let a
    /// shoulder-surfer confirm a guess without ever revealing a field.
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        let needle = needle.to_lowercase();
        let hay = |s: &str| s.to_lowercase().contains(&needle);

        hay(&self.label)
            || self.tags.iter().any(|t| hay(t))
            || self.attributes.iter().any(|(k, v)| hay(k) || hay(v))
            || self.fields.iter().any(|f| {
                hay(&f.name) || (!f.kind.is_sensitive() && hay(f.value.expose()))
            })
    }

    pub fn touch(&mut self) {
        self.modified = now();
    }
}

/// A keychain: a named group of items that locks and unlocks as a unit.
///
/// Mirrors both a Secret Service *collection* and a macOS *keychain*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub id: Uuid,
    pub label: String,
    /// Secret Service alias, e.g. `default` or `login`. Clients that call
    /// `ReadAlias("default")` are routed to the collection holding this.
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub items: Vec<Item>,
    pub created: Timestamp,
    pub modified: Timestamp,
}

impl Collection {
    pub fn new(label: impl Into<String>) -> Self {
        let ts = now();
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            alias: None,
            items: Vec::new(),
            created: ts,
            modified: ts,
        }
    }

    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }

    pub fn item(&self, id: Uuid) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn item_mut(&mut self, id: Uuid) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    /// Secret Service `SearchItems`: an item matches when it carries *every*
    /// requested attribute with exactly the requested value.
    pub fn search(&self, attributes: &BTreeMap<String, String>) -> Vec<&Item> {
        self.items
            .iter()
            .filter(|item| {
                attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v))
            })
            .collect()
    }
}

/// Everything inside the encrypted body of a vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub collections: Vec<Collection>,
}

impl Default for VaultData {
    fn default() -> Self {
        // A fresh vault ships with one collection aliased `default`, because
        // libsecret's very first call on an empty system is
        // ReadAlias("default") and returning `/` there makes clients give up.
        Self {
            collections: vec![Collection::new("Login").with_alias("default")],
        }
    }
}

impl VaultData {
    pub fn collection(&self, id: Uuid) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    pub fn collection_mut(&mut self, id: Uuid) -> Option<&mut Collection> {
        self.collections.iter_mut().find(|c| c.id == id)
    }

    pub fn collection_by_alias(&self, alias: &str) -> Option<&Collection> {
        self.collections
            .iter()
            .find(|c| c.alias.as_deref() == Some(alias))
    }

    /// The collection new items go into when the caller does not name one.
    pub fn default_collection_mut(&mut self) -> &mut Collection {
        let idx = self
            .collections
            .iter()
            .position(|c| c.alias.as_deref() == Some("default"))
            .unwrap_or(0);
        &mut self.collections[idx]
    }

    pub fn all_items(&self) -> impl Iterator<Item = (&Collection, &Item)> {
        self.collections
            .iter()
            .flat_map(|c| c.items.iter().map(move |i| (c, i)))
    }

    pub fn find_item(&self, id: Uuid) -> Option<(&Collection, &Item)> {
        self.all_items().find(|(_, i)| i.id == id)
    }

    pub fn item_count(&self) -> usize {
        self.collections.iter().map(|c| c.items.len()).sum()
    }

    /// Remove an item from whichever collection holds it.
    pub fn remove_item(&mut self, id: Uuid) -> Option<Item> {
        for c in &mut self.collections {
            if let Some(pos) = c.items.iter().position(|i| i.id == id) {
                c.modified = now();
                return Some(c.items.remove(pos));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_requires_all_attributes_to_match() {
        let mut c = Collection::new("Login");
        c.items.push(
            Item::new(ItemKind::Login, "GitHub")
                .with_attribute("service", "github.com")
                .with_attribute("username", "ada"),
        );
        c.items
            .push(Item::new(ItemKind::Login, "GitLab").with_attribute("service", "gitlab.com"));

        let mut q = BTreeMap::new();
        q.insert("service".into(), "github.com".into());
        assert_eq!(c.search(&q).len(), 1);

        // Adding a non-matching attribute must narrow to zero, not stay at one.
        q.insert("username".into(), "grace".into());
        assert_eq!(c.search(&q).len(), 0);

        // An empty query matches everything.
        assert_eq!(c.search(&BTreeMap::new()).len(), 2);
    }

    #[test]
    fn search_does_not_leak_secret_values() {
        let item = Item::new(ItemKind::Login, "Bank")
            .with_field(Field::secret(field_names::PASSWORD, "hunter2"))
            .with_field(Field::text(field_names::USERNAME, "ada"));
        assert!(!item.matches("hunter2"));
        assert!(item.matches("ada"));
        assert!(item.matches("BANK"));
    }

    #[test]
    fn set_field_replaces_in_place() {
        let mut item = Item::new(ItemKind::Login, "X");
        item.set_field(Field::text(field_names::USERNAME, "a"));
        item.set_field(Field::text(field_names::URL, "u"));
        item.set_field(Field::text(field_names::USERNAME, "b"));
        assert_eq!(item.fields.len(), 3 - 1);
        assert_eq!(item.field_value(field_names::USERNAME), Some("b"));
        assert_eq!(item.fields[0].name, field_names::USERNAME);
    }

    #[test]
    fn default_vault_has_a_default_alias() {
        let v = VaultData::default();
        assert!(v.collection_by_alias("default").is_some());
    }
}
