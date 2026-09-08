//! The vault's data model.
//!
//! The shape is chosen so a locket item can round-trip through the
//! freedesktop Secret Service without loss: every item has a *primary secret*
//! plus a flat `a{ss}` attribute map (what `libsecret` searches on), and
//! everything richer — usernames, TOTP seeds, card numbers — rides along in
//! `fields`, which the Secret Service never sees.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use zeroize::Zeroizing;

use crate::secret::{SecretBytes, SecretString};

/// Seconds since the Unix epoch.
pub type Timestamp = u64;

pub fn now() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse `YYYY-MM-DD` to midnight UTC of that day.
///
/// The one date format the vault speaks, chosen because it is what the
/// `Date` field kind already documents and what certificates print. Days are
/// converted with the standard civil-from-days arithmetic rather than a
/// calendar dependency.
pub fn parse_date(s: &str) -> Option<Timestamp> {
    let mut parts = s.trim().splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(1970..=9999).contains(&y) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let mp = u64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    u64::try_from(days).ok().map(|d| d * 86_400)
}

/// Format a timestamp as the `YYYY-MM-DD` (UTC) that [`parse_date`] reads.
pub fn format_date(ts: Timestamp) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (ts / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
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
            ItemKind::Card => "payment-card-symbolic",
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
    /// A web address, shown in the clear.
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
/// Attribute names locket itself owns.
pub mod attr {
    /// How the primary secret is encoded, when it is not plain text.
    ///
    /// Namespaced so it cannot collide with an application's own attributes,
    /// which are otherwise passed through verbatim as the search index.
    pub const SECRET_ENCODING: &str = "locket:secret-encoding";
}

/// The only value [`attr::SECRET_ENCODING`] ever takes.
const BASE64: &str = "base64";

pub mod field_names {
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const URL: &str = "url";
    pub const TOTP: &str = "totp";
    pub const NOTES: &str = "notes";
    pub const PRIVATE_KEY: &str = "private-key";
    pub const PUBLIC_KEY: &str = "public-key";
    pub const KEY_COMMENT: &str = "comment";
    /// An OpenSSH certificate (`*-cert.pub`) issued for this key.
    pub const CERTIFICATE: &str = "certificate";
    /// Set truthy on an SSH key to require a confirmation for every signature.
    pub const CONFIRM_EACH_USE: &str = "confirm-each-use";
    /// A security key's PIN, for an `sk-` SSH key created `verify-required`.
    pub const TOKEN_PIN: &str = "token-pin";
    pub const CLIENT_ID: &str = "client-id";
    pub const CLIENT_SECRET: &str = "client-secret";
    pub const REFRESH_TOKEN: &str = "refresh-token";
    pub const ACCESS_TOKEN: &str = "access-token";
    pub const TOKEN_ENDPOINT: &str = "token-endpoint";
}

/// One attachment is refused above this many bytes. The point of an
/// attachment is a recovery-codes PDF or a key backup, not a photo library,
/// and every byte here is base64 inside a JSON body that is re-encrypted and
/// rewritten whole on each save.
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

/// An item's attachments are refused past this total.
pub const MAX_ITEM_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// How many revisions an item keeps before the oldest is dropped.
pub const MAX_REVISIONS: usize = 10;

/// Revisions are also dropped oldest-first when their serialized size passes
/// this, so one huge note edited many times cannot balloon the vault.
pub const HISTORY_BUDGET_BYTES: usize = 256 * 1024;

/// An encrypted file riding on an item — recovery codes, a key backup.
///
/// The bytes live inside the vault body like every other secret. Anything
/// writing them out again is responsible for not spooling plaintext to disk:
/// hand them to a save dialog, not a temp file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Uuid,
    /// The file name it arrived under, and the suggested name on save.
    pub name: String,
    /// MIME type, best-effort; `application/octet-stream` when unknown.
    pub mime: String,
    pub data: SecretBytes,
    pub added: Timestamp,
}

impl Attachment {
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// A prior state of an item, captured before an edit overwrote it.
///
/// The snapshot is a whole item with two exclusions that keep history from
/// feeding on itself: no nested history, and no attachments — an attachment
/// duplicated into every revision would multiply the vault by its own size.
/// Attachment changes are therefore not versioned, and the editor says so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    /// When this state was *replaced* — the moment the edit happened.
    pub saved: Timestamp,
    pub item: Item,
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
    /// When this item stops being valid — a certificate's notAfter, a token's
    /// expiry. `None` for the many kinds of item that do not expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// Prior states, newest last. Bounded by [`MAX_REVISIONS`] and
    /// [`HISTORY_BUDGET_BYTES`]; see [`Revision`] for what a snapshot excludes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<Revision>,
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
            expires: None,
            attachments: Vec::new(),
            history: Vec::new(),
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
            || self
                .fields
                .iter()
                .any(|f| hay(&f.name) || (!f.kind.is_sensitive() && hay(f.value.expose())))
    }

    /// The primary secret as the bytes an application stored.
    ///
    /// A Secret Service secret is a byte array, not a string: portal keys,
    /// wrapped tokens and DEKs are all binary. locket keeps secrets as
    /// `String` because almost every one of them is text, so a secret that is
    /// not valid UTF-8 is base64-encoded on the way in and marked with
    /// [`attr::SECRET_ENCODING`]. This is the accessor that undoes that.
    ///
    /// Reading `secret.expose().as_bytes()` directly is what silently
    /// destroyed every binary secret locket was handed: the lossy conversion
    /// replaces each invalid byte with U+FFFD, which is neither reversible nor
    /// detectable by the application getting it back.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        if self
            .attributes
            .get(attr::SECRET_ENCODING)
            .map(String::as_str)
            == Some(BASE64)
        {
            use base64ct::Encoding as _;
            if let Ok(raw) = base64ct::Base64::decode_vec(self.secret.expose()) {
                return Zeroizing::new(raw);
            }
        }
        Zeroizing::new(self.secret.expose().as_bytes().to_vec())
    }

    /// Whether the primary secret is binary, stored base64-encoded.
    ///
    /// The UI needs to know: showing the raw store to a person would present
    /// base64 as if it were the password, and decoding it to text is exactly
    /// the lossy step [`set_secret_bytes`](Self::set_secret_bytes) exists to
    /// avoid.
    pub fn secret_is_binary(&self) -> bool {
        self.attributes
            .get(attr::SECRET_ENCODING)
            .map(String::as_str)
            == Some(BASE64)
    }

    /// Whether the stored secret carries U+FFFD replacement characters.
    ///
    /// That is the fingerprint of data destroyed by a lossy conversion before
    /// the binary-secret encoding existed. The bytes are gone; the honest
    /// thing a UI can do is say so and point at the re-import path.
    pub fn secret_is_mangled(&self) -> bool {
        !self.secret_is_binary() && self.secret.expose().contains('\u{FFFD}')
    }

    /// Store bytes as the primary secret, losslessly.
    ///
    /// Text is stored as text so that `secret-tool` and the vault file stay
    /// readable; anything else is base64-encoded and marked.
    pub fn set_secret_bytes(&mut self, bytes: &[u8]) {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                self.secret = text.to_owned().into();
                self.attributes.remove(attr::SECRET_ENCODING);
            }
            Err(_) => {
                use base64ct::Encoding as _;
                self.secret = base64ct::Base64::encode_string(bytes).into();
                self.attributes
                    .insert(attr::SECRET_ENCODING.to_owned(), BASE64.to_owned());
            }
        }
    }

    pub fn touch(&mut self) {
        self.modified = now();
    }

    // -- expiry --------------------------------------------------------------

    pub fn is_expired(&self, at: Timestamp) -> bool {
        self.expires.is_some_and(|e| e <= at)
    }

    /// Expiring soon, but not yet expired — drives the "expiring" badge.
    pub fn expires_within(&self, at: Timestamp, horizon: u64) -> bool {
        self.expires
            .is_some_and(|e| e > at && e.saturating_sub(at) <= horizon)
    }

    // -- attachments ---------------------------------------------------------

    /// Attach a file's bytes, enforcing the per-attachment and per-item caps.
    pub fn add_attachment(
        &mut self,
        name: impl Into<String>,
        mime: impl Into<String>,
        data: Vec<u8>,
    ) -> crate::Result<Uuid> {
        let name = name.into();
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(crate::Error::AttachmentTooLarge {
                name,
                size: data.len(),
                max: MAX_ATTACHMENT_BYTES,
            });
        }
        let total: usize = self.attachments.iter().map(Attachment::size).sum();
        if total + data.len() > MAX_ITEM_ATTACHMENT_BYTES {
            return Err(crate::Error::AttachmentTooLarge {
                name,
                size: total + data.len(),
                max: MAX_ITEM_ATTACHMENT_BYTES,
            });
        }
        let attachment = Attachment {
            id: Uuid::new_v4(),
            name,
            mime: mime.into(),
            data: SecretBytes::new(data),
            added: now(),
        };
        let id = attachment.id;
        self.attachments.push(attachment);
        self.modified = now();
        Ok(id)
    }

    pub fn attachment(&self, id: Uuid) -> Option<&Attachment> {
        self.attachments.iter().find(|a| a.id == id)
    }

    pub fn remove_attachment(&mut self, id: Uuid) -> Option<Attachment> {
        let pos = self.attachments.iter().position(|a| a.id == id)?;
        self.modified = now();
        Some(self.attachments.remove(pos))
    }

    // -- history -------------------------------------------------------------

    /// This item as a history snapshot: itself, minus history and attachments.
    pub(crate) fn snapshot(&self) -> Item {
        let mut copy = self.clone();
        copy.history = Vec::new();
        copy.attachments = Vec::new();
        copy
    }

    /// Whether two states differ in anything history exists to recover —
    /// timestamps alone do not make a revision worth keeping.
    pub(crate) fn content_differs(a: &Item, b: &Item) -> bool {
        a.label != b.label
            || a.kind != b.kind
            || a.attributes != b.attributes
            || a.secret != b.secret
            || a.content_type != b.content_type
            || a.fields.len() != b.fields.len()
            || a.fields
                .iter()
                .zip(&b.fields)
                .any(|(x, y)| x.name != y.name || x.kind != y.kind || x.value != y.value)
            || a.tags != b.tags
            || a.expires != b.expires
    }

    /// Capture the current state as a revision. Call *before* applying an
    /// edit, so what lands in history is what the edit replaced.
    ///
    /// A state identical to the newest revision is not recorded twice, and
    /// the bounds ([`MAX_REVISIONS`], [`HISTORY_BUDGET_BYTES`]) evict
    /// oldest-first.
    pub fn record_revision(&mut self) {
        let snap = self.snapshot();
        if let Some(last) = self.history.last()
            && !Self::content_differs(&last.item, &snap)
        {
            return;
        }
        self.history.push(Revision {
            saved: now(),
            item: snap,
        });
        self.trim_history();
    }

    /// Enforce [`MAX_REVISIONS`] and [`HISTORY_BUDGET_BYTES`], oldest-first.
    pub(crate) fn trim_history(&mut self) {
        while self.history.len() > MAX_REVISIONS {
            self.history.remove(0);
        }
        while self.history.len() > 1 && self.history_size() > HISTORY_BUDGET_BYTES {
            self.history.remove(0);
        }
    }

    fn history_size(&self) -> usize {
        self.history
            .iter()
            .map(|r| serde_json::to_vec(&r.item).map(|v| v.len()).unwrap_or(0))
            .sum()
    }

    /// Drop every recorded revision.
    ///
    /// The point of history is that a replaced value is recoverable — which
    /// is exactly wrong after rotating a credential that leaked: the old one
    /// would sit in the vault until eviction. This is the way to make a
    /// rotation final, and it is not undoable.
    pub fn forget_history(&mut self) -> usize {
        let dropped = self.history.len();
        self.history.clear();
        if dropped > 0 {
            self.modified = now();
        }
        dropped
    }

    /// Restore a revision by index into [`Item::history`].
    ///
    /// The state being replaced is recorded first, so a restore is itself
    /// undoable. Attachments and identity (id, created) stay as they are —
    /// a revision never carried them.
    pub fn restore_revision(&mut self, index: usize) -> crate::Result<()> {
        let Some(revision) = self.history.get(index).cloned() else {
            return Err(crate::Error::Other(format!("no revision {index}")));
        };
        self.record_revision();
        let Revision { item: prior, .. } = revision;
        self.label = prior.label;
        self.kind = prior.kind;
        self.attributes = prior.attributes;
        self.secret = prior.secret;
        self.content_type = prior.content_type;
        self.fields = prior.fields;
        self.favorite = prior.favorite;
        self.tags = prior.tags;
        self.expires = prior.expires;
        self.modified = now();
        Ok(())
    }
}

/// A named group of items that locks and unlocks as a unit.
///
/// This is the Secret Service *collection*, carried through the vault so a
/// client's `ReadAlias`, `Collections` and per-collection locking all resolve
/// to something real rather than a single flat list.
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

/// A soft-deleted item, held outside every collection.
///
/// Trash is a separate list rather than a flag on [`Item`] so that nothing
/// serving items — the Secret Service, search, the SSH agent — has to
/// remember to filter it. A trashed item is invisible to all of them by
/// construction, which is what the delete dialog promises `libsecret`
/// clients; only the trash UI and the restore path ever see it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashedItem {
    pub item: Item,
    pub deleted: Timestamp,
    /// The collection it came from, so restore puts it back where it lived.
    pub collection: Uuid,
}

/// Preferences that belong to the vault, not to one frontend.
///
/// Stored inside the encrypted body so the daemon, the GUI and the CLI agree
/// on them wherever the file goes — a retention window enforced by only one
/// of three processes would not be a retention window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Days a trashed item survives before it is purged on unlock.
    /// `None` keeps trash forever, until emptied by hand.
    #[serde(default = "default_trash_retention")]
    pub trash_retention_days: Option<u32>,
}

fn default_trash_retention() -> Option<u32> {
    Some(30)
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            trash_retention_days: default_trash_retention(),
        }
    }
}

/// Everything inside the encrypted body of a vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trash: Vec<TrashedItem>,
    #[serde(default)]
    pub settings: VaultSettings,
}

impl Default for VaultData {
    fn default() -> Self {
        // A fresh vault ships with one collection aliased `default`, because
        // libsecret's very first call on an empty system is
        // ReadAlias("default") and returning `/` there makes clients give up.
        Self {
            collections: vec![Collection::new("Login").with_alias("default")],
            trash: Vec::new(),
            settings: VaultSettings::default(),
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

    /// Remove an item from whichever collection holds it, permanently.
    ///
    /// Most callers want [`VaultData::trash_item`]; this is the path for
    /// purging and for deletes that have already been through the trash.
    pub fn remove_item(&mut self, id: Uuid) -> Option<Item> {
        for c in &mut self.collections {
            if let Some(pos) = c.items.iter().position(|i| i.id == id) {
                c.modified = now();
                return Some(c.items.remove(pos));
            }
        }
        None
    }

    // -- trash ---------------------------------------------------------------

    /// Soft-delete: move an item out of its collection and into the trash.
    ///
    /// Returns the collection it came from, or `None` if no live item has
    /// this id. To everything except the trash UI the item is now gone.
    pub fn trash_item(&mut self, id: Uuid) -> Option<Uuid> {
        for c in &mut self.collections {
            if let Some(pos) = c.items.iter().position(|i| i.id == id) {
                let collection = c.id;
                let item = c.items.remove(pos);
                c.modified = now();
                self.trash.push(TrashedItem {
                    item,
                    deleted: now(),
                    collection,
                });
                return Some(collection);
            }
        }
        None
    }

    pub fn trashed(&self, id: Uuid) -> Option<&TrashedItem> {
        self.trash.iter().find(|t| t.item.id == id)
    }

    /// Put a trashed item back. It returns to the collection it came from,
    /// or to the default collection if that one no longer exists — restoring
    /// into nowhere would just lose it a second time.
    pub fn restore_item(&mut self, id: Uuid) -> Option<Uuid> {
        let pos = self.trash.iter().position(|t| t.item.id == id)?;
        let TrashedItem {
            item, collection, ..
        } = self.trash.remove(pos);
        let target = if self.collection(collection).is_some() {
            collection
        } else {
            self.default_collection_mut().id
        };
        let c = self
            .collection_mut(target)
            .expect("restore target was just resolved to an existing collection");
        c.items.push(item);
        c.modified = now();
        Some(target)
    }

    /// Delete a trashed item for good.
    pub fn purge_item(&mut self, id: Uuid) -> Option<Item> {
        let pos = self.trash.iter().position(|t| t.item.id == id)?;
        Some(self.trash.remove(pos).item)
    }

    /// Drop everything that has been in the trash longer than the vault's
    /// retention window. Returns how many were purged. Runs on unlock.
    pub fn purge_expired_trash(&mut self, at: Timestamp) -> usize {
        let Some(days) = self.settings.trash_retention_days else {
            return 0;
        };
        let cutoff = at.saturating_sub(u64::from(days) * 86_400);
        let before = self.trash.len();
        self.trash.retain(|t| t.deleted > cutoff);
        before - self.trash.len()
    }
}

#[cfg(test)]
mod tests {

    /// The regression that mattered: a Secret Service secret is a byte array,
    /// and reading it back as a string destroyed every binary one. Portal
    /// keys, wrapped tokens and DEKs are all binary.
    #[test]
    fn a_binary_secret_survives_a_round_trip() {
        // 64 random-looking bytes, the shape of an XDG portal application key.
        let raw: Vec<u8> = (0u16..64)
            .map(|i| (i.wrapping_mul(7) ^ 0xA5) as u8)
            .collect();
        assert!(
            std::str::from_utf8(&raw).is_err(),
            "this fixture has to be invalid UTF-8 to test anything"
        );

        let mut item = Item::new(ItemKind::Application, "Application key for com.example.App");
        item.set_secret_bytes(&raw);

        assert_eq!(
            item.secret_bytes().as_slice(),
            raw.as_slice(),
            "binary secret came back changed"
        );
        assert_eq!(
            item.attributes
                .get(attr::SECRET_ENCODING)
                .map(String::as_str),
            Some("base64"),
            "a non-UTF-8 secret must be marked, or the decode is a guess"
        );
    }

    #[test]
    fn a_text_secret_is_still_stored_as_text() {
        let mut item = Item::new(ItemKind::Login, "GitHub");
        item.set_secret_bytes(b"hunter2");

        assert_eq!(
            item.secret.expose(),
            "hunter2",
            "text was needlessly encoded"
        );
        assert!(!item.attributes.contains_key(attr::SECRET_ENCODING));
        assert_eq!(item.secret_bytes().as_slice(), b"hunter2");
    }

    #[test]
    fn switching_from_binary_back_to_text_clears_the_marker() {
        let mut item = Item::new(ItemKind::Login, "x");
        item.set_secret_bytes(&[0xff, 0xfe]);
        assert!(item.attributes.contains_key(attr::SECRET_ENCODING));

        item.set_secret_bytes(b"now text");
        assert!(
            !item.attributes.contains_key(attr::SECRET_ENCODING),
            "a stale marker would make the next read try to base64-decode plain text"
        );
        assert_eq!(item.secret_bytes().as_slice(), b"now text");
    }

    #[test]
    fn the_ui_can_tell_binary_from_text_from_damaged() {
        let mut item = Item::new(ItemKind::Login, "x");
        item.set_secret_bytes(b"plain text");
        assert!(!item.secret_is_binary());
        assert!(!item.secret_is_mangled());

        item.set_secret_bytes(&[0xff, 0xfe, 0x00]);
        assert!(item.secret_is_binary());
        // Base64 output never contains U+FFFD; a binary secret is not mangled.
        assert!(!item.secret_is_mangled());

        // The fingerprint of a pre-encoding lossy import: replacement
        // characters stored as the secret itself, with no encoding marker.
        item.attributes.remove(attr::SECRET_ENCODING);
        item.secret = "app\u{FFFD}secret\u{FFFD}".to_owned().into();
        assert!(!item.secret_is_binary());
        assert!(item.secret_is_mangled());
    }
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

    #[test]
    fn dates_roundtrip_and_reject_nonsense() {
        for date in [
            "1970-01-01",
            "2000-02-29",
            "2026-08-27",
            "2038-01-19",
            "9999-12-31",
        ] {
            let ts = parse_date(date).expect(date);
            assert_eq!(format_date(ts), date);
            assert_eq!(ts % 86_400, 0, "not midnight UTC");
        }
        // Cross-checked against `datetime(2026, 8, 27, tzinfo=UTC).timestamp()`.
        assert_eq!(parse_date("2026-08-27"), Some(1_787_788_800));
        for bad in [
            "",
            "tomorrow",
            "2026-13-01",
            "2026-00-10",
            "2026-01-32",
            "1969-12-31",
        ] {
            assert!(parse_date(bad).is_none(), "accepted `{bad}`");
        }
    }

    #[test]
    fn history_dedupes_and_stays_bounded() {
        let mut item = Item::new(ItemKind::Login, "X").with_secret("v0");
        item.record_revision();
        item.record_revision(); // unchanged: must not double up
        assert_eq!(item.history.len(), 1);

        for n in 1..=(MAX_REVISIONS + 5) {
            item.secret = format!("v{n}").into();
            item.record_revision();
        }
        assert_eq!(
            item.history.len(),
            MAX_REVISIONS,
            "history grew past its bound"
        );
        // The newest states survived; the oldest were evicted.
        assert_eq!(
            item.history.last().unwrap().item.secret.expose(),
            format!("v{}", MAX_REVISIONS + 5)
        );
    }

    #[test]
    fn forgetting_history_leaves_the_current_value_alone() {
        let mut item = Item::new(ItemKind::Login, "Bank").with_secret("leaked");
        item.record_revision();
        item.secret = "rotated".into();
        item.record_revision();
        assert_eq!(item.history.len(), 2);
        assert!(
            item.history
                .iter()
                .any(|r| r.item.secret.expose() == "leaked"),
            "the fixture should hold the leaked value"
        );

        assert_eq!(item.forget_history(), 2);
        assert!(item.history.is_empty());
        assert!(
            !item
                .history
                .iter()
                .any(|r| r.item.secret.expose() == "leaked"),
            "the rotated-away value survived"
        );
        assert_eq!(
            item.secret.expose(),
            "rotated",
            "forgetting changed the secret"
        );
        // Idempotent, and does not touch `modified` when there was nothing.
        let modified = item.modified;
        assert_eq!(item.forget_history(), 0);
        assert_eq!(item.modified, modified);
    }

    #[test]
    fn trash_restore_falls_back_to_default_when_the_collection_is_gone() {
        let mut data = VaultData::default();
        let mut work = Collection::new("Work");
        let item = Item::new(ItemKind::Login, "Work login");
        let id = item.id;
        work.items.push(item);
        let work_id = work.id;
        data.collections.push(work);

        data.trash_item(id).unwrap();
        data.collections.retain(|c| c.id != work_id);

        let restored_to = data.restore_item(id).expect("restore failed");
        assert_ne!(restored_to, work_id);
        let (c, _) = data.find_item(id).expect("item not restored");
        assert_eq!(c.alias.as_deref(), Some("default"));
    }
}
