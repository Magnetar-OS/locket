//! Label-first lookup for the panel applet and anything else that wants to
//! find one credential quickly.
//!
//! This is an ordinary Secret Service *client* — it talks to locketd's Secret
//! Service, on whichever bus name the daemon holds, exactly as `libsecret`
//! would, and holds no key material of its own. Kept here rather than reimplemented per frontend so
//! there is one definition of the lookup; the browser's native host predates
//! it and has its own, narrower rules.
//!
//! Two properties the callers depend on:
//!
//! * **[`search`] never returns a secret.** It answers with labels and
//!   subtitles, so a surface that only needs to *show* candidates never has
//!   the values on hand.
//! * **[`secret_of`] fetches exactly one**, by a path a previous search
//!   returned, at the moment the person asks for it.

use zbus::zvariant::OwnedObjectPath;

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_path = "/org/freedesktop/secrets",
    assume_defaults = false
)]
trait QuickService {
    fn open_session(
        &self,
        algorithm: &str,
        input: &zbus::zvariant::Value<'_>,
    ) -> zbus::Result<(zbus::zvariant::OwnedValue, OwnedObjectPath)>;

    fn search_items(
        &self,
        attributes: std::collections::HashMap<&str, &str>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Item", assume_defaults = false)]
trait QuickItem {
    fn get_secret(&self, session: &OwnedObjectPath) -> zbus::Result<(SecretStruct,)>;

    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<std::collections::HashMap<String, String>>;

    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;
}

#[derive(Debug, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
struct SecretStruct {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

/// One candidate, without its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The item's object path; pass it back to [`secret_of`].
    pub path: String,
    pub label: String,
    /// Username or service, for the second line.
    pub subtitle: String,
}

/// Whether `needle` matches this item, case-insensitively.
///
/// Label and the handful of attributes a person would recognise. Secret
/// values are not searched — and could not be, since nothing here has read
/// one — which is the same rule the vault's own search follows.
fn matches(
    needle: &str,
    label: &str,
    attributes: &std::collections::HashMap<String, String>,
) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.to_lowercase();
    let hay = |s: &str| s.to_lowercase().contains(&needle);
    hay(label)
        || [
            "username",
            "user",
            "service",
            "url",
            "uri",
            "host",
            "application",
        ]
        .iter()
        .filter_map(|k| attributes.get(*k))
        .any(|v| hay(v))
}

fn subtitle_of(attributes: &std::collections::HashMap<String, String>) -> String {
    for key in ["username", "user", "service", "url", "host", "application"] {
        if let Some(v) = attributes.get(key).filter(|v| !v.is_empty()) {
            return v.clone();
        }
    }
    String::new()
}

/// locketd's Secret Service, on the bus name its manager answers on.
///
/// The applet's lock state comes from `org.locket.Manager1`; the search must
/// reach the same daemon. Taking whatever owns `org.freedesktop.secrets`
/// found gnome-keyring when locketd ran on its own name beside it, and
/// listed that keyring's items under locket's status.
async fn service(connection: &zbus::Connection) -> Option<QuickServiceProxy<'static>> {
    let manager = crate::client::manager_on(connection).await?;
    let name = manager.inner().destination().to_owned();
    QuickServiceProxy::builder(connection)
        .destination(name)
        .ok()?
        .path("/org/freedesktop/secrets")
        .ok()?
        .build()
        .await
        .ok()
}

/// Items whose label or recognisable attributes match `needle`, capped at
/// `limit`. Metadata only.
///
/// An empty list is the honest answer when the vault is locked: a locked
/// service reports no unlocked items, and the caller says so rather than
/// this function pretending to know why.
pub async fn search(needle: &str, limit: usize) -> Vec<Entry> {
    let Ok(connection) = zbus::Connection::session().await else {
        return Vec::new();
    };
    search_on(&connection, needle, limit).await
}

async fn search_on(connection: &zbus::Connection, needle: &str, limit: usize) -> Vec<Entry> {
    let Some(service) = service(connection).await else {
        return Vec::new();
    };
    // An empty attribute set means "everything readable".
    let Ok((unlocked, _locked)) = service.search_items(Default::default()).await else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for path in unlocked {
        if found.len() >= limit {
            break;
        }
        let Ok(builder) = QuickItemProxy::builder(connection)
            .destination(service.inner().destination().to_owned())
        else {
            continue;
        };
        let Ok(builder) = builder.path(path.clone()) else {
            continue;
        };
        let Ok(item) = builder.build().await else {
            continue;
        };
        let label = item.label().await.unwrap_or_default();
        let attributes = item.attributes().await.unwrap_or_default();
        if !matches(needle, &label, &attributes) {
            continue;
        }
        found.push(Entry {
            path: path.to_string(),
            label,
            subtitle: subtitle_of(&attributes),
        });
    }
    found.sort_by_key(|e| e.label.to_lowercase());
    found
}

/// The secret behind one path from [`search`].
///
/// `None` when it cannot be read, or when it is not text — a binary secret
/// is a key, and putting base64 on the clipboard as if it were a password
/// would be a lie the person only finds out about after pasting it.
///
/// Wiped when dropped, and so are the bytes it came in as, whichever way.
pub async fn secret_of(path: &str) -> Option<locket_core::SecretString> {
    let connection = zbus::Connection::session().await.ok()?;
    let service = service(&connection).await?;
    let empty = zbus::zvariant::Value::from("");
    let (_out, session) = service.open_session("plain", &empty).await.ok()?;

    let path = OwnedObjectPath::try_from(path).ok()?;
    let item = QuickItemProxy::builder(&connection)
        .destination(service.inner().destination().to_owned())
        .ok()?
        .path(path)
        .ok()?
        .build()
        .await
        .ok()?;
    let (secret,) = item.get_secret(&session).await.ok()?;
    match String::from_utf8(secret.value) {
        // The same buffer, moved: nothing is left behind to wipe.
        Ok(text) => Some(text.into()),
        Err(not_text) => {
            zeroize::Zeroize::zeroize(&mut not_text.into_bytes());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The applet shows locketd's lock state, from `org.locket.Manager1`, so
    /// its search has to reach the same daemon. It searched whatever owned
    /// `org.freedesktop.secrets` — gnome-keyring, when locketd runs on its
    /// own name beside it — and listed another keyring's items under
    /// locket's status.
    #[tokio::test]
    async fn search_reaches_the_daemon_the_status_comes_from() {
        use crate::service::{ServiceConfig, ServiceState, register_objects};
        use crate::testing::Daemon;
        use locket_core::model::{Item, ItemKind};

        let daemon = Daemon::start().await;
        {
            let mut state = daemon.state.lock().await;
            let vault = state.vault.as_mut().unwrap();
            vault.add_item_default(Item::new(ItemKind::Note, "in locket"));
            vault.save().unwrap();
        }
        crate::service::sync_objects(daemon.server.object_server(), &daemon.state)
            .await
            .unwrap();
        // locketd on its own name, as it runs beside gnome-keyring...
        daemon
            .server
            .release_name(crate::WELL_KNOWN_NAME)
            .await
            .unwrap();
        daemon.server.request_name(crate::DEV_NAME).await.unwrap();

        // ...and another keyring on the freedesktop one.
        let dir = tempfile::tempdir().unwrap();
        let mut other = locket_core::Vault::create(
            dir.path().join("other.vault"),
            "other",
            locket_core::crypto::KdfParams::insecure_fast(),
        )
        .unwrap();
        other.add_item_default(Item::new(ItemKind::Note, "in another keyring"));
        let mut state = ServiceState::new(ServiceConfig::default());
        state.vault = Some(other);
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(state));
        let keyring = daemon.bus.connect().await;
        register_objects(keyring.object_server(), &state)
            .await
            .unwrap();
        keyring.request_name(crate::WELL_KNOWN_NAME).await.unwrap();

        let client = daemon.bus.connect().await;
        let found = search_on(&client, "", 10).await;
        let labels: Vec<&str> = found.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(labels, ["in locket"]);
    }

    fn attrs(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn matching_covers_the_label_and_the_obvious_attributes() {
        let a = attrs(&[("username", "ada"), ("service", "github.com")]);
        assert!(matches("git", "GitHub", &a));
        assert!(matches("ADA", "GitHub", &a));
        assert!(matches("github.com", "Something else", &a));
        assert!(!matches("gitlab", "GitHub", &a));
        // An empty needle is "show me everything", which is what an
        // just-opened search box means.
        assert!(matches("", "anything", &attrs(&[])));
    }

    #[test]
    fn the_subtitle_prefers_a_username_over_a_url() {
        assert_eq!(
            subtitle_of(&attrs(&[("url", "https://x"), ("username", "ada")])),
            "ada"
        );
        assert_eq!(subtitle_of(&attrs(&[("url", "https://x")])), "https://x");
        assert_eq!(subtitle_of(&attrs(&[])), "");
        // An empty value is not a subtitle.
        assert_eq!(subtitle_of(&attrs(&[("username", ""), ("host", "h")])), "h");
    }
}
