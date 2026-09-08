//! Label-first lookup for the panel applet and anything else that wants to
//! find one credential quickly.
//!
//! This is an ordinary Secret Service *client* — it talks to whatever holds
//! `org.freedesktop.secrets`, exactly as `libsecret` would, and holds no key
//! material of its own. Kept here rather than reimplemented per frontend so
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

async fn service(connection: &zbus::Connection) -> Option<QuickServiceProxy<'static>> {
    for name in crate::client::BUS_NAMES {
        if let Ok(builder) = QuickServiceProxy::builder(connection).destination(*name)
            && let Ok(builder) = builder.path("/org/freedesktop/secrets")
            && let Ok(proxy) = builder.build().await
            // Reachability is the question, not the answer: a name that is
            // registered but unowned answers nothing.
            && proxy.search_items(Default::default()).await.is_ok()
        {
            return Some(proxy);
        }
    }
    None
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
    let Some(service) = service(&connection).await else {
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
        let Ok(builder) = QuickItemProxy::builder(&connection)
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
pub async fn secret_of(path: &str) -> Option<String> {
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
    String::from_utf8(secret.value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
