//! `locket-native-host` — the bridge between a browser extension and the vault.
//!
//! Launched by the browser, one process per extension connection, speaking
//! native messaging on stdin/stdout. It reaches the vault the same way any
//! other application does: as an ordinary Secret Service client. It holds no
//! key material, never sees the passphrase, and cannot unlock anything.
//!
//! See [`protocol`] for why the message set is shaped the way it is.

#![forbid(unsafe_code)]

mod protocol;

use locket_secret::frontend::{self, Question};
use protocol::{Match, Request, Response};
use zbus::zvariant::OwnedObjectPath;

/// The Secret Service, from the client side.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
trait SecretService {
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
trait SecretItem {
    fn get_secret(&self, session: &OwnedObjectPath) -> zbus::Result<(SecretStruct,)>;

    fn set_secret(&self, secret: &SecretStruct) -> zbus::Result<()>;

    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<std::collections::HashMap<String, String>>;

    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets",
    assume_defaults = false
)]
trait SecretCollection {
    fn create_item(
        &self,
        properties: std::collections::HashMap<&str, zbus::zvariant::Value<'_>>,
        secret: &SecretStruct,
        replace: bool,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
}

#[derive(Debug, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
struct SecretStruct {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

/// Who is asked before a password leaves.
trait Presence {
    async fn allow(&self, question: &Question) -> bool;
}

/// The person at the keyboard, through locket's own dialog.
struct Dialog;

impl Presence for Dialog {
    async fn allow(&self, question: &Question) -> bool {
        frontend::ask(question, frontend::CONFIRM_TIMEOUT).await
    }
}

struct Host<P> {
    connection: zbus::Connection,
    session: OwnedObjectPath,
    presence: P,
}

impl<P: Presence> Host<P> {
    async fn connect(connection: zbus::Connection, presence: P) -> Option<Self> {
        let service = SecretServiceProxy::new(&connection).await.ok()?;
        // `plain` is fine: this is a local client on the user's own bus, and
        // the extension is the untrusted party here, not the transport.
        let empty = zbus::zvariant::Value::from("");
        let (_out, session) = service.open_session("plain", &empty).await.ok()?;
        Some(Self {
            connection,
            session,
            presence,
        })
    }

    async fn item(&self, path: &OwnedObjectPath) -> Option<SecretItemProxy<'_>> {
        SecretItemProxy::builder(&self.connection)
            .destination("org.freedesktop.secrets")
            .ok()?
            .path(path.clone())
            .ok()?
            .build()
            .await
            .ok()
    }

    /// Every item the service will show us, as (path, attributes, label).
    async fn all_items(
        &self,
    ) -> Vec<(
        OwnedObjectPath,
        std::collections::HashMap<String, String>,
        String,
    )> {
        let Ok(service) = SecretServiceProxy::new(&self.connection).await else {
            return Vec::new();
        };
        // An empty attribute set means "everything readable".
        let Ok((unlocked, _locked)) = service.search_items(Default::default()).await else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for path in unlocked {
            let Some(item) = self.item(&path).await else {
                continue;
            };
            let attributes = item.attributes().await.unwrap_or_default();
            let label = item.label().await.unwrap_or_default();
            out.push((path, attributes, label));
        }
        out
    }

    async fn search(&self, url: &str) -> Response {
        let mut items = Vec::new();
        for (path, attributes, label) in self.all_items().await {
            // Match against whatever the entry recorded as its location, and
            // fall back to the label — plenty of real entries are just named
            // after the site.
            let candidates = [
                attributes.get("url").map(String::as_str),
                attributes.get("uri").map(String::as_str),
                attributes.get("service").map(String::as_str),
                attributes.get("host").map(String::as_str),
                Some(label.as_str()),
            ];
            let Some(stored) = candidates
                .into_iter()
                .flatten()
                .find(|c| protocol::origin_matches(c, url))
            else {
                continue;
            };

            items.push(Match {
                id: path.to_string(),
                label: label.clone(),
                username: attributes
                    .get("username")
                    .or_else(|| attributes.get("user"))
                    .cloned()
                    .unwrap_or_default(),
                url: stored.to_owned(),
            });
        }
        Response::Matches { items }
    }

    async fn get(&self, id: &str, url: &str) -> Response {
        // The id is an object path the extension got from `search`; validate
        // it rather than trusting it to be well formed.
        let Ok(path) = OwnedObjectPath::try_from(id) else {
            return Response::Error {
                message: "not a valid item id".into(),
            };
        };
        let Some(item) = self.item(&path).await else {
            return Response::Error {
                message: "no such item".into(),
            };
        };

        // Re-check the origin at the moment of release, against the page the
        // secret is actually going into. The id is not an authorisation: the
        // extension is assumed hostile, and a tab can navigate between the
        // search and the click.
        let attributes = item.attributes().await.unwrap_or_default();
        let label = item.label().await.unwrap_or_default();
        let allowed = [
            attributes.get("url").map(String::as_str),
            attributes.get("uri").map(String::as_str),
            attributes.get("service").map(String::as_str),
            attributes.get("host").map(String::as_str),
            Some(label.as_str()),
        ]
        .into_iter()
        .flatten()
        .any(|stored| protocol::origin_matches(stored, url));
        if !allowed {
            tracing::warn!("refused a secret for an origin it is not saved for");
            return Response::Error {
                message: "that entry is not saved for this site".into(),
            };
        }

        // The origin check above only protects an honest extension from a tab
        // that navigated. The extension itself names `url`, and a hostile one
        // can name any site it likes; what it cannot do is answer this
        // dialog, which locket puts up and reads the answer from itself.
        let question = Question::Fill {
            site: protocol::origin_of(url),
            entry: label,
        };
        if !self.presence.allow(&question).await {
            tracing::info!("a fill was not allowed");
            return Response::Refused;
        }

        match item.get_secret(&self.session).await {
            Ok((secret,)) => match String::from_utf8(secret.value) {
                Ok(password) => Response::Secret {
                    id: id.to_owned(),
                    password,
                },
                // A lossy conversion here would type replacement characters
                // into the form and look like a wrong password forever. Some
                // secrets genuinely are binary — portal application keys are
                // 64 random bytes — and none of those belong in a login form.
                Err(_) => Response::Error {
                    message: "that entry's secret is not text, so it cannot be typed into a page"
                        .into(),
                },
            },
            Err(e) => Response::Error {
                message: format!("could not read the secret: {e}"),
            },
        }
    }
}

impl<P: Presence> Host<P> {
    /// Store a submitted credential: update the entry already saved for this
    /// origin and username, or create a new one in the default collection.
    async fn save(&self, url: &str, username: &str, password: &str) -> Response {
        let origin = protocol::origin_of(url);
        if origin.is_empty() {
            return Response::Error {
                message: "the page has no usable origin".into(),
            };
        }

        let secret = SecretStruct {
            session: self.session.clone(),
            parameters: Vec::new(),
            value: password.as_bytes().to_vec(),
            content_type: "text/plain".into(),
        };

        // An existing entry for the same origin *and* username is updated in
        // place — SetSecret files the old value into the item's history on
        // the service side, so a bad save is undoable from locket.
        for (path, attributes, label) in self.all_items().await {
            let stored_user = attributes
                .get("username")
                .or_else(|| attributes.get("user"))
                .map(String::as_str)
                .unwrap_or_default();
            if stored_user != username {
                continue;
            }
            let matches_origin = [
                attributes.get("url").map(String::as_str),
                attributes.get("uri").map(String::as_str),
                attributes.get("service").map(String::as_str),
                attributes.get("host").map(String::as_str),
                Some(label.as_str()),
            ]
            .into_iter()
            .flatten()
            .any(|stored| protocol::origin_matches(stored, url));
            if !matches_origin {
                continue;
            }

            let Some(item) = self.item(&path).await else {
                continue;
            };
            // Saving what is already there is a no-op, not a revision. The
            // extension no longer reads the stored password to decide whether
            // a submitted one is new — that would mean a confirmation dialog on
            // every login — so the comparison happens here, and nothing about
            // the stored value leaves this process.
            if let Ok((current,)) = item.get_secret(&self.session).await
                && zeroize::Zeroizing::new(current.value).as_slice() == secret.value
            {
                return Response::Unchanged;
            }
            return match item.set_secret(&secret).await {
                Ok(()) => Response::Saved { updated: true },
                Err(e) => Response::Error {
                    message: format!("could not update the entry: {e}"),
                },
            };
        }

        // No match: a new login in the default collection, attributed the
        // way locket's own importers attribute — so the next Search finds it.
        let collection = match SecretCollectionProxy::builder(&self.connection)
            .path("/org/freedesktop/secrets/aliases/default")
        {
            Ok(builder) => match builder.build().await {
                Ok(collection) => collection,
                Err(e) => {
                    return Response::Error {
                        message: format!("no default collection: {e}"),
                    };
                }
            },
            Err(e) => {
                return Response::Error {
                    message: format!("no default collection: {e}"),
                };
            }
        };

        let label = origin.clone();
        let mut attributes = std::collections::HashMap::new();
        attributes.insert("url", origin.as_str());
        if !username.is_empty() {
            attributes.insert("username", username);
        }
        attributes.insert("xdg:schema", "org.freedesktop.Secret.Generic");
        let mut properties: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> =
            std::collections::HashMap::new();
        properties.insert(
            "org.freedesktop.Secret.Item.Label",
            zbus::zvariant::Value::from(label.as_str()),
        );
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            zbus::zvariant::Value::from(attributes),
        );

        match collection.create_item(properties, &secret, false).await {
            Ok(_) => Response::Saved { updated: false },
            Err(e) => Response::Error {
                message: format!("could not save the entry: {e}"),
            },
        }
    }
}

/// The Secret Service on the session bus, asking through locket's dialog.
async fn connect() -> Option<Host<Dialog>> {
    let connection = zbus::Connection::session().await.ok()?;
    Host::connect(connection, Dialog).await
}

/// Is a daemon there, and is it unlocked?
async fn status() -> Response {
    match locket_secret::client::status().await {
        Some(s) => Response::Status {
            unlocked: !s.locked,
            daemon: true,
        },
        None => Response::Status {
            unlocked: false,
            daemon: false,
        },
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // stdout is the protocol channel — logging must never touch it.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "locket_nmh=warn".into()),
        )
        .init();

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let request = match protocol::read_message(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => break, // browser closed the pipe
            Err(e) => {
                tracing::warn!("bad request: {e}");
                let _ = protocol::write_message(
                    &mut writer,
                    &Response::Error {
                        message: e.to_string(),
                    },
                );
                continue;
            }
        };

        let response = match request {
            Request::Status => status().await,
            other => match connect().await {
                None => Response::Error {
                    message: "no secret service is running".into(),
                },
                Some(host) => {
                    // Refuse everything while locked. Unlocking is locket's
                    // job, not a web page's.
                    let locked = locket_secret::client::status()
                        .await
                        .map(|s| s.locked)
                        .unwrap_or(true);
                    if locked {
                        Response::Locked
                    } else {
                        match other {
                            Request::Search { url } => host.search(&url).await,
                            Request::Get { id, url } => host.get(&id, &url).await,
                            Request::Save {
                                url,
                                username,
                                password,
                            } => host.save(&url, &username, &password).await,
                            Request::Status => unreachable!("handled above"),
                        }
                    }
                }
            },
        };

        if let Err(e) = protocol::write_message(&mut writer, &response) {
            tracing::error!("could not reply: {e}");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::model::{Item, ItemKind};
    use locket_secret::testing::Daemon;

    /// Answers every question the same way, and counts them.
    struct Answer {
        allow: bool,
        asked: std::cell::Cell<u32>,
    }

    impl Answer {
        fn new(allow: bool) -> Self {
            Self {
                allow,
                asked: std::cell::Cell::new(0),
            }
        }
    }

    impl Presence for &Answer {
        async fn allow(&self, _question: &Question) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.allow
        }
    }

    /// A daemon holding one login for github.com, and its item id.
    async fn daemon_with_login() -> (Daemon, String) {
        let daemon = Daemon::start().await;
        let id = {
            let mut state = daemon.state.lock().await;
            let vault = state.vault.as_mut().unwrap();
            let mut item = Item::new(ItemKind::Login, "GitHub")
                .with_attribute("url", "https://github.com")
                .with_attribute("username", "ada");
            item.set_secret_bytes(b"hunter2");
            let collection = vault.data().collections[0].id;
            let id = vault.add_item(collection, item).unwrap();
            vault.save().unwrap();
            locket_secret::service::item_path(collection, id).to_string()
        };
        locket_secret::service::register_vault_objects(
            daemon.server.object_server(),
            &daemon.state,
        )
        .await
        .unwrap();
        (daemon, id)
    }

    /// The extension names the page, so a hostile one can name any site and
    /// the origin check passes. What it cannot do is answer locket's dialog:
    /// without the person's yes, no password leaves.
    #[tokio::test]
    async fn a_password_is_released_only_when_the_person_allows_it() {
        let (daemon, id) = daemon_with_login().await;

        let refuse = Answer::new(false);
        let host = Host::connect(daemon.bus.connect().await, &refuse)
            .await
            .unwrap();
        assert_eq!(
            host.get(&id, "https://github.com/login").await,
            Response::Refused
        );
        assert_eq!(refuse.asked.get(), 1, "the person was never asked");

        let allow = Answer::new(true);
        let host = Host::connect(daemon.bus.connect().await, &allow)
            .await
            .unwrap();
        assert_eq!(
            host.get(&id, "https://github.com/login").await,
            Response::Secret {
                id: id.clone(),
                password: "hunter2".into()
            }
        );
    }

    /// A page the entry is not saved for is refused before anyone is asked:
    /// a dialog offering github.com's password to another site would be a
    /// question with only one safe answer.
    #[tokio::test]
    async fn another_sites_page_is_refused_without_asking() {
        let (daemon, id) = daemon_with_login().await;
        let allow = Answer::new(true);
        let host = Host::connect(daemon.bus.connect().await, &allow)
            .await
            .unwrap();
        assert!(matches!(
            host.get(&id, "https://github.com.evil.test/").await,
            Response::Error { .. }
        ));
        assert_eq!(allow.asked.get(), 0);
    }

    /// Saving what is already stored writes nothing and asks nobody.
    #[tokio::test]
    async fn saving_the_stored_password_again_changes_nothing() {
        let (daemon, _) = daemon_with_login().await;
        let refuse = Answer::new(false);
        let host = Host::connect(daemon.bus.connect().await, &refuse)
            .await
            .unwrap();
        assert_eq!(
            host.save("https://github.com/session", "ada", "hunter2")
                .await,
            Response::Unchanged
        );
        assert_eq!(refuse.asked.get(), 0);
        let state = daemon.state.lock().await;
        let item = state
            .vault
            .as_ref()
            .unwrap()
            .data()
            .all_items()
            .find(|(_, i)| i.label == "GitHub")
            .map(|(_, i)| i.clone())
            .unwrap();
        assert!(item.history.is_empty(), "an unchanged save made a revision");
    }
}
