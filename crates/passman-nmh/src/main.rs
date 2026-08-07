//! `passman-native-host` — the bridge between a browser extension and the vault.
//!
//! Launched by the browser, one process per extension connection, speaking
//! native messaging on stdin/stdout. It reaches the vault the same way any
//! other application does: as an ordinary Secret Service client. It holds no
//! key material, never sees the passphrase, and cannot unlock anything.
//!
//! See [`protocol`] for why the message set is shaped the way it is.

mod protocol;

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

struct Host {
    connection: zbus::Connection,
    session: OwnedObjectPath,
}

impl Host {
    async fn connect() -> Option<Self> {
        let connection = zbus::Connection::session().await.ok()?;
        let service = SecretServiceProxy::new(&connection).await.ok()?;
        // `plain` is fine: this is a local client on the user's own bus, and
        // the extension is the untrusted party here, not the transport.
        let empty = zbus::zvariant::Value::from("");
        let (_out, session) = service.open_session("plain", &empty).await.ok()?;
        Some(Self {
            connection,
            session,
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
    async fn all_items(&self) -> Vec<(OwnedObjectPath, std::collections::HashMap<String, String>, String)> {
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

    async fn get(&self, id: &str) -> Response {
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
        match item.get_secret(&self.session).await {
            Ok((secret,)) => Response::Secret {
                id: id.to_owned(),
                password: String::from_utf8_lossy(&secret.value).into_owned(),
            },
            Err(e) => Response::Error {
                message: format!("could not read the secret: {e}"),
            },
        }
    }
}

/// Is a daemon there, and is it unlocked?
async fn status() -> Response {
    match passman_secret::client::status().await {
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
                .unwrap_or_else(|_| "passman_nmh=warn".into()),
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
            other => match Host::connect().await {
                None => Response::Error {
                    message: "no secret service is running".into(),
                },
                Some(host) => {
                    // Refuse everything while locked. Unlocking is passman's
                    // job, not a web page's.
                    let locked = passman_secret::client::status()
                        .await
                        .map(|s| s.locked)
                        .unwrap_or(true);
                    if locked {
                        Response::Locked
                    } else {
                        match other {
                            Request::Search { url } => host.search(&url).await,
                            Request::Get { id } => host.get(&id).await,
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
