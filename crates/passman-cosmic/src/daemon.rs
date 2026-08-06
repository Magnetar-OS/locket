//! Talking to `passmand` over `org.passman.Manager1`.
//!
//! Two directions:
//!
//! * **Outbound** — when the user unlocks in the GUI, the same passphrase is
//!   handed to the daemon so one entry unlocks both. Without this the GUI would
//!   show your secrets while every `libsecret` app still saw a locked vault.
//! * **Inbound** — the daemon emits `UnlockRequested` when an application asks
//!   for a secret it cannot reach. The subscription below turns that into a
//!   message, so the unlock screen appears *because an app needs something*
//!   rather than at an arbitrary moment.
//!
//! The daemon is optional. Everything degrades to "GUI edits the vault file
//! directly", which is what happens when passman is used without a daemon.

use cosmic::iced::Subscription;
use cosmic::iced::futures::{SinkExt, StreamExt, channel::mpsc};
use cosmic::iced::stream;
// One definition of the interface, shared with the applet.
use passman_secret::client;

/// What the daemon tells the frontend.
#[derive(Clone, Debug)]
pub enum DaemonEvent {
    /// A daemon is present. `locked` is its state at the time of connecting.
    Connected { locked: bool },
    /// An application asked for a secret and the vault is locked.
    UnlockRequested,
    /// The daemon went away, or was never there.
    Unavailable,
}

/// Watch the daemon for unlock requests.
pub fn subscription() -> Subscription<DaemonEvent> {
    Subscription::run(|| {
        stream::channel(8, |mut tx: mpsc::Sender<DaemonEvent>| async move {
            let mut backoff = 1u64;
            loop {
                let Some((_connection, proxy)) = client::connect().await else {
                    let _ = tx.send(DaemonEvent::Unavailable).await;
                    // Back off rather than spinning on a machine with no
                    // daemon, but keep trying so starting one later is noticed.
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(30);
                    continue;
                };
                backoff = 1;

                let locked = proxy.locked().await.unwrap_or(true);
                let _ = tx.send(DaemonEvent::Connected { locked }).await;

                let Ok(mut requests) = proxy.receive_unlock_requested().await else {
                    let _ = tx.send(DaemonEvent::Unavailable).await;
                    continue;
                };

                // Ends when the daemon drops off the bus, which sends us back
                // around to reconnect.
                while requests.next().await.is_some() {
                    tracing::info!("daemon asked for an unlock");
                    let _ = tx.send(DaemonEvent::UnlockRequested).await;
                }
                let _ = tx.send(DaemonEvent::Unavailable).await;
            }
        })
    })
}

/// Hand a passphrase to the daemon. Returns whether it unlocked.
///
/// A missing daemon is `Ok(false)`, not an error: running without one is a
/// supported configuration, not a failure.
pub async fn unlock(passphrase: String) -> bool {
    let Some((_connection, proxy)) = client::connect().await else {
        return false;
    };
    match proxy.unlock(&passphrase).await {
        Ok(ok) => {
            if ok {
                tracing::info!("daemon unlocked");
            } else {
                tracing::warn!("daemon rejected the passphrase");
            }
            ok
        }
        Err(e) => {
            tracing::warn!("could not unlock the daemon: {e}");
            false
        }
    }
}

/// Ask the daemon to drop its key too, so locking the GUI locks everything.
pub async fn lock() -> bool {
    let Some((_connection, proxy)) = client::connect().await else {
        return false;
    };
    proxy.lock().await.is_ok()
}
