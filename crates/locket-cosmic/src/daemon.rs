//! Talking to `locketd` over `org.locket.Manager1`.
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
//! directly", which is what happens when locket is used without a daemon.

use cosmic::iced::Subscription;
use cosmic::iced::futures::{SinkExt, StreamExt, channel::mpsc};
use cosmic::iced::stream;
// One definition of the interface, shared with the applet.
use locket_secret::client;

/// What the daemon tells the frontend.
#[derive(Clone, Debug)]
pub enum DaemonEvent {
    /// A daemon is present. `locked` is its state at the time of connecting.
    Connected { locked: bool },
    /// An application asked for a secret and the vault is locked.
    UnlockRequested,
    /// The daemon locked, for this reason: `request`, `idle`, `session`,
    /// `suspend`, `shutdown` or `error`.
    Locked { reason: String },
    /// The daemon went away, or was never there.
    Unavailable,
}

/// What the subscription hears from the bus.
enum Heard {
    UnlockRequested,
    Locked(String),
    /// The daemon's name changed hands: `true` when somebody owns it now.
    Owner(bool),
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

                let Ok(requests) = proxy.receive_unlock_requested().await else {
                    let _ = tx.send(DaemonEvent::Unavailable).await;
                    continue;
                };
                // A signal stream does not end when the daemon leaves the bus
                // — it follows the name to whoever owns it next — so a
                // restarted daemon has to be noticed through the name itself.
                // Without this it ran on its own idle default, because
                // `Connected` is what hands it the user's setting.
                let Ok(owners) = proxy.inner().receive_owner_changed().await else {
                    let _ = tx.send(DaemonEvent::Unavailable).await;
                    continue;
                };
                let Ok(locks) = proxy.receive_vault_locked().await else {
                    let _ = tx.send(DaemonEvent::Unavailable).await;
                    continue;
                };
                let locks = locks.filter_map(|signal| {
                    std::future::ready(match signal.args() {
                        Ok(args) => Some(Heard::Locked(args.reason().to_owned())),
                        Err(e) => {
                            tracing::warn!("unreadable VaultLocked signal: {e}");
                            None
                        }
                    })
                });
                let mut heard = cosmic::iced::futures::stream::select(
                    cosmic::iced::futures::stream::select(
                        requests.map(|_| Heard::UnlockRequested),
                        owners.map(|owner| Heard::Owner(owner.is_some())),
                    ),
                    locks,
                );

                while let Some(event) = heard.next().await {
                    let event = match event {
                        Heard::UnlockRequested => {
                            tracing::info!("daemon asked for an unlock");
                            DaemonEvent::UnlockRequested
                        }
                        Heard::Locked(reason) => {
                            tracing::info!(reason, "daemon locked");
                            DaemonEvent::Locked { reason }
                        }
                        // A fresh connection, so the lock state is the new
                        // daemon's rather than a value cached from the old.
                        Heard::Owner(true) => DaemonEvent::Connected {
                            locked: match client::connect().await {
                                Some((_connection, fresh)) => fresh.locked().await.unwrap_or(true),
                                None => true,
                            },
                        },
                        Heard::Owner(false) => DaemonEvent::Unavailable,
                    };
                    let _ = tx.send(event).await;
                }
                let _ = tx.send(DaemonEvent::Unavailable).await;
            }
        })
    })
}

/// How the daemon answered a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// No daemon on the bus: running without one is a supported
    /// configuration, not a failure.
    NoDaemon,
    /// It did what was asked.
    Done,
    /// It was there and did not: a passphrase it rejected, or a call that
    /// failed.
    Refused,
}

/// Hand a passphrase to the daemon.
pub async fn unlock(passphrase: locket_core::SecretString) -> Reply {
    let Some((_connection, proxy)) = client::connect().await else {
        return Reply::NoDaemon;
    };
    match proxy.unlock(passphrase.expose()).await {
        Ok(true) => {
            tracing::info!("daemon unlocked");
            Reply::Done
        }
        Ok(false) => {
            tracing::warn!("daemon rejected the passphrase");
            Reply::Refused
        }
        Err(e) => {
            tracing::warn!("could not unlock the daemon: {e}");
            Reply::Refused
        }
    }
}

/// Tell the daemon the person dismissed its unlock request, so the
/// application that asked is refused now instead of after a timeout.
pub async fn cancel_unlock() {
    let Some((_connection, proxy)) = client::connect().await else {
        return;
    };
    if let Err(e) = proxy.cancel_unlock().await {
        tracing::warn!("could not refuse the unlock request: {e}");
    }
}

/// Give the daemon the idle timeout from the desktop's settings.
///
/// The frontend owns the number; the daemon's `--auto-lock` flag is only the
/// default for a session where no frontend ever runs. Sent on connect and on
/// every change, so the two never disagree about what "auto-lock" means.
pub async fn set_auto_lock(seconds: u64) {
    let Some((_connection, proxy)) = client::connect().await else {
        return;
    };
    if let Err(e) = proxy.set_auto_lock(seconds).await {
        tracing::warn!("could not set the daemon's auto-lock: {e}");
    }
}

/// Tell the daemon we have written the vault file, so it re-reads it.
///
/// Best effort: no daemon is a supported setup, and a daemon that cannot
/// reload has said so in its own log.
pub async fn reload() -> bool {
    let Some((_connection, proxy)) = client::connect().await else {
        return false;
    };
    proxy.reload().await.unwrap_or(false)
}

/// Ask the daemon to drop its key too, so locking the GUI locks everything.
pub async fn lock() -> Reply {
    let Some((_connection, proxy)) = client::connect().await else {
        return Reply::NoDaemon;
    };
    match proxy.lock().await {
        Ok(()) => Reply::Done,
        Err(e) => {
            tracing::warn!("could not lock the daemon: {e}");
            Reply::Refused
        }
    }
}
