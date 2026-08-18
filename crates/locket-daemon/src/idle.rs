//! Locking the vault when nobody is using it, and when the session locks.
//!
//! The frontend has an idle timer of its own, but it only knows about its own
//! window: close it and the daemon would hold the data-encryption key until
//! logout. Everything here is about the session as a whole.

use std::sync::Arc;

use futures_util::StreamExt as _;
use locket_secret::service::SharedState;

/// Poll interval for the idle check.
///
/// Coarse on purpose. The deadline moves every time anything touches the
/// vault, so scheduling for an exact instant would mean rescheduling on every
/// request to gain nothing a person could perceive.
const TICK: std::time::Duration = std::time::Duration::from_secs(15);

/// Lock the vault once it has been idle for as long as the setting says.
///
/// The timeout is read from the shared state on every tick rather than taken
/// as an argument, because the frontend changes it at runtime — this task has
/// to be running even when the timeout is currently zero, or turning it on in
/// Settings would do nothing until the next login.
pub async fn auto_lock(
    state: SharedState,
    agent: Option<Arc<std::sync::Mutex<locket_agent::Agent>>>,
) {
    loop {
        tokio::time::sleep(TICK).await;

        let (seconds, idle) = {
            let guard = state.lock().await;
            if guard.is_locked() {
                continue;
            }
            (guard.auto_lock_seconds(), guard.idle_seconds())
        };
        if seconds == 0 {
            continue;
        }
        // SSH counts as use. Someone running `ssh` every minute is using their
        // vault, even though no Secret Service client read anything.
        let idle = match agent.as_ref() {
            Some(agent) => {
                let last = agent
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .last_request();
                idle.min(seconds_since(last))
            }
            None => idle,
        };

        if idle >= seconds {
            tracing::info!(idle, "locking the vault after idling");
            state.lock().await.close_vault();
        }
    }
}

fn seconds_since(unix_seconds: u64) -> u64 {
    if unix_seconds == 0 {
        return u64::MAX;
    }
    locket_core::model::now().saturating_sub(unix_seconds)
}

/// `org.freedesktop.login1`, the part of it we need.
#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait LoginManager {
    /// Emitted with `true` before suspend and `false` after resume.
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;

    fn get_session(&self, session_id: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

    fn get_session_by_pid(&self, pid: u32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1"
)]
trait LoginSession {
    /// Emitted when something asks the session to lock — `loginctl
    /// lock-session`, a lid switch, an idle timeout.
    #[zbus(signal)]
    fn lock(&self) -> zbus::Result<()>;

    /// Set by the screen locker itself once it is up.
    #[zbus(property)]
    fn locked_hint(&self) -> zbus::Result<bool>;
}

/// Lock the vault when the session locks or the machine suspends.
///
/// Both signals are watched because they are set by different things: the
/// `Lock` signal is what `loginctl lock-session` sends, while a compositor
/// that locks its own screen announces it by setting `LockedHint`. Missing
/// either would mean a locked screen with a readable vault behind it.
pub async fn lock_with_session(state: SharedState) -> zbus::Result<()> {
    let connection = zbus::Connection::system().await?;
    let manager = LoginManagerProxy::new(&connection).await?;

    let mut sleeping = manager.receive_prepare_for_sleep().await?;
    let session_path = session_path(&manager).await;

    let session = match session_path {
        Some(path) => Some(
            LoginSessionProxy::builder(&connection)
                .path(path)?
                .build()
                .await?,
        ),
        None => {
            tracing::warn!("no logind session found; only suspend will lock the vault");
            None
        }
    };

    let mut locks = match session.as_ref() {
        Some(s) => Some(s.receive_lock().await?),
        None => None,
    };
    let mut hints = match session.as_ref() {
        Some(s) => Some(s.receive_locked_hint_changed().await),
        None => None,
    };

    loop {
        tokio::select! {
            Some(signal) = sleeping.next() => {
                if signal.args().map(|a| a.start).unwrap_or(false) {
                    lock(&state, "the machine is suspending").await;
                }
            }
            Some(_) = async { match locks.as_mut() { Some(s) => s.next().await, None => None } } => {
                lock(&state, "the session was locked").await;
            }
            Some(change) = async { match hints.as_mut() { Some(s) => s.next().await, None => None } } => {
                if change.get().await.unwrap_or(false) {
                    lock(&state, "the screen locker came up").await;
                }
            }
            else => return Ok(()),
        }
    }
}

async fn lock(state: &SharedState, why: &str) {
    let mut guard = state.lock().await;
    if guard.is_locked() {
        return;
    }
    tracing::info!("locking the vault: {why}");
    guard.close_vault();
}

/// This process's logind session, by id if the environment names one and by
/// pid otherwise — a daemon started by systemd inherits the former, one
/// started by hand may not.
async fn session_path(
    manager: &LoginManagerProxy<'_>,
) -> Option<zbus::zvariant::OwnedObjectPath> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID")
        && let Ok(path) = manager.get_session(&id).await
    {
        return Some(path);
    }
    manager.get_session_by_pid(std::process::id()).await.ok()
}
