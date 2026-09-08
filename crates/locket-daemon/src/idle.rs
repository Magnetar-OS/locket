//! Locking the vault when nobody is using it, and when the session locks.
//!
//! The frontend has an idle timer of its own, but it only knows about its own
//! window: close it and the daemon would hold the data-encryption key until
//! logout. Everything here is about the session as a whole.

use std::sync::Arc;

use futures_util::StreamExt as _;
use locket_secret::service::SharedState;

/// `org.freedesktop.Notifications`, the one call we make.
#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: Vec<&str>,
        hints: std::collections::HashMap<&str, zbus::zvariant::Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// Tell the desktop the vault just locked, and why.
///
/// The vault locking is the one daemon event that changes what every other
/// application can do, and it happens with no window on screen to say so —
/// an application "forgetting" its login half an hour later is the silent
/// failure this line of text prevents. Best effort: a session without a
/// notification service just gets the journal line.
///
/// The body carries the reason and nothing else — no labels, no counts,
/// nothing read out of the vault.
async fn notify_locked(why: &str) {
    let result = async {
        let connection = zbus::Connection::session().await?;
        let proxy = NotificationsProxy::new(&connection).await?;
        proxy
            .notify(
                "locket",
                0,
                "com.magnetaros.Locket",
                "Vault locked",
                why,
                Vec::new(),
                Default::default(),
                5_000,
            )
            .await
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("could not send the lock notification: {e}");
    }
}

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
    notify: bool,
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
            if notify {
                notify_locked("Locked after being idle. Unlock in locket when you need it.").await;
            }
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

    fn get_user(&self, uid: u32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

/// The per-user object, for the one property that survives running outside a
/// login session.
#[zbus::proxy(
    interface = "org.freedesktop.login1.User",
    default_service = "org.freedesktop.login1"
)]
trait LoginUser {
    /// The user's primary graphical session, as `(id, object path)`.
    #[zbus(property)]
    fn display(&self) -> zbus::Result<(String, zbus::zvariant::OwnedObjectPath)>;
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
pub async fn lock_with_session(state: SharedState, notify: bool) -> zbus::Result<()> {
    let connection = zbus::Connection::system().await?;
    let manager = LoginManagerProxy::new(&connection).await?;

    let mut sleeping = manager.receive_prepare_for_sleep().await?;
    let session_path = session_path(&manager).await;

    let session = match session_path {
        Some(path) => {
            // Said out loud because the failure is silent otherwise: a daemon
            // that found no session still runs, still locks on suspend, and
            // never mentions that the screen lock goes unwatched.
            tracing::info!(session = %path.as_str(), "following the session's lock state");
            Some(
                LoginSessionProxy::builder(&connection)
                    .path(path)?
                    .build()
                    .await?,
            )
        }
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
                    lock(&state, "the machine is suspending", notify).await;
                }
            }
            Some(_) = async { match locks.as_mut() { Some(s) => s.next().await, None => None } } => {
                lock(&state, "the session was locked", notify).await;
            }
            Some(change) = async { match hints.as_mut() { Some(s) => s.next().await, None => None } } => {
                if change.get().await.unwrap_or(false) {
                    lock(&state, "the screen locker came up", notify).await;
                }
            }
            else => return Ok(()),
        }
    }
}

async fn lock(state: &SharedState, why: &str, notify: bool) {
    {
        let mut guard = state.lock().await;
        if guard.is_locked() {
            return;
        }
        tracing::info!("locking the vault: {why}");
        guard.close_vault();
    }
    // After suspend the notification lands on resume, which is exactly when
    // someone would wonder why their applications re-ask for things.
    if notify {
        notify_locked(&format!("Locked because {why}.")).await;
    }
}

/// This process's logind session.
///
/// Three ways, because none of them works everywhere:
///
/// 1. `XDG_SESSION_ID`, when something put it in the environment.
/// 2. The session owning this pid, for a daemon started by hand from a
///    terminal inside the session.
/// 3. The user's *display* session, asked of logind directly.
///
/// The third exists because the first two both fail in the arrangement the
/// shipped unit actually creates: a systemd **user** unit runs under
/// `user@<uid>.service`, which logind classes as a manager session rather
/// than a login one. `XDG_SESSION_ID` is not in the user manager's
/// environment, and `GetSessionByPID` answers "does not belong to any known
/// session" — measured on a live COSMIC session, where it left the daemon
/// following suspend only and silently not following the screen lock at all.
async fn session_path(manager: &LoginManagerProxy<'_>) -> Option<zbus::zvariant::OwnedObjectPath> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID")
        && let Ok(path) = manager.get_session(&id).await
    {
        return Some(path);
    }
    if let Ok(path) = manager.get_session_by_pid(std::process::id()).await {
        return Some(path);
    }

    // Safety: `getuid` reads this process's own real uid and cannot fail.
    let uid = unsafe { libc::getuid() };
    let user = manager.get_user(uid).await.ok()?;
    let user = LoginUserProxy::builder(manager.inner().connection())
        .path(user)
        .ok()?
        .build()
        .await
        .ok()?;
    let (id, path) = user.display().await.ok()?;
    // A user with no graphical session gets an empty path rather than an
    // error, and following that would be following nothing.
    if id.is_empty() {
        return None;
    }
    Some(path)
}
