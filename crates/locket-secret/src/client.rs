//! Client side of `org.locket.Manager1`.
//!
//! Shared by the GUI and the panel applet so there is one definition of the
//! interface rather than a copy per frontend — a drifting proxy is the kind of
//! bug that only shows up as "the applet says locked but the window says
//! unlocked".

use zbus::Connection;

/// Bus names to look for, in order. The daemon defaults to the locket name so
/// it does not displace gnome-keyring, but takes the freedesktop name when
/// started with `--replace-keyring`.
pub const BUS_NAMES: &[&str] = &[crate::WELL_KNOWN_NAME, crate::DEV_NAME];

pub const MANAGER_PATH: &str = "/org/locket/Manager";

#[zbus::proxy(interface = "org.locket.Manager1", assume_defaults = false)]
pub trait Manager {
    fn unlock(&self, passphrase: &str) -> zbus::Result<bool>;
    fn lock(&self) -> zbus::Result<()>;
    /// Tell the daemon its copy of the vault file is out of date.
    fn reload(&self) -> zbus::Result<bool>;
    /// Set the daemon's idle timeout, in seconds. 0 turns it off.
    fn set_auto_lock(&self, seconds: u64) -> zbus::Result<()>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn item_count(&self) -> zbus::Result<u32>;

    #[zbus(property)]
    fn vault_path(&self) -> zbus::Result<String>;

    /// Allow or refuse a signature the daemon asked about.
    fn answer_confirm(&self, id: u32, allow: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    fn unlock_requested(&self) -> zbus::Result<()>;

    /// One SSH signature is waiting to be allowed; `key` names the identity.
    #[zbus(signal)]
    fn confirm_requested(&self, id: u32, key: String) -> zbus::Result<()>;
}

/// Connect to whichever bus name the daemon holds.
///
/// The connection is returned alongside the proxy because dropping it would
/// take the proxy's signal stream with it.
pub async fn connect() -> Option<(Connection, ManagerProxy<'static>)> {
    let connection = Connection::session().await.ok()?;
    for name in BUS_NAMES {
        let Ok(builder) = ManagerProxy::builder(&connection).destination(*name) else {
            continue;
        };
        let Ok(builder) = builder.path(MANAGER_PATH) else {
            continue;
        };
        let Ok(proxy) = builder.build().await else {
            continue;
        };
        // Building a proxy succeeds even for an absent service, so probe a
        // property to find out whether anybody is actually there.
        if proxy.locked().await.is_ok() {
            tracing::debug!("connected to locketd on {name}");
            return Some((connection, proxy));
        }
    }
    None
}

/// A snapshot of the daemon's state, for status displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub locked: bool,
    pub items: u32,
}

/// Read the daemon's current state. `None` means no daemon is running.
pub async fn status() -> Option<Status> {
    let (_connection, proxy) = connect().await?;
    Some(Status {
        locked: proxy.locked().await.ok()?,
        // An unlocked daemon knows its item count; a locked one reports zero.
        items: proxy.item_count().await.unwrap_or(0),
    })
}

/// Ask the daemon to lock. Returns whether it was reached.
pub async fn lock() -> bool {
    match connect().await {
        Some((_c, proxy)) => proxy.lock().await.is_ok(),
        None => false,
    }
}

/// Hand a passphrase to the daemon. `false` covers both "refused" and "no
/// daemon", because running without one is a supported configuration rather
/// than an error.
pub async fn unlock(passphrase: &str) -> bool {
    match connect().await {
        Some((_c, proxy)) => proxy.unlock(passphrase).await.unwrap_or(false),
        None => false,
    }
}
