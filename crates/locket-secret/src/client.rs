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
    /// The person dismissed the unlock dialog.
    fn cancel_unlock(&self) -> zbus::Result<()>;
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

    #[zbus(signal)]
    fn unlock_requested(&self) -> zbus::Result<()>;

    /// The vault locked. `reason` is one of `request`, `idle`, `session`,
    /// `suspend`, `shutdown`, `error`.
    #[zbus(signal)]
    fn vault_locked(&self, reason: String) -> zbus::Result<()>;
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

/// Tell a daemon that is already running that `vault` was just written, so it
/// re-reads the file instead of serving what it read before.
///
/// For a writer that has to work with no daemon at all — the command line.
/// `None` means there was nobody to tell: no session bus, no daemon on it, or
/// a daemon serving a different file. Otherwise the result of `Reload`.
///
/// Unlike [`connect`], this never starts a daemon. It asks the bus who owns
/// the name before calling it, because a call to a name nobody owns is what
/// makes the bus activate the service registered for it — and a recovery tool
/// run because the daemon will not start must not sit waiting for it to.
pub async fn reload_running(vault: &std::path::Path) -> Option<zbus::Result<bool>> {
    let connection = Connection::session().await.ok()?;
    let bus = zbus::fdo::DBusProxy::new(&connection).await.ok()?;
    for name in BUS_NAMES {
        let Ok(bus_name) = zbus::names::BusName::try_from(*name) else {
            continue;
        };
        if !bus.name_has_owner(bus_name).await.unwrap_or(false) {
            continue;
        }
        let Ok(proxy) = ManagerProxy::builder(&connection)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .destination(*name)
            .and_then(|b| b.path(MANAGER_PATH))
        else {
            continue;
        };
        let Ok(proxy) = proxy.build().await else {
            continue;
        };
        // Something else may own the name — gnome-keyring, on the freedesktop
        // one — and a locketd may be serving another vault.
        let Ok(served) = proxy.vault_path().await else {
            continue;
        };
        if !same_file(std::path::Path::new(&served), vault) {
            continue;
        }
        return Some(proxy.reload().await);
    }
    None
}

/// Whether two paths name one file, however each was spelled.
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
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
