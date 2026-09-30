//! A private message bus for tests that have to go over D-Bus.
//!
//! Built only with the `test-bus` feature, which this crate's own tests and
//! the native host's enable as a dev-dependency; nothing shipped links it.
//!
//! Each test gets its own `dbus-daemon`, started from a configuration written
//! here rather than the system's `session.conf`. That difference is the point:
//! the stock session configuration reads the service directories under
//! `/usr/share/dbus-1/services`, and a call to a name nobody owns would then
//! *activate* whatever is registered for it — `org.freedesktop.secrets` on this
//! machine is the live keyring. This bus has no service directories, so a
//! mistake here fails with `ServiceUnknown` instead of starting anything.
//!
//! Nothing in these tests may use `Connection::session()`: every connection is
//! made to the address this bus printed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use crate::manager::{MANAGER_PATH, Manager};
use crate::service::{
    ServiceConfig, ServiceState, SharedState, register_objects, spawn_upkeep, sync_objects,
};
use locket_core::Vault;
use locket_core::crypto::KdfParams;
use tokio::sync::Mutex;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// A `dbus-daemon` that lives as long as this value.
pub struct PrivateBus {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}

impl PrivateBus {
    pub fn start() -> Self {
        Self::start_with(None)
    }

    /// A bus that can activate the services described in `services` — a
    /// directory the test wrote, never the system's. For checking that
    /// something does *not* start a service by calling its name.
    pub fn start_activating(services: &Path) -> Self {
        Self::start_with(Some(services))
    }

    fn start_with(services: Option<&Path>) -> Self {
        let dir = tempfile::tempdir().expect("temporary directory for the bus");
        let config = dir.path().join("bus.conf");
        let services = services
            .map(|d| format!("<servicedir>{}</servicedir>", d.display()))
            .unwrap_or_default();
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir={}</listen>
  {services}
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                dir.path().display()
            ),
        )
        .expect("write the bus configuration");

        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("dbus-daemon must be installed to run the bus tests");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("piped stdout"))
            .read_line(&mut line)
            .expect("read the bus address");
        let address = line.trim().to_owned();
        assert!(!address.is_empty(), "dbus-daemon printed no address");
        Self {
            child,
            address,
            _dir: dir,
        }
    }

    /// Where this bus listens, for a client that is its own process.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// A new connection to this bus.
    pub async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("a valid bus address")
            .build()
            .await
            .expect("connect to the private bus")
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A daemon's worth of objects served on a private bus, over a vault in a
/// temporary directory.
pub struct Daemon {
    pub bus: PrivateBus,
    pub server: zbus::Connection,
    pub state: SharedState,
    pub vault_path: PathBuf,
    _dir: tempfile::TempDir,
}

pub const PASSPHRASE: &str = "correct horse";

/// How long a locked search holds its caller here: the daemon's twenty
/// seconds, scaled down so a test of "nobody answered" does not take them.
pub const UNLOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// How long an unlock dialog stays answerable here; two minutes in the daemon.
pub const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

impl Daemon {
    /// Serve a fresh vault, unlocked, with its objects published the way
    /// `locketd` publishes them.
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("temporary directory for the vault");
        let vault_path = dir.path().join("test.vault");
        let vault = Vault::create(&vault_path, PASSPHRASE, KdfParams::insecure_fast())
            .expect("create a vault");
        Self::serve(dir, vault_path, Some(vault)).await
    }

    /// Serve an existing vault file, locked.
    pub async fn start_locked(dir: tempfile::TempDir, vault_path: PathBuf) -> Self {
        Self::serve(dir, vault_path, None).await
    }

    async fn serve(dir: tempfile::TempDir, vault_path: PathBuf, vault: Option<Vault>) -> Self {
        let bus = PrivateBus::start();
        let mut state = ServiceState::new(ServiceConfig {
            bus_name: "org.locket.test".into(),
            autosave: true,
            unlock_wait: UNLOCK_WAIT,
            prompt_timeout: PROMPT_TIMEOUT,
        });
        state.index = Vault::read_index(&vault_path).unwrap_or_default();
        state.vault = vault;
        let state = Arc::new(Mutex::new(state));

        let server = bus.connect().await;
        register_objects(server.object_server(), &state)
            .await
            .expect("publish the service objects");
        spawn_upkeep(&server, &state);
        server
            .object_server()
            .at(
                MANAGER_PATH,
                Manager::new(state.clone(), vault_path.clone()),
            )
            .await
            .expect("publish the manager");
        // The name clients look for. Safe to take here and only here: this
        // bus is private, so nothing else can be displaced by it.
        server
            .request_name(crate::WELL_KNOWN_NAME)
            .await
            .expect("own the Secret Service name on the private bus");

        Self {
            bus,
            server,
            state,
            vault_path,
            _dir: dir,
        }
    }

    /// Lock the vault and answer unlock requests the way `locketd` does, with
    /// `launch` standing in for starting the GUI — never the real one: a test
    /// must not put a window on this desktop.
    pub async fn lock_and_serve_prompts(
        &self,
        launch: impl Fn() -> std::io::Result<String> + Send + Sync + 'static,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        {
            let mut state = self.state.lock().await;
            state.prompts = Some(tx);
            state.lock_vault();
        }
        sync_objects(self.server.object_server(), &self.state)
            .await
            .expect("take the item objects down");
        tokio::spawn(crate::manager::serve_prompts(
            self.server.clone(),
            self.state.clone(),
            rx,
            launch,
        ));
    }

    /// Unlock after `delay`, as a person typing the passphrase would.
    pub fn unlock_after(&self, delay: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        let path = self.vault_path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let vault = Vault::open(&path, PASSPHRASE).expect("open the test vault");
            state.lock().await.install_unlocked(vault);
        })
    }

    /// The server's unique name, which clients address directly.
    pub fn name(&self) -> String {
        self.server
            .unique_name()
            .expect("a bus connection has a unique name")
            .to_string()
    }

    /// A client of this daemon.
    pub async fn client(&self) -> Client {
        Client {
            connection: self.bus.connect().await,
            destination: self.name(),
        }
    }

    /// Where the vault file is, for a second writer.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }
}

/// One bus peer, talking to the daemon with raw method calls.
pub struct Client {
    pub connection: zbus::Connection,
    destination: String,
}

impl Client {
    pub async fn proxy(&self, path: &str, interface: &str) -> zbus::Proxy<'static> {
        zbus::Proxy::new_owned(
            self.connection.clone(),
            self.destination.clone(),
            path.to_owned(),
            interface.to_owned(),
        )
        .await
        .expect("build a proxy")
    }

    pub async fn service(&self) -> zbus::Proxy<'static> {
        self.proxy(crate::SERVICE_PATH, "org.freedesktop.Secret.Service")
            .await
    }

    pub async fn manager(&self) -> zbus::Proxy<'static> {
        self.proxy(MANAGER_PATH, "org.locket.Manager1").await
    }

    /// Open a `plain` session.
    pub async fn open_session(&self) -> OwnedObjectPath {
        let (_, path): (OwnedValue, OwnedObjectPath) = self
            .service()
            .await
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .expect("OpenSession");
        path
    }

    /// Every item `SearchItems({})` reports.
    pub async fn search_all(&self) -> zbus::Result<Vec<OwnedObjectPath>> {
        let (unlocked, _locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
            .service()
            .await
            .call("SearchItems", &(HashMap::<String, String>::new(),))
            .await?;
        Ok(unlocked)
    }

    /// An item's label, read over the bus as the native host and the applet do.
    pub async fn item_label(&self, path: &OwnedObjectPath) -> zbus::Result<String> {
        self.proxy(path.as_str(), "org.freedesktop.Secret.Item")
            .await
            .get_property::<String>("Label")
            .await
    }

    /// Whether an object is published at `path`, by introspecting it.
    pub async fn exists(&self, path: &str) -> bool {
        let proxy = self
            .proxy(path, "org.freedesktop.DBus.Introspectable")
            .await;
        let xml: String = proxy.call("Introspect", &()).await.unwrap_or_default();
        xml.contains("org.freedesktop.Secret.")
    }

    /// The introspection XML of one object.
    pub async fn introspect(&self, path: &str) -> String {
        self.proxy(path, "org.freedesktop.DBus.Introspectable")
            .await
            .call("Introspect", &())
            .await
            .expect("Introspect")
    }
}

/// The error name of a failed call, for asserting on the D-Bus error names
/// clients branch on.
pub fn error_name(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        zbus::Error::FDO(fdo) => zbus::DBusError::name(fdo.as_ref()).to_string(),
        other => format!("<not a method error: {other}>"),
    }
}
