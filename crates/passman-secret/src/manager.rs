//! `org.passman.Manager1` — passman's own control surface.
//!
//! The freedesktop Secret Service has no way to *unlock* a service: its
//! `Prompt` objects say "ask the user" without saying how, because on GNOME
//! the answer is a gnome-keyring-specific dialog. This interface is that
//! missing half — the frontend calls [`Manager::unlock`] with a passphrase,
//! and the daemon reopens the vault and republishes the object tree.
//!
//! It also closes the loop on prompts. When a `libsecret` client calls
//! `Prompt()` on a locked vault, the daemon emits [`unlock_requested`]; a
//! running frontend raises its unlock dialog and calls `Unlock`. The Prompt
//! then completes successfully instead of being refused, which is what makes
//! "an app asked for a secret and passman asked me for my passphrase" work.
//!
//! [`unlock_requested`]: Manager::unlock_requested

use std::path::PathBuf;
use std::sync::Arc;

use passman_core::Vault;
use tokio::sync::Mutex;
use zbus::object_server::SignalEmitter;
use zbus::{ObjectServer, fdo, interface};

use crate::service::{ServiceState, SharedState, register_vault_objects};

/// How long a Secret Service `Prompt` waits for the user before giving up.
pub const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

pub const MANAGER_PATH: &str = "/org/passman/Manager";

pub struct Manager {
    pub state: SharedState,
    /// Retained across lock/unlock: once the vault is dropped there is nothing
    /// left to tell us which file to reopen.
    pub vault_path: PathBuf,
}

impl Manager {
    pub fn new(state: SharedState, vault_path: PathBuf) -> Self {
        Self { state, vault_path }
    }
}

#[interface(name = "org.passman.Manager1")]
impl Manager {
    /// Open the vault and publish its objects. Returns whether it worked.
    ///
    /// A wrong passphrase is a `false` return rather than a D-Bus error: it is
    /// an expected outcome of a user typing, not a fault.
    async fn unlock(
        &self,
        passphrase: String,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<bool> {
        {
            let state = self.state.lock().await;
            if !state.is_locked() {
                return Ok(true);
            }
        }

        // Argon2id is deliberately slow; keep it off the executor's core
        // threads so the daemon stays responsive to other bus traffic.
        let path = self.vault_path.clone();
        let opened = tokio::task::spawn_blocking(move || Vault::open(&path, &passphrase))
            .await
            .map_err(|e| fdo::Error::Failed(format!("unlock task failed: {e}")))?;

        let vault = match opened {
            Ok(v) => v,
            Err(e) => {
                tracing::info!("unlock refused: {e}");
                return Ok(false);
            }
        };

        {
            let mut state = self.state.lock().await;
            // Upgrade an older file now that it is open, so the next locked
            // start has a collection index to answer ReadAlias from.
            let mut vault = vault;
            if vault.format() < passman_core::vault::FORMAT_VERSION
                && let Err(e) = vault.save()
            {
                tracing::warn!("could not upgrade the vault format: {e}");
            }
            state.index = vault
                .data()
                .collections
                .iter()
                .map(|c| passman_core::vault::CollectionIndex {
                    id: c.id,
                    label: c.label.clone(),
                    alias: c.alias.clone(),
                })
                .collect();
            state.vault = Some(vault);
        }
        register_vault_objects(server, &self.state)
            .await
            .map_err(fdo::Error::from)?;

        tracing::info!("vault unlocked over org.passman.Manager1");
        Ok(true)
    }

    /// Drop the data-encryption key. Objects stay published but report locked.
    async fn lock(&self) -> fdo::Result<()> {
        let mut state = self.state.lock().await;
        if let Some(v) = state.vault.as_mut()
            && let Err(e) = v.save()
        {
            tracing::error!("failed to save on lock: {e}");
        }
        state.vault = None;
        tracing::info!("vault locked");
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.state.lock().await.is_locked()
    }

    #[zbus(property)]
    async fn vault_path(&self) -> String {
        self.vault_path.display().to_string()
    }

    #[zbus(property)]
    async fn item_count(&self) -> u32 {
        let state = self.state.lock().await;
        state
            .vault
            .as_ref()
            .map(|v| v.data().item_count() as u32)
            .unwrap_or(0)
    }

    /// Emitted when a Secret Service client needs the vault unlocked.
    ///
    /// A frontend should raise its unlock dialog and call `Unlock`.
    #[zbus(signal)]
    pub async fn unlock_requested(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

/// Bridge `Prompt` objects to the frontend.
///
/// Runs for the lifetime of the daemon: each time a locked-vault prompt
/// arrives it emits `UnlockRequested` and then waits for the vault to actually
/// become unlocked, answering the waiting `libsecret` client either way.
///
/// Polling for the state change (rather than having `unlock` notify) keeps the
/// two paths independent: an unlock typed directly into the frontend, with no
/// prompt outstanding, resolves any pending prompt just the same.
pub async fn serve_prompts(
    connection: zbus::Connection,
    state: SharedState,
    mut requests: tokio::sync::mpsc::Receiver<crate::service::PromptRequest>,
) {
    while let Some(request) = requests.recv().await {
        let crate::service::PromptRequest::Unlock { reply } = request;

        if !state.lock().await.is_locked() {
            let _ = reply.send(true);
            continue;
        }

        let emitter = match SignalEmitter::new(&connection, MANAGER_PATH) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("cannot emit unlock request: {e}");
                let _ = reply.send(false);
                continue;
            }
        };
        if let Err(e) = Manager::unlock_requested(&emitter).await {
            tracing::error!("failed to emit UnlockRequested: {e}");
            let _ = reply.send(false);
            continue;
        }
        tracing::info!("asked the frontend to unlock");

        // A signal only helps if something is listening. Give a running
        // frontend a moment to react, then start one — otherwise an
        // application asking for a secret on a machine with no passman window
        // open just waits for a prompt nobody can answer.
        if !wait_until_unlocked(&state, std::time::Duration::from_secs(2)).await {
            match spawn_frontend() {
                Ok(path) => tracing::info!("no frontend responded; launched {path} to prompt"),
                Err(e) => tracing::warn!("could not launch the frontend to prompt: {e}"),
            }
        }

        let unlocked = wait_until_unlocked(&state, PROMPT_TIMEOUT).await;
        if !unlocked {
            tracing::info!("unlock request timed out after {PROMPT_TIMEOUT:?}");
        }
        let _ = reply.send(unlocked);
    }
}

/// Start the GUI so somebody can answer the prompt.
///
/// Resolved next to this executable before falling back to `PATH`: the daemon
/// runs as a systemd user unit, whose environment is not the login shell's, so
/// a `PATH` lookup is not something an unlock path should depend on.
fn spawn_frontend() -> std::io::Result<String> {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("passman")))
        .filter(|p| p.is_file());

    let candidate = match &sibling {
        Some(p) => p.as_os_str().to_owned(),
        None => std::ffi::OsString::from("passman"),
    };
    std::process::Command::new(&candidate)
        .spawn()
        .map(|_| candidate.to_string_lossy().into_owned())
}

async fn wait_until_unlocked(state: &Arc<Mutex<ServiceState>>, timeout: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    loop {
        ticker.tick().await;
        if !state.lock().await.is_locked() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceConfig;
    use passman_core::crypto::KdfParams;

    fn state() -> SharedState {
        Arc::new(Mutex::new(ServiceState::new(ServiceConfig {
            bus_name: "org.passman.test".into(),
            autosave: false,
        })))
    }

    #[tokio::test]
    async fn wait_returns_immediately_when_already_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let s = state();
        s.lock().await.vault = Some(vault);

        let start = std::time::Instant::now();
        assert!(wait_until_unlocked(&s, std::time::Duration::from_secs(5)).await);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn wait_times_out_while_locked() {
        let s = state();
        assert!(!wait_until_unlocked(&s, std::time::Duration::from_millis(300)).await);
    }

    #[tokio::test]
    async fn wait_observes_an_unlock_that_happens_mid_wait() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let s = state();
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            s2.lock().await.vault = Some(vault);
        });

        assert!(
            wait_until_unlocked(&s, std::time::Duration::from_secs(5)).await,
            "an unlock during the wait was not observed"
        );
    }
}
