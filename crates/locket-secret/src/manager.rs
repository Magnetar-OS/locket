//! `org.locket.Manager1` — locket's own control surface.
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
//! "an app asked for a secret and locket asked me for my passphrase" work.
//!
//! [`unlock_requested`]: Manager::unlock_requested

use std::path::PathBuf;
use std::sync::Arc;

use locket_core::Vault;
use tokio::sync::Mutex;
use zbus::object_server::SignalEmitter;
use zbus::{ObjectServer, fdo, interface};

use crate::service::{ServiceState, SharedState, sync_objects};

/// How long a Secret Service `Prompt` waits for the user before giving up.
pub const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

pub const MANAGER_PATH: &str = "/org/locket/Manager";

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

#[interface(name = "org.locket.Manager1")]
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
            if vault.format() < locket_core::vault::FORMAT_VERSION
                && let Err(e) = vault.save()
            {
                tracing::warn!("could not upgrade the vault format: {e}");
            }
            state.index = vault
                .data()
                .collections
                .iter()
                .map(|c| locket_core::vault::CollectionIndex {
                    id: c.id,
                    label: c.label.clone(),
                    alias: c.alias.clone(),
                })
                .collect();
            state.open_vault(vault);
        }
        sync_objects(server, &self.state)
            .await
            .map_err(fdo::Error::from)?;

        tracing::info!("vault unlocked over org.locket.Manager1");
        Ok(true)
    }

    /// Drop the data-encryption key, and the item objects with it.
    async fn lock(&self, #[zbus(object_server)] server: &ObjectServer) -> fdo::Result<()> {
        {
            self.state.lock().await.lock_vault();
        }
        sync_objects(server, &self.state)
            .await
            .map_err(fdo::Error::from)?;
        tracing::info!("vault locked");
        Ok(())
    }

    /// Set the idle timeout, in seconds. 0 turns it off.
    ///
    /// The frontend owns this number — it is stored with the rest of the
    /// desktop's settings in `cosmic-config` — and pushes it here so that one
    /// setting means one thing. `locketd --auto-lock` is the default for a
    /// session where no frontend ever runs.
    async fn set_auto_lock(&self, seconds: u64) -> fdo::Result<()> {
        let state = self.state.lock().await;
        if state.auto_lock_seconds() != seconds {
            tracing::info!(seconds, "idle auto-lock changed by the frontend");
        }
        state.set_auto_lock_seconds(seconds);
        Ok(())
    }

    /// Re-read the vault file, for when another process has written to it.
    ///
    /// The frontend edits the vault file directly, so after it saves the
    /// daemon is holding a stale copy — one that would serve outdated secrets
    /// and, worse, refuse its own next save for conflicting. Rather than
    /// having the daemon poll, whoever wrote the file says so.
    ///
    /// Returns false when the vault is locked (nothing to refresh) or the
    /// reload failed, which happens when the other writer changed the key
    /// material: the DEK we hold no longer opens that file, and the honest
    /// answer is to lock and ask for the new passphrase.
    async fn reload(&self, #[zbus(object_server)] server: &ObjectServer) -> fdo::Result<bool> {
        let reloaded = {
            let mut state = self.state.lock().await;
            let Some(vault) = state.vault.as_mut() else {
                return Ok(false);
            };
            if !vault.changed_on_disk() {
                return Ok(true);
            }
            match vault.reload() {
                Ok(()) => {
                    tracing::info!("reloaded the vault after an external write");
                    // Everything watching the vault — the SSH agent above all —
                    // has to see the new contents, not the ones it cached.
                    state.notify_opened();
                    true
                }
                Err(e) => {
                    tracing::warn!("could not reload the vault: {e}; locking instead");
                    state.close_vault();
                    false
                }
            }
        };
        // Items the other writer added are reachable at their paths before
        // this returns, and removed ones are gone.
        sync_objects(server, &self.state)
            .await
            .map_err(fdo::Error::from)?;
        Ok(reloaded)
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
///
/// Signing confirmations do not come through here: see [`crate::frontend`].
pub async fn serve_prompts(
    connection: zbus::Connection,
    state: SharedState,
    mut requests: tokio::sync::mpsc::Receiver<crate::service::PromptRequest>,
) {
    while let Some(request) = requests.recv().await {
        let reply = request.reply;

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
        // application asking for a secret on a machine with no locket window
        // open just waits for a prompt nobody can answer.
        if !wait_until_unlocked(&state, std::time::Duration::from_secs(2)).await {
            match crate::frontend::spawn_prompt() {
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

async fn wait_until_unlocked(
    state: &Arc<Mutex<ServiceState>>,
    timeout: std::time::Duration,
) -> bool {
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
    use locket_core::crypto::KdfParams;

    fn state() -> SharedState {
        Arc::new(Mutex::new(ServiceState::new(ServiceConfig {
            bus_name: "org.locket.test".into(),
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
