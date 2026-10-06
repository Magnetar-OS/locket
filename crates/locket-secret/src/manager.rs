//! `org.locket.Manager1` — locket's own control surface.
//!
//! The freedesktop Secret Service has no way to *unlock* a service: its
//! `Prompt` objects say "ask the user" without saying how, because on GNOME
//! the answer is a gnome-keyring-specific dialog. This interface is that
//! missing half — the frontend calls [`Manager::unlock`] with a passphrase,
//! and the daemon reopens the vault and republishes the object tree.
//!
//! A vault with a TPM or security-key slot can be unlocked with that slot's
//! key instead, through [`Manager::unlock_with_key`].
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

use locket_core::{
    Vault,
    crypto::SymKey,
    slots::{RawKeyOpener, SlotKind},
};
use tokio::sync::Mutex;
use zbus::object_server::SignalEmitter;
use zbus::{ObjectServer, fdo, interface};

use crate::service::{LockReason, PromptRequest, ServiceState, SharedState, sync_objects};

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

    /// Open the vault with `open` and publish its objects, unless it is open
    /// already. `false` when `open` was refused.
    async fn unlock_by(
        &self,
        server: &ObjectServer,
        with: &'static str,
        open: impl FnOnce(&std::path::Path) -> locket_core::Result<Vault> + Send + 'static,
    ) -> fdo::Result<bool> {
        if !self.state.lock().await.is_locked() {
            return Ok(true);
        }

        // Argon2id is deliberately slow; keep it off the executor's core
        // threads so the daemon stays responsive to other bus traffic.
        let path = self.vault_path.clone();
        let opened = tokio::task::spawn_blocking(move || open(&path))
            .await
            .map_err(|e| fdo::Error::Failed(format!("unlock task failed: {e}")))?;

        let vault = match opened {
            Ok(v) => v,
            Err(e) => {
                tracing::info!("unlock with {with} refused: {e}");
                return Ok(false);
            }
        };

        if !self.state.lock().await.install_unlocked(vault) {
            // Another unlock finished first; its vault stays.
            return Ok(true);
        }
        sync_objects(server, &self.state)
            .await
            .map_err(fdo::Error::from)?;

        tracing::info!("vault unlocked over org.locket.Manager1 with {with}");
        Ok(true)
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
        // Wiped when the task ends, whichever way the unlock went.
        let passphrase = zeroize::Zeroizing::new(passphrase);
        self.unlock_by(server, "a passphrase", move |path| {
            Vault::open(path, &passphrase)
        })
        .await
    }

    /// Open the vault with the key of one of its hardware slots. Returns
    /// whether it worked.
    ///
    /// The daemon talks to no TPM and no security key. Whoever asks the
    /// person for the PIN or the touch — the unlock dialog, the window —
    /// does that, opens its own copy with the key the device released, and
    /// hands the same key here, so one PIN or one touch unlocks both. `factor`
    /// is the slot's type as the vault file spells it: `tpm2` or `fido2`.
    ///
    /// The key crosses the session bus as a passphrase does through
    /// [`Manager::unlock`], and is worth the same there: it opens this vault.
    async fn unlock_with_key(
        &self,
        factor: String,
        key: Vec<u8>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<bool> {
        let key = zeroize::Zeroizing::new(key);
        let kind = SlotKind::from_name(&factor)
            .filter(|kind| *kind != SlotKind::Passphrase)
            .ok_or_else(|| {
                fdo::Error::InvalidArgs(format!("`{factor}` is not a hardware factor"))
            })?;
        // A key of the wrong length opens nothing, like any other wrong key.
        let Ok(key) = SymKey::try_from_slice(&key) else {
            return Ok(false);
        };
        self.unlock_by(server, kind.label(), move |path| {
            Vault::open_with(path, &RawKeyOpener { kind, key })
        })
        .await
    }

    /// Drop the data-encryption key, and the item objects with it.
    async fn lock(&self, #[zbus(object_server)] server: &ObjectServer) -> fdo::Result<()> {
        {
            self.state.lock().await.lock_vault(LockReason::Request);
        }
        sync_objects(server, &self.state)
            .await
            .map_err(fdo::Error::from)?;
        tracing::info!("vault locked");
        Ok(())
    }

    /// The person dismissed the unlock dialog: refuse the requests waiting
    /// on it now. Their `Prompt`s complete with `dismissed = true`, which is
    /// the Secret Service's way of saying no, instead of each client waiting
    /// out its timeout.
    async fn cancel_unlock(&self) -> fdo::Result<()> {
        self.state.lock().await.unlock_refused.notify_waiters();
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

    /// Emitted when the vault has locked, with why: `request`, `idle`,
    /// `session`, `suspend`, `shutdown` or `error`. See
    /// [`crate::service::LockReason`].
    #[zbus(signal)]
    pub async fn vault_locked(emitter: &SignalEmitter<'_>, reason: &str) -> zbus::Result<()>;
}

/// Announce a lock on the manager's path.
pub(crate) async fn announce_lock(
    connection: &zbus::Connection,
    reason: LockReason,
) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(connection, MANAGER_PATH)?;
    Manager::vault_locked(&emitter, reason.as_str()).await
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
/// One dialog answers everybody. Requests that arrive while it is up wait on
/// it and get its answer, whichever way it goes; a request whose caller has
/// stopped waiting raises nothing. Otherwise each application that asked
/// during one unattended stretch would have its own two minutes of dialog
/// queued up, re-launched one after another long after it had given up.
///
/// Signing confirmations do not come through here: see [`crate::frontend`].
///
/// `launch` starts a frontend when none answered the signal —
/// [`crate::frontend::spawn_prompt`] in the daemon.
pub async fn serve_prompts(
    connection: zbus::Connection,
    state: SharedState,
    mut requests: tokio::sync::mpsc::Receiver<PromptRequest>,
    launch: impl Fn() -> std::io::Result<String>,
) {
    let (refused, patience) = {
        let guard = state.lock().await;
        (guard.unlock_refused.clone(), guard.config.prompt_timeout)
    };
    while let Some(request) = next_waiting(&mut requests).await {
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
        let answer = async {
            if !wait_until_unlocked(&state, std::time::Duration::from_secs(2)).await {
                match launch() {
                    Ok(path) => {
                        tracing::info!("no frontend responded; launched {path} to prompt");
                    }
                    Err(e) => tracing::warn!("could not launch the frontend to prompt: {e}"),
                }
            }
            let unlocked = wait_until_unlocked(&state, patience).await;
            if !unlocked {
                tracing::info!("unlock request timed out after {patience:?}");
            }
            unlocked
        };
        let unlocked = tokio::select! {
            unlocked = answer => unlocked,
            () = refused.notified() => {
                tracing::info!("the unlock dialog was dismissed; refusing");
                false
            }
        };
        let _ = reply.send(unlocked);
        // Everything queued behind this request was waiting on the same
        // dialog, and gets the same answer.
        while let Ok(queued) = requests.try_recv() {
            let _ = queued.reply.send(unlocked);
        }
    }
}

/// The next request somebody is still waiting on.
///
/// A `SearchItems` call stops waiting before its client's call timeout does
/// ([`crate::service::UNLOCK_WAIT`]), and its request may still be in the
/// queue. Serving it would raise a dialog for an application that has already
/// been answered.
async fn next_waiting(
    requests: &mut tokio::sync::mpsc::Receiver<PromptRequest>,
) -> Option<PromptRequest> {
    loop {
        let request = requests.recv().await?;
        if !request.reply.is_closed() {
            return Some(request);
        }
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
            ..ServiceConfig::default()
        })))
    }

    /// A caller that stopped waiting must not get a dialog raised for it.
    #[tokio::test]
    async fn a_request_nobody_waits_on_is_passed_over() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (abandoned, gone) = tokio::sync::oneshot::channel();
        tx.send(PromptRequest { reply: abandoned }).await.unwrap();
        drop(gone);
        let (live, mut answer) = tokio::sync::oneshot::channel();
        tx.send(PromptRequest { reply: live }).await.unwrap();

        let next = next_waiting(&mut rx).await.expect("the live request");
        next.reply.send(true).unwrap();
        assert_eq!(answer.try_recv(), Ok(true));
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
