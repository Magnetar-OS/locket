//! `locketd` — the session daemon that owns the unlocked vault.
//!
//! Everything that needs a secret talks to this process: the COSMIC frontend,
//! the CLI, and — via `org.freedesktop.secrets` — every `libsecret` client on
//! the system. Keeping the DEK in one place means the vault is unlocked once
//! per session rather than once per application.
//!
//! By default it claims `org.locket.secrets`, *not* `org.freedesktop.secrets`,
//! so that starting it never silently displaces a running gnome-keyring. Pass
//! `--replace-keyring` when you actually mean to take over.

use std::path::PathBuf;
use std::sync::Arc;

mod idle;

use clap::Parser;
use locket_core::{Vault, crypto::KdfParams};
use locket_secret::service::{ServiceConfig, ServiceState, register_objects};
use tokio::sync::Mutex;
use zbus::fdo::RequestNameFlags;

#[derive(Parser, Debug)]
#[command(name = "locketd", version, about = "locket session daemon")]
struct Args {
    /// Vault file. Defaults to $XDG_DATA_HOME/locket/default.vault
    #[arg(long)]
    vault: Option<PathBuf>,

    /// Bus name to claim.
    #[arg(long, default_value = locket_secret::DEV_NAME)]
    bus_name: String,

    /// Claim `org.freedesktop.secrets`, taking over from gnome-keyring.
    #[arg(long)]
    replace_keyring: bool,

    /// Create the vault if it does not exist.
    #[arg(long)]
    init: bool,

    /// Start with the vault locked and wait to be unlocked.
    ///
    /// The point of a login-time daemon: it comes up before anybody has typed
    /// anything, then `pam_locket.so` (or the frontend) unlocks it. Without
    /// this the daemon would demand a passphrase at startup, which is exactly
    /// the prompt PAM exists to avoid.
    #[arg(long, conflicts_with = "passphrase_env")]
    locked: bool,

    /// Read the passphrase from this environment variable instead of the
    /// terminal. For tests and headless startup only — an environment variable
    /// is visible to anything that can read /proc/<pid>/environ.
    #[arg(long, value_name = "VAR")]
    passphrase_env: Option<String>,

    /// Also serve org.freedesktop.impl.portal.Secret, so sandboxed Flatpak
    /// apps get their per-application key from locket. Requires the matching
    /// .portal file to be installed; see res/locket.portal.
    #[arg(long)]
    portal: bool,

    /// Listen on the unlock socket so `pam_locket.so` can unlock the vault
    /// at login. Defaults to $XDG_RUNTIME_DIR/locket/unlock.sock
    #[arg(long)]
    unlock_socket: bool,

    /// Serve an SSH agent from the vault's SSH keys.
    #[arg(long)]
    ssh_agent: bool,

    /// Agent socket path. Defaults to $XDG_RUNTIME_DIR/locket/ssh-agent.sock
    #[arg(long, value_name = "PATH")]
    ssh_agent_socket: Option<PathBuf>,

    /// Lock the vault after this many seconds without a request. 0 disables it.
    ///
    /// The frontend has its own idle timer, but it only knows about its own
    /// window: close it and the daemon would hold the key until logout. This
    /// is the one that covers the session.
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    auto_lock: u64,

    /// Do not lock the vault when the session locks or the machine suspends.
    ///
    /// Both are on by default: a locked screen that leaves every secret
    /// readable by anything on the session bus is not a locked screen.
    #[arg(long)]
    no_lock_on_idle_session: bool,

    /// Do not send a desktop notification when the vault locks.
    ///
    /// On by default: the vault locking changes what every other application
    /// can do, and it happens with no window on screen to say so. The
    /// notification carries the reason and nothing from the vault.
    #[arg(long)]
    no_lock_notifications: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    harden();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // `locket_agent` is in the default set because that is where
                // "touch your security key" is logged. A signature that waits
                // silently for hardware looks like a hang.
                .unwrap_or_else(|_| {
                    "locketd=info,locket_secret=info,locket_agent=info".into()
                }),
        )
        .init();

    let args = Args::parse();

    let bus_name = if args.replace_keyring {
        locket_secret::WELL_KNOWN_NAME.to_owned()
    } else {
        args.bus_name.clone()
    };

    let vault_path = match args.vault {
        Some(p) => p,
        None => Vault::default_path()?,
    };

    let vault = if args.locked {
        if !vault_path.exists() {
            return Err(format!("no vault at {}", vault_path.display()).into());
        }
        tracing::info!(path = %vault_path.display(), "starting locked; waiting to be unlocked");
        None
    } else {
        let passphrase = match &args.passphrase_env {
            Some(var) => std::env::var(var)
                .map_err(|_| format!("environment variable `{var}` is not set"))?,
            None => {
                rpassword::prompt_password(format!("Passphrase for {}: ", vault_path.display()))?
            }
        };

        let vault = if vault_path.exists() {
            tracing::info!(path = %vault_path.display(), "opening vault");
            Vault::open(&vault_path, &passphrase)?
        } else if args.init {
            tracing::info!(path = %vault_path.display(), "creating vault");
            Vault::create(&vault_path, &passphrase, KdfParams::default())?
        } else {
            return Err(format!(
                "no vault at {} (pass --init to create one)",
                vault_path.display()
            )
            .into());
        };

        tracing::info!(
            collections = vault.data().collections.len(),
            items = vault.data().item_count(),
            "vault unlocked"
        );
        Some(vault)
    };

    // The agent starts empty and is filled by the observer below, including
    // when the vault is already open. A daemon that starts `--locked` — which
    // is how the installed unit starts, so PAM can unlock it — would otherwise
    // serve an empty agent for the rest of the session.
    let ssh_agent = args.ssh_agent.then(|| {
        let mut agent = locket_agent::Agent::new();
        if let Some(signer) = token_signer() {
            agent = agent.with_signer(signer);
        }
        Arc::new(std::sync::Mutex::new(agent))
    });

    let mut state = ServiceState::new(ServiceConfig {
        bus_name: bus_name.clone(),
        autosave: true,
    });
    if let Some(vault) = vault {
        state.vault = Some(vault);
    }
    if let Some(agent) = ssh_agent.as_ref() {
        state.add_observer(Arc::new(AgentKeys(agent.clone())));
    }
    // Read the plaintext collection index so a locked daemon can still answer
    // ReadAlias and Collections. Without it clients conclude no keyring exists.
    match Vault::read_index(&vault_path) {
        Ok(index) => {
            tracing::info!(collections = index.len(), "loaded collection index");
            state.index = index;
        }
        Err(e) => tracing::warn!("could not read the collection index: {e}"),
    }
    let state = Arc::new(Mutex::new(state));

    if let Some(agent) = ssh_agent.as_ref() {
        // Wired after the state exists, because asking the frontend goes
        // through the same prompt bridge the Secret Service uses.
        let confirmer = Arc::new(AskFrontend {
            state: state.clone(),
            handle: tokio::runtime::Handle::current(),
        });
        let mut guard = agent.lock().unwrap_or_else(|p| p.into_inner());
        let existing = std::mem::take(&mut *guard);
        *guard = existing.with_confirmer(confirmer);
    }

    let ssh_agent_handle = ssh_agent.clone();
    if let Some(agent) = ssh_agent {
        let socket = match args.ssh_agent_socket {
            Some(p) => p,
            None => locket_agent::listener::default_socket_path()
                .ok_or("XDG_RUNTIME_DIR is unset; pass --ssh-agent-socket")?,
        };
        let listener = locket_agent::listener::bind(&socket)?;
        tracing::info!(socket = %socket.display(), "serving SSH agent");
        println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket.display());
        tokio::spawn(locket_agent::listener::serve(listener, agent));
    }

    // Seeded from the flag and then owned by the frontend, which stores it
    // with the rest of the desktop's settings. The task runs either way, so
    // switching auto-lock on in Settings takes effect without a restart.
    state.lock().await.set_auto_lock_seconds(args.auto_lock);
    let notify = !args.no_lock_notifications;
    tokio::spawn(idle::auto_lock(
        state.clone(),
        ssh_agent_handle.clone(),
        notify,
    ));
    if !args.no_lock_on_idle_session {
        let state = state.clone();
        tokio::spawn(async move {
            // A missing logind is not an error worth failing startup over —
            // the daemon still works, it just cannot follow the session.
            if let Err(e) = idle::lock_with_session(state, notify).await {
                tracing::warn!("not following the session's lock state: {e}");
            }
        });
    }

    // The prompt bridge turns a locked-vault Prompt into a request the
    // frontend can answer; without a receiver the Prompt objects can only
    // refuse.
    let (prompt_tx, prompt_rx) = tokio::sync::mpsc::channel(8);
    state.lock().await.prompts = Some(prompt_tx);

    let connection = zbus::connection::Builder::session()?.build().await?;
    register_objects(connection.object_server(), &state).await?;

    connection
        .object_server()
        .at(
            locket_secret::manager::MANAGER_PATH,
            locket_secret::manager::Manager::new(state.clone(), vault_path.clone()),
        )
        .await?;
    tokio::spawn(locket_secret::manager::serve_prompts(
        connection.clone(),
        state.clone(),
        prompt_rx,
    ));

    if args.unlock_socket {
        let socket = locket_secret::unlock_socket::default_path()
            .ok_or("XDG_RUNTIME_DIR is unset; cannot place the unlock socket")?;
        let listener = locket_secret::unlock_socket::bind(&socket)?;
        tracing::info!(socket = %socket.display(), "listening for PAM unlock requests");
        tokio::spawn(locket_secret::unlock_socket::serve(
            listener,
            state.clone(),
            vault_path.clone(),
            connection.clone(),
        ));
    }

    if args.portal {
        connection
            .object_server()
            .at(
                "/org/freedesktop/portal/desktop",
                locket_secret::portal::SecretPortal::new(state.clone()),
            )
            .await?;
        connection
            .request_name_with_flags(
                "org.freedesktop.impl.portal.desktop.locket",
                RequestNameFlags::AllowReplacement.into(),
            )
            .await?;
        tracing::info!("serving org.freedesktop.impl.portal.Secret");
    }

    // AllowReplacement lets a newer locketd — or the user's real keyring —
    // take the name back without a manual kill.
    let request_flags = if args.replace_keyring {
        RequestNameFlags::AllowReplacement | RequestNameFlags::ReplaceExisting
    } else {
        RequestNameFlags::AllowReplacement.into()
    };
    connection
        .request_name_with_flags(bus_name.as_str(), request_flags)
        .await?;

    tracing::info!(bus_name = %bus_name, "serving org.freedesktop.Secret.*");
    if args.replace_keyring {
        tracing::warn!("claimed the gnome-keyring name; clients will reconnect here");
    }

    // Persist and drop the DEK on the way out rather than relying on process
    // teardown to do it.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
        _ = terminate() => tracing::info!("terminated"),
    }

    let mut guard = state.lock().await;
    if let Some(v) = guard.vault.as_mut()
        && let Err(e) = v.save()
    {
        tracing::error!("failed to save vault on shutdown: {e}");
    }
    guard.close_vault();
    tracing::info!("vault locked, exiting");
    Ok(())
}

/// Keeps the SSH agent's identities in step with the vault.
///
/// Both directions matter. Unlocking has to *add* the keys, because the daemon
/// normally starts locked and nothing else would ever load them. Locking has to
/// *drop* them: they are decrypted copies, and leaving them behind would let
/// anything that can reach the agent socket keep authenticating as you after
/// you locked the vault — which is exactly what locking is for.
struct AgentKeys(Arc<std::sync::Mutex<locket_agent::Agent>>);

impl AgentKeys {
    fn with<R>(&self, f: impl FnOnce(&mut locket_agent::Agent) -> R) -> R {
        let mut guard = self.0.lock().unwrap_or_else(|poisoned| {
            self.0.clear_poison();
            poisoned.into_inner()
        });
        f(&mut guard)
    }
}

impl locket_secret::service::VaultObserver for AgentKeys {
    fn vault_opened(&self, vault: &Vault) {
        self.with(|agent| agent.reload_from_vault(vault));
    }

    fn vault_closed(&self) {
        self.with(|agent| agent.forget_keys());
    }
}

/// Asks the frontend to allow one signature, from the agent's blocking thread.
///
/// The agent handles requests on a `spawn_blocking` thread, which is exactly
/// where blocking on a runtime future is allowed — and blocking is what is
/// wanted here: an `ssh` client is waiting for its signature and there is
/// nothing useful to do until someone answers.
struct AskFrontend {
    state: locket_secret::service::SharedState,
    handle: tokio::runtime::Handle,
}

impl locket_agent::confirm::SigningConfirmer for AskFrontend {
    fn confirm(&self, key: &str) -> bool {
        let state = self.state.clone();
        let key = key.to_owned();
        self.handle.block_on(async move {
            let sender = {
                let guard = state.lock().await;
                guard.prompts.clone()
            };
            let Some(tx) = sender else {
                tracing::warn!("no prompt bridge; refusing to sign with `{key}`");
                return false;
            };
            let (reply, wait) = tokio::sync::oneshot::channel();
            if tx
                .send(locket_secret::service::PromptRequest::ConfirmSigning { key, reply })
                .await
                .is_err()
            {
                return false;
            }
            // Every failure is a refusal: this key was marked as one that must
            // not be used without asking.
            wait.await.unwrap_or(false)
        })
    }
}

/// How the agent reaches a security key, when this build can.
///
/// Returned unconditionally rather than gated on a token being plugged in
/// right now: `sk-` identities are still real when the key is in your pocket,
/// and the token only has to be present at the moment you sign.
#[cfg(feature = "fido")]
fn token_signer() -> Option<Arc<dyn locket_agent::sk::TokenSigner>> {
    Some(Arc::new(locket_agent::fido::HardwareSigner))
}

#[cfg(not(feature = "fido"))]
fn token_signer() -> Option<Arc<dyn locket_agent::sk::TokenSigner>> {
    None
}

/// Process hardening, before anything secret exists to protect.
///
/// This is the process that holds the only unlocked copy of the
/// data-encryption key, so:
///
/// - `PR_SET_DUMPABLE(0)`: no core dumps, and no `ptrace` /
///   `process_vm_readv` from other processes running as this user — which is
///   every process in the session, including whatever a browser just
///   downloaded and ran.
/// - `mlockall(MCL_CURRENT | MCL_FUTURE)`: nothing this process maps reaches
///   swap, so the DEK cannot outlive the session on disk.
///
/// Both are best-effort with a log line, not preconditions: `mlockall` can
/// exceed `RLIMIT_MEMLOCK` on a locked-down system, and a daemon that
/// refuses to serve secrets because it could not lock memory would fail the
/// user harder than swap ever would. `zeroize` on drop is unaffected either
/// way.
///
/// This is the fallback half of the roadmap's key-residence work; moving the
/// DEK itself into `memfd_secret` remains open (see ROADMAP.md, milestone 2).
fn harden() {
    // Safety: these calls take integers or a plain struct by pointer and
    // affect solely this process's own attributes.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            eprintln!("locketd: could not disable core dumps and ptrace attach");
        }
        // The default RLIMIT_MEMLOCK (8 MiB on most distros) cannot hold a
        // whole tokio process, so lift the soft limit to whatever the hard
        // limit allows before asking. The installed unit sets
        // LimitMEMLOCK=infinity; elsewhere this locks as much as the admin
        // permitted and says so.
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
        }
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            // Runs before tracing is up, so plain stderr; the journal gets it.
            eprintln!(
                "locketd: mlockall failed (RLIMIT_MEMLOCK {} bytes is too small); \
                 memory may reach swap. Core dumps and ptrace are still blocked.",
                lim.rlim_max
            );
        }
    }
}

async fn terminate() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(e) => {
            tracing::error!("cannot listen for SIGTERM: {e}");
            std::future::pending::<()>().await;
        }
    }
}
