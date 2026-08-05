//! `passmand` — the session daemon that owns the unlocked vault.
//!
//! Everything that needs a secret talks to this process: the COSMIC frontend,
//! the CLI, and — via `org.freedesktop.secrets` — every `libsecret` client on
//! the system. Keeping the DEK in one place means the vault is unlocked once
//! per session rather than once per application.
//!
//! By default it claims `org.passman.secrets`, *not* `org.freedesktop.secrets`,
//! so that starting it never silently displaces a running gnome-keyring. Pass
//! `--replace-keyring` when you actually mean to take over.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use passman_core::{Vault, crypto::KdfParams};
use passman_secret::service::{ServiceConfig, ServiceState, register_objects};
use tokio::sync::Mutex;
use zbus::fdo::RequestNameFlags;

#[derive(Parser, Debug)]
#[command(name = "passmand", version, about = "passman session daemon")]
struct Args {
    /// Vault file. Defaults to $XDG_DATA_HOME/passman/default.vault
    #[arg(long)]
    vault: Option<PathBuf>,

    /// Bus name to claim.
    #[arg(long, default_value = passman_secret::DEV_NAME)]
    bus_name: String,

    /// Claim `org.freedesktop.secrets`, taking over from gnome-keyring.
    #[arg(long)]
    replace_keyring: bool,

    /// Create the vault if it does not exist.
    #[arg(long)]
    init: bool,

    /// Read the passphrase from this environment variable instead of the
    /// terminal. For tests and headless startup only — an environment variable
    /// is visible to anything that can read /proc/<pid>/environ.
    #[arg(long, value_name = "VAR")]
    passphrase_env: Option<String>,

    /// Also serve org.freedesktop.impl.portal.Secret, so sandboxed Flatpak
    /// apps get their per-application key from passman. Requires the matching
    /// .portal file to be installed; see res/passman.portal.
    #[arg(long)]
    portal: bool,

    /// Serve an SSH agent from the vault's SSH keys.
    #[arg(long)]
    ssh_agent: bool,

    /// Agent socket path. Defaults to $XDG_RUNTIME_DIR/passman/ssh-agent.sock
    #[arg(long, value_name = "PATH")]
    ssh_agent_socket: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "passmand=info,passman_secret=info".into()),
        )
        .init();

    let args = Args::parse();

    let bus_name = if args.replace_keyring {
        passman_secret::WELL_KNOWN_NAME.to_owned()
    } else {
        args.bus_name.clone()
    };

    let vault_path = match args.vault {
        Some(p) => p,
        None => Vault::default_path()?,
    };

    let passphrase = match &args.passphrase_env {
        Some(var) => {
            std::env::var(var).map_err(|_| format!("environment variable `{var}` is not set"))?
        }
        None => rpassword::prompt_password(format!("Passphrase for {}: ", vault_path.display()))?,
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

    // Load SSH identities before the vault moves into the shared state.
    let ssh_agent = args.ssh_agent.then(|| {
        let agent = passman_agent::Agent::load_from_vault(&vault);
        tracing::info!(keys = agent.len(), "loaded SSH identities");
        Arc::new(Mutex::new(agent))
    });

    let mut state = ServiceState::new(ServiceConfig {
        bus_name: bus_name.clone(),
        autosave: true,
    });
    state.vault = Some(vault);
    let state = Arc::new(Mutex::new(state));

    if let Some(agent) = ssh_agent {
        let socket = match args.ssh_agent_socket {
            Some(p) => p,
            None => passman_agent::listener::default_socket_path()
                .ok_or("XDG_RUNTIME_DIR is unset; pass --ssh-agent-socket")?,
        };
        let listener = passman_agent::listener::bind(&socket)?;
        tracing::info!(socket = %socket.display(), "serving SSH agent");
        println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket.display());
        tokio::spawn(passman_agent::listener::serve(listener, agent));
    }

    let connection = zbus::connection::Builder::session()?.build().await?;
    register_objects(connection.object_server(), &state).await?;

    if args.portal {
        connection
            .object_server()
            .at(
                "/org/freedesktop/portal/desktop",
                passman_secret::portal::SecretPortal::new(state.clone()),
            )
            .await?;
        connection
            .request_name_with_flags(
                "org.freedesktop.impl.portal.desktop.passman",
                RequestNameFlags::AllowReplacement.into(),
            )
            .await?;
        tracing::info!("serving org.freedesktop.impl.portal.Secret");
    }

    // AllowReplacement lets a newer passmand — or the user's real keyring —
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
    guard.vault = None;
    tracing::info!("vault locked, exiting");
    Ok(())
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
