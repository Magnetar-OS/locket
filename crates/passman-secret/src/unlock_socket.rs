//! The daemon end of the unlock socket.
//!
//! Accepts a passphrase from a local client — in practice `pam_passman.so` at
//! login — and unlocks the vault with it. See [`passman_ipc`] for why the
//! socket's location is the security boundary rather than the protocol.

use std::path::{Path, PathBuf};

use passman_core::Vault;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::service::{SharedState, register_vault_objects};

/// Bind the unlock socket, replacing a stale one left by a crashed daemon.
///
/// The parent directory is forced to 0700 and the socket to 0600. Both live
/// under `/run/user/<uid>`, which is already private to the user, but a
/// password path should not depend on someone else's defaults staying correct.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    if path.exists() {
        // Distinguish a live daemon from a leftover socket file: connecting
        // succeeds only if somebody is actually accepting.
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("another daemon is listening on {}", path.display()),
            ));
        }
        let _ = std::fs::remove_file(path);
    }

    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

/// The default socket path for this process's user.
pub fn default_path() -> Option<PathBuf> {
    passman_ipc::socket_path()
}

/// Serve unlock requests until the process exits.
pub async fn serve(
    listener: UnixListener,
    state: SharedState,
    vault_path: PathBuf,
    connection: zbus::Connection,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("unlock socket accept failed: {e}");
                continue;
            }
        };
        let state = state.clone();
        let vault_path = vault_path.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, state, vault_path, connection).await {
                tracing::debug!("unlock request ended: {e}");
            }
        });
    }
}

/// Re-wrap the vault key under a new passphrase, at PAM's request.
///
/// Proving knowledge of the old passphrase is the whole security argument
/// here: the socket is reachable by this uid, so without that check anything
/// running as the user could set the vault's passphrase to a value of its own
/// choosing and lock the owner out — or worse, know it.
///
/// Opening the file is what constitutes the proof, and it also gives us a copy
/// to rewrite even when the daemon is locked.
async fn rekey(
    state: &SharedState,
    vault_path: &Path,
    old: &str,
    new: &str,
) -> bool {
    let path = vault_path.to_path_buf();
    let (old, new) = (old.to_owned(), new.to_owned());

    // Argon2id twice — once to open, once to re-wrap — so this belongs off the
    // executor's core threads like every other passphrase operation.
    let result = tokio::task::spawn_blocking(move || -> passman_core::Result<()> {
        let mut vault = Vault::open(&path, &old)?;
        vault.change_passphrase(&new, passman_core::crypto::KdfParams::default())?;
        vault.save()
    })
    .await;

    match result {
        Ok(Ok(())) => {
            tracing::info!("vault passphrase changed to match the new login password");
            // Our in-memory copy is now stale — the file has a new key slot.
            let mut guard = state.lock().await;
            if let Some(vault) = guard.vault.as_mut()
                && let Err(e) = vault.reload()
            {
                tracing::warn!("locking: could not reload after the rekey ({e})");
                guard.close_vault();
            }
            true
        }
        Ok(Err(e)) => {
            // Almost always "the old login password was not the vault
            // passphrase", which is an ordinary state of affairs and not
            // something to shout about in the journal at every password change.
            tracing::info!("unlock socket: rekey refused ({e})");
            false
        }
        Err(e) => {
            tracing::error!("rekey task failed: {e}");
            false
        }
    }
}

async fn handle(
    mut stream: UnixStream,
    state: SharedState,
    vault_path: PathBuf,
    connection: zbus::Connection,
) -> std::io::Result<()> {
    // Read the whole request into memory first, then parse it with the shared
    // codec, so the framing lives in exactly one place — the crate the PAM
    // module links against.
    let mut framed = zeroize::Zeroizing::new(Vec::new());
    {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await?;
        let raw = u32::from_be_bytes(len);
        let body_len = (raw & 0x7FFF_FFFF) as usize;
        if body_len > 2 * passman_ipc::MAX_PASSPHRASE_LEN + 9 {
            // Refuse rather than allocate on a bad client's say-so.
            let _ = stream.write_all(&[passman_ipc::REPLY_REFUSED]).await;
            return Ok(());
        }
        framed.extend_from_slice(&len);
        let mut body = zeroize::Zeroizing::new(vec![0u8; body_len]);
        stream.read_exact(&mut body).await?;
        framed.extend_from_slice(&body);
    }

    let request = match passman_ipc::read_request(&mut framed.as_slice()) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("unlock socket: malformed request ({e})");
            let _ = stream.write_all(&[passman_ipc::REPLY_REFUSED]).await;
            return Ok(());
        }
    };

    let passphrase = match &request {
        passman_ipc::Request::Unlock(p) => p.to_string(),
        passman_ipc::Request::Rekey { old, new } => {
            let ok = rekey(&state, &vault_path, old, new).await;
            stream
                .write_all(&[if ok {
                    passman_ipc::REPLY_UNLOCKED
                } else {
                    passman_ipc::REPLY_REFUSED
                }])
                .await?;
            return Ok(());
        }
    };
    let passphrase = passphrase.as_str();

    // Already open: report success without re-deriving anything.
    if !state.lock().await.is_locked() {
        stream.write_all(&[passman_ipc::REPLY_UNLOCKED]).await?;
        return Ok(());
    }

    let passphrase = passphrase.to_owned();
    let path = vault_path.clone();
    // Argon2id is slow by design; keep it off the executor's core threads.
    let opened = tokio::task::spawn_blocking(move || Vault::open(&path, &passphrase))
        .await
        .map_err(std::io::Error::other)?;

    let unlocked = match opened {
        Ok(mut vault) => {
            if vault.format() < passman_core::vault::FORMAT_VERSION
                && let Err(e) = vault.save()
            {
                tracing::warn!("could not upgrade the vault format: {e}");
            }
            let mut guard = state.lock().await;
            guard.index = vault
                .data()
                .collections
                .iter()
                .map(|c| passman_core::vault::CollectionIndex {
                    id: c.id,
                    label: c.label.clone(),
                    alias: c.alias.clone(),
                })
                .collect();
            guard.open_vault(vault);
            drop(guard);
            if let Err(e) = register_vault_objects(connection.object_server(), &state).await {
                tracing::error!("could not publish vault objects after unlock: {e}");
            }
            tracing::info!("vault unlocked over the unlock socket");
            true
        }
        Err(e) => {
            // Deliberately vague in the log: this runs at login, and the
            // journal is not the place to narrate passphrase attempts.
            tracing::info!("unlock socket: passphrase refused ({e})");
            false
        }
    };

    stream
        .write_all(&[if unlocked {
            passman_ipc::REPLY_UNLOCKED
        } else {
            passman_ipc::REPLY_REFUSED
        }])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_sets_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("unlock.sock");
        // A tokio listener needs a runtime to be created in.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let _listener = bind(&path).unwrap();

        let sock_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(sock_mode & 0o177, 0, "socket is reachable by others");

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o077, 0, "socket directory is not private");
    }

    #[test]
    fn a_stale_socket_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unlock.sock");
        // Simulate a crashed daemon: a socket file nobody is accepting on.
        std::fs::write(&path, b"").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        assert!(bind(&path).is_ok(), "a stale socket file blocked startup");
    }

    #[test]
    fn a_live_socket_is_not_displaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unlock.sock");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let _first = bind(&path).unwrap();

        let second = bind(&path);
        assert!(
            second.is_err(),
            "a second daemon silently stole the unlock socket"
        );
    }
}
