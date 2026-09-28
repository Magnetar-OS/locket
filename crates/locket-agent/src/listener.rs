//! The Unix socket side of the agent.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::{Agent, MAX_MESSAGE_LEN, error::Result, protocol};

/// Default socket location: `$XDG_RUNTIME_DIR/locket/ssh-agent.sock`.
///
/// `XDG_RUNTIME_DIR` is per-user and mode 0700, which is what keeps the socket
/// out of reach of other accounts.
pub fn default_socket_path() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("locket").join("ssh-agent.sock"))
}

/// Bind the agent socket, replacing a stale one left by a crashed daemon.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // A socket file left behind by a crashed daemon makes bind() fail with
    // EADDRINUSE even though nobody is listening. Distinguish the two by
    // trying to connect: success means a live agent we must not displace.
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("another agent is already listening on {}", path.display()),
            )
            .into());
        }
        tracing::debug!("removing stale agent socket at {}", path.display());
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

/// Serve the agent until the process exits.
pub async fn serve(listener: UnixListener, agent: Arc<Mutex<Agent>>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("agent accept failed: {e}");
                continue;
            }
        };
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, agent).await {
                tracing::debug!("agent connection ended: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: UnixStream, agent: Arc<Mutex<Agent>>) -> Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    loop {
        // Drain every complete message already buffered before reading more,
        // since clients may pipeline requests.
        while let Some((body, used)) = protocol::take_message(&buf)? {
            let response = dispatch(&agent, body.to_vec()).await?;
            stream.write_all(&response).await?;
            buf.drain(..used);
        }

        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(()); // client hung up
        }
        if buf.len() + n > MAX_MESSAGE_LEN + 4 {
            return Err(crate::Error::TooLarge(buf.len() + n));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Handle one request on a blocking thread.
///
/// Signing with a security key waits for someone to walk over and touch it —
/// seconds, sometimes tens of them — and a runtime worker is the wrong place
/// to spend that.
///
/// A plain `std` mutex rather than tokio's, because every holder of this lock
/// is synchronous: this closure, and the daemon reacting to the vault being
/// locked or unlocked. An async mutex would force that second caller to be
/// async for no benefit.
///
/// The lock is held while the request is answered, so a second one queues
/// behind a pending touch. That is the honest behaviour with one token: it can
/// only be touched for one thing at a time.
///
/// It is *not* held while a person is asked to confirm a signature: see
/// [`crate::agent::PendingConfirmation`]. The key is looked up again once the
/// answer is in, so a vault that locked in the meantime refuses the
/// signature rather than signing after the lock.
async fn dispatch(agent: &Arc<Mutex<Agent>>, body: Vec<u8>) -> Result<Vec<u8>> {
    let agent = agent.clone();
    tokio::task::spawn_blocking(move || {
        let pending = lock(&agent).confirmation_for(&body);
        let confirmed = pending.is_some_and(|pending| pending.ask());
        lock(&agent).handle_confirmed(&body, confirmed)
    })
    .await
    .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))
}

fn lock(agent: &Mutex<Agent>) -> std::sync::MutexGuard<'_, Agent> {
    agent.lock().unwrap_or_else(|poisoned| {
        // A panic in one request must not take the agent out of service.
        agent.clear_poison();
        poisoned.into_inner()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::SigningConfirmer;
    use crate::wire::Writer;
    use crate::{AgentKey, protocol};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    /// Answers yes — but first locks the vault underneath the question, the
    /// way the daemon's observer does when the screen locks: by taking the
    /// agent and dropping its keys. Records whether that got through.
    struct LocksWhileAsking {
        agent: OnceLock<Arc<Mutex<Agent>>>,
        locked_in_time: AtomicBool,
    }

    impl SigningConfirmer for LocksWhileAsking {
        fn confirm(&self, _key: &str) -> bool {
            let agent = self.agent.get().expect("agent wired").clone();
            let locking = std::thread::spawn(move || lock(&agent).forget_keys());
            let deadline = Instant::now() + Duration::from_secs(2);
            while !locking.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            self.locked_in_time
                .store(locking.is_finished(), Ordering::SeqCst);
            true
        }
    }

    /// The daemon drops the agent's keys from inside its own state lock, and
    /// the answer to a confirmation arrives through that same lock. With the
    /// agent held across the question the two waited on each other forever:
    /// every Secret Service call hung until the daemon was restarted.
    #[tokio::test]
    async fn locking_during_a_confirmation_neither_deadlocks_nor_signs() {
        let mut key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        key.set_comment("gated");
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let key = AgentKey::from_openssh(&pem, None, None)
            .unwrap()
            .confirm_each_use(true);
        let blob = key.public_blob.clone();

        let asker = Arc::new(LocksWhileAsking {
            agent: OnceLock::new(),
            locked_in_time: AtomicBool::new(false),
        });
        let agent = Arc::new(Mutex::new(
            Agent::with_keys(vec![key]).with_confirmer(asker.clone()),
        ));
        asker.agent.set(agent.clone()).ok().unwrap();

        let mut request = Writer::new();
        request
            .write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
            .write_string(&blob)
            .write_string(b"data")
            .write_u32(0);
        let response = dispatch(&agent, request.as_slice().to_vec()).await.unwrap();

        assert!(
            asker.locked_in_time.load(Ordering::SeqCst),
            "the vault could not lock while a confirmation was open"
        );
        assert_eq!(
            response,
            protocol::failure(),
            "signed with a key the vault had already dropped"
        );
    }
}
