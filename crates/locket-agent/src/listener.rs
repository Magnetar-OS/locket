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
/// The agent is *not* held while a person is asked to confirm a signature,
/// nor while a security key waits for its touch: see
/// [`crate::agent::PendingConfirmation`] and [`crate::agent::PendingTouch`].
/// The key is looked up again once the answer is in, so a vault that locked in
/// the meantime refuses the signature rather than signing after the lock.
///
/// Touches still happen one at a time, behind [`TOUCHES`]: a token can only be
/// touched for one thing at once, and a second request sent to it mid-touch
/// would be refused as busy rather than wait its turn.
async fn dispatch(agent: &Arc<Mutex<Agent>>, body: Vec<u8>) -> Result<Vec<u8>> {
    let agent = agent.clone();
    tokio::task::spawn_blocking(move || {
        let pending = lock(&agent).confirmation_for(&body);
        let confirmed = pending.is_some_and(|pending| pending.ask());
        if lock(&agent).touch_for(&body, confirmed).is_some() {
            let _one_at_a_time = TOUCHES
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Asked again after waiting for the turn: the vault may have
            // locked meanwhile, and then nobody should be asked to touch.
            // Bound first so the agent is released before the touch: an
            // `if let` keeps its scrutinee's guard alive through the block.
            let touch = lock(&agent).touch_for(&body, confirmed);
            if let Some(touch) = touch {
                let assertion = touch.touch();
                return lock(&agent).handle_touched(&body, confirmed, assertion);
            }
        }
        lock(&agent).handle_confirmed(&body, confirmed)
    })
    .await
    .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))
}

/// Held for the length of one security-key touch; see [`dispatch`].
static TOUCHES: Mutex<()> = Mutex::new(());

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
    use crate::sk::{SkSignRequest, TokenAssertion, TokenSigner};
    use crate::wire::Writer;
    use crate::{AgentKey, protocol};
    use ssh_key::sha2::{Digest as _, Sha256};
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

    /// A token that, while it waits for its touch, has the vault lock
    /// underneath it — the way the daemon's observer does when the screen
    /// locks. Records whether the lock got through before the touch ended.
    struct LocksWhileTouched {
        agent: OnceLock<Arc<Mutex<Agent>>>,
        lock_the_vault: bool,
        locked_in_time: AtomicBool,
    }

    impl TokenSigner for LocksWhileTouched {
        fn assert(&self, _request: &SkSignRequest) -> crate::Result<TokenAssertion> {
            if self.lock_the_vault {
                let agent = self.agent.get().expect("agent wired").clone();
                let locking = std::thread::spawn(move || lock(&agent).forget_keys());
                let deadline = Instant::now() + Duration::from_secs(2);
                while !locking.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                self.locked_in_time
                    .store(locking.is_finished(), Ordering::SeqCst);
            }
            // Well-formed enough for the signature blob; nothing verifies it.
            let mut auth_data = Sha256::digest(b"ssh:").to_vec();
            auth_data.push(0x01);
            auth_data.extend_from_slice(&7u32.to_be_bytes());
            Ok(TokenAssertion {
                auth_data,
                signature: vec![0u8; 64],
            })
        }
    }

    /// An `sk-ssh-ed25519` identity whose credential the token above claims.
    fn security_key() -> AgentKey {
        use ssh_key::{private, public};

        let credential = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let public::KeyData::Ed25519(point) = credential.public_key().key_data() else {
            panic!("expected an ed25519 key");
        };
        let sk = private::SkEd25519::new(
            public::SkEd25519::new(*point, "ssh:"),
            0x01,
            b"credential-handle".to_vec(),
        )
        .unwrap();
        let key =
            ssh_key::PrivateKey::new(private::KeypairData::SkEd25519(sk), "token@laptop").unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        AgentKey::from_openssh(&pem, None, None).unwrap()
    }

    /// A touch waits for a person, up to the token's own timeout. With the
    /// agent held across it, a vault lock in the meantime could not drop the
    /// keys — the daemon waited inside its state lock for the token to give
    /// up. The lock has to get through, and the signature then be refused.
    #[tokio::test]
    async fn locking_during_a_touch_wait_is_not_blocked() {
        for lock_the_vault in [true, false] {
            let key = security_key();
            let blob = key.public_blob.clone();
            let token = Arc::new(LocksWhileTouched {
                agent: OnceLock::new(),
                lock_the_vault,
                locked_in_time: AtomicBool::new(false),
            });
            let agent = Arc::new(Mutex::new(
                Agent::with_keys(vec![key]).with_signer(token.clone()),
            ));
            token.agent.set(agent.clone()).ok().unwrap();

            let mut request = Writer::new();
            request
                .write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
                .write_string(&blob)
                .write_string(b"data")
                .write_u32(0);
            let response = dispatch(&agent, request.as_slice().to_vec()).await.unwrap();

            if lock_the_vault {
                assert!(
                    token.locked_in_time.load(Ordering::SeqCst),
                    "the vault could not lock while the token waited for a touch"
                );
                assert_eq!(
                    response,
                    protocol::failure(),
                    "signed with a key the vault had already dropped"
                );
            } else {
                let (body, _) = protocol::take_message(&response).unwrap().unwrap();
                assert_eq!(body[0], protocol::SSH_AGENT_SIGN_RESPONSE);
            }
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
