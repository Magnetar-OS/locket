//! The Unix socket side of the agent.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::{Agent, MAX_MESSAGE_LEN, error::Result, protocol};

/// Default socket location: `$XDG_RUNTIME_DIR/passman/ssh-agent.sock`.
///
/// `XDG_RUNTIME_DIR` is per-user and mode 0700, which is what keeps the socket
/// out of reach of other accounts.
pub fn default_socket_path() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("passman").join("ssh-agent.sock"))
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
            let response = {
                let mut guard = agent.lock().await;
                guard.handle(body)
            };
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
