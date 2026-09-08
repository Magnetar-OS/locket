//! Secret Service sessions: the negotiated transport a client uses to move
//! secrets across the bus.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    dh::{self, AES_KEY_LEN, DhExchange},
};

/// How secrets are encoded for one client.
#[derive(Clone)]
pub enum Transport {
    /// No encryption. Permitted by the spec; used by simple clients.
    Plain,
    /// AES-128-CBC under a Diffie-Hellman-derived key.
    Dh(Box<[u8; AES_KEY_LEN]>),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Plain => f.write_str("Plain"),
            Transport::Dh(_) => f.write_str("Dh([redacted])"),
        }
    }
}

/// One open session.
#[derive(Debug, Clone)]
pub struct Session {
    pub path: OwnedObjectPath,
    pub transport: Transport,
    /// Unique bus name of the client that opened it, so the session can be
    /// torn down when that client disconnects.
    pub owner: Option<String>,
}

impl Session {
    /// Encode a secret for the wire. Returns `(parameters, value)`.
    pub fn encode(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match &self.transport {
            Transport::Plain => Ok((Vec::new(), plaintext.to_vec())),
            Transport::Dh(key) => dh::encrypt(key, plaintext),
        }
    }

    /// Decode a secret received from a client.
    pub fn decode(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match &self.transport {
            Transport::Plain => Ok(Zeroizing::new(value.to_vec())),
            Transport::Dh(key) => Ok(Zeroizing::new(dh::decrypt(key, parameters, value)?)),
        }
    }
}

/// All sessions currently open against the service.
#[derive(Default)]
pub struct SessionStore {
    sessions: HashMap<OwnedObjectPath, Session>,
    counter: AtomicU64,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Negotiate a session.
    ///
    /// Returns the session plus the `output` value to hand back from
    /// `OpenSession` — our DH public key, or an empty string for `plain`.
    pub fn open(
        &mut self,
        algorithm: &str,
        input: Option<&[u8]>,
        owner: Option<String>,
    ) -> Result<(Session, Vec<u8>)> {
        let (transport, output) = match algorithm {
            dh::ALGORITHM_PLAIN => (Transport::Plain, Vec::new()),
            dh::ALGORITHM_DH => {
                let peer = input.ok_or_else(|| {
                    Error::Crypto("DH session requires the client's public key".into())
                })?;
                let exchange = DhExchange::generate()?;
                let key = exchange.derive_session_key(peer)?;
                (Transport::Dh(Box::new(key)), exchange.public_key())
            }
            other => return Err(Error::UnsupportedAlgorithm(other.to_owned())),
        };

        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let path = OwnedObjectPath::try_from(format!("{}/s{n}", crate::SESSION_PREFIX))
            .map_err(|e| Error::Other(e.to_string()))?;

        let session = Session {
            path: path.clone(),
            transport,
            owner,
        };
        self.sessions.insert(path, session.clone());
        Ok((session, output))
    }

    pub fn get(&self, path: &OwnedObjectPath) -> Result<&Session> {
        self.sessions
            .get(path)
            .ok_or_else(|| Error::NoSession(path.to_string()))
    }

    pub fn close(&mut self, path: &OwnedObjectPath) -> Option<Session> {
        self.sessions.remove(path)
    }

    /// Drop every session belonging to a bus name that has vanished.
    pub fn close_for_owner(&mut self, owner: &str) -> Vec<OwnedObjectPath> {
        let doomed: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.owner.as_deref() == Some(owner))
            .map(|(p, _)| p.clone())
            .collect();
        for p in &doomed {
            self.sessions.remove(p);
        }
        doomed
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_session_passes_secrets_through() {
        let mut store = SessionStore::new();
        let (session, output) = store.open(dh::ALGORITHM_PLAIN, None, None).unwrap();
        assert!(output.is_empty());

        let (params, value) = session.encode(b"hunter2").unwrap();
        assert!(params.is_empty());
        assert_eq!(value, b"hunter2");
        assert_eq!(&*session.decode(&params, &value).unwrap(), b"hunter2");
    }

    #[test]
    fn dh_session_roundtrips_against_a_client_side_exchange() {
        let mut store = SessionStore::new();

        // Stand in for libsecret: generate a keypair, send the public half.
        let client = DhExchange::generate().unwrap();
        let (session, server_public) = store
            .open(dh::ALGORITHM_DH, Some(&client.public_key()), None)
            .unwrap();

        let client_key = client.derive_session_key(&server_public).unwrap();

        // Service -> client.
        let (params, value) = session.encode(b"hunter2").unwrap();
        assert_ne!(value, b"hunter2");
        assert_eq!(
            dh::decrypt(&client_key, &params, &value).unwrap(),
            b"hunter2"
        );

        // Client -> service.
        let (iv, ct) = dh::encrypt(&client_key, b"new-password").unwrap();
        assert_eq!(&*session.decode(&iv, &ct).unwrap(), b"new-password");
    }

    #[test]
    fn dh_without_a_public_key_is_an_error() {
        let mut store = SessionStore::new();
        assert!(store.open(dh::ALGORITHM_DH, None, None).is_err());
    }

    #[test]
    fn unknown_algorithms_are_rejected() {
        let mut store = SessionStore::new();
        assert!(matches!(
            store.open("rot13", None, None),
            Err(Error::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn sessions_get_distinct_paths_and_can_be_closed() {
        let mut store = SessionStore::new();
        let (a, _) = store.open(dh::ALGORITHM_PLAIN, None, None).unwrap();
        let (b, _) = store.open(dh::ALGORITHM_PLAIN, None, None).unwrap();
        assert_ne!(a.path, b.path);
        assert_eq!(store.len(), 2);

        assert!(store.close(&a.path).is_some());
        assert!(store.get(&a.path).is_err());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn disconnecting_a_client_closes_only_its_sessions() {
        let mut store = SessionStore::new();
        let (mine, _) = store
            .open(dh::ALGORITHM_PLAIN, None, Some(":1.42".into()))
            .unwrap();
        let (theirs, _) = store
            .open(dh::ALGORITHM_PLAIN, None, Some(":1.99".into()))
            .unwrap();

        let closed = store.close_for_owner(":1.42");
        assert_eq!(closed, vec![mine.path]);
        assert!(store.get(&theirs.path).is_ok());
    }
}
