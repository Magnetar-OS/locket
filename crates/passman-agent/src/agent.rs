//! Identity storage and request handling.

use passman_core::{
    Vault,
    model::{ItemKind, field_names},
};
use signature::Signer;
use ssh_key::{PrivateKey, Signature};

use crate::error::{Error, Result};
use crate::protocol::{self, Request};
use crate::wire::Writer;

/// One usable identity.
pub struct AgentKey {
    /// The SSH public-key blob, which is what clients match against.
    pub public_blob: Vec<u8>,
    pub comment: String,
    key: PrivateKey,
}

impl AgentKey {
    /// Build from an OpenSSH private key, decrypting it if a passphrase is
    /// supplied and the key needs one.
    pub fn from_openssh(
        pem: &str,
        passphrase: Option<&str>,
        comment: Option<&str>,
    ) -> Result<Self> {
        let key = PrivateKey::from_openssh(pem).map_err(|e| Error::BadKey(e.to_string()))?;
        let key = if key.is_encrypted() {
            let pw = passphrase.ok_or_else(|| {
                Error::BadKey("key is encrypted but no passphrase is stored with it".into())
            })?;
            key.decrypt(pw).map_err(|e| Error::BadKey(e.to_string()))?
        } else {
            key
        };

        let public_blob = key
            .public_key()
            .to_bytes()
            .map_err(|e| Error::BadKey(e.to_string()))?;
        let comment = comment
            .map(str::to_owned)
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| key.comment().to_owned());

        Ok(Self {
            public_blob,
            comment,
            key,
        })
    }

    /// Produce an SSH signature blob: `string alg_name, string signature`.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self
            .key
            .try_sign(data)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let mut inner = Writer::new();
        inner
            .write_string(signature.algorithm().as_str().as_bytes())
            .write_string(signature.as_bytes());
        Ok(inner.into_bytes())
    }
}

impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("comment", &self.comment)
            .field("public_blob_len", &self.public_blob.len())
            .finish_non_exhaustive()
    }
}

/// The agent's identity set and protocol logic.
///
/// Pure: it takes a request body and returns a framed response, which makes
/// the whole protocol testable without a socket.
#[derive(Default)]
pub struct Agent {
    keys: Vec<AgentKey>,
    /// `SSH_AGENTC_LOCK` state. While locked the agent reports no identities
    /// and refuses to sign, as OpenSSH's own agent does.
    locked: bool,
}

impl Agent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_keys(keys: Vec<AgentKey>) -> Self {
        Self {
            keys,
            locked: false,
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Collect every SSH key stored in an unlocked vault.
    ///
    /// Keys that fail to parse are logged and skipped rather than failing the
    /// whole load — one bad paste should not cost you every other identity.
    pub fn load_from_vault(vault: &Vault) -> Self {
        let mut keys = Vec::new();
        for (_, item) in vault.data().all_items() {
            if item.kind != ItemKind::SshKey {
                continue;
            }
            let Some(pem) = item.field_value(field_names::PRIVATE_KEY) else {
                continue;
            };
            // An encrypted key may carry its passphrase as the item's primary
            // secret, which is the natural place to put it.
            let passphrase = Some(item.secret.expose()).filter(|s| !s.is_empty());
            let comment = item
                .field_value(field_names::KEY_COMMENT)
                .or(Some(item.label.as_str()));

            match AgentKey::from_openssh(pem, passphrase, comment) {
                Ok(key) => keys.push(key),
                Err(e) => tracing::warn!("skipping SSH key `{}`: {e}", item.label),
            }
        }
        Self::with_keys(keys)
    }

    fn identities_answer(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENT_IDENTITIES_ANSWER);
        if self.locked {
            // Locked: advertise nothing.
            w.write_u32(0);
            return w.into_framed();
        }
        w.write_u32(self.keys.len() as u32);
        for key in &self.keys {
            w.write_string(&key.public_blob)
                .write_string(key.comment.as_bytes());
        }
        w.into_framed()
    }

    fn sign_response(&self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if self.locked {
            return Err(Error::NoSuchKey);
        }
        let key = self
            .keys
            .iter()
            .find(|k| k.public_blob == key_blob)
            .ok_or(Error::NoSuchKey)?;

        let blob = key.sign(data)?;
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENT_SIGN_RESPONSE)
            .write_string(&blob);
        Ok(w.into_framed())
    }

    /// Handle one request body; returns the framed response.
    pub fn handle(&mut self, body: &[u8]) -> Vec<u8> {
        let request = match Request::parse(body) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("malformed agent request: {e}");
                return protocol::failure();
            }
        };

        match request {
            Request::RequestIdentities => self.identities_answer(),

            Request::Sign { key_blob, data, .. } => {
                match self.sign_response(&key_blob, &data) {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::debug!("refusing to sign: {e}");
                        protocol::failure()
                    }
                }
            }

            // Mutating the vault over the agent socket is refused on purpose:
            // every process running as this user can reach the socket.
            Request::AddIdentity | Request::RemoveIdentity { .. } | Request::RemoveAllIdentities => {
                tracing::info!("refused an agent request to modify the identity set");
                protocol::failure()
            }

            Request::Lock => {
                self.locked = true;
                protocol::success()
            }
            Request::Unlock => {
                // Unlocking is the vault's job, not a bus peer's.
                protocol::failure()
            }

            Request::Extension { name } => {
                tracing::debug!("unsupported agent extension `{name}`");
                protocol::extension_failure()
            }

            Request::Unknown(n) => {
                tracing::debug!("unsupported agent message {n}");
                protocol::failure()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;
    use ssh_key::{Algorithm, rand_core::OsRng};

    fn test_key(comment: &str) -> AgentKey {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        key.set_comment(comment);
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        AgentKey::from_openssh(&pem, None, Some(comment)).unwrap()
    }

    /// Strip framing and the message-type byte.
    fn body_of(framed: &[u8]) -> (u8, Vec<u8>) {
        let (body, _) = protocol::take_message(framed).unwrap().unwrap();
        (body[0], body[1..].to_vec())
    }

    #[test]
    fn lists_identities_with_blobs_and_comments() {
        let mut agent = Agent::with_keys(vec![test_key("one"), test_key("two")]);
        let framed = agent.handle(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);

        let (kind, rest) = body_of(&framed);
        assert_eq!(kind, protocol::SSH_AGENT_IDENTITIES_ANSWER);

        let mut r = Reader::new(&rest);
        assert_eq!(r.read_u32().unwrap(), 2);
        let blob1 = r.read_string().unwrap().to_vec();
        assert_eq!(r.read_utf8().unwrap(), "one");
        let _blob2 = r.read_string().unwrap();
        assert_eq!(r.read_utf8().unwrap(), "two");
        assert!(r.is_empty());
        assert!(!blob1.is_empty());
    }

    #[test]
    fn signs_with_a_known_key_and_the_signature_verifies() {
        let key = test_key("signer");
        let blob = key.public_blob.clone();
        // Keep a public key for verification before moving the private one.
        let public = ssh_key::PublicKey::from_bytes(&blob).unwrap();

        let mut agent = Agent::with_keys(vec![key]);
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
            .write_string(&blob)
            .write_string(b"data to be signed")
            .write_u32(0);

        let (kind, rest) = body_of(&agent.handle(w.as_slice()));
        assert_eq!(kind, protocol::SSH_AGENT_SIGN_RESPONSE);

        // Unwrap: string(sig blob) -> { string alg, string sig }
        let mut r = Reader::new(&rest);
        let sig_blob = r.read_string().unwrap();
        let mut inner = Reader::new(sig_blob);
        assert_eq!(inner.read_utf8().unwrap(), "ssh-ed25519");
        let raw = inner.read_string().unwrap();

        let signature = Signature::new(Algorithm::Ed25519, raw.to_vec()).unwrap();
        // `PublicKey::verify` inherently means sshsig verification, which
        // shadows the trait method — reach for the trait explicitly.
        assert!(
            <ssh_key::PublicKey as signature::Verifier<Signature>>::verify(
                &public,
                b"data to be signed",
                &signature
            )
            .is_ok(),
            "agent signature did not verify against the advertised public key"
        );
    }

    #[test]
    fn refuses_to_sign_for_an_unknown_key() {
        let mut agent = Agent::with_keys(vec![test_key("a")]);
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
            .write_string(b"not-a-real-blob")
            .write_string(b"data")
            .write_u32(0);
        assert_eq!(agent.handle(w.as_slice()), protocol::failure());
    }

    #[test]
    fn identity_mutation_is_refused() {
        let mut agent = Agent::with_keys(vec![test_key("a")]);
        assert_eq!(
            agent.handle(&[protocol::SSH_AGENTC_ADD_IDENTITY]),
            protocol::failure()
        );
        assert_eq!(
            agent.handle(&[protocol::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            protocol::failure()
        );
        // The key set is untouched.
        assert_eq!(agent.len(), 1);
    }

    #[test]
    fn locking_hides_identities_and_blocks_signing() {
        let key = test_key("a");
        let blob = key.public_blob.clone();
        let mut agent = Agent::with_keys(vec![key]);

        assert_eq!(agent.handle(&[protocol::SSH_AGENTC_LOCK]), protocol::success());
        assert!(agent.is_locked());

        let (_, rest) = body_of(&agent.handle(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]));
        let mut r = Reader::new(&rest);
        assert_eq!(r.read_u32().unwrap(), 0, "locked agent advertised a key");

        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
            .write_string(&blob)
            .write_string(b"data")
            .write_u32(0);
        assert_eq!(agent.handle(w.as_slice()), protocol::failure());
    }

    #[test]
    fn garbage_input_yields_failure_not_a_panic() {
        let mut agent = Agent::new();
        assert_eq!(agent.handle(&[]), protocol::failure());
        // A sign request whose key blob length runs off the end.
        assert_eq!(
            agent.handle(&[protocol::SSH_AGENTC_SIGN_REQUEST, 0xFF, 0xFF, 0xFF, 0xFF]),
            protocol::failure()
        );
        assert_eq!(agent.handle(&[200]), protocol::failure());
    }

    #[test]
    fn loads_ssh_keys_out_of_a_vault() {
        use passman_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();

        vault.add_item_default(
            Item::new(ItemKind::SshKey, "build server")
                .with_field(Field::new(
                    field_names::PRIVATE_KEY,
                    FieldKind::PrivateKey,
                    pem.to_string(),
                ))
                .with_field(Field::text(field_names::KEY_COMMENT, "me@host")),
        );
        // A login must not be picked up as an identity.
        vault.add_item_default(Item::new(ItemKind::Login, "unrelated").with_secret("x"));
        // Nor should an SSH item with an unparseable key take the rest down.
        vault.add_item_default(Item::new(ItemKind::SshKey, "broken").with_field(Field::new(
            field_names::PRIVATE_KEY,
            FieldKind::PrivateKey,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnonsense\n-----END OPENSSH PRIVATE KEY-----",
        )));

        let agent = Agent::load_from_vault(&vault);
        assert_eq!(agent.len(), 1);
        assert_eq!(agent.keys[0].comment, "me@host");
    }
}
