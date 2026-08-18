//! Identity storage and request handling.

use std::sync::Arc;

use locket_core::{
    Vault,
    model::{ItemKind, field_names},
};
use signature::Signer;
use ssh_key::{PrivateKey, Signature, private::KeypairData};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::protocol::{self, Request};
use crate::signing::{self, RsaHash};
use crate::sk::{self, SkAlgorithm, SkSignRequest, TokenSigner};
use crate::confirm::SigningConfirmer;
use crate::wire::Writer;

/// `SSH_SK_USER_VERIFICATION_REQD` — the key was created `verify-required`, so
/// the token must check a PIN or a fingerprint and not merely a touch.
const SK_USER_VERIFICATION_REQD: u8 = 0x04;

/// What a security-key identity needs at signing time.
///
/// Present only for `sk-` keys; everything else signs in software from the
/// scalar in the vault.
struct TokenKey {
    algorithm: SkAlgorithm,
    application: String,
    key_handle: Vec<u8>,
    user_verification: bool,
    pin: Option<Zeroizing<String>>,
}

/// One usable identity.
pub struct AgentKey {
    /// The SSH public-key blob, which is what clients match against.
    pub public_blob: Vec<u8>,
    pub comment: String,
    key: PrivateKey,
    /// `Some` when the signing key lives on a security key rather than here.
    token: Option<TokenKey>,
    /// Whether every signature has to be confirmed by the person at the
    /// keyboard. Off unless the item asks for it.
    confirm_each_use: bool,
    /// An OpenSSH certificate for this key, advertised as a second identity.
    ///
    /// A certificate is a *public* artifact signed by a CA; the private key
    /// behind both identities is the same one. A server configured for
    /// certificate authentication will not accept the bare key, so a vault
    /// holding only the key is unusable there — which is why this is carried
    /// alongside rather than instead.
    certificate: Option<Vec<u8>>,
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
        let token = token_key(key.key_data());

        Ok(Self {
            public_blob,
            comment,
            key,
            token,
            confirm_each_use: false,
            certificate: None,
        })
    }

    /// Require a confirmation before each signature with this key.
    pub fn confirm_each_use(mut self, required: bool) -> Self {
        self.confirm_each_use = required;
        self
    }

    /// Attach an OpenSSH certificate, if it is for this key and still valid.
    ///
    /// Refuses a certificate that belongs to another key — advertising it
    /// would offer an identity we cannot sign for — and one outside its
    /// validity window, since every server would reject it while still
    /// counting the attempt against the client's limit.
    pub fn attach_certificate(&mut self, openssh: &str) -> Result<()> {
        let cert = ssh_key::Certificate::from_openssh(openssh.trim())
            .map_err(|e| Error::BadKey(format!("certificate: {e}")))?;

        if cert.public_key() != self.key.public_key().key_data() {
            return Err(Error::BadKey(
                "certificate is for a different key than the one stored with it".into(),
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now < cert.valid_after() {
            return Err(Error::BadKey(format!(
                "certificate is not valid until {}",
                cert.valid_after()
            )));
        }
        if now > cert.valid_before() {
            return Err(Error::BadKey(format!(
                "certificate expired at {}",
                cert.valid_before()
            )));
        }

        self.certificate = Some(
            cert.to_bytes()
                .map_err(|e| Error::BadKey(format!("certificate: {e}")))?,
        );
        Ok(())
    }

    /// The identities this key answers to: the certificate first when there is
    /// one, since a server that takes certificates prefers them.
    fn identities(&self) -> impl Iterator<Item = &[u8]> {
        self.certificate
            .as_deref()
            .into_iter()
            .chain(std::iter::once(self.public_blob.as_slice()))
    }

    /// Attach the token's PIN, for a key created `verify-required`.
    pub fn with_token_pin(mut self, pin: Option<String>) -> Self {
        if let Some(token) = self.token.as_mut() {
            token.pin = pin.filter(|p| !p.is_empty()).map(Zeroizing::new);
        }
        self
    }

    /// Whether signing with this key needs a security key to be present.
    pub fn needs_token(&self) -> bool {
        self.token.is_some()
    }

    /// Produce an SSH signature blob.
    ///
    /// For an ordinary key that is `string alg_name, string signature`; for a
    /// security key the token does the signing and the blob gains the flags
    /// and counter it reported — see [`crate::sk`].
    ///
    /// `flags` is the client's `SSH_AGENTC_SIGN_REQUEST` word. It only means
    /// anything for RSA, where it names the hash the server will accept.
    fn sign(
        &self,
        data: &[u8],
        flags: u32,
        signer: Option<&dyn TokenSigner>,
        confirmer: Option<&dyn SigningConfirmer>,
    ) -> Result<Vec<u8>> {
        if self.confirm_each_use {
            // Fail closed. This key was marked as one that must not be used
            // without asking, so "there is nobody to ask" is a refusal, not a
            // reason to go ahead.
            let Some(confirmer) = confirmer else {
                return Err(Error::Refused(format!(
                    "`{}` requires confirmation for each use and there is no way to ask",
                    self.comment
                )));
            };
            if !confirmer.confirm(&self.comment) {
                return Err(Error::Refused(format!(
                    "signing with `{}` was not confirmed",
                    self.comment
                )));
            }
        }

        let Some(token) = self.token.as_ref() else {
            let (algorithm, raw) = match self.key.key_data() {
                // RSA is signed here rather than through `ssh-key`, which
                // cannot pick a hash — see [`crate::signing`].
                KeypairData::Rsa(keypair) => {
                    let hash = RsaHash::from_flags(flags);
                    tracing::debug!("signing with {} for `{}`", hash.algorithm(), self.comment);
                    (
                        hash.algorithm().to_owned(),
                        signing::rsa_signature(keypair, data, hash)?,
                    )
                }
                _ => {
                    let signature: Signature = self
                        .key
                        .try_sign(data)
                        .map_err(|e| Error::Signing(e.to_string()))?;
                    (
                        signature.algorithm().as_str().to_owned(),
                        signature.as_bytes().to_vec(),
                    )
                }
            };

            let mut inner = Writer::new();
            inner
                .write_string(algorithm.as_bytes())
                .write_string(&raw);
            return Ok(inner.into_bytes());
        };

        let signer = signer.ok_or_else(|| {
            Error::Signing(format!(
                "`{}` is a security-key identity and this build has no way to reach a token",
                self.comment
            ))
        })?;

        tracing::info!(
            "touch your {} to sign with `{}`",
            signer.describe(),
            self.comment
        );
        let assertion = signer.assert(&SkSignRequest {
            algorithm: token.algorithm,
            application: token.application.clone(),
            key_handle: token.key_handle.clone(),
            message: data.to_vec(),
            user_verification: token.user_verification,
            pin: token.pin.clone(),
        })?;
        sk::signature_blob(token.algorithm, &token.application, &assertion)
    }
}

/// Whether a field's value reads as "yes".
///
/// Generous in what it accepts because this is typed by hand into a text field
/// — and the failure mode of being strict here is a key that silently signs
/// without asking, which is the thing the setting exists to prevent.
fn is_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("true" | "yes" | "y" | "1" | "on" | "always" | "require" | "required")
    )
}

/// Pull the token-side details out of a security-key keypair.
fn token_key(keypair: &KeypairData) -> Option<TokenKey> {
    match keypair {
        KeypairData::SkEd25519(sk) => Some(TokenKey {
            algorithm: SkAlgorithm::Ed25519,
            application: sk.public().application().to_owned(),
            key_handle: sk.key_handle().to_vec(),
            user_verification: sk.flags() & SK_USER_VERIFICATION_REQD != 0,
            pin: None,
        }),
        KeypairData::SkEcdsaSha2NistP256(sk) => Some(TokenKey {
            algorithm: SkAlgorithm::EcdsaNistP256,
            application: sk.public().application().to_owned(),
            key_handle: sk.key_handle().to_vec(),
            user_verification: sk.flags() & SK_USER_VERIFICATION_REQD != 0,
            pin: None,
        }),
        _ => None,
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
    /// What `SSH_AGENTC_UNLOCK` has to present to undo that.
    lock_passphrase: Option<Zeroizing<Vec<u8>>>,
    /// How to reach a security key, when this build and this machine have one.
    signer: Option<Arc<dyn TokenSigner>>,
    /// How to ask the person at the keyboard to allow a signature.
    confirmer: Option<Arc<dyn SigningConfirmer>>,
    /// When this agent last answered anything, in seconds since the epoch.
    ///
    /// The daemon's idle lock reads it: an `ssh` session every minute is
    /// someone using their vault, and locking it out from under them because
    /// no *secret* was read would be its own bug.
    last_request: u64,
}

impl Agent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_keys(keys: Vec<AgentKey>) -> Self {
        Self {
            keys,
            locked: false,
            lock_passphrase: None,
            signer: None,
            confirmer: None,
            last_request: 0,
        }
    }

    /// Supply the thing that drives a security key.
    ///
    /// Without one, `sk-` identities are dropped at load rather than
    /// advertised: an identity the agent cannot sign for still costs the
    /// client one of the server's permitted authentication attempts, so
    /// offering it is worse than not having it.
    pub fn with_signer(mut self, signer: Arc<dyn TokenSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Supply the thing that asks the user to allow a signature.
    ///
    /// Only consulted for keys that ask for it. Without one, those keys refuse
    /// to sign at all rather than signing unasked.
    pub fn with_confirmer(mut self, confirmer: Arc<dyn SigningConfirmer>) -> Self {
        self.confirmer = Some(confirmer);
        self
    }

    /// Replace the identity set from a freshly-opened vault.
    ///
    /// Called whenever the vault is unlocked or its contents change. Without
    /// it a daemon that started locked — which is how the installed unit
    /// starts, so that PAM can unlock it — would serve an empty agent for the
    /// rest of the session.
    pub fn reload_from_vault(&mut self, vault: &Vault) {
        let signer = self.signer.clone();
        self.keys = Self::load_from_vault(vault, signer).keys;
        tracing::info!(keys = self.keys.len(), "reloaded SSH identities");
    }

    /// Forget every private key, because the vault they came from is locked.
    ///
    /// The keys are decrypted copies: leaving them here would let anything
    /// that can reach the socket keep authenticating as you long after you
    /// locked the vault, which is precisely what locking is meant to stop.
    pub fn forget_keys(&mut self) {
        if !self.keys.is_empty() {
            tracing::info!(keys = self.keys.len(), "vault locked; dropping SSH identities");
        }
        self.keys.clear();
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

    /// `SSH_AGENTC_LOCK`: hide the identities behind a passphrase.
    ///
    /// Returns false if already locked, which is what OpenSSH's agent does —
    /// otherwise a second lock would silently replace the passphrase and the
    /// first one would no longer open it.
    fn lock(&mut self, passphrase: Zeroizing<Vec<u8>>) -> bool {
        if self.locked {
            return false;
        }
        self.locked = true;
        self.lock_passphrase = Some(passphrase);
        true
    }

    /// `SSH_AGENTC_UNLOCK`: the counterpart, so `ssh-add -X` works.
    ///
    /// Compared in constant time. The comparison is worth protecting even
    /// though the socket is already restricted to this user: the agent is
    /// reachable by every process running as you, which is the whole reason
    /// locking it is a thing people do.
    fn unlock(&mut self, passphrase: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        if !self.locked {
            return false;
        }
        let Some(expected) = self.lock_passphrase.as_ref() else {
            // Locked without a passphrase can only happen if a future caller
            // sets `locked` directly; refuse rather than unlock for free.
            return false;
        };
        if expected.len() != passphrase.len() {
            return false;
        }
        if !bool::from(expected.as_slice().ct_eq(passphrase)) {
            return false;
        }
        self.locked = false;
        self.lock_passphrase = None;
        true
    }

    /// Collect every SSH key stored in an unlocked vault.
    ///
    /// Keys that fail to parse are logged and skipped rather than failing the
    /// whole load — one bad paste should not cost you every other identity.
    /// The same applies to security-key identities when `signer` is `None`.
    pub fn load_from_vault(vault: &Vault, signer: Option<Arc<dyn TokenSigner>>) -> Self {
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
                Ok(key) if key.needs_token() && signer.is_none() => tracing::warn!(
                    "skipping `{}`: it is a security-key identity and no token backend is \
                     available in this build",
                    item.label
                ),
                Ok(key) => {
                    let mut key = key
                        .with_token_pin(
                            item.field_value(field_names::TOKEN_PIN).map(str::to_owned),
                        )
                        .confirm_each_use(is_truthy(
                            item.field_value(field_names::CONFIRM_EACH_USE),
                        ));
                    if let Some(cert) = item.field_value(field_names::CERTIFICATE)
                        && !cert.trim().is_empty()
                        && let Err(e) = key.attach_certificate(cert)
                    {
                        // The bare key is still worth serving: an expired or
                        // mismatched certificate is not a reason to lose the
                        // identity underneath it.
                        tracing::warn!("ignoring the certificate on `{}`: {e}", item.label);
                    }
                    keys.push(key);
                }
                Err(e) => tracing::warn!("skipping SSH key `{}`: {e}", item.label),
            }
        }
        let agent = Self::with_keys(keys);
        match signer {
            Some(s) => agent.with_signer(s),
            None => agent,
        }
    }

    fn identities_answer(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENT_IDENTITIES_ANSWER);
        if self.locked {
            // Locked: advertise nothing.
            w.write_u32(0);
            return w.into_framed();
        }
        let identities: Vec<(&[u8], &str)> = self
            .keys
            .iter()
            .flat_map(|k| k.identities().map(move |blob| (blob, k.comment.as_str())))
            .collect();
        w.write_u32(identities.len() as u32);
        for (blob, comment) in identities {
            w.write_string(blob).write_string(comment.as_bytes());
        }
        w.into_framed()
    }

    fn sign_response(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        if self.locked {
            return Err(Error::NoSuchKey);
        }
        let key = self
            .keys
            .iter()
            .find(|k| k.identities().any(|blob| blob == key_blob))
            .ok_or(Error::NoSuchKey)?;

        let blob = key.sign(
            data,
            flags,
            self.signer.as_deref(),
            self.confirmer.as_deref(),
        )?;
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENT_SIGN_RESPONSE)
            .write_string(&blob);
        Ok(w.into_framed())
    }

    /// Seconds since the epoch when this agent last answered a request, or 0
    /// if it never has.
    pub fn last_request(&self) -> u64 {
        self.last_request
    }

    /// Handle one request body; returns the framed response.
    pub fn handle(&mut self, body: &[u8]) -> Vec<u8> {
        self.last_request = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let request = match Request::parse(body) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("malformed agent request: {e}");
                return protocol::failure();
            }
        };

        match request {
            Request::RequestIdentities => self.identities_answer(),

            Request::Sign {
                key_blob,
                data,
                flags,
            } => {
                match self.sign_response(&key_blob, &data, flags) {
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

            Request::Lock { passphrase } => {
                if self.lock(passphrase) {
                    protocol::success()
                } else {
                    protocol::failure()
                }
            }
            Request::Unlock { passphrase } => {
                if self.unlock(&passphrase) {
                    protocol::success()
                } else {
                    tracing::debug!("agent unlock refused: wrong passphrase");
                    protocol::failure()
                }
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
    use crate::sk::TokenAssertion;
    use crate::wire::Reader;
    use ssh_key::{
        Algorithm, LineEnding, public,
        private::{self, KeypairData},
        rand_core::OsRng,
        sha2::{Digest, Sha256},
    };
    use std::sync::Mutex;

    /// A security key in software.
    ///
    /// Produces assertions exactly the way a token does — signing
    /// `auth_data ‖ SHA256(message)` with the credential's key — so the
    /// encoding above can be checked against `ssh-key`'s own verifier without
    /// anyone having to touch hardware.
    struct FakeToken {
        credential: PrivateKey,
        counter: u32,
        flags: u8,
        /// What the agent asked for, for the tests that care.
        seen: Mutex<Vec<Asked>>,
    }

    /// One request as the token saw it.
    struct Asked {
        application: String,
        key_handle: Vec<u8>,
        user_verification: bool,
        pin: Option<String>,
    }

    impl FakeToken {
        fn new(credential: PrivateKey) -> Self {
            Self {
                credential,
                counter: 42,
                flags: 0x05,
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl TokenSigner for FakeToken {
        fn assert(&self, request: &SkSignRequest) -> Result<TokenAssertion> {
            self.seen.lock().unwrap().push(Asked {
                application: request.application.clone(),
                key_handle: request.key_handle.clone(),
                user_verification: request.user_verification,
                pin: request.pin.as_ref().map(|p| p.to_string()),
            });

            let mut auth_data = Sha256::digest(request.application.as_bytes()).to_vec();
            auth_data.push(self.flags);
            auth_data.extend_from_slice(&self.counter.to_be_bytes());

            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&request.message));

            let signature: Signature = self
                .credential
                .try_sign(&signed)
                .map_err(|e| Error::Signing(e.to_string()))?;

            Ok(TokenAssertion {
                auth_data,
                signature: signature.as_bytes().to_vec(),
            })
        }
    }

    /// An `sk-ssh-ed25519` identity plus the software token that backs it.
    fn security_key(flags: u8) -> (AgentKey, Arc<FakeToken>) {
        let credential = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public::KeyData::Ed25519(point) = credential.public_key().key_data() else {
            panic!("expected an ed25519 key");
        };

        let sk = private::SkEd25519::new(
            public::SkEd25519::new(*point, "ssh:"),
            flags,
            b"credential-handle".to_vec(),
        )
        .unwrap();
        let key = PrivateKey::new(KeypairData::SkEd25519(sk), "token@laptop").unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();

        let agent_key = AgentKey::from_openssh(&pem, None, Some("token@laptop")).unwrap();
        (agent_key, Arc::new(FakeToken::new(credential)))
    }

    /// Ask the agent to sign, and hand back the signature blob it produced.
    fn sign_through(agent: &mut Agent, blob: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
            .write_string(blob)
            .write_string(message)
            .write_u32(0);
        let response = agent.handle(w.as_slice());
        if response == protocol::failure() {
            return None;
        }
        let (kind, rest) = body_of(&response);
        assert_eq!(kind, protocol::SSH_AGENT_SIGN_RESPONSE);
        Some(Reader::new(&rest).read_string().unwrap().to_vec())
    }

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

        // A lock request carries the passphrase that will unlock it again.
        let mut lock = Writer::new();
        lock.write_u8(protocol::SSH_AGENTC_LOCK).write_string(b"pw");
        assert_eq!(agent.handle(lock.as_slice()), protocol::success());
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
    fn locking_and_unlocking_the_agent_round_trips() {
        let mut agent = Agent::with_keys(vec![test_key("a")]);
        let lock = |pw: &[u8]| {
            let mut w = Writer::new();
            w.write_u8(protocol::SSH_AGENTC_LOCK).write_string(pw);
            w.into_bytes()
        };
        let unlock = |pw: &[u8]| {
            let mut w = Writer::new();
            w.write_u8(protocol::SSH_AGENTC_UNLOCK).write_string(pw);
            w.into_bytes()
        };

        assert_eq!(agent.handle(&lock(b"hunter2")), protocol::success());
        assert!(agent.is_locked());
        // Locking twice would otherwise replace the passphrase.
        assert_eq!(agent.handle(&lock(b"other")), protocol::failure());

        assert_eq!(agent.handle(&unlock(b"wrong")), protocol::failure());
        assert!(agent.is_locked(), "a wrong passphrase unlocked the agent");
        assert_eq!(agent.handle(&unlock(b"hunter2")), protocol::success());
        assert!(!agent.is_locked());

        // And the identities are back.
        let (_, rest) = body_of(&agent.handle(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]));
        assert_eq!(Reader::new(&rest).read_u32().unwrap(), 1);
    }

    #[test]
    fn unlocking_an_unlocked_agent_is_refused() {
        let mut agent = Agent::with_keys(vec![test_key("a")]);
        let mut w = Writer::new();
        w.write_u8(protocol::SSH_AGENTC_UNLOCK).write_string(b"anything");
        assert_eq!(agent.handle(w.as_slice()), protocol::failure());
    }

    #[test]
    fn locking_the_vault_drops_the_keys_and_unlocking_brings_them_back() {
        // The security property behind `forget_keys`: an agent that kept its
        // keys would go on authenticating as you after the vault was locked.
        use locket_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        vault.add_item_default(
            Item::new(ItemKind::SshKey, "build server").with_field(Field::new(
                field_names::PRIVATE_KEY,
                FieldKind::PrivateKey,
                key.to_openssh(LineEnding::LF).unwrap().to_string(),
            )),
        );

        let mut agent = Agent::new();
        agent.reload_from_vault(&vault);
        assert_eq!(agent.len(), 1);
        let blob = agent.keys[0].public_blob.clone();

        agent.forget_keys();
        assert_eq!(agent.len(), 0, "the keys survived the vault locking");
        assert!(
            sign_through(&mut agent, &blob, b"data").is_none(),
            "signed with a key the vault had locked"
        );

        agent.reload_from_vault(&vault);
        assert_eq!(agent.len(), 1, "unlocking did not bring the keys back");
        assert!(sign_through(&mut agent, &blob, b"data").is_some());
    }

    #[test]
    fn reloading_picks_up_a_key_added_since() {
        use locket_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let mut agent = Agent::new();
        agent.reload_from_vault(&vault);
        assert_eq!(agent.len(), 0);

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        vault.add_item_default(
            Item::new(ItemKind::SshKey, "added later").with_field(Field::new(
                field_names::PRIVATE_KEY,
                FieldKind::PrivateKey,
                key.to_openssh(LineEnding::LF).unwrap().to_string(),
            )),
        );
        agent.reload_from_vault(&vault);
        assert_eq!(agent.len(), 1);
    }

    #[test]
    fn an_rsa_key_signs_under_the_algorithm_the_client_asked_for() {
        // `ssh-key` cannot sign RSA at all from a file-loaded key, so this is
        // the regression guard for the whole `signing` module being wired in.
        let key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None }).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let agent_key = AgentKey::from_openssh(&pem, None, Some("rsa")).unwrap();
        let blob = agent_key.public_blob.clone();
        let mut agent = Agent::with_keys(vec![agent_key]);

        for (flags, expected) in [
            (0, "ssh-rsa"),
            (protocol::SSH_AGENT_RSA_SHA2_256, "rsa-sha2-256"),
            (protocol::SSH_AGENT_RSA_SHA2_512, "rsa-sha2-512"),
        ] {
            let mut w = Writer::new();
            w.write_u8(protocol::SSH_AGENTC_SIGN_REQUEST)
                .write_string(&blob)
                .write_string(b"data")
                .write_u32(flags);
            let (kind, rest) = body_of(&agent.handle(w.as_slice()));
            assert_eq!(kind, protocol::SSH_AGENT_SIGN_RESPONSE, "refused flags {flags}");

            let mut r = Reader::new(&rest);
            let sig_blob = r.read_string().unwrap();
            let mut inner = Reader::new(sig_blob);
            assert_eq!(inner.read_utf8().unwrap(), expected);
            assert!(!inner.read_string().unwrap().is_empty());
        }
    }

    /// A key with a certificate issued for it, and the CA that signed it.
    fn certified_key(valid_from: u64, valid_until: u64) -> (AgentKey, ssh_key::Certificate) {
        use ssh_key::certificate;

        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            user.public_key(),
            valid_from,
            valid_until,
        )
        .unwrap();
        builder.key_id("ada@example").unwrap();
        builder.valid_principal("ada").unwrap();
        let cert = builder.sign(&ca).unwrap();

        let pem = user.to_openssh(LineEnding::LF).unwrap();
        let key = AgentKey::from_openssh(&pem, None, Some("user@host")).unwrap();
        (key, cert)
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn a_certified_key_is_advertised_twice_certificate_first() {
        let (mut key, cert) = certified_key(now() - 60, now() + 3600);
        key.attach_certificate(&cert.to_openssh().unwrap()).unwrap();
        let plain = key.public_blob.clone();

        let mut agent = Agent::with_keys(vec![key]);
        let (_, rest) = body_of(&agent.handle(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]));
        let mut r = Reader::new(&rest);
        assert_eq!(r.read_u32().unwrap(), 2, "a certified key is two identities");

        let first = r.read_string().unwrap().to_vec();
        assert_eq!(r.read_utf8().unwrap(), "user@host");
        let second = r.read_string().unwrap().to_vec();
        assert_eq!(r.read_utf8().unwrap(), "user@host");

        assert_eq!(first, cert.to_bytes().unwrap(), "the certificate is not offered first");
        assert_eq!(second, plain);
    }

    #[test]
    fn signing_for_the_certificate_blob_uses_the_key_underneath() {
        let (mut key, cert) = certified_key(now() - 60, now() + 3600);
        key.attach_certificate(&cert.to_openssh().unwrap()).unwrap();
        let public = ssh_key::PublicKey::from_bytes(&key.public_blob).unwrap();
        let cert_blob = cert.to_bytes().unwrap();

        let mut agent = Agent::with_keys(vec![key]);
        let sig_blob = sign_through(&mut agent, &cert_blob, b"data to be signed")
            .expect("refused to sign for its own certificate");

        // The signature is made with the underlying key, so it verifies
        // against the plain public key — which is what a server does after
        // checking the certificate's CA signature.
        let mut inner = Reader::new(&sig_blob);
        assert_eq!(inner.read_utf8().unwrap(), "ssh-ed25519");
        let raw = inner.read_string().unwrap();
        let signature = Signature::new(Algorithm::Ed25519, raw.to_vec()).unwrap();
        assert!(
            <ssh_key::PublicKey as signature::Verifier<Signature>>::verify(
                &public,
                b"data to be signed",
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let (mut key, _) = certified_key(now() - 60, now() + 3600);
        let (_, other_cert) = certified_key(now() - 60, now() + 3600);
        let err = key
            .attach_certificate(&other_cert.to_openssh().unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("different key"), "unexpected: {err}");
    }

    #[test]
    fn a_certificate_outside_its_validity_window_is_refused() {
        // Offering one would cost the client an authentication attempt against
        // the server's limit for something no server will accept.
        let (mut key, expired) = certified_key(now() - 7200, now() - 3600);
        assert!(
            key.attach_certificate(&expired.to_openssh().unwrap())
                .unwrap_err()
                .to_string()
                .contains("expired")
        );

        let (mut key, future) = certified_key(now() + 3600, now() + 7200);
        assert!(
            key.attach_certificate(&future.to_openssh().unwrap())
                .unwrap_err()
                .to_string()
                .contains("not valid until")
        );
    }

    #[test]
    fn a_bad_certificate_does_not_cost_you_the_key_underneath() {
        use locket_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        vault.add_item_default(
            Item::new(ItemKind::SshKey, "certified")
                .with_field(Field::new(
                    field_names::PRIVATE_KEY,
                    FieldKind::PrivateKey,
                    key.to_openssh(LineEnding::LF).unwrap().to_string(),
                ))
                .with_field(Field::new(
                    field_names::CERTIFICATE,
                    FieldKind::Text,
                    "ssh-ed25519-cert-v01@openssh.com not-actually-base64",
                )),
        );

        let agent = Agent::load_from_vault(&vault, None);
        assert_eq!(agent.len(), 1, "a broken certificate lost the key as well");
        assert!(agent.keys[0].certificate.is_none());
    }

    /// Records what it was asked, and answers however it was told to.
    struct Asker {
        allow: bool,
        asked: Mutex<Vec<String>>,
    }

    impl crate::confirm::SigningConfirmer for Asker {
        fn confirm(&self, key: &str) -> bool {
            self.asked.lock().unwrap().push(key.to_owned());
            self.allow
        }
    }

    #[test]
    fn a_key_marked_confirm_each_use_asks_before_signing() {
        let key = test_key("gated").confirm_each_use(true);
        let blob = key.public_blob.clone();
        let asker = Arc::new(Asker {
            allow: true,
            asked: Mutex::new(Vec::new()),
        });

        let mut agent = Agent::with_keys(vec![key]).with_confirmer(asker.clone());
        assert!(sign_through(&mut agent, &blob, b"data").is_some());
        assert_eq!(asker.asked.lock().unwrap().as_slice(), &["gated".to_owned()]);
    }

    #[test]
    fn refusing_the_confirmation_refuses_the_signature() {
        let key = test_key("gated").confirm_each_use(true);
        let blob = key.public_blob.clone();
        let asker = Arc::new(Asker {
            allow: false,
            asked: Mutex::new(Vec::new()),
        });

        let mut agent = Agent::with_keys(vec![key]).with_confirmer(asker);
        assert!(
            sign_through(&mut agent, &blob, b"data").is_none(),
            "signed despite the confirmation being refused"
        );
    }

    #[test]
    fn a_gated_key_with_nothing_to_ask_refuses_rather_than_signing() {
        // Fail closed: "there is nobody to ask" is not permission.
        let key = test_key("gated").confirm_each_use(true);
        let blob = key.public_blob.clone();
        let mut agent = Agent::with_keys(vec![key]);
        assert!(sign_through(&mut agent, &blob, b"data").is_none());
    }

    #[test]
    fn an_ungated_key_never_asks() {
        let key = test_key("open");
        let blob = key.public_blob.clone();
        let asker = Arc::new(Asker {
            allow: false,
            asked: Mutex::new(Vec::new()),
        });

        let mut agent = Agent::with_keys(vec![key]).with_confirmer(asker.clone());
        assert!(
            sign_through(&mut agent, &blob, b"data").is_some(),
            "an ordinary key was gated by a confirmer that refuses everything"
        );
        assert!(asker.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn the_confirm_field_is_read_off_the_item() {
        use locket_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        for (label, value) in [("gated", "yes"), ("also-gated", "TRUE"), ("open", "no")] {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            vault.add_item_default(
                Item::new(ItemKind::SshKey, label)
                    .with_field(Field::new(
                        field_names::PRIVATE_KEY,
                        FieldKind::PrivateKey,
                        key.to_openssh(LineEnding::LF).unwrap().to_string(),
                    ))
                    .with_field(Field::text(field_names::CONFIRM_EACH_USE, value)),
            );
        }

        let agent = Agent::load_from_vault(&vault, None);
        assert_eq!(agent.len(), 3);
        let gated: Vec<_> = agent
            .keys
            .iter()
            .filter(|k| k.confirm_each_use)
            .map(|k| k.comment.as_str())
            .collect();
        assert_eq!(gated, vec!["gated", "also-gated"]);
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
    fn a_security_key_signature_verifies_as_a_real_sk_signature() {
        let message = b"session identifier and the rest of a real sign request";
        let (key, token) = security_key(0x01);
        let blob = key.public_blob.clone();
        let public = ssh_key::PublicKey::from_bytes(&blob).unwrap();
        assert_eq!(public.algorithm().as_str(), "sk-ssh-ed25519@openssh.com");

        let mut agent = Agent::with_keys(vec![key]).with_signer(token.clone());
        let sig_blob = sign_through(&mut agent, &blob, message).expect("agent refused to sign");

        // Parsed by ssh-key's decoder, which expects flags and counter to sit
        // outside the signature string, and verified by its own independent
        // implementation of the sk scheme.
        let signature = Signature::try_from(sig_blob.as_slice())
            .expect("ssh-key could not decode the signature blob we produced");
        assert_eq!(signature.algorithm().as_str(), "sk-ssh-ed25519@openssh.com");
        assert!(
            <ssh_key::PublicKey as signature::Verifier<Signature>>::verify(
                &public, message, &signature
            )
            .is_ok(),
            "the security-key signature did not verify against the advertised public key"
        );
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let (key, token) = security_key(0x01);
        let blob = key.public_blob.clone();
        let public = ssh_key::PublicKey::from_bytes(&blob).unwrap();

        let mut agent = Agent::with_keys(vec![key]).with_signer(token);
        let sig_blob = sign_through(&mut agent, &blob, b"the real request").unwrap();
        let signature = Signature::try_from(sig_blob.as_slice()).unwrap();

        assert!(
            <ssh_key::PublicKey as signature::Verifier<Signature>>::verify(
                &public,
                b"a different request",
                &signature
            )
            .is_err(),
            "a signature verified against a message it was not made over"
        );
    }

    #[test]
    fn the_token_is_asked_for_the_keys_own_application_and_handle() {
        let (key, token) = security_key(SK_USER_VERIFICATION_REQD);
        let blob = key.public_blob.clone();
        let key = key.with_token_pin(Some("1234".into()));

        let mut agent = Agent::with_keys(vec![key]).with_signer(token.clone());
        sign_through(&mut agent, &blob, b"data").unwrap();

        let seen = token.seen.lock().unwrap();
        let asked = seen.first().unwrap();
        assert_eq!(asked.application, "ssh:");
        assert_eq!(asked.key_handle, b"credential-handle");
        assert!(
            asked.user_verification,
            "a verify-required key was asserted without user verification"
        );
        assert_eq!(asked.pin.as_deref(), Some("1234"));
    }

    #[test]
    fn a_touch_only_key_does_not_demand_user_verification() {
        let (key, token) = security_key(0x01);
        let blob = key.public_blob.clone();
        let mut agent = Agent::with_keys(vec![key]).with_signer(token.clone());
        sign_through(&mut agent, &blob, b"data").unwrap();

        let seen = token.seen.lock().unwrap();
        let asked = seen.first().unwrap();
        assert!(!asked.user_verification, "a touch-only key demanded user verification");
        assert_eq!(asked.pin, None);
    }

    #[test]
    fn without_a_token_backend_a_security_key_refuses_rather_than_signing_wrongly() {
        let (key, _) = security_key(0x01);
        let blob = key.public_blob.clone();
        let mut agent = Agent::with_keys(vec![key]);
        assert!(
            sign_through(&mut agent, &blob, b"data").is_none(),
            "signed without a token"
        );
    }

    #[test]
    fn security_key_identities_are_not_advertised_without_a_token_backend() {
        // Offering an identity the agent cannot sign for is worse than not
        // having it: the client spends one of the server's permitted
        // authentication attempts on it.
        use locket_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let credential = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public::KeyData::Ed25519(point) = credential.public_key().key_data() else {
            panic!("expected an ed25519 key");
        };
        let sk = private::SkEd25519::new(
            public::SkEd25519::new(*point, "ssh:"),
            0x01,
            b"handle".to_vec(),
        )
        .unwrap();
        let pem = PrivateKey::new(KeypairData::SkEd25519(sk), "sk")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();

        vault.add_item_default(
            Item::new(ItemKind::SshKey, "yubikey").with_field(Field::new(
                field_names::PRIVATE_KEY,
                FieldKind::PrivateKey,
                pem.to_string(),
            )),
        );

        assert_eq!(Agent::load_from_vault(&vault, None).len(), 0);

        let token = Arc::new(FakeToken::new(credential));
        let agent = Agent::load_from_vault(&vault, Some(token));
        assert_eq!(agent.len(), 1, "a token backend should make the key usable");
    }

    #[test]
    fn the_token_pin_comes_off_the_item() {
        use locket_core::{
            crypto::KdfParams,
            model::{Field, FieldKind, Item, ItemKind},
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let credential = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public::KeyData::Ed25519(point) = credential.public_key().key_data() else {
            panic!("expected an ed25519 key");
        };
        let sk = private::SkEd25519::new(
            public::SkEd25519::new(*point, "ssh:"),
            SK_USER_VERIFICATION_REQD,
            b"handle".to_vec(),
        )
        .unwrap();
        let pem = PrivateKey::new(KeypairData::SkEd25519(sk), "sk")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();

        vault.add_item_default(
            Item::new(ItemKind::SshKey, "yubikey")
                .with_field(Field::new(
                    field_names::PRIVATE_KEY,
                    FieldKind::PrivateKey,
                    pem.to_string(),
                ))
                .with_field(Field::secret(field_names::TOKEN_PIN, "9876")),
        );

        let token = Arc::new(FakeToken::new(credential));
        let mut agent = Agent::load_from_vault(&vault, Some(token.clone()));
        let blob = agent.keys[0].public_blob.clone();
        sign_through(&mut agent, &blob, b"data").unwrap();

        assert_eq!(token.seen.lock().unwrap()[0].pin.as_deref(), Some("9876"));
    }

    #[test]
    fn loads_ssh_keys_out_of_a_vault() {
        use locket_core::{
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

        let agent = Agent::load_from_vault(&vault, None);
        assert_eq!(agent.len(), 1);
        assert_eq!(agent.keys[0].comment, "me@host");
    }
}
