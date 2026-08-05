//! Vault cryptography.
//!
//! The scheme is deliberately boring:
//!
//! * **KDF** — Argon2id derives a 32-byte *key-encryption key* (KEK) from the
//!   user's passphrase and a per-vault random salt.
//! * **Key wrapping** — the vault body is encrypted under a random 32-byte
//!   *data-encryption key* (DEK); the DEK is sealed under the KEK. Changing the
//!   passphrase therefore rewraps 32 bytes instead of re-encrypting the vault,
//!   and the unlocked daemon holds only the DEK — the passphrase and the KEK
//!   are dropped as soon as unwrapping finishes.
//! * **AEAD** — XChaCha20-Poly1305 everywhere. The 192-bit nonce means random
//!   nonces are safe without a counter, which matters because a vault file may
//!   be copied between machines and written concurrently by daemon and CLI.
//!
//! The header is authenticated as associated data on the body, so an attacker
//! cannot downgrade the KDF parameters without invalidating the tag.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, secret::SecretBytes};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// Argon2id cost parameters, stored in the vault header.
///
/// They live in the file rather than in code so that a vault created on a
/// beefy desktop still opens on a phone, and so costs can be raised over time
/// without breaking existing vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub m_cost: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// OWASP's 2024 baseline for Argon2id: 64 MiB, 3 passes, 4 lanes.
    ///
    /// Takes roughly 100 ms on a modern desktop core — slow enough to hurt an
    /// offline cracker, fast enough that unlocking does not feel broken.
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for tests. Never use for a real vault.
    #[doc(hidden)]
    pub fn insecure_fast() -> Self {
        Self {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn to_argon2(self) -> Result<argon2::Argon2<'static>> {
        let params = argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| Error::KdfParams(e.to_string()))?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// A 32-byte symmetric key, wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymKey([u8; KEY_LEN]);

impl SymKey {
    pub fn random() -> Result<Self> {
        let mut k = [0u8; KEY_LEN];
        getrandom::fill(&mut k)?;
        Ok(Self(k))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; KEY_LEN] = slice.try_into().map_err(|_| Error::FieldLength {
            field: "key",
            found: slice.len(),
            expected: KEY_LEN,
        })?;
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive a KEK from a passphrase.
    pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Self> {
        let mut out = [0u8; KEY_LEN];
        params
            .to_argon2()?
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(Self(out))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&self.0))
    }

    /// Encrypt `plaintext`, binding `aad` into the authentication tag.
    ///
    /// Returns a fresh random nonce alongside the ciphertext; the caller must
    /// store both.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)?;
        let ciphertext = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            // The AEAD error type is deliberately opaque; at this point the only
            // realistic cause is a plaintext larger than the ChaCha20 keystream.
            .map_err(|_| Error::Other("message too large to encrypt".into()))?;
        Ok((nonce, ciphertext))
    }

    /// Decrypt and verify. Any tampering — with ciphertext *or* `aad` —
    /// surfaces as [`Error::Unauthenticated`].
    pub fn open(&self, nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Unauthenticated)
    }

    /// Seal another key under this one.
    pub fn wrap(&self, dek: &SymKey, aad: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        self.seal(&dek.0, aad)
    }

    /// Unseal a key sealed with [`SymKey::wrap`].
    pub fn unwrap_key(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<SymKey> {
        let mut plaintext = self.open(nonce, ciphertext, aad)?;
        let key = SymKey::try_from_slice(&plaintext);
        plaintext.zeroize();
        key
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymKey([redacted])")
    }
}

/// Generate a random salt for a new vault.
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)?;
    Ok(salt)
}

/// Random bytes, for callers that want a [`SecretBytes`].
pub fn random_secret(len: usize) -> Result<SecretBytes> {
    SecretBytes::random(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SymKey::random().unwrap();
        let (nonce, ct) = key.seal(b"hunter2", b"header").unwrap();
        assert_eq!(key.open(&nonce, &ct, b"header").unwrap(), b"hunter2");
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let key = SymKey::random().unwrap();
        let (nonce, ct) = key.seal(b"hunter2", b"header").unwrap();
        // Downgrading the header must invalidate the body.
        assert!(matches!(
            key.open(&nonce, &ct, b"heXder"),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = SymKey::random().unwrap();
        let (nonce, mut ct) = key.seal(b"hunter2", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(
            key.open(&nonce, &ct, b""),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = SymKey::random().unwrap();
        let b = SymKey::random().unwrap();
        let (nonce, ct) = a.seal(b"hunter2", b"").unwrap();
        assert!(matches!(b.open(&nonce, &ct, b""), Err(Error::Unauthenticated)));
    }

    #[test]
    fn kdf_is_deterministic_and_salt_dependent() {
        let p = KdfParams::insecure_fast();
        let salt_a = [7u8; SALT_LEN];
        let salt_b = [9u8; SALT_LEN];
        let k1 = SymKey::derive("correct horse", &salt_a, p).unwrap();
        let k2 = SymKey::derive("correct horse", &salt_a, p).unwrap();
        let k3 = SymKey::derive("correct horse", &salt_b, p).unwrap();
        assert_eq!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose());
    }

    #[test]
    fn key_wrapping_roundtrip() {
        let kek = SymKey::random().unwrap();
        let dek = SymKey::random().unwrap();
        let (nonce, ct) = kek.wrap(&dek, b"hdr").unwrap();
        let unwrapped = kek.unwrap_key(&nonce, &ct, b"hdr").unwrap();
        assert_eq!(unwrapped.expose(), dek.expose());
    }
}
