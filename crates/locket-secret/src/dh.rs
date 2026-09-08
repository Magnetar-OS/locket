//! Secret Service session transport crypto.
//!
//! The spec defines two session algorithms:
//!
//! * `plain` — secrets cross the bus in the clear.
//! * `dh-ietf1024-sha256-aes128-cbc-pkcs7` — Diffie-Hellman over the RFC 2409
//!   Second Oakley Group, HKDF-SHA256 to a 128-bit key, AES-128-CBC with PKCS#7.
//!
//! `libsecret` negotiates the DH variant first and only falls back to `plain`
//! if the service rejects it, so implementing this is what makes locket a
//! drop-in for gnome-keyring rather than a curiosity that only works with
//! hand-written clients.
//!
//! # On the strength of this exchange
//!
//! A 1024-bit MODP group is well below what you would choose for a new
//! protocol in 2026. It is fixed by the wire format — every existing client
//! implements exactly this — and it is not the vault's security boundary: it
//! only protects a secret in transit over the session bus, against a peer that
//! can already see your D-Bus traffic. The vault at rest is XChaCha20-Poly1305
//! under Argon2id (see `locket_core::crypto`).

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub const ALGORITHM_PLAIN: &str = "plain";
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// Modulus size in bytes; shared secrets are left-padded to this width before
/// hashing, which is where naive implementations diverge from libsecret.
pub const MODULUS_LEN: usize = 128;
pub const AES_KEY_LEN: usize = 16;
pub const IV_LEN: usize = 16;

/// RFC 2409 §6.2, the Second Oakley Group (1024-bit MODP).
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF",
);

const GENERATOR: u32 = 2;

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("the Oakley group 2 prime is valid hex")
}

/// Left-pad a big-endian integer to the modulus width.
///
/// `BigUint::to_bytes_be` drops leading zero bytes, so roughly one in 256
/// exchanges would otherwise derive a different key from the peer's — an
/// intermittent failure that is miserable to debug.
fn pad_to_modulus(mut bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    if bytes.len() < MODULUS_LEN {
        let mut padded = vec![0u8; MODULUS_LEN - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes.zeroize();
        Zeroizing::new(padded)
    } else {
        Zeroizing::new(bytes)
    }
}

/// Our side of a Diffie-Hellman exchange.
pub struct DhExchange {
    private: BigUint,
    public: BigUint,
}

impl DhExchange {
    /// Generate an ephemeral keypair.
    pub fn generate() -> Result<Self> {
        let mut raw = Zeroizing::new(vec![0u8; MODULUS_LEN]);
        getrandom::fill(&mut raw).map_err(|e| Error::Crypto(e.to_string()))?;
        let private = BigUint::from_bytes_be(&raw);
        let public = BigUint::from(GENERATOR).modpow(&private, &prime());
        Ok(Self { private, public })
    }

    /// Our public key, padded, ready to hand back in `OpenSession`'s output.
    pub fn public_key(&self) -> Vec<u8> {
        pad_to_modulus(self.public.to_bytes_be()).to_vec()
    }

    /// Complete the exchange against the peer's public key and derive the
    /// AES-128 session key.
    pub fn derive_session_key(&self, peer_public: &[u8]) -> Result<[u8; AES_KEY_LEN]> {
        let p = prime();
        let peer = BigUint::from_bytes_be(peer_public);

        // Reject the degenerate public keys that force a known shared secret.
        if peer <= BigUint::from(1u32) || peer >= p.clone() - BigUint::from(1u32) {
            return Err(Error::Crypto(
                "peer offered a degenerate Diffie-Hellman public key".into(),
            ));
        }

        let shared = pad_to_modulus(peer.modpow(&self.private, &p).to_bytes_be());

        // HKDF-SHA256, null salt, empty info — as the spec requires.
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut key = [0u8; AES_KEY_LEN];
        hk.expand(&[], &mut key)
            .map_err(|e| Error::Crypto(format!("HKDF expand failed: {e}")))?;
        Ok(key)
    }
}

/// Encrypt a secret for transport. Returns `(iv, ciphertext)`; the IV travels
/// in the Secret struct's `parameters` field.
pub fn encrypt(key: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut iv = [0u8; IV_LEN];
    getrandom::fill(&mut iv).map_err(|e| Error::Crypto(e.to_string()))?;
    let ciphertext =
        Aes128CbcEnc::new(key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    Ok((iv.to_vec(), ciphertext))
}

/// Decrypt a secret received from a client.
pub fn decrypt(key: &[u8; AES_KEY_LEN], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let iv: [u8; IV_LEN] = iv.try_into().map_err(|_| {
        Error::Crypto(format!(
            "session IV must be {IV_LEN} bytes, got {}",
            iv.len()
        ))
    })?;
    Aes128CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Crypto("secret failed to decrypt (bad padding or wrong key)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_is_1024_bits() {
        assert_eq!(prime().to_bytes_be().len(), MODULUS_LEN);
    }

    #[test]
    fn both_sides_derive_the_same_key() {
        let server = DhExchange::generate().unwrap();
        let client = DhExchange::generate().unwrap();

        let server_key = server.derive_session_key(&client.public_key()).unwrap();
        let client_key = client.derive_session_key(&server.public_key()).unwrap();
        assert_eq!(server_key, client_key);
    }

    #[test]
    fn public_keys_are_always_padded_to_the_modulus_width() {
        for _ in 0..32 {
            assert_eq!(
                DhExchange::generate().unwrap().public_key().len(),
                MODULUS_LEN
            );
        }
    }

    #[test]
    fn independent_exchanges_produce_different_keys() {
        let a = DhExchange::generate().unwrap();
        let b = DhExchange::generate().unwrap();
        let c = DhExchange::generate().unwrap();
        assert_ne!(
            a.derive_session_key(&b.public_key()).unwrap(),
            a.derive_session_key(&c.public_key()).unwrap()
        );
    }

    #[test]
    fn degenerate_public_keys_are_rejected() {
        let server = DhExchange::generate().unwrap();
        // 0, 1 and p-1 each pin the shared secret to a value the peer knows.
        for bad in [
            BigUint::from(0u32),
            BigUint::from(1u32),
            prime() - BigUint::from(1u32),
            prime(),
        ] {
            assert!(
                server
                    .derive_session_key(&pad_to_modulus(bad.to_bytes_be()))
                    .is_err(),
                "accepted a degenerate public key"
            );
        }
    }

    #[test]
    fn aes_roundtrip() {
        let server = DhExchange::generate().unwrap();
        let client = DhExchange::generate().unwrap();
        let key = server.derive_session_key(&client.public_key()).unwrap();

        for plaintext in [b"".as_slice(), b"hunter2", &[0x41u8; 16], &[0x42u8; 4096]] {
            let (iv, ct) = encrypt(&key, plaintext).unwrap();
            assert_eq!(iv.len(), IV_LEN);
            // PKCS#7 always adds a block, so ciphertext is never the input.
            assert_ne!(ct.as_slice(), plaintext);
            assert_eq!(decrypt(&key, &iv, &ct).unwrap(), plaintext);
        }
    }

    #[test]
    fn decrypt_rejects_the_wrong_key_or_iv() {
        let a = DhExchange::generate().unwrap();
        let b = DhExchange::generate().unwrap();
        let key = a.derive_session_key(&b.public_key()).unwrap();
        let mut other = key;
        other[0] ^= 0xff;

        let (iv, ct) = encrypt(&key, b"a much longer secret value here").unwrap();
        assert!(decrypt(&other, &iv, &ct).is_err());
        assert!(decrypt(&key, &[0u8; 4], &ct).is_err());
    }
}
