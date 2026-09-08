//! RSA signing, and the hash the client asked for.
//!
//! An RSA public key is always advertised as `ssh-rsa`, but the *signature*
//! may be made with SHA-1, SHA-256 or SHA-512, and it is the client that
//! decides: `SSH_AGENTC_SIGN_REQUEST` carries flags saying which. OpenSSH has
//! disabled SHA-1 server-side since 8.8, so a client talking to a modern
//! server asks for `rsa-sha2-256` or `-512` and rejects a signature that comes
//! back under a different name.
//!
//! `ssh-key` cannot do any of this for us. A key loaded from a file has
//! algorithm `Rsa { hash: None }` — no hash was recorded, because the file
//! does not carry one — and both its signer and its own conversion into the
//! `rsa` crate fail with a bare "cryptographic error" in that state. So the
//! keypair's components are handed to `rsa` directly and the hash is chosen
//! per request.

use rsa::BigUint;
use rsa::pkcs1v15::SigningKey;
use signature::{SignatureEncoding, Signer};
use ssh_key::Mpint;
use ssh_key::private::RsaKeypair;

use crate::error::{Error, Result};
use crate::protocol::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

/// Which hash a signature was asked for, and what to call it on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHash {
    /// `ssh-rsa`. Only produced when a client explicitly asks — which it does
    /// by sending no flags at all, the pre-8.8 default. Refusing it here would
    /// break the older servers that are the only reason to still hold an RSA
    /// key.
    Sha1,
    Sha256,
    Sha512,
}

impl RsaHash {
    /// Read the client's choice out of the sign-request flags.
    ///
    /// SHA-512 wins if both bits are set: the flags are a preference list and
    /// OpenSSH sets the strongest it will accept.
    pub fn from_flags(flags: u32) -> Self {
        if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
            RsaHash::Sha512
        } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
            RsaHash::Sha256
        } else {
            RsaHash::Sha1
        }
    }

    /// The signature algorithm name. Not the same as the *key* name, which is
    /// `ssh-rsa` in all three cases.
    pub fn algorithm(self) -> &'static str {
        match self {
            RsaHash::Sha1 => "ssh-rsa",
            RsaHash::Sha256 => "rsa-sha2-256",
            RsaHash::Sha512 => "rsa-sha2-512",
        }
    }
}

/// Sign `data` with an RSA keypair under the requested hash.
///
/// Returns the raw signature; the caller wraps it with the algorithm name.
pub fn rsa_signature(keypair: &RsaKeypair, data: &[u8], hash: RsaHash) -> Result<Vec<u8>> {
    let key = private_key(keypair)?;
    let signature = match hash {
        RsaHash::Sha1 => SigningKey::<sha1::Sha1>::new(key).sign(data).to_vec(),
        RsaHash::Sha256 => SigningKey::<sha2::Sha256>::new(key).sign(data).to_vec(),
        RsaHash::Sha512 => SigningKey::<sha2::Sha512>::new(key).sign(data).to_vec(),
    };
    Ok(signature)
}

/// Rebuild an `rsa` private key from the SSH keypair's components.
fn private_key(keypair: &RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let big = |m: &Mpint, what: &'static str| -> Result<BigUint> {
        m.as_positive_bytes()
            .map(BigUint::from_bytes_be)
            .ok_or_else(|| {
                Error::BadKey(format!("RSA component `{what}` is not a positive integer"))
            })
    };

    rsa::RsaPrivateKey::from_components(
        big(&keypair.public.n, "n")?,
        big(&keypair.public.e, "e")?,
        big(&keypair.private.d, "d")?,
        vec![big(&keypair.private.p, "p")?, big(&keypair.private.q, "q")?],
    )
    .map_err(|e| Error::BadKey(format!("RSA key components do not form a usable key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey, rand_core::OsRng};

    /// Key generation dominates this test's runtime; `ssh-key` picks the size.
    fn rsa_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None }).unwrap()
    }

    fn keypair(key: &PrivateKey) -> &RsaKeypair {
        match key.key_data() {
            ssh_key::private::KeypairData::Rsa(kp) => kp,
            _ => panic!("not an RSA key"),
        }
    }

    #[test]
    fn flags_pick_the_hash_the_client_asked_for() {
        assert_eq!(RsaHash::from_flags(0), RsaHash::Sha1);
        assert_eq!(RsaHash::from_flags(SSH_AGENT_RSA_SHA2_256), RsaHash::Sha256);
        assert_eq!(RsaHash::from_flags(SSH_AGENT_RSA_SHA2_512), RsaHash::Sha512);
        // Both set: take the stronger.
        assert_eq!(
            RsaHash::from_flags(SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512),
            RsaHash::Sha512
        );
        // Unrelated bits must not change the choice.
        assert_eq!(RsaHash::from_flags(0x8000_0000), RsaHash::Sha1);
    }

    #[test]
    fn the_wire_name_is_the_signature_algorithm_not_the_key_algorithm() {
        assert_eq!(RsaHash::Sha1.algorithm(), "ssh-rsa");
        assert_eq!(RsaHash::Sha256.algorithm(), "rsa-sha2-256");
        assert_eq!(RsaHash::Sha512.algorithm(), "rsa-sha2-512");
    }

    #[test]
    fn every_hash_produces_a_signature_that_verifies() {
        use rsa::pkcs1v15::VerifyingKey;
        use signature::Verifier;

        let key = rsa_key();
        let kp = keypair(&key);
        let public = rsa::RsaPublicKey::from(&private_key(kp).unwrap());

        for hash in [RsaHash::Sha1, RsaHash::Sha256, RsaHash::Sha512] {
            let raw = rsa_signature(kp, b"a sign request", hash).unwrap();
            assert_eq!(
                raw.len(),
                rsa::traits::PublicKeyParts::size(&public),
                "a PKCS#1 v1.5 signature is exactly the modulus size"
            );

            let ok = match hash {
                RsaHash::Sha1 => VerifyingKey::<sha1::Sha1>::new(public.clone())
                    .verify(b"a sign request", &raw.as_slice().try_into().unwrap()),
                RsaHash::Sha256 => VerifyingKey::<sha2::Sha256>::new(public.clone())
                    .verify(b"a sign request", &raw.as_slice().try_into().unwrap()),
                RsaHash::Sha512 => VerifyingKey::<sha2::Sha512>::new(public.clone())
                    .verify(b"a sign request", &raw.as_slice().try_into().unwrap()),
            };
            assert!(ok.is_ok(), "{hash:?} signature did not verify");
        }
    }

    #[test]
    fn the_hash_actually_changes_the_signature() {
        // Guards against a refactor that quietly ignores the requested hash:
        // the wire name would still be right and the server would reject it.
        let key = rsa_key();
        let kp = keypair(&key);
        let a = rsa_signature(kp, b"message", RsaHash::Sha256).unwrap();
        let b = rsa_signature(kp, b"message", RsaHash::Sha512).unwrap();
        assert_ne!(a, b);
    }
}
