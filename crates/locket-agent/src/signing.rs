//! RSA signing, and the hash the client asked for.
//!
//! An RSA public key is always advertised as `ssh-rsa`, but the *signature*
//! may be made with SHA-1, SHA-256 or SHA-512, and it is the client that
//! decides: `SSH_AGENTC_SIGN_REQUEST` carries flags saying which. OpenSSH has
//! disabled SHA-1 server-side since 8.8, so a client talking to a modern
//! server asks for `rsa-sha2-256` or `-512` and rejects a signature that comes
//! back under a different name.
//!
//! `ssh-key` does not make that choice for us: its own RSA signer signs with
//! SHA-512 whatever the client asked for, and unblinded. So the keypair is
//! converted to an `rsa` private key, the hash is chosen per request, and the
//! signature is made with a blinding factor.

use getrandom::SysRng;
use rsa::pkcs1v15::SigningKey;
use rsa::rand_core::TryCryptoRng;
use signature::{RandomizedSigner, SignatureEncoding};
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
    rsa_signature_with(&mut SysRng, keypair, data, hash)
}

/// [`rsa_signature`], drawing the blinding factor from `rng`.
///
/// Signed through the *randomised* signer on purpose. PKCS#1 v1.5 signing
/// needs no randomness and the plain `Signer` uses none — which in the `rsa`
/// crate means the private-key exponentiation runs unblinded, on arithmetic
/// whose timing RUSTSEC-2023-0071 is about. An agent signs data its callers
/// choose, for anything that can reach its socket, a forwarded one included;
/// with a fresh blinding factor per signature, how long one took says
/// nothing about the key.
fn rsa_signature_with(
    rng: &mut impl TryCryptoRng,
    keypair: &RsaKeypair,
    data: &[u8],
    hash: RsaHash,
) -> Result<Vec<u8>> {
    let key = private_key(keypair)?;
    // `try_sign…`, not `sign…`: a key too small for the digest cannot be
    // padded, and the infallible form panics on that rather than saying so.
    let failed = |e: signature::Error| Error::Signing(format!("{}: {e}", hash.algorithm()));
    let signature = match hash {
        RsaHash::Sha1 => SigningKey::<sha1::Sha1>::new(key)
            .try_sign_with_rng(rng, data)
            .map_err(failed)?
            .to_vec(),
        RsaHash::Sha256 => SigningKey::<sha2::Sha256>::new(key)
            .try_sign_with_rng(rng, data)
            .map_err(failed)?
            .to_vec(),
        RsaHash::Sha512 => SigningKey::<sha2::Sha512>::new(key)
            .try_sign_with_rng(rng, data)
            .map_err(failed)?
            .to_vec(),
    };
    Ok(signature)
}

/// The `rsa` private key an SSH keypair describes.
fn private_key(keypair: &RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    rsa::RsaPrivateKey::try_from(keypair).map_err(|e| {
        Error::BadKey(format!(
            "the RSA key's components do not form a usable key: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::PrivateKey;
    use ssh_key::private::KeypairData;

    /// Key generation dominates this test's runtime, so the key is the
    /// smallest size still in ordinary use rather than `ssh-key`'s default.
    fn rsa_key() -> PrivateKey {
        let keypair = RsaKeypair::random(&mut crate::test_rng(), 2048).unwrap();
        PrivateKey::new(KeypairData::Rsa(keypair), "").unwrap()
    }

    fn keypair(key: &PrivateKey) -> &RsaKeypair {
        match key.key_data() {
            KeypairData::Rsa(kp) => kp,
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

    /// PKCS#1 v1.5 cannot pad a SHA-512 digest into a 512-bit modulus.
    /// `Signer::sign` panics on that, and the panic took the request down
    /// with the agent's lock held instead of answering `SSH_AGENT_FAILURE`.
    #[test]
    fn a_key_too_small_for_the_hash_is_an_error_not_a_panic() {
        // Below the size the crate will generate without being told it is
        // on purpose; such keys still exist in files.
        let small = rsa::RsaPrivateKey::new_unchecked(&mut crate::test_rng(), 512).unwrap();
        let kp = RsaKeypair::try_from(&small).unwrap();

        assert!(matches!(
            rsa_signature(&kp, b"message", RsaHash::Sha512),
            Err(Error::Signing(_))
        ));
        // The same key still signs where the digest fits.
        assert!(rsa_signature(&kp, b"message", RsaHash::Sha256).is_ok());
    }

    /// The system RNG, counting what is drawn from it.
    struct Counting {
        drawn: usize,
    }

    impl rsa::rand_core::TryRng for Counting {
        type Error = getrandom::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.drawn += 4;
            SysRng.try_next_u32()
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.drawn += 8;
            SysRng.try_next_u64()
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.drawn += dest.len();
            SysRng.try_fill_bytes(dest)
        }
    }

    impl TryCryptoRng for Counting {}

    /// The private-key operation has to be blinded: anything that can reach
    /// the agent socket — a forwarded one included — can ask for signatures
    /// over data it chose and time them, which is the position
    /// RUSTSEC-2023-0071 is about. `Signer::try_sign` does not blind; only the
    /// randomised signer does. A PKCS#1 v1.5 signature is the
    /// same bytes either way, so what shows the difference is whether
    /// randomness was drawn while making it.
    #[test]
    fn the_private_key_operation_is_blinded() {
        let key = rsa_key();
        let kp = keypair(&key);
        for hash in [RsaHash::Sha1, RsaHash::Sha256, RsaHash::Sha512] {
            let mut rng = Counting { drawn: 0 };
            let blinded = rsa_signature_with(&mut rng, kp, b"a sign request", hash).unwrap();
            assert!(rng.drawn > 0, "{hash:?}: signed without a blinding factor");
            // Still the one signature there is for this key, hash and message.
            assert_eq!(
                blinded,
                rsa_signature(kp, b"a sign request", hash).unwrap(),
                "{hash:?}"
            );
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
