//! Security-key (`sk-`) SSH keys, where the token holds the signing key.
//!
//! An `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`
//! private key file contains no signing scalar. It holds a public key, an
//! *application* string (`ssh:` by convention), a flags byte and a credential
//! handle. Signing means asking the token for a FIDO2 assertion and dressing
//! the result up in SSH's clothing.
//!
//! # What the token signs
//!
//! ```text
//! SHA256(application) ‖ flags ‖ counter ‖ SHA256(message)
//! └────────────── auth_data ─────────┘   └ client data hash ┘
//! ```
//!
//! which is a plain CTAP2 assertion over `rp_id = application` with the SSH
//! sign-request as the challenge. The verifier — OpenSSH, or `ssh-key`'s own
//! `Verifier` impl — rebuilds that from the public key and the trailer, so the
//! `auth_data` the token returns must be exactly the 37 bytes it reconstructs.
//! An assertion carrying extension data is refused here rather than sent to a
//! server that will reject it for reasons nobody can see from the client.
//!
//! # Wire format (OpenSSH `PROTOCOL.u2f`)
//!
//! ```text
//! string  "sk-ssh-ed25519@openssh.com"
//! string  signature          -- 64 raw bytes, or mpint r ‖ mpint s
//! byte    flags
//! uint32  counter
//! ```
//!
//! Note the trailer sits *outside* the signature string. `ssh_key::Signature`
//! keeps it inside its `data` and only splits it back out when encoding an
//! Ed25519 key — its ECDSA path does not — so the blob is written here rather
//! than delegated, and the tests decode what we wrote with `ssh-key` to prove
//! the two agree.

use ssh_key::{Mpint, private::KeypairData, sha2::Digest, sha2::Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::wire::Writer;

/// `rp_id_hash(32) ‖ flags(1) ‖ counter(4)`, with no extensions.
const AUTH_DATA_LEN: usize = 37;
/// A raw Ed25519 signature.
const ED25519_SIG_LEN: usize = 64;

/// The two security-key algorithms OpenSSH defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkAlgorithm {
    Ed25519,
    EcdsaNistP256,
}

impl SkAlgorithm {
    /// The algorithm name as it appears on the wire.
    pub fn name(self) -> &'static str {
        match self {
            SkAlgorithm::Ed25519 => "sk-ssh-ed25519@openssh.com",
            SkAlgorithm::EcdsaNistP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// Recognise a keypair the token has to sign for.
    pub fn of(keypair: &KeypairData) -> Option<Self> {
        match keypair {
            KeypairData::SkEd25519(_) => Some(SkAlgorithm::Ed25519),
            KeypairData::SkEcdsaSha2NistP256(_) => Some(SkAlgorithm::EcdsaNistP256),
            _ => None,
        }
    }
}

/// Everything a token needs to produce one SSH signature.
pub struct SkSignRequest {
    pub algorithm: SkAlgorithm,
    /// The credential's relying-party id — SSH calls it the *application*.
    pub application: String,
    pub key_handle: Vec<u8>,
    /// The SSH sign request. The token hashes it into the client-data hash, so
    /// this is the message itself and not a digest of it.
    pub message: Vec<u8>,
    /// Set when the key was created `verify-required`: a touch alone will not
    /// do, the token must also check a PIN or a fingerprint.
    pub user_verification: bool,
    /// The token's PIN, when one is stored alongside the key.
    pub pin: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for SkSignRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkSignRequest")
            .field("algorithm", &self.algorithm)
            .field("application", &self.application)
            .field("key_handle_len", &self.key_handle.len())
            .field("message_len", &self.message.len())
            .field("user_verification", &self.user_verification)
            .field("pin", &self.pin.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One assertion, as the token produced it.
#[derive(Debug, Clone)]
pub struct TokenAssertion {
    pub auth_data: Vec<u8>,
    /// Raw 64 bytes for Ed25519 credentials, ASN.1 DER for ES256 ones.
    pub signature: Vec<u8>,
}

/// Whatever can drive a security key.
///
/// The same seam as `SlotOpener` in `locket-core`: hardware is reduced to one
/// call returning bytes, so the protocol logic above it stays testable on a
/// machine with no token — and so `locket-agent` needs no `hidapi` to build.
pub trait TokenSigner: Send + Sync {
    fn assert(&self, request: &SkSignRequest) -> Result<TokenAssertion>;

    /// For logs: what the user should go and touch.
    fn describe(&self) -> &str {
        "security key"
    }
}

/// Build the SSH signature blob from an assertion.
///
/// `application` is checked against the `rp_id` hash the token returned, which
/// catches the case of a different token answering with a credential of its
/// own — the signature would verify against nothing and the failure would
/// otherwise surface as a bare "permission denied".
pub fn signature_blob(
    algorithm: SkAlgorithm,
    application: &str,
    assertion: &TokenAssertion,
) -> Result<Vec<u8>> {
    if assertion.auth_data.len() != AUTH_DATA_LEN {
        return Err(Error::Signing(format!(
            "the token returned {} bytes of authenticator data, expected {AUTH_DATA_LEN}; \
             an assertion carrying extensions cannot be verified by an SSH server",
            assertion.auth_data.len()
        )));
    }

    let (rp_id_hash, trailer) = assertion.auth_data.split_at(32);
    if rp_id_hash != Sha256::digest(application.as_bytes()).as_slice() {
        return Err(Error::Signing(format!(
            "the token asserted a credential for a different application than `{application}`"
        )));
    }
    let flags = trailer[0];
    let counter = u32::from_be_bytes([trailer[1], trailer[2], trailer[3], trailer[4]]);

    let inner = match algorithm {
        SkAlgorithm::Ed25519 => {
            if assertion.signature.len() != ED25519_SIG_LEN {
                return Err(Error::Signing(format!(
                    "expected a {ED25519_SIG_LEN}-byte Ed25519 signature, got {}",
                    assertion.signature.len()
                )));
            }
            assertion.signature.clone()
        }
        SkAlgorithm::EcdsaNistP256 => ecdsa_der_to_ssh(&assertion.signature)?,
    };

    let mut w = Writer::new();
    w.write_string(algorithm.name().as_bytes())
        .write_string(&inner)
        .write_u8(flags)
        .write_u32(counter);
    Ok(w.into_bytes())
}

/// Re-encode an ASN.1 DER ECDSA signature as SSH's `mpint r ‖ mpint s`.
///
/// Tokens return ES256 signatures in DER; SSH has its own integer encoding, so
/// one of the two has to give. Parsing is strict — a signature is not a place
/// to be liberal in what you accept — and `Mpint` applies SSH's sign-padding
/// rule so a component with the high bit set does not read as negative.
fn ecdsa_der_to_ssh(der: &[u8]) -> Result<Vec<u8>> {
    let bad =
        |what: &str| Error::Signing(format!("malformed ECDSA signature from the token: {what}"));

    let mut pos = 0;
    let byte = |pos: &mut usize| -> Result<u8> {
        let b = *der.get(*pos).ok_or_else(|| bad("truncated"))?;
        *pos += 1;
        Ok(b)
    };

    if byte(&mut pos)? != 0x30 {
        return Err(bad("not a SEQUENCE"));
    }
    // Short form covers every P-256 signature (at most 72 bytes); the long
    // form is accepted only in its one-byte length variant.
    let seq_len = match byte(&mut pos)? {
        n if n < 0x80 => n as usize,
        0x81 => byte(&mut pos)? as usize,
        _ => return Err(bad("unsupported length encoding")),
    };
    if der.len() - pos != seq_len {
        return Err(bad("SEQUENCE length does not match the data"));
    }

    let component = |pos: &mut usize| -> Result<Mpint> {
        if byte(pos)? != 0x02 {
            return Err(bad("component is not an INTEGER"));
        }
        let len = match byte(pos)? {
            n if n < 0x80 => n as usize,
            _ => return Err(bad("unsupported integer length encoding")),
        };
        if len == 0 {
            return Err(bad("empty integer"));
        }
        let end = pos.checked_add(len).ok_or_else(|| bad("truncated"))?;
        let raw = der.get(*pos..end).ok_or_else(|| bad("truncated"))?;
        *pos = end;
        if raw[0] & 0x80 != 0 {
            // DER integers are signed; a negative r or s is not a signature.
            return Err(bad("negative integer"));
        }
        let m = Mpint::from_positive_bytes(raw).map_err(|e| bad(&e.to_string()))?;
        if m.as_bytes().is_empty() {
            // Zero is a valid mpint and not a valid signature component.
            return Err(bad("zero integer"));
        }
        Ok(m)
    };

    let r = component(&mut pos)?;
    let s = component(&mut pos)?;
    if pos != der.len() {
        return Err(bad("trailing bytes after the two integers"));
    }

    // `Mpint` has already applied SSH's sign-padding rule, so its bytes are
    // exactly the `string` payload. Writing it here rather than through
    // `ssh_encoding::Encode` keeps this crate off ssh-key's own (older)
    // encoding version.
    let mut out = Writer::new();
    out.write_string(r.as_bytes()).write_string(s.as_bytes());
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_data(application: &str, flags: u8, counter: u32) -> Vec<u8> {
        let mut d = Sha256::digest(application.as_bytes()).to_vec();
        d.push(flags);
        d.extend_from_slice(&counter.to_be_bytes());
        d
    }

    #[test]
    fn the_blob_carries_the_trailer_outside_the_signature_string() {
        let assertion = TokenAssertion {
            auth_data: auth_data("ssh:", 0x05, 0x0102_0304),
            signature: vec![9u8; 64],
        };
        let blob = signature_blob(SkAlgorithm::Ed25519, "ssh:", &assertion).unwrap();

        let mut r = crate::wire::Reader::new(&blob);
        assert_eq!(r.read_utf8().unwrap(), "sk-ssh-ed25519@openssh.com");
        assert_eq!(r.read_string().unwrap(), &[9u8; 64]);
        assert_eq!(r.read_u8().unwrap(), 0x05);
        assert_eq!(r.read_u32().unwrap(), 0x0102_0304);
        assert!(r.is_empty(), "trailing bytes in the signature blob");
    }

    #[test]
    fn an_assertion_for_another_application_is_refused() {
        let assertion = TokenAssertion {
            auth_data: auth_data("not-ssh", 1, 1),
            signature: vec![9u8; 64],
        };
        let err = signature_blob(SkAlgorithm::Ed25519, "ssh:", &assertion).unwrap_err();
        assert!(
            err.to_string().contains("different application"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authenticator_data_with_extensions_is_refused() {
        // A token that appends extension output signs over bytes the verifier
        // will not reconstruct, so the signature would fail server-side.
        let mut auth = auth_data("ssh:", 1, 1);
        auth.extend_from_slice(b"extension output");
        let assertion = TokenAssertion {
            auth_data: auth,
            signature: vec![9u8; 64],
        };
        assert!(signature_blob(SkAlgorithm::Ed25519, "ssh:", &assertion).is_err());
    }

    #[test]
    fn a_short_ed25519_signature_is_refused() {
        let assertion = TokenAssertion {
            auth_data: auth_data("ssh:", 1, 1),
            signature: vec![9u8; 63],
        };
        assert!(signature_blob(SkAlgorithm::Ed25519, "ssh:", &assertion).is_err());
    }

    /// DER: SEQUENCE { INTEGER r, INTEGER s }, minimally encoded.
    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut body = vec![0x02, r.len() as u8];
        body.extend_from_slice(r);
        body.push(0x02);
        body.push(s.len() as u8);
        body.extend_from_slice(s);
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn ecdsa_der_becomes_two_ssh_mpints() {
        let out = ecdsa_der_to_ssh(&der(&[0x01, 0x02], &[0x03])).unwrap();
        assert_eq!(
            out,
            vec![
                0, 0, 0, 2, 0x01, 0x02, // mpint r
                0, 0, 0, 1, 0x03, // mpint s
            ]
        );
    }

    #[test]
    fn an_mpint_with_the_high_bit_set_gains_a_zero_byte() {
        // Without the pad, 0xF1 would decode as a negative number and the
        // server's verification would fail for no visible reason.
        let out = ecdsa_der_to_ssh(&der(&[0x00, 0xF1], &[0x02])).unwrap();
        assert_eq!(&out[..4], &[0, 0, 0, 2]);
        assert_eq!(&out[4..6], &[0x00, 0xF1]);
    }

    #[test]
    fn malformed_der_is_refused_rather_than_guessed_at() {
        assert!(ecdsa_der_to_ssh(&[]).is_err());
        assert!(
            ecdsa_der_to_ssh(&[0x31, 0x00]).is_err(),
            "wrong tag accepted"
        );
        // Length that disagrees with the body.
        assert!(ecdsa_der_to_ssh(&[0x30, 0x08, 0x02, 0x01, 0x01]).is_err());
        // Trailing junk after r and s.
        let mut trailing = der(&[0x01], &[0x02]);
        trailing[1] += 1;
        trailing.push(0xFF);
        assert!(ecdsa_der_to_ssh(&trailing).is_err());
        // A negative component.
        assert!(ecdsa_der_to_ssh(&der(&[0x80, 0x01], &[0x02])).is_err());
    }

    #[test]
    fn the_ecdsa_blob_puts_the_trailer_outside_too() {
        let assertion = TokenAssertion {
            auth_data: auth_data("ssh:", 0x01, 7),
            signature: der(&[0x11], &[0x22]),
        };
        let blob = signature_blob(SkAlgorithm::EcdsaNistP256, "ssh:", &assertion).unwrap();
        let mut r = crate::wire::Reader::new(&blob);
        assert_eq!(r.read_utf8().unwrap(), "sk-ecdsa-sha2-nistp256@openssh.com");
        let inner = r.read_string().unwrap();
        assert_eq!(inner, &[0, 0, 0, 1, 0x11, 0, 0, 0, 1, 0x22]);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.read_u32().unwrap(), 7);
        assert!(r.is_empty());
    }
}
