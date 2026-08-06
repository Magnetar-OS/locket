//! Key slots: several independent ways to unwrap the same vault key.
//!
//! Modelled on `systemd-cryptenroll`'s keyslots. The vault body is encrypted
//! under one random data-encryption key; each slot stores that same DEK
//! wrapped under a key-encryption key derived from a different *factor*:
//!
//! | factor       | KEK comes from                                       |
//! |--------------|------------------------------------------------------|
//! | passphrase   | Argon2id over the passphrase and a per-slot salt      |
//! | TPM 2.0      | a secret unsealed by the TPM, gated by a PIN          |
//! | FIDO2        | the `hmac-secret` output of a hardware token          |
//!
//! This is what makes a hardware factor *additive*: enrolling a TPM or a
//! security key does not replace the passphrase, so losing the device is
//! recoverable. It is also why this module has no hardware dependencies — a
//! factor only has to hand back 32 bytes, and [`SlotOpener`] is the seam where
//! `passman-tpm` and `passman-fido` plug in.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, Result,
    crypto::{KdfParams, NONCE_LEN, SALT_LEN, SymKey},
};

/// What a slot needs in order to reproduce its key-encryption key.
///
/// Everything here is public metadata: it is stored unencrypted in the vault
/// header, so it must never contain key material. The TPM's sealed blob is
/// safe to store because it is only usable by the TPM that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SlotFactor {
    /// Argon2id over a user passphrase.
    Passphrase {
        #[serde(flatten)]
        params: KdfParams,
        /// Base64 salt, unique per slot.
        salt: String,
    },
    /// A secret sealed to a TPM 2.0, released on the correct PIN.
    Tpm2 {
        /// Base64 of the TPM's sealed object (public + private parts).
        sealed: String,
        /// Which storage parent the blob was sealed under.
        ///
        /// The parent is regenerated from a fixed template on every use, so a
        /// blob is only loadable under the exact template that sealed it.
        /// Recording it means changing the default parent cannot silently
        /// brick a slot somebody already enrolled.
        #[serde(default)]
        parent: TpmParent,
        /// PCRs bound into the policy, if any. Empty means PIN only.
        #[serde(default)]
        pcrs: Vec<u32>,
        /// Whether unsealing requires a PIN (a TPM `authValue`).
        #[serde(default)]
        with_pin: bool,
    },
    /// A FIDO2 token's `hmac-secret` output.
    Fido2 {
        /// Base64 credential id returned at enrolment.
        credential_id: String,
        /// Base64 salt fed to `hmac-secret`; the token maps it to 32 bytes.
        salt: String,
        /// Relying-party id the credential was created under.
        rp_id: String,
        /// Whether the token must verify the user (PIN or on-device biometric)
        /// rather than merely confirm presence.
        #[serde(default)]
        user_verification: bool,
    },
}

impl SlotFactor {
    pub fn kind(&self) -> SlotKind {
        match self {
            SlotFactor::Passphrase { .. } => SlotKind::Passphrase,
            SlotFactor::Tpm2 { .. } => SlotKind::Tpm2,
            SlotFactor::Fido2 { .. } => SlotKind::Fido2,
        }
    }
}

/// The storage-root template a TPM slot's blob was sealed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TpmParent {
    /// RSA-2048. The historical default, and painfully slow on firmware TPMs:
    /// key generation alone costs seconds.
    #[default]
    Rsa2048,
    /// NIST P-256. Same security envelope, orders of magnitude faster to
    /// derive, which matters because the parent is regenerated on every unlock.
    EccP256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Passphrase,
    Tpm2,
    Fido2,
}

impl SlotKind {
    pub const fn label(self) -> &'static str {
        match self {
            SlotKind::Passphrase => "Passphrase",
            SlotKind::Tpm2 => "TPM 2.0",
            SlotKind::Fido2 => "Security key",
        }
    }
}

/// One way in to the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub id: Uuid,
    /// Human label, e.g. "Passphrase" or "YubiKey 5C".
    pub label: String,
    pub factor: SlotFactor,
    /// The DEK, sealed under this slot's KEK.
    pub wrapped_key: crate::vault::SealedBlob,
    pub created: crate::model::Timestamp,
}

impl Slot {
    /// Bytes bound into this slot's AEAD as associated data.
    ///
    /// Covers the slot's identity and factor metadata but not the wrapped key
    /// itself, so tampering with (say) the Argon2 cost or the PCR set breaks
    /// authentication rather than weakening the slot.
    pub(crate) fn aad(&self, magic: &str, format: u16) -> Vec<u8> {
        serde_json::to_vec(&(magic, format, self.id, &self.label, &self.factor))
            .unwrap_or_default()
    }

    /// Unwrap the DEK given this slot's key-encryption key.
    pub(crate) fn unwrap_dek(&self, kek: &SymKey, magic: &str, format: u16) -> Result<SymKey> {
        kek.unwrap_key(
            &self.wrapped_key.nonce_bytes("slot.wrapped_key.nonce")?,
            &self.wrapped_key.ciphertext_bytes("slot.wrapped_key.ciphertext")?,
            &self.aad(magic, format),
        )
    }

    /// Build a passphrase slot wrapping `dek`.
    pub(crate) fn new_passphrase(
        label: impl Into<String>,
        passphrase: &str,
        params: KdfParams,
        dek: &SymKey,
        magic: &str,
        format: u16,
    ) -> Result<Self> {
        let salt = crate::crypto::random_salt()?;
        let mut slot = Slot {
            id: Uuid::new_v4(),
            label: label.into(),
            factor: SlotFactor::Passphrase {
                params,
                salt: base64_encode(&salt),
            },
            wrapped_key: crate::vault::SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
            created: crate::model::now(),
        };

        let kek = SymKey::derive(passphrase, &salt, params)?;
        let (nonce, ct) = kek.wrap(dek, &slot.aad(magic, format))?;
        slot.wrapped_key = crate::vault::SealedBlob::new(nonce, ct);
        Ok(slot)
    }

    /// Build a slot from a KEK supplied by hardware.
    pub(crate) fn new_with_kek(
        label: impl Into<String>,
        factor: SlotFactor,
        kek: &SymKey,
        dek: &SymKey,
        magic: &str,
        format: u16,
    ) -> Result<Self> {
        let mut slot = Slot {
            id: Uuid::new_v4(),
            label: label.into(),
            factor,
            wrapped_key: crate::vault::SealedBlob {
                nonce: String::new(),
                ciphertext: String::new(),
            },
            created: crate::model::now(),
        };
        let (nonce, ct) = kek.wrap(dek, &slot.aad(magic, format))?;
        slot.wrapped_key = crate::vault::SealedBlob::new(nonce, ct);
        Ok(slot)
    }
}

/// Turns a slot's factor into its key-encryption key.
///
/// Implemented in `passman-core` for passphrases, and in `passman-tpm` /
/// `passman-fido` for hardware. Returning `Ok(None)` means "this opener does
/// not handle that factor", which lets [`crate::Vault::unlock`] walk the slots
/// and try each opener without treating a mismatch as an error.
pub trait SlotOpener {
    fn kek_for(&self, factor: &SlotFactor) -> Result<Option<SymKey>>;

    /// Human description, used in error messages when every slot fails.
    fn describe(&self) -> &str {
        "unlock factor"
    }
}

/// Opens passphrase slots.
pub struct PassphraseOpener<'a> {
    pub passphrase: &'a str,
}

impl<'a> PassphraseOpener<'a> {
    pub fn new(passphrase: &'a str) -> Self {
        Self { passphrase }
    }
}

impl SlotOpener for PassphraseOpener<'_> {
    fn kek_for(&self, factor: &SlotFactor) -> Result<Option<SymKey>> {
        let SlotFactor::Passphrase { params, salt } = factor else {
            return Ok(None);
        };
        let salt = base64_decode(salt, "slot.salt")?;
        let salt: [u8; SALT_LEN] = salt.as_slice().try_into().map_err(|_| Error::FieldLength {
            field: "slot.salt",
            found: salt.len(),
            expected: SALT_LEN,
        })?;
        Ok(Some(SymKey::derive(self.passphrase, &salt, *params)?))
    }

    fn describe(&self) -> &str {
        "passphrase"
    }
}

/// Opens a slot from key material a caller already has.
///
/// The hardware crates use this: they talk to the device, get 32 bytes, and
/// hand them over without `passman-core` needing to know how.
pub struct RawKeyOpener {
    pub kind: SlotKind,
    pub key: SymKey,
}

impl SlotOpener for RawKeyOpener {
    fn kek_for(&self, factor: &SlotFactor) -> Result<Option<SymKey>> {
        if factor.kind() == self.kind {
            Ok(Some(self.key.clone()))
        } else {
            Ok(None)
        }
    }

    fn describe(&self) -> &str {
        self.kind.label()
    }
}

pub fn base64_encode(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

pub(crate) fn base64_decode(s: &str, field: &'static str) -> Result<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s).map_err(|_| Error::Base64 { field })
}

/// Nonce length re-export, so `vault` and `slots` agree.
pub(crate) const _NONCE_LEN: usize = NONCE_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: &str = "passman-vault";
    const FORMAT: u16 = 2;

    #[test]
    fn passphrase_slot_roundtrips() {
        let dek = SymKey::random().unwrap();
        let slot = Slot::new_passphrase(
            "Passphrase",
            "hunter2",
            KdfParams::insecure_fast(),
            &dek,
            MAGIC,
            FORMAT,
        )
        .unwrap();

        let kek = PassphraseOpener::new("hunter2")
            .kek_for(&slot.factor)
            .unwrap()
            .unwrap();
        let recovered = slot.unwrap_dek(&kek, MAGIC, FORMAT).unwrap();
        assert_eq!(recovered.expose(), dek.expose());
    }

    #[test]
    fn wrong_passphrase_fails_the_slot() {
        let dek = SymKey::random().unwrap();
        let slot = Slot::new_passphrase(
            "Passphrase",
            "right",
            KdfParams::insecure_fast(),
            &dek,
            MAGIC,
            FORMAT,
        )
        .unwrap();

        let kek = PassphraseOpener::new("wrong")
            .kek_for(&slot.factor)
            .unwrap()
            .unwrap();
        assert!(matches!(
            slot.unwrap_dek(&kek, MAGIC, FORMAT),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn tampering_with_slot_metadata_breaks_it() {
        let dek = SymKey::random().unwrap();
        let mut slot = Slot::new_passphrase(
            "Passphrase",
            "pw",
            KdfParams::insecure_fast(),
            &dek,
            MAGIC,
            FORMAT,
        )
        .unwrap();

        let kek = PassphraseOpener::new("pw")
            .kek_for(&slot.factor)
            .unwrap()
            .unwrap();
        // The slot opens before tampering...
        assert!(slot.unwrap_dek(&kek, MAGIC, FORMAT).is_ok());

        // ...and not after relabelling it, because the label is in the AAD.
        slot.label = "Something else".into();
        assert!(matches!(
            slot.unwrap_dek(&kek, MAGIC, FORMAT),
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn hardware_slots_wrap_the_same_dek() {
        let dek = SymKey::random().unwrap();
        let tpm_kek = SymKey::random().unwrap();

        let slot = Slot::new_with_kek(
            "TPM 2.0",
            SlotFactor::Tpm2 {
                sealed: base64_encode(b"opaque-tpm-blob"),
                parent: Default::default(),
                pcrs: vec![7],
                with_pin: true,
            },
            &tpm_kek,
            &dek,
            MAGIC,
            FORMAT,
        )
        .unwrap();

        let opener = RawKeyOpener {
            kind: SlotKind::Tpm2,
            key: tpm_kek,
        };
        let kek = opener.kek_for(&slot.factor).unwrap().unwrap();
        assert_eq!(
            slot.unwrap_dek(&kek, MAGIC, FORMAT).unwrap().expose(),
            dek.expose()
        );
    }

    #[test]
    fn openers_decline_factors_they_do_not_handle() {
        let fido = SlotFactor::Fido2 {
            credential_id: base64_encode(b"cred"),
            salt: base64_encode(&[0u8; 32]),
            rp_id: "passman".into(),
            user_verification: true,
        };
        // A passphrase opener must not claim a FIDO2 slot.
        assert!(PassphraseOpener::new("pw").kek_for(&fido).unwrap().is_none());

        let tpm_opener = RawKeyOpener {
            kind: SlotKind::Tpm2,
            key: SymKey::random().unwrap(),
        };
        assert!(tpm_opener.kek_for(&fido).unwrap().is_none());
    }

    #[test]
    fn factor_metadata_survives_serialisation() {
        for factor in [
            SlotFactor::Passphrase {
                params: KdfParams::default(),
                salt: base64_encode(&[1u8; SALT_LEN]),
            },
            SlotFactor::Tpm2 {
                sealed: base64_encode(b"blob"),
                parent: Default::default(),
                pcrs: vec![0, 7],
                with_pin: true,
            },
            SlotFactor::Fido2 {
                credential_id: base64_encode(b"cred"),
                salt: base64_encode(&[2u8; 32]),
                rp_id: "passman".into(),
                user_verification: true,
            },
        ] {
            let json = serde_json::to_string(&factor).unwrap();
            let back: SlotFactor = serde_json::from_str(&json).unwrap();
            assert_eq!(factor, back, "round trip changed the factor");
        }
    }
}
