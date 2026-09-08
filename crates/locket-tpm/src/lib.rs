//! TPM 2.0 sealed key slots.
//!
//! Enrols a [`SlotFactor::Tpm2`] slot whose key-encryption key is a random
//! secret *sealed to this machine's TPM*, optionally behind a PIN. The PIN is
//! not a password and is never used to derive anything: it is a TPM
//! `authValue` that releases a hardware-held secret, so its own entropy is not
//! what stands between an attacker and the key. The dictionary-attack lockout
//! on the chip is what makes a short PIN defensible — six digits are fine when
//! the hardware allows a handful of guesses, and indefensible when an attacker
//! can try them offline at GPU speed.
//!
//! Because the slot only *adds* a way in, losing the machine does not lose the
//! vault: the passphrase slot still opens it.
//!
//! # A note on `noDA`
//!
//! `tss-esapi`'s own sealing example builds the object with `with_no_da(true)`,
//! which **exempts it from dictionary-attack protection**. That is fine for a
//! test fixture and completely wrong here: it would turn the PIN into an
//! unlimited-guess secret with roughly 20 bits of entropy. This crate clears
//! `noDA` whenever a PIN is in use, and that choice is load-bearing — there is
//! a test asserting it.
//!
//! # Testing
//!
//! Anything that talks to hardware needs a TPM the caller can open
//! (`/dev/tpmrm0` is `root:tss 0660`, or point the TCTI at an `swtpm`
//! simulator), so those tests are `#[ignore]`d and additionally gated on
//! `LOCKET_TPM_TESTS=1`. The pure logic — blob framing, template attributes,
//! factor handling — is tested unconditionally.

#![forbid(unsafe_code)]

use base64ct::{Base64, Encoding};
use locket_core::{
    crypto::SymKey,
    slots::{SlotFactor, SlotOpener, TpmParent},
};
use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, RsaExponent,
        SensitiveData, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    utils::create_restricted_decryption_rsa_public,
};
use zeroize::Zeroizing;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no TPM available: {0}")]
    NoTpm(String),

    #[error("TPM refused the operation: {0}")]
    Tpm(String),

    #[error("the sealed blob is malformed")]
    MalformedBlob,

    #[error("this slot is not a TPM slot")]
    WrongFactor,

    #[error("a PIN is required for this slot")]
    PinRequired,

    #[error("{0}")]
    Other(String),
}

impl From<tss_esapi::Error> for Error {
    fn from(e: tss_esapi::Error) -> Self {
        Error::Tpm(e.to_string())
    }
}

/// Length of the secret sealed into the TPM; it becomes the slot's KEK.
const SEALED_SECRET_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Blob framing
// ---------------------------------------------------------------------------

/// Pack the TPM's public and private halves into one storable blob.
///
/// Layout: `u32 big-endian public length || public || private`.
fn pack(public: &[u8], private: &[u8]) -> String {
    let mut out = Vec::with_capacity(4 + public.len() + private.len());
    out.extend_from_slice(&(public.len() as u32).to_be_bytes());
    out.extend_from_slice(public);
    out.extend_from_slice(private);
    Base64::encode_string(&out)
}

fn unpack(blob: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let raw = Base64::decode_vec(blob).map_err(|_| Error::MalformedBlob)?;
    if raw.len() < 4 {
        return Err(Error::MalformedBlob);
    }
    let pub_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if raw.len() < 4 + pub_len {
        return Err(Error::MalformedBlob);
    }
    Ok((raw[4..4 + pub_len].to_vec(), raw[4 + pub_len..].to_vec()))
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// The default parent for *new* enrolments.
///
/// ECC, because the parent is regenerated from its template on every single
/// unlock and firmware TPMs are painfully slow at RSA key generation — on the
/// AMD fTPM this machine has, RSA-2048 costs seconds per unlock where P-256
/// costs milliseconds. Existing slots keep whatever they recorded.
pub const DEFAULT_PARENT: TpmParent = TpmParent::EccP256;

/// The storage-root-key template. Deterministic, so the parent is recreated on
/// demand rather than occupying one of the TPM's few persistent handles.
///
/// A blob is only loadable under the exact template that sealed it, which is
/// why the choice is recorded in the slot rather than assumed.
fn primary_template(parent: TpmParent) -> Result<Public> {
    match parent {
        TpmParent::Rsa2048 => create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .map_err(Into::into),

        TpmParent::EccP256 => {
            let object_attributes = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_decrypt(true)
                .build()?;

            let ecc_parameters = PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()?;

            PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(object_attributes)
                .with_ecc_parameters(ecc_parameters)
                .with_ecc_unique_identifier(Default::default())
                .build()
                .map_err(Into::into)
        }
    }
}

/// The template for the sealed data object.
fn sealed_template(with_pin: bool) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        // The crux: with a PIN the object must participate in dictionary
        // attack protection, otherwise the PIN is just a very short password.
        .with_no_da(!with_pin)
        .with_user_with_auth(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(Default::default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .map_err(Into::into)
}

fn auth_from_pin(pin: Option<&str>) -> Result<Option<Auth>> {
    match pin {
        None => Ok(None),
        Some("") => Ok(None),
        Some(p) => Auth::try_from(p.as_bytes().to_vec())
            .map(Some)
            .map_err(|e| Error::Other(format!("PIN is not usable as a TPM auth value: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// TPM operations
// ---------------------------------------------------------------------------

/// Open a context against the system TPM.
///
/// Honours the standard TCTI environment variables so an `swtpm` simulator can
/// be substituted for testing.
pub fn open_context() -> Result<Context> {
    let tcti = TctiNameConf::from_environment_variable()
        .map_err(|e| Error::NoTpm(format!("no usable TCTI: {e}")))?;
    Context::new(tcti).map_err(|e| Error::NoTpm(e.to_string()))
}

/// Seal a fresh random secret to this TPM.
///
/// Returns the slot metadata to store in the vault and the key-encryption key
/// to enrol with; hand the latter to `Vault::add_slot` and drop it. It can
/// always be recovered later with [`unseal`].
pub fn enroll(pin: Option<&str>) -> Result<(SlotFactor, SymKey)> {
    let mut secret = Zeroizing::new(vec![0u8; SEALED_SECRET_LEN]);
    getrandom::fill(&mut secret).map_err(|e| Error::Other(e.to_string()))?;

    let with_pin = pin.is_some_and(|p| !p.is_empty());
    let auth = auth_from_pin(pin)?;
    let sensitive =
        SensitiveData::try_from(secret.to_vec()).map_err(|e| Error::Other(e.to_string()))?;

    let mut context = open_context()?;
    let (public, private) = context.execute_with_nullauth_session(|ctx| {
        let primary = ctx.create_primary(
            Hierarchy::Owner,
            primary_template(DEFAULT_PARENT)?,
            None,
            None,
            None,
            None,
        )?;
        let sealed = ctx.create(
            primary.key_handle,
            sealed_template(with_pin)?,
            auth,
            Some(sensitive),
            None,
            None,
        )?;
        Ok::<_, Error>((sealed.out_public, sealed.out_private))
    })?;

    let factor = SlotFactor::Tpm2 {
        // `Public` is a structure and marshalls; `Private` is already an
        // opaque TPM-encrypted buffer, so its bytes go through verbatim.
        sealed: pack(&public.marshall()?, private.value()),
        parent: DEFAULT_PARENT,
        // PCR binding is a separate decision from the PIN and is deliberately
        // not taken here: binding to firmware measurements means a BIOS update
        // locks you out of your own vault.
        pcrs: Vec::new(),
        with_pin,
    };

    let kek = SymKey::try_from_slice(&secret).map_err(|e| Error::Other(e.to_string()))?;
    Ok((factor, kek))
}

/// Recover a sealed slot's key-encryption key.
pub fn unseal(factor: &SlotFactor, pin: Option<&str>) -> Result<SymKey> {
    let SlotFactor::Tpm2 {
        sealed,
        with_pin,
        parent,
        ..
    } = factor
    else {
        return Err(Error::WrongFactor);
    };

    // Check this before touching the TPM: a needless failed unseal costs a
    // dictionary-attack strike against the whole device.
    if *with_pin && pin.is_none_or(str::is_empty) {
        return Err(Error::PinRequired);
    }

    let (public_bytes, private_bytes) = unpack(sealed)?;
    let public = Public::unmarshall(&public_bytes).map_err(|_| Error::MalformedBlob)?;
    let private = Private::try_from(private_bytes).map_err(|_| Error::MalformedBlob)?;
    let auth = auth_from_pin(pin)?;

    let mut context = open_context()?;
    let data = context.execute_with_nullauth_session(|ctx| {
        let primary = ctx.create_primary(
            Hierarchy::Owner,
            primary_template(*parent)?,
            None,
            None,
            None,
            None,
        )?;
        let handle = ctx.load(primary.key_handle, private, public)?;
        if let Some(auth) = auth {
            ctx.tr_set_auth(handle.into(), auth)?;
        }
        ctx.unseal(handle.into()).map_err(Error::from)
    })?;

    SymKey::try_from_slice(data.value()).map_err(|e| Error::Other(e.to_string()))
}

/// A [`SlotOpener`] that unseals TPM slots.
pub struct TpmOpener {
    pin: Option<String>,
}

impl TpmOpener {
    pub fn new(pin: Option<String>) -> Self {
        Self { pin }
    }
}

impl SlotOpener for TpmOpener {
    fn kek_for(&self, factor: &SlotFactor) -> locket_core::Result<Option<SymKey>> {
        if !matches!(factor, SlotFactor::Tpm2 { .. }) {
            return Ok(None);
        }
        match unseal(factor, self.pin.as_deref()) {
            Ok(key) => Ok(Some(key)),
            // Report as "this factor did not open it" rather than a hard
            // error, so a multi-slot vault can fall through to another factor.
            Err(e) => {
                tracing::debug!("TPM slot did not open: {e}");
                Ok(None)
            }
        }
    }

    fn describe(&self) -> &str {
        "TPM 2.0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardware_tests_enabled() -> bool {
        std::env::var("LOCKET_TPM_TESTS").is_ok_and(|v| v == "1")
    }

    #[test]
    fn blob_framing_roundtrips() {
        let public = vec![1u8, 2, 3, 4, 5];
        let private = vec![9u8; 64];
        let (p, q) = unpack(&pack(&public, &private)).unwrap();
        assert_eq!(p, public);
        assert_eq!(q, private);
    }

    #[test]
    fn empty_halves_roundtrip() {
        let (p, q) = unpack(&pack(&[], &[])).unwrap();
        assert!(p.is_empty() && q.is_empty());
    }

    #[test]
    fn malformed_blobs_are_rejected_not_panicked_on() {
        assert!(matches!(unpack("!!!not base64"), Err(Error::MalformedBlob)));
        assert!(matches!(unpack(""), Err(Error::MalformedBlob)));
        // Length prefix claims far more public bytes than exist.
        let bogus = Base64::encode_string(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert!(matches!(unpack(&bogus), Err(Error::MalformedBlob)));
    }

    #[test]
    fn a_pin_forces_dictionary_attack_protection_on() {
        // The property the whole design rests on: with a PIN, the sealed
        // object must not be exempt from the TPM's lockout.
        let with_pin = sealed_template(true).expect("template builds");
        let without = sealed_template(false).expect("template builds");

        let attrs = |p: &Public| match p {
            Public::KeyedHash {
                object_attributes, ..
            } => *object_attributes,
            _ => panic!("expected a keyed-hash object"),
        };

        assert!(
            !attrs(&with_pin).no_da(),
            "a PIN-protected object was exempted from dictionary-attack lockout"
        );
        assert!(attrs(&without).no_da());
    }

    #[test]
    fn non_tpm_factors_are_declined() {
        let opener = TpmOpener::new(None);
        let passphrase = SlotFactor::Passphrase {
            params: locket_core::crypto::KdfParams::insecure_fast(),
            salt: Base64::encode_string(&[0u8; 32]),
        };
        assert!(opener.kek_for(&passphrase).unwrap().is_none());
        assert!(matches!(unseal(&passphrase, None), Err(Error::WrongFactor)));
    }

    #[test]
    fn a_pinned_slot_refuses_a_missing_pin_without_touching_hardware() {
        let factor = SlotFactor::Tpm2 {
            sealed: pack(&[0u8; 8], &[0u8; 8]),
            parent: Default::default(),
            pcrs: vec![],
            with_pin: true,
        };
        // Must fail the PIN check rather than spend a lockout strike.
        assert!(matches!(unseal(&factor, None), Err(Error::PinRequired)));
        assert!(matches!(unseal(&factor, Some("")), Err(Error::PinRequired)));
    }

    #[test]
    #[ignore = "requires a TPM; set LOCKET_TPM_TESTS=1"]
    fn seal_and_unseal_against_real_hardware() {
        if !hardware_tests_enabled() {
            return;
        }
        let (factor, kek) = enroll(Some("123456")).expect("enrolment failed");
        let recovered = unseal(&factor, Some("123456")).expect("unseal failed");
        assert_eq!(kek.expose(), recovered.expose());
        assert!(
            unseal(&factor, Some("654321")).is_err(),
            "wrong PIN unsealed"
        );
    }

    #[test]
    #[ignore = "requires a TPM; set LOCKET_TPM_TESTS=1"]
    fn a_tpm_slot_opens_a_real_vault() {
        if !hardware_tests_enabled() {
            return;
        }
        use locket_core::{Vault, crypto::KdfParams};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let (factor, kek) = enroll(Some("1234")).unwrap();
        vault.add_slot("TPM 2.0", factor, &kek).unwrap();
        drop(vault);

        let opened = Vault::open_with(&path, &TpmOpener::new(Some("1234".into()))).unwrap();
        assert_eq!(opened.slots().len(), 2);
    }
}
