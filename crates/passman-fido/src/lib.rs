//! FIDO2 `hmac-secret` key slots.
//!
//! Enrols a [`SlotFactor::Fido2`] slot whose key-encryption key comes from a
//! hardware security key.
//!
//! What makes this different from a fingerprint reader is that `hmac-secret`
//! returns **key material**, not a verdict. `fprintd` can only tell you "yes,
//! that was them", which means a daemon must already hold the key and merely
//! gates releasing it. A FIDO2 token given a salt returns
//! `HMAC-SHA256(credential_secret, salt)` — 32 bytes that exist nowhere but on
//! the token. So the vault key genuinely cannot be reconstructed without the
//! physical device, and "attacker has your disk image" is not enough.
//!
//! With user verification on, the token additionally requires its own PIN or
//! on-device biometric, and enforces its own retry limit — the same
//! hardware-rate-limited property the TPM slot relies on, but portable between
//! machines.
//!
//! # Testing
//!
//! Everything that talks to a token is `#[ignore]`d and gated on
//! `PASSMAN_FIDO_TESTS=1`, because it needs a physical key *and* a human to
//! touch it. The derivation and factor logic is tested unconditionally.

#![forbid(unsafe_code)]

use base64ct::{Base64, Encoding};
use ctap_hid_fido2::{
    FidoKeyHid, FidoKeyHidFactory, LibCfg,
    fidokey::{
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
        get_assertion::get_assertion_params::Extension as AssertionExt,
        make_credential::make_credential_params::Extension as CredentialExt,
    },
};
use hkdf::Hkdf;
use passman_core::{
    crypto::SymKey,
    slots::{SlotFactor, SlotOpener},
};
use sha2::Sha256;
use zeroize::Zeroizing;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no FIDO2 security key found; plug one in and try again")]
    NoDevice,

    #[error("the security key reported an error: {0}")]
    Device(String),

    #[error("this slot is not a FIDO2 slot")]
    WrongFactor,

    #[error("the security key did not return an hmac-secret value; it may not support the extension")]
    NoHmacSecret,

    #[error("stored credential data is malformed")]
    MalformedSlot,

    #[error("{0}")]
    Other(String),
}

/// The relying-party id credentials are created under.
///
/// Not a real domain on purpose: these credentials are only ever used locally,
/// and a token scopes `hmac-secret` per (rp_id, credential), so a passman
/// credential cannot be exercised by a website.
pub const DEFAULT_RP_ID: &str = "passman.local";

const SALT_LEN: usize = 32;
const HKDF_DOMAIN: &[u8] = b"passman:fido2-hmac-secret:v1";

/// Stretch a token's raw `hmac-secret` output into a slot key.
///
/// The output is already 32 uniformly random bytes, so this is domain
/// separation rather than entropy extraction — it stops the same token+salt
/// being reused as a key for anything else passman might add later.
pub fn derive_slot_key(hmac_output: &[u8]) -> Result<SymKey> {
    let hk = Hkdf::<Sha256>::new(None, hmac_output);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_DOMAIN, out.as_mut_slice())
        .map_err(|e| Error::Other(format!("HKDF expand failed: {e}")))?;
    SymKey::try_from_slice(out.as_slice()).map_err(|e| Error::Other(e.to_string()))
}

fn open_device() -> Result<FidoKeyHid> {
    let cfg = LibCfg::init();
    FidoKeyHidFactory::create(&cfg).map_err(|e| {
        // The crate reports "no device" as a generic error; make it actionable.
        if ctap_hid_fido2::get_fidokey_devices().is_empty() {
            Error::NoDevice
        } else {
            Error::Device(e.to_string())
        }
    })
}

fn random_challenge() -> Result<[u8; 32]> {
    let mut c = [0u8; 32];
    getrandom::fill(&mut c).map_err(|e| Error::Other(e.to_string()))?;
    Ok(c)
}

/// Pull the `hmac-secret` output out of an assertion's extension list.
fn hmac_output_from(extensions: &[AssertionExt]) -> Option<[u8; 32]> {
    extensions.iter().find_map(|e| match e {
        AssertionExt::HmacSecret(Some(v)) => Some(*v),
        // The two-salt variant returns a pair; we only ever send one salt, so
        // the first output is ours.
        AssertionExt::HmacSecret2(Some((a, _))) => Some(*a),
        _ => None,
    })
}

/// Create a credential on the token and derive the slot's key from it.
///
/// Requires a touch (and a PIN, if the token has one). Returns the slot
/// metadata to store plus the key-encryption key to enrol with.
pub fn enroll(pin: Option<&str>, user_verification: bool) -> Result<(SlotFactor, SymKey)> {
    let device = open_device()?;

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Other(e.to_string()))?;
    let challenge = random_challenge()?;

    let mut builder = MakeCredentialArgsBuilder::new(DEFAULT_RP_ID, &challenge)
        .extensions(&[CredentialExt::HmacSecret(Some(true))]);
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    } else {
        builder = builder.without_pin_and_uv();
    }

    let attestation = device
        .make_credential_with_args(&builder.build())
        .map_err(|e| Error::Device(e.to_string()))?;
    let credential_id = attestation.credential_descriptor.id;
    if credential_id.is_empty() {
        return Err(Error::Device("token returned an empty credential id".into()));
    }

    // Immediately exercise the credential so the enrolled key is the one that
    // will actually come back later, rather than one we assumed.
    let key = assert_hmac(&device, &credential_id, &salt, pin)?;

    let factor = SlotFactor::Fido2 {
        credential_id: Base64::encode_string(&credential_id),
        salt: Base64::encode_string(&salt),
        rp_id: DEFAULT_RP_ID.to_owned(),
        user_verification,
    };
    Ok((factor, key))
}

/// Ask the token for `HMAC-SHA256(credential_secret, salt)` and stretch it.
fn assert_hmac(
    device: &FidoKeyHid,
    credential_id: &[u8],
    salt: &[u8; SALT_LEN],
    pin: Option<&str>,
) -> Result<SymKey> {
    let challenge = random_challenge()?;
    let mut builder = GetAssertionArgsBuilder::new(DEFAULT_RP_ID, &challenge)
        .credential_id(credential_id)
        .extensions(&[AssertionExt::HmacSecret(Some(*salt))]);
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    }

    let assertions = device
        .get_assertion_with_args(&builder.build())
        .map_err(|e| Error::Device(e.to_string()))?;

    let output = assertions
        .iter()
        .find_map(|a| hmac_output_from(&a.extensions))
        .ok_or(Error::NoHmacSecret)?;
    derive_slot_key(&output)
}

/// Recover a FIDO2 slot's key-encryption key. Requires the token and a touch.
pub fn unlock(factor: &SlotFactor, pin: Option<&str>) -> Result<SymKey> {
    let SlotFactor::Fido2 {
        credential_id,
        salt,
        rp_id,
        ..
    } = factor
    else {
        return Err(Error::WrongFactor);
    };
    if rp_id != DEFAULT_RP_ID {
        tracing::debug!("slot was enrolled under rp_id `{rp_id}`");
    }

    let credential_id =
        Base64::decode_vec(credential_id).map_err(|_| Error::MalformedSlot)?;
    let salt_bytes = Base64::decode_vec(salt).map_err(|_| Error::MalformedSlot)?;
    let salt: [u8; SALT_LEN] = salt_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::MalformedSlot)?;

    let device = open_device()?;
    assert_hmac(&device, &credential_id, &salt, pin)
}

/// A [`SlotOpener`] backed by a security key.
pub struct FidoOpener {
    pin: Option<String>,
}

impl FidoOpener {
    pub fn new(pin: Option<String>) -> Self {
        Self { pin }
    }
}

impl SlotOpener for FidoOpener {
    fn kek_for(&self, factor: &SlotFactor) -> passman_core::Result<Option<SymKey>> {
        if !matches!(factor, SlotFactor::Fido2 { .. }) {
            return Ok(None);
        }
        match unlock(factor, self.pin.as_deref()) {
            Ok(key) => Ok(Some(key)),
            // Report as "did not open" so a multi-slot vault can fall through
            // to another factor rather than failing outright.
            Err(e) => {
                tracing::debug!("FIDO2 slot did not open: {e}");
                Ok(None)
            }
        }
    }

    fn describe(&self) -> &str {
        "security key"
    }
}

/// Whether any FIDO2 token is currently attached.
pub fn device_present() -> bool {
    !ctap_hid_fido2::get_fidokey_devices().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardware_tests_enabled() -> bool {
        std::env::var("PASSMAN_FIDO_TESTS").is_ok_and(|v| v == "1")
    }

    #[test]
    fn derivation_is_deterministic_and_input_dependent() {
        let a = derive_slot_key(&[7u8; 32]).unwrap();
        let b = derive_slot_key(&[7u8; 32]).unwrap();
        let c = derive_slot_key(&[8u8; 32]).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn derivation_does_not_pass_the_token_output_through_verbatim() {
        // If this ever became an identity function, the raw token output would
        // be the vault key with no domain separation.
        let raw = [9u8; 32];
        assert_ne!(derive_slot_key(&raw).unwrap().expose(), &raw);
    }

    #[test]
    fn non_fido_factors_are_declined() {
        let opener = FidoOpener::new(None);
        let tpm = SlotFactor::Tpm2 {
            sealed: Base64::encode_string(b"blob"),
            parent: Default::default(),
            pcrs: vec![],
            with_pin: true,
        };
        assert!(opener.kek_for(&tpm).unwrap().is_none());
        assert!(matches!(unlock(&tpm, None), Err(Error::WrongFactor)));
    }

    #[test]
    fn malformed_slots_are_rejected_before_touching_a_device() {
        let bad_salt = SlotFactor::Fido2 {
            credential_id: Base64::encode_string(b"cred"),
            salt: Base64::encode_string(&[0u8; 8]), // wrong length
            rp_id: DEFAULT_RP_ID.into(),
            user_verification: true,
        };
        assert!(matches!(unlock(&bad_salt, None), Err(Error::MalformedSlot)));

        let bad_b64 = SlotFactor::Fido2 {
            credential_id: "!!!not base64".into(),
            salt: Base64::encode_string(&[0u8; 32]),
            rp_id: DEFAULT_RP_ID.into(),
            user_verification: true,
        };
        assert!(matches!(unlock(&bad_b64, None), Err(Error::MalformedSlot)));
    }

    #[test]
    fn hmac_output_is_picked_out_of_the_extension_list() {
        assert_eq!(
            hmac_output_from(&[AssertionExt::HmacSecret(Some([3u8; 32]))]),
            Some([3u8; 32])
        );
        // Order must not matter, and unrelated extensions must be skipped.
        assert_eq!(
            hmac_output_from(&[
                AssertionExt::CredBlob((Some(true), None)),
                AssertionExt::HmacSecret(Some([4u8; 32])),
            ]),
            Some([4u8; 32])
        );
        assert_eq!(hmac_output_from(&[]), None);
        assert_eq!(hmac_output_from(&[AssertionExt::HmacSecret(None)]), None);
    }

    #[test]
    fn device_presence_check_does_not_panic_without_a_token() {
        // Must be safe to call on a machine with no security key attached.
        let _ = device_present();
    }

    #[test]
    #[ignore = "requires a FIDO2 token and a human touch; set PASSMAN_FIDO_TESTS=1"]
    fn enroll_and_unlock_a_real_token() {
        if !hardware_tests_enabled() {
            return;
        }
        let pin = std::env::var("PASSMAN_FIDO_PIN").ok();
        let (factor, key) = enroll(pin.as_deref(), pin.is_some()).expect("enrolment failed");
        let again = unlock(&factor, pin.as_deref()).expect("unlock failed");
        assert_eq!(
            key.expose(),
            again.expose(),
            "the token returned a different hmac-secret for the same salt"
        );
    }

    #[test]
    #[ignore = "requires a FIDO2 token and a human touch; set PASSMAN_FIDO_TESTS=1"]
    fn a_fido_slot_opens_a_real_vault() {
        if !hardware_tests_enabled() {
            return;
        }
        use passman_core::{Vault, crypto::KdfParams};

        let pin = std::env::var("PASSMAN_FIDO_PIN").ok();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();

        let (factor, kek) = enroll(pin.as_deref(), pin.is_some()).unwrap();
        vault.add_slot("Security key", factor, &kek).unwrap();
        drop(vault);

        let opened = Vault::open_with(&path, &FidoOpener::new(pin)).unwrap();
        assert_eq!(opened.slots().len(), 2);
        // The passphrase must still work — hardware is additive.
        assert!(Vault::open(&path, "pw").is_ok());
    }
}
