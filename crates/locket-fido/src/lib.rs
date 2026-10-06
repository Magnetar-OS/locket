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
//! Enrolment and unlock are written against [`Authenticator`], the two
//! operations a slot needs from a token. The tests run them against a token
//! in software that behaves as CTAP 2 says a real one does — a secret per
//! credential, a different one once the user has been verified, nothing for a
//! credential it did not make — and so cover everything but the USB
//! conversation itself. That part, [`HidToken`], needs a physical key *and* a
//! human to touch it: its tests are `#[ignore]`d behind `LOCKET_FIDO_TESTS=1`
//! and have never been run, because no token has been attached to the machine
//! this was written on.

#![forbid(unsafe_code)]

use base64ct::{Base64, Encoding};
use ctap_hid_fido2::{
    FidoKeyHid, FidoKeyHidFactory, LibCfg,
    fidokey::{
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
        get_assertion::get_assertion_params::{Extension as AssertionExt, GetAssertionArgs},
        make_credential::make_credential_params::Extension as CredentialExt,
    },
};
use hkdf::Hkdf;
use locket_core::{
    crypto::SymKey,
    slots::{Slot, SlotFactor, SlotOpener},
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

    #[error("this vault has no security-key factor")]
    NoSlot,

    #[error(
        "the security key did not return an hmac-secret value; it may not support the extension"
    )]
    NoHmacSecret,

    #[error("the security key returned no assertion; the credential may belong to another token")]
    NoAssertion,

    #[error("stored credential data is malformed")]
    MalformedSlot,

    #[error("{0}")]
    Other(String),
}

/// The relying-party id credentials are created under.
///
/// Not a real domain on purpose: these credentials are only ever used locally,
/// and a token scopes `hmac-secret` per (rp_id, credential), so a locket
/// credential cannot be exercised by a website.
pub const DEFAULT_RP_ID: &str = "locket.local";

const SALT_LEN: usize = 32;
const HKDF_DOMAIN: &[u8] = b"locket:fido2-hmac-secret:v1";

/// Stretch a token's raw `hmac-secret` output into a slot key.
///
/// The output is already 32 uniformly random bytes, so this is domain
/// separation rather than entropy extraction — it stops the same token+salt
/// being reused as a key for anything else locket might add later.
pub fn derive_slot_key(hmac_output: &[u8]) -> Result<SymKey> {
    let hk = Hkdf::<Sha256>::new(None, hmac_output);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_DOMAIN, out.as_mut_slice())
        .map_err(|e| Error::Other(format!("HKDF expand failed: {e}")))?;
    SymKey::try_from_slice(out.as_slice()).map_err(|e| Error::Other(e.to_string()))
}

/// What a key slot needs from a security key.
///
/// The seam between the slot logic and the token. [`HidToken`] is the real
/// thing, a CTAP 2 device over USB HID; the tests put a token in software
/// behind the same two calls.
pub trait Authenticator {
    /// Create a credential with the `hmac-secret` extension under `rp_id`,
    /// and return its id. Needs a touch, and `pin` if the token has one.
    fn make_credential(&self, rp_id: &str, pin: Option<&str>) -> Result<Vec<u8>>;

    /// `HMAC-SHA256(credential_secret, salt)` from one credential. Needs a
    /// touch. The token keeps two secrets per credential and answers from the
    /// one for "the user was verified" only when given its `pin`, so the same
    /// credential and salt give a different value with and without it.
    fn hmac_secret(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; SALT_LEN],
        pin: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// A security key attached over USB.
pub struct HidToken(FidoKeyHid);

impl HidToken {
    /// The first token found.
    pub fn open() -> Result<Self> {
        let cfg = LibCfg::init();
        FidoKeyHidFactory::create(&cfg).map(Self).map_err(|e| {
            // The crate reports "no device" as a generic error; make it
            // actionable.
            if ctap_hid_fido2::get_fidokey_devices().is_empty() {
                Error::NoDevice
            } else {
                Error::Device(e.to_string())
            }
        })
    }
}

impl Authenticator for HidToken {
    fn make_credential(&self, rp_id: &str, pin: Option<&str>) -> Result<Vec<u8>> {
        let challenge = random_challenge()?;
        let mut builder = MakeCredentialArgsBuilder::new(rp_id, &challenge)
            .extensions(&[CredentialExt::HmacSecret(Some(true))]);
        if let Some(pin) = pin {
            builder = builder.pin(pin);
        } else {
            builder = builder.without_pin_and_uv();
        }
        let attestation = self
            .0
            .make_credential_with_args(&builder.build())
            .map_err(|e| Error::Device(e.to_string()))?;
        Ok(attestation.credential_descriptor.id)
    }

    fn hmac_secret(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; SALT_LEN],
        pin: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let challenge = random_challenge()?;
        let args = hmac_assertion_args(rp_id, &challenge, credential_id, salt, pin);
        let assertions = self
            .0
            .get_assertion_with_args(&args)
            .map_err(|e| Error::Device(e.to_string()))?;
        assertions
            .iter()
            .find_map(|a| hmac_output_from(&a.extensions))
            .map(Zeroizing::new)
            .ok_or(Error::NoHmacSecret)
    }
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

/// The `getAssertion` that asks a slot's credential for its `hmac-secret`.
fn hmac_assertion_args<'a>(
    rp_id: &str,
    challenge: &[u8],
    credential_id: &[u8],
    salt: &[u8; SALT_LEN],
    pin: Option<&'a str>,
) -> GetAssertionArgs<'a> {
    let builder = GetAssertionArgsBuilder::new(rp_id, challenge)
        .credential_id(credential_id)
        .extensions(&[AssertionExt::HmacSecret(Some(*salt))]);
    // The builder starts out demanding user verification. Without a PIN that
    // means the token's own biometric, which most tokens do not have, so it
    // has to be cleared explicitly — as `assert` does.
    match pin {
        Some(pin) => builder.pin(pin),
        None => builder.without_pin_and_uv(),
    }
    .build()
}

/// Create a credential on the attached token and derive the slot's key from
/// it. See [`enroll_on`].
pub fn enroll(pin: Option<&str>, user_verification: bool) -> Result<(SlotFactor, SymKey)> {
    enroll_on(&HidToken::open()?, pin, user_verification)
}

/// Create a credential on `token` and derive the slot's key from it.
///
/// Requires a touch (and a PIN, if the token has one). Returns the slot
/// metadata to store plus the key-encryption key to enrol with.
pub fn enroll_on(
    token: &dyn Authenticator,
    pin: Option<&str>,
    user_verification: bool,
) -> Result<(SlotFactor, SymKey)> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Other(e.to_string()))?;

    let credential_id = token.make_credential(DEFAULT_RP_ID, pin)?;
    if credential_id.is_empty() {
        return Err(Error::Device(
            "token returned an empty credential id".into(),
        ));
    }

    // Immediately exercise the credential so the enrolled key is the one that
    // will actually come back later, rather than one we assumed.
    let output = token.hmac_secret(DEFAULT_RP_ID, &credential_id, &salt, pin)?;
    let key = derive_slot_key(output.as_slice())?;

    let factor = SlotFactor::Fido2 {
        credential_id: Base64::encode_string(&credential_id),
        salt: Base64::encode_string(&salt),
        rp_id: DEFAULT_RP_ID.to_owned(),
        user_verification,
    };
    Ok((factor, key))
}

/// Recover a FIDO2 slot's key-encryption key from the attached token.
pub fn unlock(factor: &SlotFactor, pin: Option<&str>) -> Result<SymKey> {
    // The slot is checked before a device is looked for: a malformed one is
    // not a reason to ask anybody to plug a token in.
    let slot = SlotRequest::from(factor)?;
    slot.ask(&HidToken::open()?, pin)
}

/// Recover a FIDO2 slot's key-encryption key from `token`. Requires a touch.
pub fn unlock_on(
    token: &dyn Authenticator,
    factor: &SlotFactor,
    pin: Option<&str>,
) -> Result<SymKey> {
    SlotRequest::from(factor)?.ask(token, pin)
}

/// The key of the vault's security-key factor, from the attached token. See
/// [`unlock_key_on`].
pub fn unlock_key(slots: &[Slot], pin: Option<&str>) -> Result<SymKey> {
    if !slots
        .iter()
        .any(|slot| matches!(slot.factor, SlotFactor::Fido2 { .. }))
    {
        return Err(Error::NoSlot);
    }
    unlock_key_on(&HidToken::open()?, slots, pin)
}

/// The key of the first security-key slot among `slots` that `token` holds
/// the credential for.
///
/// For a caller that needs the key itself rather than an open vault — to open
/// its own copy and hand the same key to the daemon. A vault may have a slot
/// per token (one carried, one in a drawer); the token plugged in answers for
/// its own and has nothing to say for the others.
pub fn unlock_key_on(
    token: &dyn Authenticator,
    slots: &[Slot],
    pin: Option<&str>,
) -> Result<SymKey> {
    let mut refused = Error::NoSlot;
    for slot in slots {
        if !matches!(slot.factor, SlotFactor::Fido2 { .. }) {
            continue;
        }
        match unlock_on(token, &slot.factor, pin) {
            Ok(key) => return Ok(key),
            Err(e) => refused = e,
        }
    }
    Err(refused)
}

/// What a FIDO2 slot asks its token.
struct SlotRequest<'a> {
    rp_id: &'a str,
    credential_id: Vec<u8>,
    salt: [u8; SALT_LEN],
}

impl<'a> SlotRequest<'a> {
    fn from(factor: &'a SlotFactor) -> Result<Self> {
        let SlotFactor::Fido2 {
            credential_id,
            salt,
            rp_id,
            ..
        } = factor
        else {
            return Err(Error::WrongFactor);
        };
        let credential_id = Base64::decode_vec(credential_id).map_err(|_| Error::MalformedSlot)?;
        let salt = Base64::decode_vec(salt).map_err(|_| Error::MalformedSlot)?;
        let salt: [u8; SALT_LEN] = salt
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedSlot)?;
        Ok(Self {
            // The relying party the credential was made under, which is the
            // only one the token will answer for.
            rp_id,
            credential_id,
            salt,
        })
    }

    fn ask(&self, token: &dyn Authenticator, pin: Option<&str>) -> Result<SymKey> {
        // The raw output is as good as the slot key; it wipes itself once
        // stretched.
        let output = token.hmac_secret(self.rp_id, &self.credential_id, &self.salt, pin)?;
        derive_slot_key(output.as_slice())
    }
}

/// One CTAP2 assertion, exactly as the token produced it.
///
/// Deliberately unparsed. Every protocol that builds on FIDO — WebAuthn, SSH's
/// `sk-` keys — wraps these two byte strings in its own way, and a token's
/// signature covers `auth_data || SHA256(challenge)` verbatim, so anything this
/// crate re-encoded would have to be re-derived byte for byte by the caller
/// anyway.
#[derive(Debug, Clone)]
pub struct Assertion {
    /// `rp_id_hash(32) || flags(1) || counter(4)`, plus extension data.
    pub auth_data: Vec<u8>,
    /// Raw for Ed25519 credentials, ASN.1 DER for ES256 ones.
    pub signature: Vec<u8>,
}

/// Ask the token to sign a challenge with an existing credential.
///
/// `challenge` is hashed to the CTAP client-data hash, so callers pass the
/// message itself rather than a digest of it. Requires a touch, and a PIN or
/// on-device biometric when `user_verification` is set.
///
/// This is the generic half of what an `sk-` SSH key needs; the SSH-specific
/// encoding lives in `locket-agent`, which is why nothing here knows what a
/// signature blob looks like.
pub fn assert(
    rp_id: &str,
    credential_id: &[u8],
    challenge: &[u8],
    pin: Option<&str>,
    user_verification: bool,
) -> Result<Assertion> {
    let device = HidToken::open()?.0;

    let builder = GetAssertionArgsBuilder::new(rp_id, challenge).credential_id(credential_id);
    let mut args = match pin {
        Some(pin) => builder.pin(pin).build(),
        None => builder.without_pin_and_uv().build(),
    };
    // The builder can only clear user verification, not ask for it; a key
    // created with `verify-required` needs it demanded explicitly, and the
    // token then chooses how (its own PIN, or a fingerprint).
    if user_verification && pin.is_none() {
        args.uv = Some(true);
    }

    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| Error::Device(e.to_string()))?;

    let assertion = assertions.into_iter().next().ok_or(Error::NoAssertion)?;
    if assertion.auth_data.is_empty() || assertion.signature.is_empty() {
        return Err(Error::NoAssertion);
    }
    Ok(Assertion {
        auth_data: assertion.auth_data,
        signature: assertion.signature,
    })
}

/// A [`SlotOpener`] backed by a security key.
pub struct FidoOpener<'a> {
    /// `None` is the token attached over USB, found when a slot is opened.
    token: Option<&'a dyn Authenticator>,
    pin: Option<Zeroizing<String>>,
}

impl FidoOpener<'static> {
    /// Open with the attached token.
    pub fn new(pin: Option<String>) -> Self {
        Self {
            token: None,
            pin: pin.map(Zeroizing::new),
        }
    }
}

impl<'a> FidoOpener<'a> {
    /// Open with a particular token.
    pub fn on(token: &'a dyn Authenticator, pin: Option<String>) -> Self {
        Self {
            token: Some(token),
            pin: pin.map(Zeroizing::new),
        }
    }
}

impl SlotOpener for FidoOpener<'_> {
    fn kek_for(&self, factor: &SlotFactor) -> locket_core::Result<Option<SymKey>> {
        if !matches!(factor, SlotFactor::Fido2 { .. }) {
            return Ok(None);
        }
        let pin = self.pin.as_deref().map(String::as_str);
        let unlocked = match self.token {
            Some(token) => unlock_on(token, factor, pin),
            None => unlock(factor, pin),
        };
        match unlocked {
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
        std::env::var("LOCKET_FIDO_TESTS").is_ok_and(|v| v == "1")
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

    /// ctap-hid-fido2's `GetAssertionArgs` defaults to `uv: Some(true)`, and
    /// only `pin()` or `without_pin_and_uv()` clear it. Without a PIN the
    /// request asked the token for built-in user verification, which a token
    /// with no fingerprint reader refuses: a PIN-less slot could not be
    /// enrolled or opened. The same file's `assert` already clears it.
    #[test]
    fn a_pinless_hmac_assertion_does_not_demand_user_verification() {
        let (challenge, credential, salt) = ([1u8; 32], [2u8; 16], [3u8; SALT_LEN]);

        let without = hmac_assertion_args(DEFAULT_RP_ID, &challenge, &credential, &salt, None);
        assert_eq!(without.uv, None, "a PIN-less assertion demanded UV");
        assert!(without.pin.is_none());
        assert!(without.up, "a touch is still required");

        let with = hmac_assertion_args(DEFAULT_RP_ID, &challenge, &credential, &salt, Some("1234"));
        assert_eq!(with.pin, Some("1234"));
        assert_eq!(with.credential_ids, vec![credential.to_vec()]);
    }

    // -- against a token in software ----------------------------------------

    use hmac::{Hmac, KeyInit, Mac};
    use locket_core::{Vault, crypto::KdfParams};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A security key in software.
    ///
    /// Behaves as CTAP 2.1 says a token does for `hmac-secret` (§12.5): every
    /// credential carries two random secrets, `CredRandomWithUV` and
    /// `CredRandomWithoutUV`; an assertion answers `HMAC-SHA256(secret, salt)`
    /// from the one that matches whether the user was verified; a credential
    /// this token did not make, or one made for another relying party, is
    /// `CTAP2_ERR_NO_CREDENTIALS`. With a PIN set, a wrong one is refused.
    struct SoftToken {
        pin: Option<&'static str>,
        credentials: Mutex<HashMap<Vec<u8>, Credential>>,
        touches: Mutex<usize>,
    }

    struct Credential {
        rp_id: String,
        with_uv: [u8; 32],
        without_uv: [u8; 32],
    }

    impl SoftToken {
        fn new(pin: Option<&'static str>) -> Self {
            Self {
                pin,
                credentials: Mutex::new(HashMap::new()),
                touches: Mutex::new(0),
            }
        }

        /// Whether the user counts as verified for this request.
        fn verify(&self, pin: Option<&str>) -> Result<bool> {
            match (self.pin, pin) {
                (_, None) => Ok(false),
                (Some(ours), Some(given)) if ours == given => Ok(true),
                (Some(_), Some(_)) => Err(Error::Device("CTAP2_ERR_PIN_INVALID".into())),
                (None, Some(_)) => Err(Error::Device("CTAP2_ERR_PIN_NOT_SET".into())),
            }
        }

        fn touches(&self) -> usize {
            *self.touches.lock().unwrap()
        }
    }

    fn random32() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        bytes
    }

    impl Authenticator for SoftToken {
        fn make_credential(&self, rp_id: &str, pin: Option<&str>) -> Result<Vec<u8>> {
            let verified = self.verify(pin)?;
            if self.pin.is_some() && !verified {
                return Err(Error::Device("CTAP2_ERR_PUAT_REQUIRED".into()));
            }
            *self.touches.lock().unwrap() += 1;
            let id = random32().to_vec();
            self.credentials.lock().unwrap().insert(
                id.clone(),
                Credential {
                    rp_id: rp_id.to_owned(),
                    with_uv: random32(),
                    without_uv: random32(),
                },
            );
            Ok(id)
        }

        fn hmac_secret(
            &self,
            rp_id: &str,
            credential_id: &[u8],
            salt: &[u8; SALT_LEN],
            pin: Option<&str>,
        ) -> Result<Zeroizing<[u8; 32]>> {
            let verified = self.verify(pin)?;
            let credentials = self.credentials.lock().unwrap();
            let credential = credentials
                .get(credential_id)
                .filter(|c| c.rp_id == rp_id)
                .ok_or_else(|| Error::Device("CTAP2_ERR_NO_CREDENTIALS".into()))?;
            *self.touches.lock().unwrap() += 1;
            let secret = if verified {
                &credential.with_uv
            } else {
                &credential.without_uv
            };
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
            mac.update(salt);
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }
    }

    #[test]
    fn a_token_gives_back_the_key_it_enrolled_and_another_token_does_not() {
        let token = SoftToken::new(None);
        let (factor, key) = enroll_on(&token, None, false).unwrap();
        assert_eq!(token.touches(), 2, "one touch to create, one to prove");
        let SlotFactor::Fido2 { rp_id, .. } = &factor else {
            panic!("not a FIDO2 slot");
        };
        assert_eq!(rp_id, DEFAULT_RP_ID);

        let again = unlock_on(&token, &factor, None).unwrap();
        assert_eq!(key.expose(), again.expose());

        // A second enrolment on the same token is its own credential and key.
        let (_, other_key) = enroll_on(&token, None, false).unwrap();
        assert_ne!(key.expose(), other_key.expose());

        // Somebody else's token has nothing to say for this slot.
        let stranger = SoftToken::new(None);
        assert!(matches!(
            unlock_on(&stranger, &factor, None),
            Err(Error::Device(why)) if why.contains("NO_CREDENTIALS")
        ));
    }

    /// The token answers from a different secret once the user is verified,
    /// so a slot enrolled with the token's PIN opens with it and not without.
    #[test]
    fn a_slot_enrolled_with_the_pin_needs_the_pin() {
        let token = SoftToken::new(Some("2468"));
        assert!(
            enroll_on(&token, None, false).is_err(),
            "a token with a PIN made a credential without it"
        );
        let (factor, key) = enroll_on(&token, Some("2468"), true).unwrap();

        assert_eq!(
            unlock_on(&token, &factor, Some("2468")).unwrap().expose(),
            key.expose()
        );
        let without = unlock_on(&token, &factor, None).unwrap();
        assert_ne!(
            without.expose(),
            key.expose(),
            "the PIN made no difference to the key"
        );
        assert!(unlock_on(&token, &factor, Some("0000")).is_err());
    }

    /// `unlock` used to ask every slot's credential under locket's own
    /// relying party, whatever the slot recorded. A token scopes credentials
    /// to the relying party they were made for and answers for no other.
    #[test]
    fn a_slot_is_asked_under_the_relying_party_it_recorded() {
        let token = SoftToken::new(None);
        let credential_id = token.make_credential("vault.example", None).unwrap();
        let salt = [5u8; SALT_LEN];
        let factor = SlotFactor::Fido2 {
            credential_id: Base64::encode_string(&credential_id),
            salt: Base64::encode_string(&salt),
            rp_id: "vault.example".into(),
            user_verification: false,
        };
        let expected = token
            .hmac_secret("vault.example", &credential_id, &salt, None)
            .unwrap();
        assert_eq!(
            unlock_on(&token, &factor, None).unwrap().expose(),
            derive_slot_key(expected.as_slice()).unwrap().expose()
        );
    }

    /// The whole life of a security-key factor on a vault — two of them, a
    /// token carried and a spare: added, each used to unlock with no
    /// passphrase, kept through a passphrase change, and removed.
    #[test]
    fn a_security_key_factor_unlocks_a_vault_through_a_rekey_and_until_removed() {
        use locket_core::slots::{RawKeyOpener, SlotKind};

        let carried = SoftToken::new(Some("2468"));
        let spare = SoftToken::new(None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");

        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let (factor, kek) = enroll_on(&carried, Some("2468"), true).unwrap();
        let slot = vault.add_slot("Security key", factor, &kek).unwrap();
        let (factor, kek) = enroll_on(&spare, None, false).unwrap();
        vault.add_slot("Spare key", factor, &kek).unwrap();
        drop(vault);

        // Either token opens it; a stranger's does not.
        assert!(Vault::open_with(&path, &FidoOpener::on(&carried, Some("2468".into()))).is_ok());
        assert!(Vault::open_with(&path, &FidoOpener::on(&spare, None)).is_ok());
        let stranger = SoftToken::new(None);
        assert!(matches!(
            Vault::open_with(&path, &FidoOpener::on(&stranger, None)),
            Err(locket_core::Error::WrongPassphrase)
        ));

        // The key itself, whichever slot the token in hand belongs to.
        let slots = Vault::read_slots(&path).unwrap();
        for (token, pin) in [(&carried, Some("2468")), (&spare, None)] {
            let key = unlock_key_on(token, &slots, pin).unwrap();
            let by_key = RawKeyOpener {
                kind: SlotKind::Fido2,
                key,
            };
            assert!(Vault::open_with(&path, &by_key).is_ok());
        }
        assert!(unlock_key_on(&stranger, &slots, None).is_err());

        // Opened with a token, the passphrase can be replaced, and both
        // tokens still open the vault afterwards.
        let mut vault = Vault::open_with(&path, &FidoOpener::on(&spare, None)).unwrap();
        vault
            .change_passphrase("a new passphrase", KdfParams::insecure_fast())
            .unwrap();
        drop(vault);
        assert!(Vault::open(&path, "pw").is_err());
        assert!(Vault::open_with(&path, &FidoOpener::on(&carried, Some("2468".into()))).is_ok());

        // The carried token is lost: its slot is removed, the spare stays.
        let mut vault = Vault::open(&path, "a new passphrase").unwrap();
        vault.remove_slot(slot).unwrap();
        drop(vault);
        assert!(Vault::open_with(&path, &FidoOpener::on(&carried, Some("2468".into()))).is_err());
        assert!(Vault::open_with(&path, &FidoOpener::on(&spare, None)).is_ok());
    }

    /// Nobody is asked to plug a token in for a vault that has no use for one.
    #[test]
    fn a_vault_without_a_security_key_factor_asks_for_no_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        let slots = Vault::read_slots(&path).unwrap();
        assert!(matches!(unlock_key(&slots, None), Err(Error::NoSlot)));
    }

    #[test]
    fn device_presence_check_does_not_panic_without_a_token() {
        // Must be safe to call on a machine with no security key attached.
        let _ = device_present();
    }

    #[test]
    #[ignore = "requires a FIDO2 token and a human touch; set LOCKET_FIDO_TESTS=1"]
    fn enroll_and_unlock_a_real_token() {
        if !hardware_tests_enabled() {
            return;
        }
        let pin = std::env::var("LOCKET_FIDO_PIN").ok();
        let (factor, key) = enroll(pin.as_deref(), pin.is_some()).expect("enrolment failed");
        let again = unlock(&factor, pin.as_deref()).expect("unlock failed");
        assert_eq!(
            key.expose(),
            again.expose(),
            "the token returned a different hmac-secret for the same salt"
        );
    }

    /// The property `locket-agent`'s `sk-` encoder rests on: an SSH assertion
    /// comes back with exactly 37 bytes of authenticator data, over the
    /// application the credential was made under. A token that appended
    /// extension output here would produce signatures no SSH server accepts.
    #[test]
    #[ignore = "requires a FIDO2 token and a human touch; set LOCKET_FIDO_TESTS=1"]
    fn an_ssh_style_assertion_has_bare_37_byte_authenticator_data() {
        if !hardware_tests_enabled() {
            return;
        }
        use sha2::Digest as _;

        const SSH_RP_ID: &str = "ssh:";
        let pin = std::env::var("LOCKET_FIDO_PIN").ok();
        let device = HidToken::open().expect("no token").0;

        let challenge = random_challenge().unwrap();
        let mut builder = MakeCredentialArgsBuilder::new(SSH_RP_ID, &challenge);
        builder = match pin.as_deref() {
            Some(pin) => builder.pin(pin),
            None => builder.without_pin_and_uv(),
        };
        let attestation = device
            .make_credential_with_args(&builder.build())
            .expect("could not create an ssh: credential");

        let assertion = assert(
            SSH_RP_ID,
            &attestation.credential_descriptor.id,
            b"an ssh sign request",
            pin.as_deref(),
            pin.is_some(),
        )
        .expect("assertion failed");

        assert_eq!(
            assertion.auth_data.len(),
            37,
            "authenticator data carried extensions; the sk- encoder rejects that"
        );
        assert_eq!(
            &assertion.auth_data[..32],
            sha2::Sha256::digest(SSH_RP_ID.as_bytes()).as_slice(),
            "the token asserted a different relying party"
        );
        assert!(!assertion.signature.is_empty());
    }

    #[test]
    #[ignore = "requires a FIDO2 token and a human touch; set LOCKET_FIDO_TESTS=1"]
    fn a_fido_slot_opens_a_real_vault() {
        if !hardware_tests_enabled() {
            return;
        }
        let pin = std::env::var("LOCKET_FIDO_PIN").ok();
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
