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
//! The tests run against `swtpm`, the software TPM, which has to be
//! installed: each test starts its own on loopback ports, with its state in
//! a temporary directory (see [`testing`]), and never opens this machine's
//! chip. They cover what the
//! design rests on — a wrong PIN costs exactly one strike of the
//! dictionary-attack counter, the lockout refuses the right PIN too, and a
//! blob sealed by one TPM is useless to another. Two further tests talk to
//! whatever the TCTI environment names — a real chip — and are `#[ignore]`d
//! behind `LOCKET_TPM_TESTS=1`.

#![forbid(unsafe_code)]

#[cfg(feature = "test-swtpm")]
pub mod testing;

use std::str::FromStr as _;

use base64ct::{Base64, Encoding};
use locket_core::{
    Vault,
    crypto::SymKey,
    slots::{Slot, SlotFactor, SlotOpener, TpmParent},
};
use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    constants::{CapabilityType, PropertyTag},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, CapabilityData, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private,
        Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, RsaExponent,
        SensitiveData, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    utils::create_restricted_decryption_rsa_public,
};
use uuid::Uuid;
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

    #[error("this vault has no TPM factor")]
    NoSlot,

    #[error("this vault already has a TPM factor; remove it before adding another")]
    AlreadyEnrolled,

    #[error(transparent)]
    Vault(#[from] locket_core::Error),

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

/// The auth value to present when unsealing a slot.
///
/// Only a slot sealed with a PIN gets one. A PIN offered to a slot sealed
/// without — the one typed for some other slot — would make the TPM check
/// the session against an auth value the object does not have, and refuse.
fn slot_auth(with_pin: bool, pin: Option<&str>) -> Result<Option<Auth>> {
    if with_pin {
        auth_from_pin(pin)
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// TPM operations
// ---------------------------------------------------------------------------

/// A TPM to seal to and unseal with.
#[derive(Debug, Clone)]
pub struct Tpm {
    tcti: TctiNameConf,
}

impl Tpm {
    /// This machine's TPM.
    ///
    /// Honours the standard TCTI environment variables, so a simulator can be
    /// named from outside; with none set it is the kernel's resource manager,
    /// `/dev/tpmrm0`.
    pub fn system() -> Result<Self> {
        Ok(Self {
            tcti: tcti_from(|name| std::env::var(name).ok())?,
        })
    }

    /// The TPM a TCTI configuration names, e.g.
    /// `swtpm:host=127.0.0.1,port=2321`.
    pub fn at(tcti: &str) -> Result<Self> {
        Ok(Self {
            tcti: tcti_from(|_| Some(tcti.to_owned()))?,
        })
    }

    /// Open a context against this TPM.
    pub fn context(&self) -> Result<Context> {
        Context::new(self.tcti.clone()).map_err(|e| Error::NoTpm(e.to_string()))
    }

    /// Seal a fresh random secret to this TPM.
    ///
    /// Returns the slot metadata to store in the vault and the key-encryption
    /// key to enrol with; hand the latter to `Vault::add_slot` and drop it.
    /// It can always be recovered later with [`Tpm::unseal`].
    pub fn enroll(&self, pin: Option<&str>) -> Result<(SlotFactor, SymKey)> {
        let mut secret = Zeroizing::new(vec![0u8; SEALED_SECRET_LEN]);
        getrandom::fill(&mut secret).map_err(|e| Error::Other(e.to_string()))?;

        let with_pin = pin.is_some_and(|p| !p.is_empty());
        let auth = auth_from_pin(pin)?;
        let sensitive =
            SensitiveData::try_from(secret.to_vec()).map_err(|e| Error::Other(e.to_string()))?;

        let mut context = self.context()?;
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
            // PCR binding is a separate decision from the PIN and is
            // deliberately not taken here: binding to firmware measurements
            // means a BIOS update locks you out of your own vault.
            pcrs: Vec::new(),
            with_pin,
        };

        let kek = SymKey::try_from_slice(&secret).map_err(|e| Error::Other(e.to_string()))?;
        Ok((factor, kek))
    }

    /// Add a TPM factor to an open vault: seal a new key under `pin` and
    /// enrol it. Returns the new slot's id.
    ///
    /// Two rules are kept here, so that every way of adding the factor keeps
    /// them. The PIN is required: without one the chip releases the key to
    /// anything on the machine that asks, and its lockout never comes into
    /// play. And a vault gets one TPM factor: unlocking tries the PIN on
    /// every TPM slot, and each one it does not fit costs a strike.
    pub fn enroll_into(&self, vault: &mut Vault, pin: &str) -> Result<Uuid> {
        if pin.is_empty() {
            return Err(Error::PinRequired);
        }
        if vault
            .slots()
            .iter()
            .any(|slot| matches!(slot.factor, SlotFactor::Tpm2 { .. }))
        {
            return Err(Error::AlreadyEnrolled);
        }
        let (factor, kek) = self.enroll(Some(pin))?;
        Ok(vault.add_slot("TPM 2.0 (PIN)", factor, &kek)?)
    }

    /// Recover a sealed slot's key-encryption key.
    ///
    /// A wrong PIN costs one strike of the chip's dictionary-attack counter,
    /// which every object on that TPM shares.
    pub fn unseal(&self, factor: &SlotFactor, pin: Option<&str>) -> Result<SymKey> {
        let SlotFactor::Tpm2 {
            sealed,
            with_pin,
            parent,
            pcrs,
        } = factor
        else {
            return Err(Error::WrongFactor);
        };

        // No PCR policy is ever built, so a slot that lists PCRs would be
        // unsealed on its PIN alone while claiming more. Refuse it, and before
        // the TPM is opened: nothing here needs the chip to know that.
        if !pcrs.is_empty() {
            return Err(Error::Other(format!(
                "this slot is bound to PCRs {pcrs:?}, and PCR policies are not supported"
            )));
        }

        // Check this before touching the TPM: a needless failed unseal costs
        // a dictionary-attack strike against the whole device.
        if *with_pin && pin.is_none_or(str::is_empty) {
            return Err(Error::PinRequired);
        }

        let (public_bytes, private_bytes) = unpack(sealed)?;
        let public = Public::unmarshall(&public_bytes).map_err(|_| Error::MalformedBlob)?;
        let private = Private::try_from(private_bytes).map_err(|_| Error::MalformedBlob)?;
        let auth = slot_auth(*with_pin, pin)?;

        let mut context = self.context()?;
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

    /// The key of the vault's TPM factor: what [`Tpm::unseal`] returns for the
    /// first TPM slot among `slots` that `pin` releases.
    ///
    /// For a caller that needs the key itself rather than an open vault — to
    /// open its own copy and hand the same key to the daemon. Each TPM slot
    /// the PIN does not fit costs a strike, which is why the application
    /// enrols one TPM factor per vault.
    pub fn unlock_key(&self, slots: &[Slot], pin: Option<&str>) -> Result<SymKey> {
        let mut refused = Error::NoSlot;
        for slot in slots {
            if !matches!(slot.factor, SlotFactor::Tpm2 { .. }) {
                continue;
            }
            match self.unseal(&slot.factor, pin) {
                Ok(key) => return Ok(key),
                Err(e) => refused = e,
            }
        }
        Err(refused)
    }

    /// How many failed authorisations this TPM is counting toward lockout.
    pub fn lockout_counter(&self) -> Result<u32> {
        let mut context = self.context()?;
        let (data, _more) = context.get_capability(
            CapabilityType::TpmProperties,
            PropertyTag::LockoutCounter.into(),
            1,
        )?;
        match data {
            CapabilityData::TpmProperties(properties) => properties
                .find(PropertyTag::LockoutCounter)
                .map(|property| property.value())
                .ok_or_else(|| Error::Other("the TPM did not report its lockout counter".into())),
            _ => Err(Error::Other(
                "the TPM answered a property query with something else".into(),
            )),
        }
    }
}

/// Which TPM to open, given a way to read an environment variable.
///
/// The variables are the ones `TctiNameConf::from_environment_variable` reads,
/// in its order. That function fails outright when none is set — the normal
/// state of a desktop session — so the default is chosen here: the kernel's
/// resource manager, which the `tss` group can open and which, unlike
/// `/dev/tpm0`, lets several processes share the chip.
fn tcti_from(var: impl Fn(&str) -> Option<String>) -> Result<TctiNameConf> {
    let named = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"]
        .into_iter()
        .find_map(var)
        .unwrap_or_else(|| "device:/dev/tpmrm0".to_owned());
    TctiNameConf::from_str(&named)
        .map_err(|e| Error::NoTpm(format!("no usable TCTI `{named}`: {e}")))
}

/// [`Tpm::enroll`] on this machine's TPM.
pub fn enroll(pin: Option<&str>) -> Result<(SlotFactor, SymKey)> {
    Tpm::system()?.enroll(pin)
}

/// [`Tpm::unseal`] on this machine's TPM.
pub fn unseal(factor: &SlotFactor, pin: Option<&str>) -> Result<SymKey> {
    Tpm::system()?.unseal(factor, pin)
}

/// A [`SlotOpener`] that unseals TPM slots.
pub struct TpmOpener {
    /// `None` is this machine's TPM, found when a slot is opened.
    tpm: Option<Tpm>,
    pin: Option<Zeroizing<String>>,
}

impl TpmOpener {
    /// Open with this machine's TPM.
    pub fn new(pin: Option<String>) -> Self {
        Self {
            tpm: None,
            pin: pin.map(Zeroizing::new),
        }
    }

    /// Open with a particular TPM.
    pub fn on(tpm: Tpm, pin: Option<String>) -> Self {
        Self {
            tpm: Some(tpm),
            pin: pin.map(Zeroizing::new),
        }
    }
}

impl SlotOpener for TpmOpener {
    fn kek_for(&self, factor: &SlotFactor) -> locket_core::Result<Option<SymKey>> {
        if !matches!(factor, SlotFactor::Tpm2 { .. }) {
            return Ok(None);
        }
        let pin = self.pin.as_deref().map(String::as_str);
        let unsealed = match &self.tpm {
            Some(tpm) => tpm.unseal(factor, pin),
            None => unseal(factor, pin),
        };
        match unsealed {
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

    /// tss-esapi's `from_environment_variable` fails when none of its
    /// variables is set, which on a desktop session is always: enrolment
    /// then reported "no TPM available" on a machine with a working one.
    #[test]
    fn with_no_tcti_variable_the_kernel_resource_manager_is_used() {
        let rm = TctiNameConf::from_str("device:/dev/tpmrm0").unwrap();
        assert_eq!(tcti_from(|_| None).unwrap(), rm);

        // A variable still wins, read in tss-esapi's order.
        let swtpm = "swtpm:host=localhost,port=2321";
        let only = |set: &'static str| move |name: &str| (name == set).then(|| swtpm.to_owned());
        for name in ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"] {
            assert!(
                matches!(tcti_from(only(name)).unwrap(), TctiNameConf::Swtpm(_)),
                "{name} was not honoured"
            );
        }
        let first = |name: &str| match name {
            "TPM2TOOLS_TCTI" => Some("device:/dev/tpm0".to_owned()),
            _ => Some(swtpm.to_owned()),
        };
        assert_eq!(
            tcti_from(first).unwrap(),
            TctiNameConf::from_str("device:/dev/tpm0").unwrap()
        );
        assert!(matches!(
            tcti_from(|_| Some("nonsense".to_owned())),
            Err(Error::NoTpm(_))
        ));
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

    /// `pcrs` promises a PCR policy, and no policy is ever built: a slot
    /// claiming one would unseal on the PIN alone while saying otherwise.
    /// Refused before the TPM is opened, like a missing PIN.
    #[test]
    fn a_slot_claiming_pcrs_is_refused_without_touching_hardware() {
        let factor = SlotFactor::Tpm2 {
            sealed: pack(&[0u8; 8], &[0u8; 8]),
            parent: Default::default(),
            pcrs: vec![7],
            with_pin: true,
        };
        assert!(
            matches!(unseal(&factor, Some("1234")), Err(Error::Other(ref msg)) if msg.contains("PCR")),
            "{:?}",
            unseal(&factor, Some("1234"))
        );
    }

    /// A slot sealed without a PIN has an empty auth value. Presenting a PIN
    /// to it anyway — the one the person typed for some other slot — makes
    /// the TPM compute the session HMAC with a key the object does not have,
    /// and the unseal fails.
    #[test]
    fn a_pinless_slot_ignores_a_pin_it_was_not_sealed_with() {
        assert!(slot_auth(false, Some("1234")).unwrap().is_none());
        assert!(slot_auth(false, None).unwrap().is_none());
        assert!(slot_auth(true, Some("1234")).unwrap().is_some());
    }

    // -- against a software TPM ---------------------------------------------

    use crate::testing::Swtpm;
    use locket_core::{
        crypto::KdfParams,
        slots::{RawKeyOpener, SlotKind},
    };

    /// The property the PIN rests on: a wrong one is refused *and counted*,
    /// once, by the chip — and a missing one is refused before the chip is
    /// asked, so it costs nothing.
    #[test]
    fn a_wrong_pin_is_refused_and_costs_exactly_one_strike() {
        let swtpm = Swtpm::start();
        let tpm = swtpm.tpm();
        let (factor, kek) = tpm.enroll(Some("246810")).expect("enrolment failed");
        assert_eq!(tpm.lockout_counter().unwrap(), 0);

        let unsealed = tpm.unseal(&factor, Some("246810")).expect("unseal failed");
        assert_eq!(kek.expose(), unsealed.expose());
        assert_eq!(
            tpm.lockout_counter().unwrap(),
            0,
            "the right PIN was counted"
        );

        assert!(matches!(tpm.unseal(&factor, None), Err(Error::PinRequired)));
        assert_eq!(
            tpm.lockout_counter().unwrap(),
            0,
            "a missing PIN was counted"
        );

        assert!(
            matches!(tpm.unseal(&factor, Some("000000")), Err(Error::Tpm(_))),
            "a wrong PIN unsealed"
        );
        assert_eq!(tpm.lockout_counter().unwrap(), 1);

        // The strike is not cleared by the right PIN: it is the chip's count.
        assert!(tpm.unseal(&factor, Some("246810")).is_ok());
        assert_eq!(tpm.lockout_counter().unwrap(), 1);
    }

    /// What the lockout costs, and why a passphrase slot always stays: after
    /// the chip's limit of wrong PINs — three on `swtpm` — the right one is
    /// refused as well.
    #[test]
    fn enough_wrong_pins_lock_the_chip_against_the_right_one_too() {
        let swtpm = Swtpm::start();
        let tpm = swtpm.tpm();
        let (factor, _kek) = tpm.enroll(Some("246810")).unwrap();

        for _ in 0..3 {
            assert!(tpm.unseal(&factor, Some("000000")).is_err());
        }
        let refused = tpm.unseal(&factor, Some("246810"));
        assert!(
            matches!(&refused, Err(Error::Tpm(why)) if why.contains("lockout")),
            "{refused:?}"
        );
    }

    /// The sealed blob is in the vault file, which may be copied. It opens
    /// nothing anywhere but on the TPM that made it.
    #[test]
    fn a_blob_sealed_by_one_tpm_is_useless_to_another() {
        let ours = Swtpm::start();
        let (factor, _kek) = ours.tpm().enroll(Some("246810")).unwrap();

        let theirs = Swtpm::start();
        assert!(
            theirs.tpm().unseal(&factor, Some("246810")).is_err(),
            "another TPM unsealed the blob"
        );
        assert!(ours.tpm().unseal(&factor, Some("246810")).is_ok());
    }

    /// The whole life of a TPM factor on a vault: added, used to unlock with
    /// no passphrase, kept through a passphrase change, and removed.
    #[test]
    fn a_tpm_factor_unlocks_a_vault_through_a_rekey_and_until_removed() {
        let swtpm = Swtpm::start();
        let tpm = swtpm.tpm();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let opener = |pin: &str| TpmOpener::on(tpm.clone(), Some(pin.to_owned()));

        let mut vault = Vault::create(&path, "pw", KdfParams::insecure_fast()).unwrap();
        vault.add_item_default(locket_core::Item::new(
            locket_core::ItemKind::Note,
            "inside",
        ));
        vault.save().unwrap();
        assert!(matches!(
            tpm.enroll_into(&mut vault, ""),
            Err(Error::PinRequired)
        ));
        let slot = tpm.enroll_into(&mut vault, "1357").unwrap();
        // One TPM factor to a vault: a second would cost a strike at every
        // unlock, for whichever of the two the PIN typed did not fit.
        assert!(matches!(
            tpm.enroll_into(&mut vault, "8642"),
            Err(Error::AlreadyEnrolled)
        ));
        drop(vault);

        // The PIN alone opens it; a wrong one does not, and says no more.
        let opened = Vault::open_with(&path, &opener("1357")).unwrap();
        assert_eq!(opened.data().item_count(), 1);
        assert!(matches!(
            Vault::open_with(&path, &opener("9999")),
            Err(locket_core::Error::WrongPassphrase)
        ));

        // The key itself, for a caller that has a daemon to pass it on to.
        let slots = Vault::read_slots(&path).unwrap();
        let key = tpm.unlock_key(&slots, Some("1357")).unwrap();
        let by_key = RawKeyOpener {
            kind: SlotKind::Tpm2,
            key,
        };
        assert!(Vault::open_with(&path, &by_key).is_ok());

        // Opened with the TPM, the passphrase can be replaced — the way back
        // in for someone who has forgotten it — and the TPM factor stays.
        let mut vault = Vault::open_with(&path, &opener("1357")).unwrap();
        vault
            .change_passphrase("a new passphrase", KdfParams::insecure_fast())
            .unwrap();
        drop(vault);
        assert!(Vault::open(&path, "pw").is_err());
        assert!(Vault::open(&path, "a new passphrase").is_ok());
        assert!(Vault::open_with(&path, &opener("1357")).is_ok());

        // Removed, it opens nothing; the passphrase still does.
        let mut vault = Vault::open(&path, "a new passphrase").unwrap();
        vault.remove_slot(slot).unwrap();
        drop(vault);
        assert!(Vault::open_with(&path, &opener("1357")).is_err());
        assert!(matches!(
            tpm.unlock_key(&Vault::read_slots(&path).unwrap(), Some("1357")),
            Err(Error::NoSlot)
        ));
        assert!(Vault::open(&path, "a new passphrase").is_ok());
    }

    // -- against whatever the TCTI environment names: a real chip ------------

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
