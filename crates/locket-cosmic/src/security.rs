//! Unlock factors: adding and removing them, and unlocking with one.
//!
//! Two rules hold here, and in the crates underneath so that the command
//! line keeps them too:
//!
//! * **The passphrase always stays.** Hardware factors are additive. A dead
//!   motherboard or a lost token must not be a lost vault, so the last
//!   passphrase slot can never be removed (`Vault::remove_slot`).
//! * **Enrolment is never silent about what it costs.** A TPM PIN is only as
//!   good as the chip's dictionary-attack lockout, and that lockout is
//!   device-wide — the screen says so, because someone choosing a 4-digit PIN
//!   deserves to know what is holding it up.

use crate::fl;
use cosmic::iced::{Alignment, Length};
use cosmic::prelude::*;
use cosmic::widget;
use locket_core::{
    SecretString, Vault,
    crypto::SymKey,
    slots::{SlotFactor, SlotKind},
};
use uuid::Uuid;

/// A factor the user can add, and whether this build can add it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    TpmPin,
    SecurityKey,
}

impl Factor {
    pub fn label(self) -> String {
        match self {
            Factor::TpmPin => fl!("factor-tpm-pin"),
            Factor::SecurityKey => fl!("factor-security-key"),
        }
    }

    /// Whether this build was compiled with support for it.
    pub const fn compiled_in(self) -> bool {
        match self {
            Factor::TpmPin => cfg!(feature = "tpm"),
            Factor::SecurityKey => cfg!(feature = "fido"),
        }
    }

    /// The kind of slot this factor opens.
    pub const fn kind(self) -> SlotKind {
        match self {
            Factor::TpmPin => SlotKind::Tpm2,
            Factor::SecurityKey => SlotKind::Fido2,
        }
    }
}

/// The hardware factors the vault at `path` can be unlocked with here: the
/// ones it has a slot for and this build can talk to. Read from the file's
/// header, so it is known before anything is unlocked.
pub fn enrolled(path: &std::path::Path) -> Vec<Factor> {
    let Ok(slots) = Vault::read_slots(path) else {
        // No vault yet, or one that cannot be read: the unlock screen says
        // which when the passphrase is tried.
        return Vec::new();
    };
    [Factor::TpmPin, Factor::SecurityKey]
        .into_iter()
        .filter(|factor| {
            factor.compiled_in() && slots.iter().any(|slot| slot.factor.kind() == factor.kind())
        })
        .collect()
}

/// Have `factor`'s device release the key of the vault's slot for it.
///
/// Blocking: a TPM takes the better part of a second, and a security key
/// waits for a touch. The key is returned rather than an open vault because
/// two things need opening with it — this window's copy and the daemon's.
pub fn slot_key(path: &std::path::Path, factor: Factor, pin: &str) -> Result<SymKey, String> {
    let refused = |error: String| {
        fl!(
            "unlock-hardware-refused",
            factor = factor.label(),
            error = error
        )
    };
    let slots = Vault::read_slots(path).map_err(|e| refused(e.to_string()))?;
    match factor {
        Factor::TpmPin => tpm_key(&slots, pin),
        Factor::SecurityKey => security_key_key(&slots, pin),
    }
    .map_err(refused)
}

/// Open the vault at `path` with a hardware factor. Blocking, like
/// [`slot_key`], whose key it also returns — for the daemon.
pub fn open(path: &std::path::Path, factor: Factor, pin: &str) -> Result<(Vault, SymKey), String> {
    let key = slot_key(path, factor, pin)?;
    let opener = locket_core::slots::RawKeyOpener {
        kind: factor.kind(),
        key: key.clone(),
    };
    let vault = Vault::open_with(path, &opener).map_err(|e| {
        fl!(
            "unlock-hardware-refused",
            factor = factor.label(),
            error = e.to_string()
        )
    })?;
    Ok((vault, key))
}

/// What the secret field of an unlock form is asking for.
pub fn unlock_placeholder(with: Option<Factor>) -> String {
    match with {
        None => fl!("unlock-passphrase"),
        Some(Factor::TpmPin) => fl!("unlock-tpm-pin"),
        Some(Factor::SecurityKey) => fl!("unlock-security-key-pin"),
    }
}

/// Whether an unlock form can be submitted with this in its secret field.
///
/// A security key may have no PIN at all, so its field may be empty. A TPM
/// factor always has one, and trying the chip without it would be refused
/// anyway.
pub fn unlock_input_missing(with: Option<Factor>, input: &SecretString) -> Option<String> {
    match with {
        None if input.is_empty() => Some(fl!("error-enter-passphrase")),
        Some(Factor::TpmPin) if input.is_empty() => Some(fl!("error-enter-pin")),
        _ => None,
    }
}

/// The other ways `hardware` says this vault can be unlocked, as a row of
/// text buttons; `None` when the passphrase is the only one.
pub fn unlock_switches<'a, M: Clone + 'static>(
    hardware: &[Factor],
    current: Option<Factor>,
    pick: impl Fn(Option<Factor>) -> M,
) -> Option<Element<'a, M>> {
    if hardware.is_empty() {
        return None;
    }
    let mut row = widget::row::with_capacity(hardware.len() + 1)
        .spacing(cosmic::theme::spacing().space_xs)
        .align_y(Alignment::Center);
    if current.is_some() {
        row = row.push(widget::button::text(fl!("unlock-with-passphrase")).on_press(pick(None)));
    }
    for &factor in hardware {
        if current == Some(factor) {
            continue;
        }
        let label = match factor {
            Factor::TpmPin => fl!("unlock-with-tpm"),
            Factor::SecurityKey => fl!("unlock-with-security-key"),
        };
        row = row.push(widget::button::text(label).on_press(pick(Some(factor))));
    }
    Some(row.into())
}

#[cfg(feature = "tpm")]
fn tpm_key(slots: &[locket_core::slots::Slot], pin: &str) -> Result<SymKey, String> {
    locket_tpm::Tpm::system()
        .and_then(|tpm| tpm.unlock_key(slots, Some(pin)))
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "tpm"))]
fn tpm_key(_slots: &[locket_core::slots::Slot], _pin: &str) -> Result<SymKey, String> {
    Err(fl!("error-no-tpm-support"))
}

#[cfg(feature = "fido")]
fn security_key_key(slots: &[locket_core::slots::Slot], pin: &str) -> Result<SymKey, String> {
    let pin = Some(pin).filter(|pin| !pin.is_empty());
    locket_fido::unlock_key(slots, pin).map_err(|e| e.to_string())
}

#[cfg(not(feature = "fido"))]
fn security_key_key(_slots: &[locket_core::slots::Slot], _pin: &str) -> Result<SymKey, String> {
    Err(fl!("error-no-fido-support"))
}

/// Human description of a slot, for the list.
pub fn describe(factor: &SlotFactor) -> String {
    match factor {
        SlotFactor::Passphrase { params, .. } => {
            let memory = params.m_cost / 1024;
            let passes = params.t_cost;
            fl!("slot-passphrase", memory = memory, passes = passes)
        }
        SlotFactor::Tpm2 {
            with_pin, parent, ..
        } => fl!(
            "slot-tpm",
            pin = if *with_pin {
                fl!("slot-tpm-with-pin")
            } else {
                String::new()
            },
            // Key-hierarchy names, not prose: the same two words in every
            // language, and the same two the TPM specification uses.
            parent = match parent {
                locket_core::slots::TpmParent::EccP256 => "P-256",
                locket_core::slots::TpmParent::Rsa2048 => "RSA-2048",
            }
        ),
        SlotFactor::Fido2 {
            user_verification, ..
        } => fl!(
            "slot-fido",
            verification = if *user_verification {
                fl!("slot-fido-uv")
            } else {
                fl!("slot-fido-presence")
            }
        ),
    }
}

/// The factors the page offers to add.
///
/// A TPM PIN, which the window, the unlock dialog and the command line can
/// all unlock with. Not a security key: unlocking with one is wired the same
/// way and tested against a token in software, but it has never been run
/// against a real key, and adding a factor is not the moment to find out.
/// A security-key slot enrolled by an earlier version is listed, unlocks,
/// and can be removed.
pub fn offered_factors() -> &'static [Factor] {
    &[Factor::TpmPin]
}

/// The PIN a TPM slot is sealed under, which is required.
///
/// Without one the chip releases the key to anything on this machine that
/// asks, and the dictionary-attack lockout the page describes never comes
/// into play.
pub fn tpm_pin(pin: &str) -> Result<&str, String> {
    if pin.is_empty() {
        return Err(fl!("error-tpm-pin-required"));
    }
    Ok(pin)
}

/// Enrol a TPM slot. Blocking: talks to the chip.
#[cfg(feature = "tpm")]
pub fn enroll_tpm(vault: &mut Vault, pin: &str) -> Result<Uuid, String> {
    let pin = tpm_pin(pin)?;
    locket_tpm::Tpm::system()
        .and_then(|tpm| tpm.enroll_into(vault, pin))
        .map_err(|e| match e {
            locket_tpm::Error::AlreadyEnrolled => fl!("error-tpm-already-enrolled"),
            e => e.to_string(),
        })
}

#[cfg(not(feature = "tpm"))]
pub fn enroll_tpm(_vault: &mut Vault, _pin: &str) -> Result<Uuid, String> {
    Err(fl!("error-no-tpm-support"))
}

/// Enrol a FIDO2 slot. Blocking: needs a touch.
#[cfg(feature = "fido")]
pub fn enroll_fido(vault: &mut Vault, pin: &str) -> Result<Uuid, String> {
    let pin = if pin.is_empty() { None } else { Some(pin) };
    let (factor, kek) = locket_fido::enroll(pin, pin.is_some()).map_err(|e| e.to_string())?;
    vault
        .add_slot("Security key", factor, &kek)
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "fido"))]
pub fn enroll_fido(_vault: &mut Vault, _pin: &str) -> Result<Uuid, String> {
    Err(fl!("error-no-fido-support"))
}

#[derive(Clone, Debug)]
pub enum Message {
    PinChanged(SecretString),
    Enroll(Factor),
    Remove(Uuid),
    Dismiss,
    CurrentPassphrase(SecretString),
    NewPassphrase(SecretString),
    ConfirmPassphrase(SecretString),
    KdfSelected(usize),
    ChangePassphrase,
}

/// The unlock-cost presets the passphrase form offers. Argon2id throughout;
/// the labels in the dropdown say what each costs.
pub const KDF_PRESETS: &[fn() -> locket_core::crypto::KdfParams] = &[
    // Balanced: the crate default (OWASP baseline).
    locket_core::crypto::KdfParams::default,
    // Stronger: 256 MiB, 4 passes.
    || locket_core::crypto::KdfParams {
        m_cost: 256 * 1024,
        t_cost: 4,
        p_cost: 4,
    },
    // Lighter: OWASP's low-memory profile, 19 MiB, 2 passes.
    || locket_core::crypto::KdfParams {
        m_cost: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    },
];

/// Dropdown labels, cached because the widget borrows them per frame.
pub static KDF_LABELS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| vec![fl!("kdf-balanced"), fl!("kdf-stronger"), fl!("kdf-lighter")]);

/// State for the security screen.
#[derive(Default)]
pub struct Security {
    pub pin: SecretString,
    pub busy: Option<Factor>,
    pub error: Option<String>,
    pub notice: Option<String>,
    // -- the passphrase form --
    pub current: SecretString,
    pub new1: SecretString,
    pub new2: SecretString,
    pub kdf_index: usize,
    pub changing: bool,
}

impl Security {
    /// Wipe the passphrase form, keeping the rest of the screen's state.
    pub fn clear_passphrase_form(&mut self) {
        self.current = SecretString::default();
        self.new1 = SecretString::default();
        self.new2 = SecretString::default();
    }
}

impl Security {
    pub fn view<'a>(&'a self, vault: Option<&'a Vault>) -> Element<'a, Message> {
        let spacing = cosmic::theme::spacing();
        let mut column = widget::column::with_capacity(12).spacing(spacing.space_s);

        column = column
            .push(widget::text::title3(fl!("security-title")))
            .push(widget::text::body(fl!("security-blurb")));

        // Errors and notices persist until dismissed: an enrolment failure is
        // worth reading, and a toast would be gone before a user looks up from
        // their security key.
        if let Some(text) = self.error.as_ref().or(self.notice.as_ref()) {
            let failed = self.error.is_some();
            let body = widget::text::body(text.clone());
            let body = if failed {
                body.class(cosmic::theme::Text::Color(
                    cosmic::theme::active().cosmic().destructive_color().into(),
                ))
            } else {
                body
            };
            column = column.push(
                widget::row::with_capacity(2)
                    .spacing(spacing.space_s)
                    .align_y(Alignment::Center)
                    .push(body.width(Length::Fill))
                    .push(
                        widget::button::standard(fl!("security-dismiss"))
                            .on_press(Message::Dismiss),
                    ),
            );
        }

        // -- existing slots -------------------------------------------------
        let Some(vault) = vault else {
            // The vault is moved into the worker while a factor is being
            // enrolled, so "locked" would be a lie during a touch prompt.
            let message = match self.busy {
                Some(Factor::TpmPin) => fl!("security-sealing"),
                Some(Factor::SecurityKey) => fl!("security-touch-key"),
                None => fl!("security-locked"),
            };
            return column.push(widget::text::body(message)).into();
        };

        let mut list = widget::list_column();
        for slot in vault.slots() {
            let last_passphrase = vault.is_last_passphrase(slot.id);
            let row = widget::row::with_capacity(3)
                .spacing(spacing.space_s)
                .align_y(Alignment::Center)
                .push(
                    widget::column::with_capacity(2)
                        .push(widget::text::body(slot.label.clone()))
                        .push(widget::text::caption(describe(&slot.factor)))
                        .width(Length::Fill),
                )
                .push(if last_passphrase {
                    // Explain the greyed-out button rather than just disabling it.
                    Element::from(widget::text::caption(fl!("security-required")))
                } else {
                    Element::from(
                        widget::button::destructive(fl!("security-remove"))
                            .on_press(Message::Remove(slot.id)),
                    )
                });
            list = list.add(row);
        }
        column = column.push(list);

        // -- add a factor ---------------------------------------------------
        column = column
            .push(widget::divider::horizontal::default())
            .push(widget::text::caption_heading(fl!("security-add-heading")));

        {
            column = column.push(
                widget::text_input::secure_input(
                    fl!("security-pin-placeholder"),
                    self.pin.expose(),
                    None,
                    true,
                )
                .on_input(|v| Message::PinChanged(v.into())),
            );

            let mut buttons = widget::row::with_capacity(2).spacing(spacing.space_xs);
            for &factor in offered_factors() {
                let busy = self.busy == Some(factor);
                let label = if busy {
                    match factor {
                        Factor::TpmPin => fl!("security-sealing-short"),
                        Factor::SecurityKey => fl!("security-touch-short"),
                    }
                } else {
                    fl!("security-add-factor", factor = factor.label())
                };
                let button = widget::button::standard(label);
                buttons = buttons.push(if busy || !factor.compiled_in() {
                    Element::from(button)
                } else {
                    Element::from(button.on_press(Message::Enroll(factor)))
                });
            }
            column = column.push(buttons);

            if !Factor::TpmPin.compiled_in() || !Factor::SecurityKey.compiled_in() {
                column = column.push(widget::text::caption(fl!("security-build-missing")));
            }

            // The honest caveat, where someone choosing a PIN will read it.
            column = column.push(widget::text::caption(fl!("security-tpm-caveat")));
            if !offered_factors().contains(&Factor::SecurityKey) {
                column = column.push(
                    widget::text::caption(fl!("security-key-unavailable"))
                        .wrapping(cosmic::iced::core::text::Wrapping::WordOrGlyph),
                );
            }
        }

        // -- change the passphrase -------------------------------------------
        column = column
            .push(widget::divider::horizontal::default())
            .push(widget::text::caption_heading(fl!(
                "security-passphrase-heading"
            )))
            .push(widget::text::caption(fl!("security-passphrase-blurb")))
            .push(
                // The current passphrase is required even though the vault is
                // open: an unlocked window must not be enough to lock its
                // owner out by rotating the passphrase under them.
                widget::text_input::secure_input(
                    fl!("security-current-passphrase"),
                    self.current.expose(),
                    None,
                    true,
                )
                .on_input(|v| Message::CurrentPassphrase(v.into())),
            )
            .push(
                widget::text_input::secure_input(
                    fl!("security-new-passphrase"),
                    self.new1.expose(),
                    None,
                    true,
                )
                .on_input(|v| Message::NewPassphrase(v.into())),
            )
            .push(
                widget::text_input::secure_input(
                    fl!("security-confirm-passphrase"),
                    self.new2.expose(),
                    None,
                    true,
                )
                .on_input(|v| Message::ConfirmPassphrase(v.into())),
            )
            .push(widget::text::caption_heading(fl!("security-kdf-cost")))
            .push(widget::dropdown(
                KDF_LABELS.as_slice(),
                Some(self.kdf_index),
                Message::KdfSelected,
            ));

        let change = widget::button::suggested(if self.changing {
            fl!("security-changing-passphrase")
        } else {
            fl!("security-change-passphrase")
        });
        column = column.push(if self.changing {
            Element::from(change)
        } else {
            Element::from(change.on_press(Message::ChangePassphrase))
        });

        widget::scrollable(widget::container(column).padding(spacing.space_s))
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::crypto::KdfParams;

    fn vault(dir: &tempfile::TempDir) -> Vault {
        Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap()
    }

    /// The page asks the vault which slot is the last passphrase; with a
    /// second passphrase slot, neither is.
    #[test]
    fn a_second_passphrase_makes_the_first_removable() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let first = v.slots()[0].id;
        assert!(v.is_last_passphrase(first));
        v.add_slot(
            "Recovery phrase",
            SlotFactor::Passphrase {
                params: KdfParams::insecure_fast(),
                salt: locket_core::slots::base64_encode(&[9u8; 32]),
            },
            &SymKey::random().unwrap(),
        )
        .unwrap();
        assert!(!v.is_last_passphrase(first));
    }

    /// Fluent wraps every interpolated value in bidi isolation marks
    /// (U+2068 … U+2069) so a number keeps its direction inside an RTL
    /// sentence. They are invisible on screen; they are not invisible to
    /// `contains`.
    fn without_isolates(s: &str) -> String {
        s.chars()
            .filter(|c| !matches!(c, '\u{2068}' | '\u{2069}'))
            .collect()
    }

    #[test]
    fn descriptions_say_what_the_factor_actually_is() {
        let pass = without_isolates(&describe(&SlotFactor::Passphrase {
            params: KdfParams::default(),
            salt: String::new(),
        }));
        assert!(
            pass.contains("Argon2id") && pass.contains("64 MiB"),
            "{pass}"
        );

        let tpm = without_isolates(&describe(&SlotFactor::Tpm2 {
            sealed: String::new(),
            parent: locket_core::slots::TpmParent::EccP256,
            pcrs: vec![],
            with_pin: true,
        }));
        assert!(tpm.contains("PIN") && tpm.contains("P-256"), "{tpm}");

        let fido = without_isolates(&describe(&SlotFactor::Fido2 {
            credential_id: String::new(),
            salt: String::new(),
            rp_id: "locket.local".into(),
            user_verification: false,
        }));
        assert!(fido.contains("presence only"), "{fido}");
    }

    /// A TPM factor can be added now that it unlocks. A security key
    /// cannot: unlocking with one has only ever met a token in software.
    #[test]
    fn only_a_factor_whose_unlock_has_met_a_device_is_offered() {
        assert_eq!(offered_factors(), [Factor::TpmPin]);
    }

    /// The unlock screen offers a hardware factor because the vault file
    /// says it has one — read without unlocking anything.
    #[test]
    fn the_factors_a_vault_can_be_unlocked_with_come_from_its_header() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let path = v.path().to_owned();
        assert!(enrolled(&path).is_empty());
        assert!(enrolled(&dir.path().join("absent.vault")).is_empty());

        v.add_slot(
            "TPM 2.0 (PIN)",
            SlotFactor::Tpm2 {
                sealed: "AAAA".into(),
                parent: Default::default(),
                pcrs: vec![],
                with_pin: true,
            },
            &SymKey::random().unwrap(),
        )
        .unwrap();
        v.add_slot(
            "Security key",
            SlotFactor::Fido2 {
                credential_id: "AAAA".into(),
                salt: locket_core::slots::base64_encode(&[0u8; 32]),
                rp_id: "locket.local".into(),
                user_verification: false,
            },
            &SymKey::random().unwrap(),
        )
        .unwrap();
        drop(v);

        let expected: Vec<Factor> = [Factor::TpmPin, Factor::SecurityKey]
            .into_iter()
            .filter(|factor| factor.compiled_in())
            .collect();
        assert_eq!(enrolled(&path), expected);
    }

    /// A TPM slot with no PIN releases its key to anything on the machine
    /// that asks, and the chip's lockout — the page's stated safeguard —
    /// never applies.
    #[test]
    fn an_empty_tpm_pin_is_refused() {
        assert!(tpm_pin("").is_err());
        assert_eq!(tpm_pin("2468"), Ok("2468"));
    }

    #[test]
    fn a_build_without_a_factor_reports_it_rather_than_offering_it() {
        // Whatever this build enabled, the flag must match the cfg.
        assert_eq!(Factor::TpmPin.compiled_in(), cfg!(feature = "tpm"));
        assert_eq!(Factor::SecurityKey.compiled_in(), cfg!(feature = "fido"));
    }
}
