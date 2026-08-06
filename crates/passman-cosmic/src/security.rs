//! Enrolling and removing unlock factors.
//!
//! Until now a TPM PIN or a security key could only be added from code, which
//! made the hardware work unreachable for anyone actually using passman. This
//! is the screen that fixes that.
//!
//! Two rules are enforced here rather than left to the user's judgement:
//!
//! * **The passphrase always stays.** Hardware factors are additive. A dead
//!   motherboard or a lost token must not be a lost vault, so a passphrase
//!   slot can never be the one you remove.
//! * **Enrolment is never silent about what it costs.** A TPM PIN is only as
//!   good as the chip's dictionary-attack lockout, and that lockout is
//!   device-wide — the screen says so, because someone choosing a 4-digit PIN
//!   deserves to know what is holding it up.

use cosmic::iced::{Alignment, Length};
use cosmic::prelude::*;
use cosmic::widget;
use passman_core::{Vault, slots::SlotFactor};
use uuid::Uuid;

/// A factor the user can add, and whether this build can add it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    TpmPin,
    SecurityKey,
}

impl Factor {
    pub const fn label(self) -> &'static str {
        match self {
            Factor::TpmPin => "TPM PIN",
            Factor::SecurityKey => "Security key",
        }
    }

    /// Whether this build was compiled with support for it.
    pub const fn compiled_in(self) -> bool {
        match self {
            Factor::TpmPin => cfg!(feature = "tpm"),
            Factor::SecurityKey => cfg!(feature = "fido"),
        }
    }
}

/// Human description of a slot, for the list.
pub fn describe(factor: &SlotFactor) -> String {
    match factor {
        SlotFactor::Passphrase { params, .. } => format!(
            "Argon2id · {} MiB · {} passes",
            params.m_cost / 1024,
            params.t_cost
        ),
        SlotFactor::Tpm2 {
            with_pin, parent, ..
        } => format!(
            "Sealed to this machine's TPM{} · {}",
            if *with_pin { ", released by PIN" } else { "" },
            match parent {
                passman_core::slots::TpmParent::EccP256 => "P-256",
                passman_core::slots::TpmParent::Rsa2048 => "RSA-2048",
            }
        ),
        SlotFactor::Fido2 {
            user_verification, ..
        } => format!(
            "Hardware token{}",
            if *user_verification {
                ", with user verification"
            } else {
                ", presence only"
            }
        ),
    }
}

/// Whether removing this slot would leave the vault without a passphrase.
///
/// Losing every passphrase slot means the vault can only ever be opened by a
/// device that might break, which is not a state a user should be able to
/// reach by clicking a button.
pub fn is_last_passphrase(vault: &Vault, slot_id: Uuid) -> bool {
    let passphrase_slots: Vec<_> = vault
        .slots()
        .iter()
        .filter(|s| matches!(s.factor, SlotFactor::Passphrase { .. }))
        .collect();
    passphrase_slots.len() == 1 && passphrase_slots[0].id == slot_id
}

/// Enrol a TPM slot. Blocking: talks to the chip.
#[cfg(feature = "tpm")]
pub fn enroll_tpm(vault: &mut Vault, pin: &str) -> Result<Uuid, String> {
    let pin = if pin.is_empty() { None } else { Some(pin) };
    let (factor, kek) = passman_tpm::enroll(pin).map_err(|e| e.to_string())?;
    let label = if pin.is_some() {
        "TPM 2.0 (PIN)"
    } else {
        "TPM 2.0"
    };
    vault
        .add_slot(label, factor, &kek)
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "tpm"))]
pub fn enroll_tpm(_vault: &mut Vault, _pin: &str) -> Result<Uuid, String> {
    Err("this build has no TPM support".into())
}

/// Enrol a FIDO2 slot. Blocking: needs a touch.
#[cfg(feature = "fido")]
pub fn enroll_fido(vault: &mut Vault, pin: &str) -> Result<Uuid, String> {
    let pin = if pin.is_empty() { None } else { Some(pin) };
    let (factor, kek) = passman_fido::enroll(pin, pin.is_some()).map_err(|e| e.to_string())?;
    vault
        .add_slot("Security key", factor, &kek)
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "fido"))]
pub fn enroll_fido(_vault: &mut Vault, _pin: &str) -> Result<Uuid, String> {
    Err("this build has no security-key support".into())
}

#[derive(Clone, Debug)]
pub enum Message {
    PinChanged(String),
    Enroll(Factor),
    Remove(Uuid),
    Dismiss,
}

/// State for the security screen.
#[derive(Default)]
pub struct Security {
    pub pin: String,
    pub busy: Option<Factor>,
    pub error: Option<String>,
    pub notice: Option<String>,
}

impl Security {
    pub fn view<'a>(&'a self, vault: Option<&'a Vault>) -> Element<'a, Message> {
        let spacing = cosmic::theme::spacing();
        let mut column = widget::column::with_capacity(12).spacing(spacing.space_s);

        column = column
            .push(widget::text::title3("Unlock factors"))
            .push(widget::text::body(
                "Any one of these opens the vault. Hardware factors are added \
                 alongside your passphrase, never instead of it — so losing a \
                 device does not lose the vault.",
            ));

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
                    .push(widget::button::standard("Dismiss").on_press(Message::Dismiss)),
            );
        }

        // -- existing slots -------------------------------------------------
        let Some(vault) = vault else {
            // The vault is moved into the worker while a factor is being
            // enrolled, so "locked" would be a lie during a touch prompt.
            let message = match self.busy {
                Some(Factor::TpmPin) => "Sealing a key to the TPM…",
                Some(Factor::SecurityKey) => "Waiting for you to touch your security key…",
                None => "Unlock the vault to manage factors.",
            };
            return column.push(widget::text::body(message)).into();
        };

        let mut list = widget::list_column();
        for slot in vault.slots() {
            let last_passphrase = is_last_passphrase(vault, slot.id);
            let row = widget::row::with_capacity(3)
                .spacing(spacing.space_s)
                .align_y(Alignment::Center)
                .push(
                    widget::column::with_capacity(2)
                        .push(widget::text::body(slot.label.clone()))
                        .push(widget::text::caption(describe(&slot.factor)))
                        .width(Length::Fill),
                )
                .push(if last_passphrase || vault.slots().len() == 1 {
                    // Explain the greyed-out button rather than just disabling it.
                    Element::from(widget::text::caption("Required"))
                } else {
                    Element::from(
                        widget::button::destructive("Remove").on_press(Message::Remove(slot.id)),
                    )
                });
            list = list.add(row);
        }
        column = column.push(list);

        // -- add a factor ---------------------------------------------------
        column = column
            .push(widget::divider::horizontal::default())
            .push(widget::text::caption_heading("Add a factor"));

        column = column.push(
            widget::text_input::secure_input("PIN (optional)", &self.pin, None, true)
                .on_input(Message::PinChanged),
        );

        let mut buttons = widget::row::with_capacity(2).spacing(spacing.space_xs);
        for factor in [Factor::TpmPin, Factor::SecurityKey] {
            let busy = self.busy == Some(factor);
            let label = if busy {
                match factor {
                    Factor::TpmPin => "Sealing…".to_owned(),
                    Factor::SecurityKey => "Touch your key…".to_owned(),
                }
            } else {
                format!("Add {}", factor.label())
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
            column = column.push(widget::text::caption(
                "Some factors are unavailable because this build was compiled \
                 without support for them.",
            ));
        }

        // The honest caveat, where someone choosing a PIN will read it.
        column = column.push(widget::text::caption(
            "A TPM PIN is protected by the chip's lockout, not by its length — \
             which is what makes a short PIN safe. That lockout is device-wide: \
             repeated wrong PINs can lock out anything else using the TPM, \
             including disk unlock, until it recovers.",
        ));

        widget::scrollable(widget::container(column).padding(spacing.space_s))
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passman_core::crypto::{KdfParams, SymKey};

    fn vault(dir: &tempfile::TempDir) -> Vault {
        Vault::create(dir.path().join("v.vault"), "pw", KdfParams::insecure_fast()).unwrap()
    }

    #[test]
    fn the_only_passphrase_is_flagged_as_unremovable() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let only = v.slots()[0].id;
        assert!(is_last_passphrase(&v, only));
    }

    #[test]
    fn a_hardware_slot_does_not_make_the_passphrase_removable() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let passphrase_slot = v.slots()[0].id;

        v.add_slot(
            "TPM 2.0",
            SlotFactor::Tpm2 {
                sealed: "AAAA".into(),
                parent: Default::default(),
                pcrs: vec![],
                with_pin: true,
            },
            &SymKey::random().unwrap(),
        )
        .unwrap();

        // Two slots now, but removing the passphrase would leave only hardware.
        assert!(
            is_last_passphrase(&v, passphrase_slot),
            "the last passphrase became removable once hardware was added"
        );
        // The hardware slot itself is fair game.
        let tpm_slot = v.slots()[1].id;
        assert!(!is_last_passphrase(&v, tpm_slot));
    }

    #[test]
    fn a_second_passphrase_makes_the_first_removable() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let first = v.slots()[0].id;
        // change_passphrase replaces rather than adds, so build the situation
        // directly: two passphrase slots means neither is the last one.
        v.add_slot(
            "Recovery phrase",
            SlotFactor::Passphrase {
                params: KdfParams::insecure_fast(),
                salt: passman_core::slots::base64_encode(&[9u8; 32]),
            },
            &SymKey::random().unwrap(),
        )
        .unwrap();
        assert!(!is_last_passphrase(&v, first));
    }

    #[test]
    fn descriptions_say_what_the_factor_actually_is() {
        let pass = describe(&SlotFactor::Passphrase {
            params: KdfParams::default(),
            salt: String::new(),
        });
        assert!(pass.contains("Argon2id") && pass.contains("64 MiB"));

        let tpm = describe(&SlotFactor::Tpm2 {
            sealed: String::new(),
            parent: passman_core::slots::TpmParent::EccP256,
            pcrs: vec![],
            with_pin: true,
        });
        assert!(tpm.contains("PIN") && tpm.contains("P-256"));

        let fido = describe(&SlotFactor::Fido2 {
            credential_id: String::new(),
            salt: String::new(),
            rp_id: "passman.local".into(),
            user_verification: false,
        });
        assert!(fido.contains("presence only"));
    }

    #[test]
    fn a_build_without_a_factor_reports_it_rather_than_offering_it() {
        // Whatever this build enabled, the flag must match the cfg.
        assert_eq!(Factor::TpmPin.compiled_in(), cfg!(feature = "tpm"));
        assert_eq!(Factor::SecurityKey.compiled_in(), cfg!(feature = "fido"));
    }
}
