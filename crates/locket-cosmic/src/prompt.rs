//! The dialog an application's unlock request raises.
//!
//! When a `libsecret` client asks for a secret from a locked vault the daemon
//! emits `UnlockRequested`, and something has to ask for the passphrase. Doing
//! that in the main window means an application's request throws a
//! 1100-by-760 password manager onto the screen — and, because the unlock
//! screen *is* the whole window, it also meant locking whatever the person was
//! already looking at to make room for it.
//!
//! So the request gets a window the size of the question: one passphrase
//! field, and a way out to the full application for anyone who wanted that
//! instead. macOS asks the same way, for the same reason — the request came
//! from another application, and answering it is not a reason to leave the one
//! you were using.

use std::sync::{Arc, LazyLock, Mutex};

use cosmic::iced::{Length, window};
use cosmic::prelude::*;
use cosmic::widget;
use locket_core::{SecretString, Vault};

use crate::fl;
use crate::security::{self, Factor};

/// The dialog's size.
///
/// Fixed, and generous enough for the body text to wrap in a language wordier
/// than English: it holds one field and three buttons, and a resize handle on
/// that is a control nobody reaches for.
pub const SIZE: cosmic::iced::Size = cosmic::iced::Size::new(460.0, 330.0);

/// The dialog's size for a vault with these hardware factors: taller by the
/// row that offers them and the longer text that explains one.
pub fn size(hardware: &[Factor]) -> cosmic::iced::Size {
    if hardware.is_empty() {
        SIZE
    } else {
        cosmic::iced::Size::new(SIZE.width, SIZE.height + 70.0)
    }
}

/// The passphrase field, so the dialog can take the caret as it appears.
pub static PASSPHRASE_ID: LazyLock<widget::Id> =
    LazyLock::new(|| widget::Id::new("locket-prompt-passphrase"));

#[derive(Clone, Debug)]
pub enum Message {
    PassphraseChanged(SecretString),
    ToggleShow,
    /// Answer with a hardware factor instead of the passphrase, or go back.
    UnlockWith(Option<Factor>),
    Submit,
    /// The TPM or the security key did not release a key; carries why.
    Refused(String),
    /// The daemon answered: `true` when the passphrase opened the vault. When
    /// the window behind was locked too, its own vault comes back in the slot
    /// — shared because `Vault` is deliberately not `Clone` and messages must
    /// be.
    Answered(bool, Arc<Mutex<Option<Vault>>>),
    /// Take the caret, which only lands once the window has a widget tree.
    Focus,
    /// Show the whole application instead.
    OpenWindow,
    /// Dismissed without an answer: the daemon is told, and the request that
    /// raised the dialog is refused — its `Prompt` completes dismissed.
    Dismiss,
    /// The window went away — the compositor closed it, or something else did.
    Closed,
    /// The header bar was dragged.
    Drag,
}

/// A live unlock request, and the window showing it.
pub struct Prompt {
    /// The window it lives in.
    pub window: window::Id,
    /// The hardware factors the vault can be unlocked with.
    pub hardware: Vec<Factor>,
    /// The one being used; `None` is the passphrase.
    pub unlock_with: Option<Factor>,
    /// What was typed: the passphrase, or the PIN of the factor above.
    pub passphrase: SecretString,
    pub show_passphrase: bool,
    /// Set while the passphrase is with the daemon. Argon2id is deliberately
    /// slow, so the button has to say that something is happening.
    pub busy: bool,
    pub error: Option<String>,
}

impl Prompt {
    pub fn new(window: window::Id, hardware: Vec<Factor>) -> Self {
        Self {
            window,
            hardware,
            unlock_with: None,
            passphrase: SecretString::default(),
            show_passphrase: false,
            busy: false,
            error: None,
        }
    }

    /// Take the passphrase out on the way to the daemon.
    ///
    /// Moved rather than copied: the field is cleared by the same call that
    /// hands it over, so nothing is left in the dialog's state afterwards, and
    /// the value wipes itself when the last holder drops it.
    pub fn take_passphrase(&mut self) -> SecretString {
        std::mem::take(&mut self.passphrase)
    }

    /// `focused` draws the header bar the way the compositor sees the window;
    /// an active-looking title bar on an unfocused window is a small lie that
    /// makes it hard to tell which window the keyboard is talking to.
    pub fn view(&self, focused: bool) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();

        let mut field = widget::column::with_capacity(2)
            .spacing(spacing.space_xxs)
            .push(
                widget::text_input::secure_input(
                    security::unlock_placeholder(self.unlock_with),
                    self.passphrase.expose(),
                    Some(Message::ToggleShow),
                    !self.show_passphrase,
                )
                .id(PASSPHRASE_ID.clone())
                .on_input(|v| Message::PassphraseChanged(v.into()))
                .on_submit(|_| Message::Submit),
            );
        if let Some(error) = &self.error {
            field = field.push(widget::text::caption(error.clone()).class(
                cosmic::theme::Text::Color(
                    cosmic::theme::active().cosmic().destructive_color().into(),
                ),
            ));
        }

        if let Some(switches) =
            security::unlock_switches(&self.hardware, self.unlock_with, Message::UnlockWith)
        {
            field = field.push(switches);
        }

        let unlock = widget::button::suggested(match (self.busy, self.unlock_with) {
            (true, Some(Factor::SecurityKey)) => fl!("unlock-touch-key"),
            (true, _) => fl!("unlock-working"),
            (false, _) => fl!("unlock-button"),
        });

        let dialog = widget::dialog()
            .icon(widget::icon::from_name("dialog-password-symbolic").size(48))
            .title(fl!("prompt-title"))
            .body(match self.unlock_with {
                None => fl!("prompt-body"),
                Some(Factor::TpmPin) => fl!("prompt-body-tpm"),
                Some(Factor::SecurityKey) => fl!("prompt-body-security-key"),
            })
            .control(field)
            // Leftmost, away from the two answers: it is a way out of the
            // dialog, not a third thing to do with the passphrase.
            .tertiary_action(
                widget::button::text(fl!("prompt-open-window")).on_press(Message::OpenWindow),
            )
            .secondary_action(
                widget::button::standard(fl!("dialog-cancel")).on_press(Message::Dismiss),
            )
            .primary_action(if self.busy {
                Element::from(unlock)
            } else {
                unlock.on_press(Message::Submit).into()
            })
            // Not floating over an application window — this *is* the window.
            .is_overlay(false)
            .width(Length::Fill);

        widget::column::with_capacity(2)
            .push(
                widget::header_bar()
                    .title(fl!("app-title"))
                    .focused(focused)
                    .on_close(Message::Dismiss)
                    .on_drag(Message::Drag),
            )
            .push(dialog)
            .apply(widget::container)
            .class(cosmic::theme::Container::WindowBackground)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
