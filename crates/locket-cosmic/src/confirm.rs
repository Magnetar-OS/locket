//! The dialog that allows one use of one secret.
//!
//! Started by whatever needs the yes — `locketd` for an SSH signature with a
//! `confirm-each-use` key, `locket-native-host` for a password the browser
//! extension wants to fill — as `locket --confirm-signing <key>` or
//! `locket --confirm-fill <site> <entry>`. It is its own process, never a
//! hand-off to a running window, and it answers on standard output: the line
//! [`locket_secret::frontend::ALLOW`] and a clean exit, or nothing. The asking
//! process holds the other end of that pipe and nobody else does, which is the
//! whole point — see [`locket_secret::frontend`] for the attack a bus-borne
//! answer allowed.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cosmic::app::{Core, Task};
use cosmic::iced::Length;
use cosmic::prelude::*;
use cosmic::widget;
use locket_secret::frontend::{CONFIRM_FILL_FLAG, CONFIRM_SIGNING_FLAG, Question};

use crate::fl;

/// The window's size: one question and two answers.
pub const SIZE: cosmic::iced::Size = cosmic::iced::Size::new(460.0, 300.0);

/// The question this process was started to ask, if it was.
///
/// `Err` is a confirmation flag with the wrong number of arguments: that start
/// must still end in a refusal, not fall through to the full application.
pub fn question_from_args(args: &[String]) -> Option<Result<Question, String>> {
    let (flag, rest) = args.split_first()?;
    match flag.as_str() {
        CONFIRM_SIGNING_FLAG => Some(match rest {
            [key] => Ok(Question::Signing { key: key.clone() }),
            _ => Err(format!("{CONFIRM_SIGNING_FLAG} takes one key name")),
        }),
        CONFIRM_FILL_FLAG => Some(match rest {
            [site, entry] => Ok(Question::Fill {
                site: site.clone(),
                entry: entry.clone(),
            }),
            _ => Err(format!("{CONFIRM_FILL_FLAG} takes a site and an entry")),
        }),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    Allow,
    Refuse,
}

/// What the dialog needs: the question, and where to put a yes.
#[derive(Clone)]
pub struct Flags {
    pub question: Question,
    pub allowed: Arc<AtomicBool>,
}

pub struct Confirm {
    core: Core,
    question: Question,
    allowed: Arc<AtomicBool>,
}

impl cosmic::Application for Confirm {
    type Executor = cosmic::executor::Default;
    type Flags = Flags;
    type Message = Message;

    const APP_ID: &'static str = "com.magnetaros.Locket";

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(mut core: Core, flags: Self::Flags) -> (Self, Task<Self::Message>) {
        core.window.show_maximize = false;
        core.window.show_minimize = false;
        let mut dialog = Confirm {
            core,
            question: flags.question,
            allowed: flags.allowed,
        };
        dialog.set_header_title(fl!("app-title"));
        let title = match dialog.core.main_window_id() {
            Some(id) => dialog.set_window_title(fl!("app-title"), id),
            None => Task::none(),
        };
        (dialog, title)
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        if let Message::Allow = message {
            self.allowed.store(true, Ordering::SeqCst);
        }
        cosmic::iced::exit()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let (icon, title, body) = match &self.question {
            Question::Signing { key } => (
                "dialog-password-symbolic",
                fl!("dialog-ssh-title"),
                fl!("dialog-ssh-body", key = key.clone()),
            ),
            Question::Fill { site, entry } => (
                "web-browser-symbolic",
                fl!("dialog-fill-title"),
                fl!(
                    "dialog-fill-body",
                    entry = entry.clone(),
                    site = site.clone()
                ),
            ),
        };
        widget::dialog()
            .icon(widget::icon::from_name(icon).size(48))
            .title(title)
            .body(body)
            .primary_action(
                widget::button::suggested(fl!("dialog-allow-once")).on_press(Message::Allow),
            )
            .secondary_action(
                widget::button::standard(fl!("dialog-refuse")).on_press(Message::Refuse),
            )
            // Not floating over an application window — this *is* the window.
            .is_overlay(false)
            .width(Length::Fill)
            .apply(widget::container)
            .class(cosmic::theme::Container::WindowBackground)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_confirmation_flags_carry_their_question() {
        assert_eq!(
            question_from_args(&args(&["--confirm-signing", "work"])),
            Some(Ok(Question::Signing { key: "work".into() }))
        );
        assert_eq!(
            question_from_args(&args(&["--confirm-fill", "github.com", "GitHub"])),
            Some(Ok(Question::Fill {
                site: "github.com".into(),
                entry: "GitHub".into()
            }))
        );
    }

    /// A malformed confirmation start is still a confirmation start: it must
    /// be refused, not treated as "open locket".
    #[test]
    fn a_malformed_confirmation_is_not_an_ordinary_start() {
        assert!(matches!(
            question_from_args(&args(&["--confirm-signing"])),
            Some(Err(_))
        ));
        assert!(matches!(
            question_from_args(&args(&["--confirm-fill", "github.com"])),
            Some(Err(_))
        ));
        assert_eq!(question_from_args(&args(&["--prompt"])), None);
        assert_eq!(question_from_args(&[]), None);
    }
}
