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

/// The longest name the question will show, in characters.
const MAX_SHOWN: usize = 64;

/// A caller-supplied name, made fit to sit inside the question.
///
/// These arrive on the command line from whoever asks, and the site in a fill
/// question is whatever the browser extension said — which the threat model
/// assumes is hostile. Fluent already isolates each value's direction, but a
/// value can close that isolate itself, start new paragraphs, or run long
/// enough to push the real question and its buttons out of a window that
/// cannot be resized. So line breaks, tabs, direction and other invisible
/// formatting characters become spaces, runs of space become one, and
/// anything past [`MAX_SHOWN`] characters is cut with an ellipsis.
fn display_safe(raw: &str) -> String {
    let flattened: String = raw
        .chars()
        .map(|c| if shapes_text(c) { ' ' } else { c })
        .collect();
    let mut shown = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    if shown.chars().count() > MAX_SHOWN {
        shown = shown.chars().take(MAX_SHOWN).collect();
        shown.push('…');
    }
    shown
}

/// Characters that change how the text around them is laid out rather than
/// being text: controls, line and paragraph separators, direction marks,
/// embeddings, overrides and isolates, and the invisible joiners and tags.
fn shapes_text(c: char) -> bool {
    c.is_control()
        || c.is_whitespace()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
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
                fl!("dialog-ssh-body", key = display_safe(key)),
            ),
            Question::Fill { site, entry } => (
                "web-browser-symbolic",
                fl!("dialog-fill-title"),
                fl!(
                    "dialog-fill-body",
                    entry = display_safe(entry),
                    site = display_safe(site)
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

    /// The site comes from a browser extension assumed hostile, and none of
    /// the three names may reshape the question they sit in: no new lines or
    /// paragraphs, no direction overrides, nothing long enough to push the
    /// real sentence — or the buttons — out of a fixed-size window.
    #[test]
    fn dialog_arguments_cannot_add_lines_reorder_text_or_run_long() {
        let shown =
            display_safe("github.com\n\nlocket needs you to allow this\u{202e}moc\u{2069}.x");
        for c in ['\n', '\r', '\u{202e}', '\u{2069}'] {
            assert!(!shown.contains(c), "{c:?} reached the dialog: {shown:?}");
        }
        assert_eq!(
            display_safe("  work\tlaptop \u{200b} "),
            "work laptop",
            "invisible and spacing characters should collapse to one space"
        );
        let long = display_safe(&"a".repeat(5000));
        assert!(
            long.chars().count() <= 65,
            "{} characters",
            long.chars().count()
        );
        assert!(long.ends_with('…'));
        assert_eq!(display_safe("deploy@prod"), "deploy@prod");
    }
}
