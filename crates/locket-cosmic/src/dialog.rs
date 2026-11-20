//! The layout locket's two small windows share: the unlock dialog an
//! application's request raises, and the one-use confirmation.
//!
//! Both are whole windows that ask one question, so they are laid out like
//! libcosmic's `widget::dialog` — icon, title, body, controls, a row of
//! answers — but drawn straight onto the window rather than as a bordered,
//! shadowed card inside it. `widget::dialog` always draws that card; it is
//! made to float over an application, and inside a window of its own it
//! reads as a dialog boxed inside a dialog.
//!
//! The window's height follows its content. A fixed size cannot be right:
//! the interface density setting scales every padding, spacing and button
//! (Spacious is half as large again as Standard), and an error caption, the
//! hardware-factor row or a wordier language each add height. A window sized
//! for one of those clipped the buttons off the bottom in the others.
//! libcosmic's `autosize` container asks the compositor for exactly the
//! size the content lays out to, every time it changes.

use std::sync::LazyLock;

use cosmic::iced::{Length, Limits};
use cosmic::prelude::*;
use cosmic::widget;

/// The window's width, at every density: wide enough for a title to sit on
/// one line in English and the three answers of the unlock dialog to fit.
/// Only the height follows the content — a width that did too would leave
/// nothing for the body text to wrap against.
pub const WIDTH: f32 = 520.0;

/// The size the window opens at, before its content has been laid out once
/// and the first resize has asked for the real height.
pub const INITIAL_SIZE: cosmic::iced::Size = cosmic::iced::Size::new(WIDTH, 300.0);

static AUTOSIZE_ID: LazyLock<widget::Id> =
    LazyLock::new(|| widget::Id::new("locket-dialog-autosize"));

/// One question in a window of its own, under `header`.
///
/// `actions` are the secondary and primary answers, drawn at the right;
/// `tertiary` sits alone at the left, as a way out rather than an answer.
pub fn window<'a, Message: Clone + 'static>(
    header: widget::HeaderBar<'a, Message>,
    icon: &'static str,
    title: String,
    body: String,
    control: Option<Element<'a, Message>>,
    tertiary: Option<Element<'a, Message>>,
    actions: [Element<'a, Message>; 2],
) -> Element<'a, Message> {
    let spacing = cosmic::theme::spacing();

    let mut text = widget::column::with_capacity(4)
        .push(widget::text::title3(title))
        .push(widget::space::vertical().height(Length::Fixed(spacing.space_xxs.into())))
        .push(widget::text::body(body));
    if let Some(control) = control {
        text = text
            .push(widget::space::vertical().height(Length::Fixed(spacing.space_s.into())))
            .push(control);
    }

    let [secondary, primary] = actions;
    let buttons = widget::row::with_capacity(4)
        .spacing(spacing.space_xxs)
        .push_maybe(tertiary)
        .push(widget::space::horizontal())
        .push(secondary)
        .push(primary);

    let content = widget::column::with_capacity(2)
        .spacing(spacing.space_l)
        .padding(spacing.space_m)
        .push(
            widget::row::with_capacity(2)
                .spacing(spacing.space_s)
                .push(widget::icon::from_name(icon).size(48))
                .push(text),
        )
        .push(buttons);

    // Shrink, not Fill, in height all the way down: the autosize container
    // lays its content out without the window's limits, so a Fill height
    // here would ask for an unbounded window.
    let window = widget::column::with_capacity(2)
        .push(header)
        .push(content)
        .width(Length::Fill)
        .apply(widget::container)
        .class(cosmic::theme::Container::WindowBackground);

    widget::autosize::autosize(window, AUTOSIZE_ID.clone())
        .limits(Limits::NONE.min_width(WIDTH).max_width(WIDTH))
        .into()
}
