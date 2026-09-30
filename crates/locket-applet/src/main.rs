//! COSMIC panel applet for locket.
//!
//! Shows whether the vault is locked and lets you lock it in one click. That
//! asymmetry is deliberate: **locking** happens here, **unlocking** opens the
//! main window instead.
//!
//! A panel popup is a poor place to type a master passphrase. It is a small
//! surface with no window decoration, no title, and nothing tying it to the
//! application that owns it — precisely the shape a spoofed prompt would take,
//! and users are trained to type into whatever appears near the panel. Locking
//! is safe to expose because a spoofed "lock" button costs nothing.

#![forbid(unsafe_code)]

mod i18n;

use cosmic::app::{Core, Task};
use cosmic::applet::token::subscription::{
    TokenRequest, TokenUpdate, activation_token_subscription,
};
use cosmic::cctk::sctk::reexports::calloop;
use cosmic::iced::window::Id;
use cosmic::iced::{Length, Rectangle, Subscription};
use cosmic::surface::action::{app_popup, destroy_popup};
use cosmic::widget;
use cosmic::{Element, iced::window};
use locket_secret::client::Status;

const ID: &str = "com.magnetaros.LocketApplet";

/// The main window's binary, as the desktop entry spells it.
const APP_EXEC: &str = "locket";

/// How often the panel icon re-checks the daemon.
///
/// The applet is a passive indicator; polling a D-Bus property every few
/// seconds costs nothing measurable and avoids holding a signal subscription
/// open against a daemon that may come and go.
const POLL: std::time::Duration = std::time::Duration::from_secs(5);

pub struct Applet {
    core: Core,
    popup: Option<Id>,
    /// `None` until the first poll completes, or when no daemon is running.
    status: Option<Status>,
    /// Where to ask for an activation token. `None` until the subscription
    /// has started, or on a compositor without the protocol.
    token: Option<calloop::channel::Sender<TokenRequest>>,

    /// The quick-search box's contents, and what it last found. Entries are
    /// metadata only — see [`locket_secret::quick`]; a secret is fetched at
    /// the moment Copy is pressed and never held here.
    query: String,
    results: Vec<locket_secret::quick::Entry>,
    /// What we last put on the clipboard, so the clear timer can check it is
    /// still ours before wiping it — the same rule the main window follows.
    clipboard_copy: Option<String>,
    /// The clear timer could not read the clipboard; it retries every tick.
    clipboard_due: bool,
    /// Counts copies, so each clear timer knows whether it is still current.
    clipboard_generation: u64,
    notice: Option<String>,
}

/// How many results the popup will show. A panel popup is not a browser;
/// past a handful the answer is to open the window and search properly.
const MAX_RESULTS: usize = 8;

/// Seconds before a copied secret is taken off the clipboard, when the
/// window's setting is unset or cannot be read — the same default the window
/// ships with, rather than a second, quieter policy.
const CLIPBOARD_CLEAR_SECS: u64 = 30;

/// Where the window keeps its settings: its application id, the version of
/// its settings store, and the key of "Clear copied secrets".
const LOCKET_SETTINGS: (&str, u64, &str) = ("com.magnetaros.Locket", 1, "clipboard_clear_seconds");

#[derive(Clone, Debug)]
pub enum Message {
    Surface(cosmic::surface::Action<Message>),
    PopupClosed(Id),
    Tick,
    Status(Option<Status>),
    Lock,
    OpenApp,
    Token(TokenUpdate),
    SearchChanged(String),
    Searched(Vec<locket_secret::quick::Entry>),
    /// Copy the secret behind this path; the label is for the notice.
    Copy(String, String),
    Copied(String, Option<String>),
    /// The clear timer for the copy with this number fired.
    ClearClipboard(u64),
    ClipboardChecked(Option<String>),
}

/// Launch the main window, handing on an activation token if we have one.
///
/// The token is what lets the compositor give the new window focus, or raise
/// the instance that is already running — a launch without one appears behind
/// the panel with nothing to say it arrived. Both variable names are set
/// because which one the other end reads depends on whether it came up under
/// Wayland or X11.
fn launch(token: Option<String>) -> Task<Message> {
    cosmic::iced::Task::future(async move {
        let env = match token {
            Some(token) => vec![
                ("XDG_ACTIVATION_TOKEN", token.clone()),
                ("DESKTOP_STARTUP_ID", token),
            ],
            None => Vec::new(),
        };
        cosmic::desktop::spawn_desktop_exec(APP_EXEC, env, Some(ID), false).await;
    })
    .discard()
}

impl Applet {
    /// Panel icon. Says at a glance whether secrets are reachable.
    fn icon_name(&self) -> &'static str {
        match self.status {
            Some(s) if !s.locked => "channel-secure-symbolic",
            Some(_) => "channel-insecure-symbolic",
            // No daemon: neither locked nor unlocked, so do not claim either.
            None => "dialog-password-symbolic",
        }
    }

    fn summary(&self) -> String {
        match self.status {
            Some(s) if !s.locked => fl!("summary-unlocked", items = s.items),
            Some(_) => fl!("summary-locked"),
            None => fl!("summary-no-daemon"),
        }
    }
}

impl cosmic::Application for Applet {
    type Executor = cosmic::SingleThreadExecutor;
    type Flags = ();
    type Message = Message;
    const APP_ID: &'static str = ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Message>) {
        let applet = Applet {
            core,
            popup: None,
            status: None,
            token: None,
            query: String::new(),
            results: Vec::new(),
            clipboard_copy: None,
            clipboard_due: false,
            clipboard_generation: 0,
            notice: None,
        };
        // Ask immediately so the icon is right before the first tick.
        (
            applet,
            cosmic::task::future(async { Message::Status(locket_secret::client::status().await) }),
        )
    }

    fn on_close_requested(&self, id: window::Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Surface(action) => {
                return cosmic::task::message(cosmic::Action::Surface(action));
            }
            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                    // Reopening with the last query still in the box would
                    // say what somebody was looking for to whoever opens it
                    // next.
                    self.query.clear();
                    self.results.clear();
                    self.notice = None;
                }
            }
            Message::Tick => {
                let status = cosmic::task::future(async {
                    Message::Status(locket_secret::client::status().await)
                });
                if std::mem::take(&mut self.clipboard_due) {
                    let clear = Message::ClearClipboard(self.clipboard_generation);
                    return Task::batch([status, cosmic::task::message(clear)]);
                }
                return status;
            }
            Message::Status(status) => self.status = status,
            Message::Lock => {
                self.results.clear();
                self.query.clear();
                self.notice = None;
                return cosmic::task::future(async {
                    locket_secret::client::lock().await;
                    // Re-read rather than assuming the lock took.
                    Message::Status(locket_secret::client::status().await)
                });
            }
            Message::OpenApp => {
                // Unlocking belongs in the real window, not a panel popup.
                //
                // The token is minted asynchronously by the Wayland thread, so
                // the launch happens when it comes back rather than here.
                match self.token.as_ref() {
                    Some(sender) => {
                        if let Err(e) = sender.send(TokenRequest {
                            app_id: ID.to_owned(),
                            exec: APP_EXEC.to_owned(),
                        }) {
                            tracing::warn!("could not ask for an activation token: {e}");
                            return launch(None);
                        }
                    }
                    None => return launch(None),
                }
            }

            Message::SearchChanged(query) => {
                self.query = query.clone();
                self.notice = None;
                // Searching only reads labels, so it is cheap enough to redo
                // per keystroke; a locked vault answers with nothing, which
                // the view reports as locked rather than as "no matches".
                if !self.status.is_some_and(|s| !s.locked) {
                    self.results.clear();
                    return Task::none();
                }
                return cosmic::task::future(async move {
                    Message::Searched(locket_secret::quick::search(&query, MAX_RESULTS).await)
                });
            }

            Message::Searched(results) => self.results = results,

            Message::Copy(path, label) => {
                return cosmic::task::future(async move {
                    Message::Copied(label, locket_secret::quick::secret_of(&path).await)
                });
            }

            Message::Copied(label, secret) => {
                let Some(secret) = secret else {
                    self.notice = Some(fl!("copy-failed", label = label));
                    return Task::none();
                };
                // Read at each copy: the setting lives with the window, and it
                // can change there at any time.
                let config =
                    cosmic::cosmic_config::Config::new(LOCKET_SETTINGS.0, LOCKET_SETTINGS.1)
                        .inspect_err(|e| tracing::debug!("locket's settings unavailable: {e}"))
                        .ok();
                let Some(seconds) = clear_after(config.as_ref()) else {
                    self.notice = Some(fl!("copied-forever", label = label));
                    self.clipboard_copy = None;
                    self.clipboard_due = false;
                    return cosmic::iced::clipboard::write::<cosmic::Action<Message>>(secret);
                };
                self.notice = Some(fl!("copied", label = label, seconds = seconds));
                self.clipboard_copy = Some(secret.clone());
                self.clipboard_due = false;
                self.clipboard_generation += 1;
                let generation = self.clipboard_generation;
                let copy = cosmic::iced::clipboard::write::<cosmic::Action<Message>>(secret);
                let clear = cosmic::task::future(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    Message::ClearClipboard(generation)
                });
                return Task::batch([copy, clear]);
            }

            Message::ClearClipboard(generation) => {
                if !timer_is_current(generation, self.clipboard_generation) {
                    return Task::none();
                }
                // Look before wiping: the person may have copied something of
                // their own since, and clearing that would be its own small
                // disaster. Same check the main window makes.
                return cosmic::iced::clipboard::read()
                    .map(|current| cosmic::Action::App(Message::ClipboardChecked(current)));
            }

            Message::ClipboardChecked(current) => {
                match clear_decision(
                    current.as_deref(),
                    self.clipboard_copy.as_deref(),
                    self.popup.is_some(),
                ) {
                    ClearDecision::Clear => {
                        self.clipboard_copy = None;
                        // Overwrite rather than clear: some clipboard managers
                        // treat an empty payload as "no change".
                        return cosmic::iced::clipboard::write::<cosmic::Action<Message>>(
                            String::new(),
                        );
                    }
                    ClearDecision::Leave => self.clipboard_copy = None,
                    ClearDecision::Retry => self.clipboard_due = true,
                }
            }

            Message::Token(update) => match update {
                TokenUpdate::Init(sender) => self.token = Some(sender),
                // The Wayland thread is gone; later launches go without a
                // token rather than not happening.
                TokenUpdate::Finished => self.token = None,
                TokenUpdate::ActivationToken { token, .. } => return launch(token),
            },
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let have_popup = self.popup;
        let button = self
            .core
            .applet
            .icon_button(self.icon_name())
            .on_press_with_rectangle(move |offset, bounds| {
                if let Some(id) = have_popup {
                    Message::Surface(destroy_popup(id))
                } else {
                    Message::Surface(app_popup::<Applet>(
                        |_| Default::default(),
                        move |state: &mut Applet| {
                            let new_id = Id::unique();
                            state.popup = Some(new_id);
                            let mut settings = state.core.applet.get_popup_settings(
                                state.core.main_window_id().unwrap(),
                                new_id,
                                None,
                                None,
                                None,
                            );
                            settings.positioner.anchor_rect = Rectangle {
                                x: (bounds.x - offset.x) as i32,
                                y: (bounds.y - offset.y) as i32,
                                width: bounds.width as i32,
                                height: bounds.height as i32,
                            };
                            settings
                        },
                        Some(Box::new(move |state: &Applet| {
                            Element::from(state.core.applet.popup_container(state.popup_view()))
                                .map(cosmic::Action::App)
                        })),
                    ))
                }
            });

        Element::from(self.core.applet.applet_tooltip::<Message>(
            button,
            self.summary(),
            self.popup.is_some(),
            Message::Surface,
            None,
        ))
    }

    fn view_window(&self, _id: Id) -> Element<'_, Message> {
        self.popup_view()
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            cosmic::iced::time::every(POLL).map(|_| Message::Tick),
            activation_token_subscription(0).map(Message::Token),
        ])
    }

    fn style(&self) -> Option<cosmic::iced::theme::Style> {
        Some(cosmic::applet::style())
    }
}

impl Applet {
    fn popup_view(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();
        let unlocked = self.status.is_some_and(|s| !s.locked);
        let running = self.status.is_some();

        let mut column = widget::column::with_capacity(8 + MAX_RESULTS)
            .spacing(spacing.space_xs)
            .padding(spacing.space_s)
            .push(widget::text::body(self.summary()));

        if !running {
            column = column.push(widget::text::caption(fl!("daemon-hint")));
        }

        column = column.push(widget::divider::horizontal::default());

        // Quick search: the 90% of interactions that do not deserve a window.
        // Only while unlocked — a search box over a locked vault would return
        // nothing and read as an empty vault rather than a locked one.
        if unlocked {
            column = column.push(
                widget::text_input(fl!("search-placeholder"), &self.query)
                    .on_input(Message::SearchChanged)
                    .width(Length::Fill),
            );

            if let Some(notice) = &self.notice {
                column = column.push(widget::text::caption(notice.clone()));
            }

            for entry in &self.results {
                let subtitle = if entry.subtitle.is_empty() {
                    entry.label.clone()
                } else {
                    entry.subtitle.clone()
                };
                column = column.push(
                    widget::row::with_capacity(2)
                        .spacing(spacing.space_xs)
                        .align_y(cosmic::iced::Alignment::Center)
                        .push(
                            widget::column::with_capacity(2)
                                .push(widget::text::body(entry.label.clone()))
                                .push(widget::text::caption(subtitle))
                                .width(Length::Fill),
                        )
                        .push(
                            widget::button::standard(fl!("copy"))
                                .on_press(Message::Copy(entry.path.clone(), entry.label.clone())),
                        ),
                );
            }

            if self.results.is_empty() && !self.query.is_empty() {
                column = column.push(widget::text::caption(fl!(
                    "search-no-match",
                    query = self.query.clone()
                )));
            }

            column = column.push(widget::divider::horizontal::default());
        } else if running {
            column = column.push(widget::text::caption(fl!("search-locked")));
        }

        if unlocked {
            column = column.push(
                widget::button::standard(fl!("lock-now"))
                    .width(Length::Fill)
                    .on_press(Message::Lock),
            );
        }

        column
            .push(
                widget::button::standard(if unlocked {
                    fl!("open-locket")
                } else {
                    // Unlocking deliberately leaves the panel.
                    fl!("unlock-in-locket")
                })
                .width(Length::Fill)
                .on_press(Message::OpenApp),
            )
            .into()
    }
}

/// Whether a clear timer is for the latest copy. Each copy starts its own
/// timer, and an older one must not wipe a newer copy early.
fn timer_is_current(fired_for: u64, latest: u64) -> bool {
    fired_for == latest
}

/// How long a copied secret stays on the clipboard, from the window's
/// settings in `config`; `None` means it is never cleared.
fn clear_after(config: Option<&cosmic::cosmic_config::Config>) -> Option<u64> {
    use cosmic::cosmic_config::ConfigGet as _;
    match config.map(|c| c.get::<u64>(LOCKET_SETTINGS.2)) {
        Some(Ok(0)) => None,
        Some(Ok(seconds)) => Some(seconds),
        Some(Err(e)) => {
            // Unset is the first-run case; either way, the window's default.
            tracing::debug!("clipboard setting unavailable ({e}); using the default");
            Some(CLIPBOARD_CLEAR_SECS)
        }
        None => Some(CLIPBOARD_CLEAR_SECS),
    }
}

/// What a clear timer does with what it read back from the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearDecision {
    /// Still the secret we put there: wipe it.
    Clear,
    /// Something else, or nothing of ours to clear: leave it alone.
    Leave,
    /// Could not be read; try again on the next tick.
    Retry,
}

/// `current` is what the clipboard read back as, `ours` what the applet put
/// there, and `open` whether the popup — the applet's only surface that takes
/// the keyboard — was open at the time.
///
/// On Wayland a client can read the clipboard only while it has the keyboard,
/// and the popup is usually closed by the time a pasted password's timer
/// fires. Not being able to look says nothing about whose it is, so the clear
/// is retried on the next tick, and succeeds once the popup is open again.
fn clear_decision(current: Option<&str>, ours: Option<&str>, open: bool) -> ClearDecision {
    match (current, ours) {
        (_, None) => ClearDecision::Leave,
        (None, Some(_)) if !open => ClearDecision::Retry,
        (Some(current), Some(ours)) if current == ours => ClearDecision::Clear,
        _ => ClearDecision::Leave,
    }
}

fn main() -> cosmic::iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "locket_applet=info".into()),
        )
        .init();

    // The languages the desktop asks for, in preference order.
    i18n::init(&i18n_embed::DesktopLanguageRequester::requested_languages());

    cosmic::applet::run::<Applet>(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The popup is closed by the time a pasted password's timer fires, and
    /// without the keyboard the clipboard reads back as nothing. That is not
    /// "somebody copied something else".
    #[test]
    fn an_unreadable_clipboard_is_retried_not_forgotten() {
        assert_eq!(
            clear_decision(None, Some("hunter2"), false),
            ClearDecision::Retry
        );
        assert_eq!(
            clear_decision(Some("hunter2"), Some("hunter2"), true),
            ClearDecision::Clear
        );
        assert_eq!(
            clear_decision(Some("mine"), Some("hunter2"), true),
            ClearDecision::Leave
        );
        assert_eq!(
            clear_decision(None, Some("hunter2"), true),
            ClearDecision::Leave
        );
    }

    /// "Clear copied secrets" is set in the window; the panel's copy button
    /// follows it rather than keeping a quieter policy of its own.
    #[test]
    fn the_windows_clipboard_setting_applies_to_the_panel_too() {
        use cosmic::cosmic_config::{Config, ConfigSet as _};
        let dir = std::env::temp_dir().join(format!(
            "locket-applet-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let config = Config::with_custom_path("com.magnetaros.Locket", 1, dir.clone()).unwrap();

        assert_eq!(
            clear_after(Some(&config)),
            Some(30),
            "unset is the window's default"
        );
        config.set("clipboard_clear_seconds", 10u64).unwrap();
        assert_eq!(clear_after(Some(&config)), Some(10));
        config.set("clipboard_clear_seconds", 0u64).unwrap();
        assert_eq!(clear_after(Some(&config)), None, "zero is never");
        assert_eq!(clear_after(None), Some(30));

        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Copy A, then B ten seconds later: A's timer must leave B alone.
    #[test]
    fn an_older_timer_does_not_clear_a_newer_copy() {
        assert!(!timer_is_current(1, 2));
        assert!(timer_is_current(2, 2));
    }
}
