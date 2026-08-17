//! COSMIC panel applet for passman.
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
use passman_secret::client::Status;

const ID: &str = "io.github.idominikos.PassmanApplet";

/// The main window's binary, as the desktop entry spells it.
const APP_EXEC: &str = "passman";

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
}

#[derive(Clone, Debug)]
pub enum Message {
    Surface(cosmic::surface::Action),
    PopupClosed(Id),
    Tick,
    Status(Option<Status>),
    Lock,
    OpenApp,
    Token(TokenUpdate),
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
            Some(s) if !s.locked => format!("Unlocked · {} items", s.items),
            Some(_) => "Locked".to_owned(),
            None => "passmand is not running".to_owned(),
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
        };
        // Ask immediately so the icon is right before the first tick.
        (
            applet,
            cosmic::task::future(async { Message::Status(passman_secret::client::status().await) }),
        )
    }

    fn on_close_requested(&self, id: window::Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Surface(action) => {
                return cosmic::task::message(cosmic::Action::Cosmic(
                    cosmic::app::Action::Surface(action),
                ));
            }
            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                }
            }
            Message::Tick => {
                return cosmic::task::future(async {
                    Message::Status(passman_secret::client::status().await)
                });
            }
            Message::Status(status) => self.status = status,
            Message::Lock => {
                return cosmic::task::future(async {
                    passman_secret::client::lock().await;
                    // Re-read rather than assuming the lock took.
                    Message::Status(passman_secret::client::status().await)
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

        let mut column = widget::column::with_capacity(4)
            .spacing(spacing.space_xs)
            .padding(spacing.space_s)
            .push(widget::text::body(self.summary()));

        if !running {
            column = column.push(widget::text::caption(
                "Start passmand to manage secrets from here.",
            ));
        }

        column = column.push(widget::divider::horizontal::default());

        if unlocked {
            column = column.push(
                widget::button::standard("Lock now")
                    .width(Length::Fill)
                    .on_press(Message::Lock),
            );
        }

        column
            .push(
                widget::button::standard(if unlocked {
                    "Open passman"
                } else {
                    // Unlocking deliberately leaves the panel.
                    "Unlock in passman"
                })
                .width(Length::Fill)
                .on_press(Message::OpenApp),
            )
            .into()
    }
}

fn main() -> cosmic::iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "passman_applet=info".into()),
        )
        .init();
    cosmic::applet::run::<Applet>(())
}
