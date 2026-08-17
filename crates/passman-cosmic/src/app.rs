//! The COSMIC frontend.
//!
//! Layout follows the shape COSMIC apps use: a nav bar for categories, a
//! search-filtered list in the content area, and item details in a context
//! drawer — the same pattern `cosmic-files` uses for its preview pane.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cosmic::app::context_drawer::{self, ContextDrawer};
use cosmic::app::{Core, Task};
use cosmic::iced::{Alignment, Length, Subscription};
use cosmic::prelude::*;
use cosmic::widget::{self, nav_bar};
use passman_core::{
    Totp, Vault,
    crypto::KdfParams,
    generator::{self, PasswordRecipe},
    model::{FieldKind, Item, ItemKind, field_names},
};
use uuid::Uuid;

use std::sync::LazyLock;

use crate::config::{self, Settings};
use crate::daemon::{self, DaemonEvent};
use crate::import;
use crate::preferences::{self, Status};
use crate::editor::{Editor, EditorMessage, Outcome};
use crate::security::{self, Security};

/// Id of the search box, so a shortcut can focus it.
static SEARCH_ID: LazyLock<widget::Id> = LazyLock::new(|| widget::Id::new("passman-search"));
/// The unlock screen's passphrase field.
///
/// Focused whenever that screen appears. Without it the window opens with
/// nothing focused: there is no focus ring to show where typing would land,
/// and the placeholder reads like a label that refuses to clear because the
/// user has not actually typed into anything yet.
static PASSPHRASE_ID: LazyLock<widget::Id> =
    LazyLock::new(|| widget::Id::new("passman-passphrase"));

/// Sidebar entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    All,
    Favorites,
    Kind(ItemKind),
    /// Unlock factors: passphrase, TPM PIN, security key.
    Security,
    /// Preferences, and whether the desktop integration is actually working.
    Settings,
}

impl Category {
    fn label(self) -> String {
        match self {
            Category::All => "All Items".to_owned(),
            Category::Favorites => "Favorites".to_owned(),
            Category::Security => "Security".to_owned(),
            Category::Settings => "Settings".to_owned(),
            Category::Kind(k) => format!("{}s", k.label()),
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            Category::All => "view-grid-symbolic",
            Category::Favorites => "starred-symbolic",
            Category::Security => "security-high-symbolic",
            Category::Settings => "preferences-system-symbolic",
            Category::Kind(k) => k.icon_name(),
        }
    }

    fn matches(self, item: &Item) -> bool {
        match self {
            Category::All => true,
            Category::Favorites => item.favorite,
            // Neither screen lists items, so nothing matches them.
            Category::Security | Category::Settings => false,
            Category::Kind(k) => item.kind == k,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    PassphraseChanged(String),
    ConfirmChanged(String),
    ToggleShowPassphrase,
    UnlockSubmit,
    /// The vault-opening task finished. The vault travels in a shared slot
    /// because `Vault` is deliberately not `Clone` and messages must be.
    VaultOpened(Arc<Mutex<Option<Vault>>>, Option<String>),
    Lock,
    SearchChanged(String),
    Select(Uuid),
    ToggleReveal(String),
    /// Show or hide the `otpauth://` QR for a one-time-code field.
    ToggleQr(String),
    CopyValue(&'static str, String),
    ClearClipboard,
    /// What the clipboard held when the clear timer fired.
    ClipboardChecked(Option<String>),
    /// The vault file changed underneath us; pick the change up.
    ReloadVaultFile,
    /// Answer the daemon's "may this key sign?" question.
    AnswerConfirm(bool),
    /// The settings store changed somewhere else; take the new values.
    SettingsChanged(Settings),
    CloseContext,
    ToggleFavorite(Uuid),
    Tick,
    CloseToast(widget::ToastId),
    // -- editing --
    NewItem,
    EditSelected,
    Editor(EditorMessage),
    RequestDelete(Uuid),
    ConfirmDelete,
    CancelDelete,
    // -- daemon --
    Daemon(DaemonEvent),
    DaemonUnlocked(bool),
    // -- unlock factors --
    Security(security::Message),
    /// Move focus to the search box.
    FocusSearch,
    FocusPassphrase,
    /// The idle timer fired; lock if nothing has happened for long enough.
    IdleCheck,
    /// The window lost focus. Re-conceals revealed secrets when configured to.
    WindowUnfocused,
    Preferences(preferences::Message),
    OpenImport,
    Import(import::Message),
    /// The vault comes back with the import's result; it was moved out for
    /// the duration so the work could run off the UI thread.
    ImportFinished(Arc<Mutex<Option<Vault>>>, import::Outcome),
    PassphraseFocus(bool),
    ConfirmFocus(bool),
    /// Enrolment finished; the vault comes back in the shared slot because it
    /// was moved into a blocking worker to keep the UI responsive.
    SecurityEnrolled(Arc<Mutex<Option<Vault>>>, Option<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Locked,
    Unlocking,
    Browsing,
}

pub struct Flags {
    pub vault_path: PathBuf,
}

/// What a second `passman` forwards to the instance already running.
///
/// Nothing: there are no subcommands, and the vault path is not worth passing
/// because switching an unlocked window to another vault mid-session is not
/// something the app can do. A bare activation just raises the window.
impl cosmic::app::CosmicFlags for Flags {
    type SubCommand = String;
    type Args = Vec<String>;
}

pub struct App {
    core: Core,
    nav: nav_bar::Model,
    vault_path: PathBuf,
    vault_exists: bool,
    vault: Option<Vault>,
    screen: Screen,

    passphrase: String,
    confirm: String,
    show_passphrase: bool,
    /// Whether each unlock field holds focus, so its placeholder can clear.
    passphrase_focused: bool,
    confirm_focused: bool,
    error: Option<String>,

    search: String,
    selected: Option<Uuid>,
    revealed: HashSet<String>,

    settings: Settings,
    /// The backing store the preferences screen writes through. `None` when
    /// `cosmic-config` is unavailable, which leaves settings usable for the
    /// session but not persisted.
    config: Option<cosmic_config::Config>,
    toasts: widget::Toasts<Message>,

    /// `Some` while the item editor is open.
    editor: Option<Editor>,
    /// The import screen, shown in place of the item list while open.
    import: Option<import::Import>,
    /// When the user last interacted, for auto-lock. Reset by any message
    /// that represents a deliberate action rather than a background tick.
    last_activity: std::time::Instant,
    /// Observed integration state, refreshed when the screen is opened.
    status: Option<Status>,
    /// Item awaiting a delete confirmation.
    pending_delete: Option<Uuid>,

    /// Set when the daemon asked for an unlock on an application's behalf, so
    /// the unlock screen can say why it appeared.
    security: Security,
    unlock_requested_by_app: bool,
    /// The secret we last put on the clipboard, so the clear timer can check
    /// it is still ours before wiping it.
    clipboard_copy: Option<String>,
    /// An SSH signature waiting to be allowed: (request id, key name).
    pending_confirm: Option<(u32, String)>,

    /// The one-time-code field currently shown as a QR, with its encoded
    /// image. Held rather than rebuilt per frame because the widget borrows
    /// the data, and because re-encoding a seed on every redraw is work for
    /// nothing.
    qr: Option<(String, widget::qr_code::Data)>,
    /// Name, version and links for the About section of Settings.
    about: widget::about::About,
}

impl App {
    /// Tell the daemon what the idle timeout is now.
    ///
    /// One setting, one meaning: the same number that locks this window also
    /// locks the daemon, which is the process actually holding the key.
    fn push_auto_lock(&self) -> Task<Message> {
        let seconds = self.settings.auto_lock_seconds;
        cosmic::task::future(async move {
            daemon::set_auto_lock(seconds).await;
            Message::Tick
        })
    }

    /// Pick up an edit another process made to the vault file.
    ///
    /// The daemon writes the same file whenever a `libsecret` client stores
    /// something, so our copy goes stale without anyone doing anything wrong.
    /// Returns true if a reload happened.
    fn reload_if_changed(&mut self) -> bool {
        let Some(vault) = self.vault.as_mut() else {
            return false;
        };
        if !vault.changed_on_disk() {
            return false;
        }
        match vault.reload() {
            Ok(()) => {
                tracing::info!("the vault file changed; reloaded it");
                true
            }
            Err(e) => {
                // The key material changed — someone changed the passphrase.
                // Our DEK is useless against that file, so the only honest
                // move is back to the unlock screen.
                tracing::warn!("could not reload the changed vault: {e}");
                self.vault = None;
                self.screen = Screen::Locked;
                self.error = Some("The vault was changed elsewhere. Unlock it again.".into());
                false
            }
        }
    }

    /// Persist, and tell the daemon its copy is now behind.
    ///
    /// Without that last part the daemon would keep serving the secrets it had
    /// before this edit, and would refuse its own next save for conflicting
    /// with a file it does not know changed.
    fn save_vault(&mut self) -> Result<Task<Message>, String> {
        let Some(vault) = self.vault.as_mut() else {
            return Ok(Task::none());
        };
        match vault.save() {
            Ok(()) => Ok(cosmic::task::future(async {
                daemon::reload().await;
                Message::Tick
            })),
            Err(passman_core::Error::ChangedOnDisk { .. }) => Err(
                "Another passman process wrote the vault a moment ago. Nothing was \
                 overwritten — try that again."
                    .to_owned(),
            ),
            Err(e) => Err(format!("Could not save: {e}")),
        }
    }

    /// Take every secret back off the screen.
    ///
    /// Revealed values and the QR go together: both put something on display
    /// that was meant to stay hidden, so anything that hides one hides both.
    fn conceal(&mut self) {
        self.revealed.clear();
        self.qr = None;
    }

    fn category(&self) -> Category {
        self.nav
            .active_data::<Category>()
            .copied()
            .unwrap_or(Category::All)
    }

    /// Items in the active category matching the search box, favourites first.
    fn visible_items(&self) -> Vec<&Item> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let category = self.category();
        let mut items: Vec<&Item> = vault
            .data()
            .all_items()
            .map(|(_, item)| item)
            .filter(|item| category.matches(item) && item.matches(&self.search))
            .collect();
        items.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        });
        items
    }

    fn selected_item(&self) -> Option<&Item> {
        let id = self.selected?;
        self.vault.as_ref()?.item(id)
    }

    fn toast(&mut self, text: impl Into<String>) -> Task<Message> {
        self.toasts.push(widget::Toast::new(text.into())).map(cosmic::Action::App)
    }

    // -- views --------------------------------------------------------------

    fn unlock_view(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();
        let creating = !self.vault_exists;

        let heading = if creating {
            "Create your vault"
        } else {
            "Unlock passman"
        };
        let blurb = if creating {
            "Choose a strong passphrase. It is the only thing protecting your \
             secrets, and it cannot be recovered if you forget it."
        } else if self.unlock_requested_by_app {
            "An application asked for a secret from your vault. Unlock to let \
             it through."
        } else {
            "Enter your passphrase to unlock the vault."
        };

        let mut form = widget::column::with_capacity(6)
            .spacing(spacing.space_s)
            .max_width(420.0)
            .align_x(Alignment::Center)
            .push(widget::icon::from_name("dialog-password-symbolic").size(64))
            .push(widget::text::title2(heading))
            .push(widget::text::body(blurb).center())
            .push(
                // The placeholder clears the moment the field takes focus
                // rather than waiting for the first keystroke. On a masked
                // field you cannot tell typed text from a placeholder by
                // looking, so a word still sitting there after you have
                // clicked in reads as content the field will not let go of.
                widget::text_input::secure_input(
                    if self.passphrase_focused { "" } else { "Passphrase" },
                    &self.passphrase,
                    Some(Message::ToggleShowPassphrase),
                    !self.show_passphrase,
                )
                .id(PASSPHRASE_ID.clone())
                .on_focus(Message::PassphraseFocus(true))
                .on_unfocus(Message::PassphraseFocus(false))
                .on_input(Message::PassphraseChanged)
                .on_submit(|_| Message::UnlockSubmit),
            );

        if creating {
            form = form.push(
                widget::text_input::secure_input(
                    if self.confirm_focused {
                        ""
                    } else {
                        "Confirm passphrase"
                    },
                    &self.confirm,
                    Some(Message::ToggleShowPassphrase),
                    !self.show_passphrase,
                )
                .on_focus(Message::ConfirmFocus(true))
                .on_unfocus(Message::ConfirmFocus(false))
                .on_input(Message::ConfirmChanged)
                .on_submit(|_| Message::UnlockSubmit),
            );
        }

        if let Some(error) = &self.error {
            form = form.push(widget::text::body(error.clone()).class(cosmic::theme::Text::Color(
                cosmic::theme::active().cosmic().destructive_color().into(),
            )));
        }

        let busy = self.screen == Screen::Unlocking;
        let action = widget::button::suggested(if creating {
            "Create vault"
        } else if busy {
            "Unlocking…"
        } else {
            "Unlock"
        });
        form = form.push(if busy {
            action.into()
        } else {
            Element::from(action.on_press(Message::UnlockSubmit))
        });

        widget::container(form)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .into()
    }

    fn browse_view(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();
        let items = self.visible_items();

        let category = self.category();
        // Say what is being searched. "Search secrets" on a filtered category
        // implies it searches everything, which it does not.
        let search = widget::search_input(format!("Search {}", category.label()), &self.search)
            .id(SEARCH_ID.clone())
            .on_input(Message::SearchChanged)
            .on_clear(Message::SearchChanged(String::new()));

        let list: Element<'_, Message> = if items.is_empty() {
            // An empty state should say which emptiness this is, and offer the
            // action that resolves it. "Nothing here yet" next to a full vault
            // — because a category filter is on — is actively misleading.
            let searching = !self.search.is_empty();
            let total = self
                .vault
                .as_ref()
                .map(|v| v.data().item_count())
                .unwrap_or(0);

            let (icon, headline, detail) = if searching {
                (
                    "system-search-symbolic",
                    format!("No match for “{}”", self.search),
                    match category {
                        Category::All => "Nothing in the vault matches.".to_owned(),
                        other => format!("Nothing in {} matches. Try All Items.", other.label()),
                    },
                )
            } else if total == 0 {
                (
                    "dialog-password-symbolic",
                    "Your vault is empty".to_owned(),
                    "Add something, or import from another password manager.".to_owned(),
                )
            } else {
                (
                    category.icon_name(),
                    format!("No {} yet", category.label().to_lowercase()),
                    format!("The vault holds {total} item(s) in other categories."),
                )
            };

            let mut empty = widget::column::with_capacity(4)
                .spacing(spacing.space_xs)
                .align_x(Alignment::Center)
                .push(widget::icon::from_name(icon).size(48))
                .push(widget::text::title4(headline))
                .push(widget::text::body(detail).center());

            if searching {
                empty = empty.push(
                    widget::button::standard("Clear search")
                        .on_press(Message::SearchChanged(String::new())),
                );
            } else if category != Category::Security {
                empty = empty
                    .push(widget::button::suggested("New item").on_press(Message::NewItem));
            }

            widget::container(empty)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
                .into()
        } else {
            let mut column = widget::list_column();
            for item in items {
                let selected = self.selected == Some(item.id);
                // Compact drops the subtitle rather than shrinking the type:
                // the second line is what costs the height, and smaller text
                // would cost legibility for the same gain.
                let compact = self.settings.compact_list;
                let text: Element<'_, Message> = if compact {
                    widget::row::with_capacity(2)
                        .spacing(spacing.space_xs)
                        .align_y(Alignment::Center)
                        .push(widget::text::body(item.label.clone()))
                        .push(widget::text::caption(item.subtitle().to_owned()))
                        .width(Length::Fill)
                        .into()
                } else {
                    widget::column::with_capacity(2)
                        .push(widget::text::body(item.label.clone()))
                        .push(widget::text::caption(item.subtitle().to_owned()))
                        .width(Length::Fill)
                        .into()
                };

                let row = widget::row::with_capacity(3)
                    .spacing(if compact { spacing.space_xs } else { spacing.space_s })
                    .align_y(Alignment::Center)
                    .push(
                        widget::icon::from_name(item.kind.icon_name())
                            .size(if compact { 16 } else { 24 }),
                    )
                    .push(text)
                    .push_maybe(item.favorite.then(|| {
                        widget::icon::from_name("starred-symbolic").size(16)
                    }));

                column = column.add(
                    widget::button::custom(row)
                        .width(Length::Fill)
                        .class(if selected {
                            cosmic::theme::Button::Suggested
                        } else {
                            cosmic::theme::Button::Text
                        })
                        .on_press(Message::Select(item.id)),
                );
            }
            widget::scrollable(column).height(Length::Fill).into()
        };

        widget::column::with_capacity(2)
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .push(search)
            .push(list)
            .into()
    }

    /// One labelled value with reveal/copy affordances.
    ///
    /// Takes owned strings: callers pass computed values (a live TOTP code, a
    /// formatted label) that do not outlive the call.
    fn field_row(
        &self,
        name: String,
        display_name: String,
        value: &str,
        kind: FieldKind,
    ) -> Element<'static, Message> {
        let spacing = cosmic::theme::spacing();
        let revealed = self.revealed.contains(&name);
        let sensitive = kind.is_sensitive();

        let shown = if sensitive && !revealed {
            "•".repeat(value.chars().count().clamp(8, 24))
        } else {
            value.to_owned()
        };

        let mut controls = widget::row::with_capacity(2).spacing(spacing.space_xxs);
        if sensitive {
            controls = controls.push(
                widget::button::standard(if revealed { "Hide" } else { "Reveal" })
                    .on_press(Message::ToggleReveal(name.clone())),
            );
        }
        controls = controls.push(
            widget::button::standard("Copy")
                .on_press(Message::CopyValue(
                    if sensitive { "Secret" } else { "Value" },
                    value.to_owned(),
                )),
        );

        widget::column::with_capacity(3)
            .spacing(spacing.space_xxs)
            .push(widget::text::caption_heading(display_name))
            .push(
                widget::row::with_capacity(2)
                    .align_y(Alignment::Center)
                    .spacing(spacing.space_s)
                    .push(if sensitive && revealed {
                        Element::from(widget::text::monotext(shown).width(Length::Fill))
                    } else {
                        Element::from(widget::text::body(shown).width(Length::Fill))
                    })
                    .push(controls),
            )
            .push(widget::divider::horizontal::default())
            .into()
    }

    fn detail_view(&self) -> Option<Element<'_, Message>> {
        let item = self.selected_item()?;
        let spacing = cosmic::theme::spacing();

        let mut column = widget::column::with_capacity(12).spacing(spacing.space_s);

        column = column.push(
            widget::row::with_capacity(2)
                .spacing(spacing.space_s)
                .align_y(Alignment::Center)
                .push(widget::icon::from_name(item.kind.icon_name()).size(40))
                .push(
                    widget::column::with_capacity(2)
                        .push(widget::text::title4(item.label.clone()))
                        .push(widget::text::caption(item.kind.label())),
                ),
        );

        column = column.push(
            widget::row::with_capacity(3)
                .spacing(spacing.space_xxs)
                .push(widget::button::standard("Edit").on_press(Message::EditSelected))
                .push(
                    widget::button::standard(if item.favorite {
                        "Unfavorite"
                    } else {
                        "Favorite"
                    })
                    .on_press(Message::ToggleFavorite(item.id)),
                )
                .push(
                    widget::button::destructive("Delete")
                        .on_press(Message::RequestDelete(item.id)),
                ),
        );

        // The primary secret, as other applications see it over the
        // Secret Service.
        if !item.secret.is_empty() {
            column = column.push(self.field_row(
                "__secret".to_owned(),
                "Password".to_owned(),
                item.secret.expose(),
                FieldKind::Secret,
            ));
        }

        for field in &item.fields {
            // TOTP seeds are shown as a live code, not as the seed.
            if field.kind == FieldKind::Totp {
                let code = Totp::parse(field.value.expose())
                    .and_then(|t| t.code().map(|c| (c, t.seconds_remaining(), t.period)));
                match code {
                    Ok((code, remaining, period)) => {
                        column = column.push(self.field_row(
                            field.name.clone(),
                            "One-time code".to_owned(),
                            &code,
                            FieldKind::Text,
                        ));
                        // A bar that drains, because "how long have I got" is
                        // the question you actually have while typing a code
                        // into a form, and a number alone makes you read it.
                        let fraction = if period == 0 {
                            0.0
                        } else {
                            remaining as f32 / period as f32
                        };
                        let bar = widget::determinate_linear(fraction).width(Length::Fill);

                        // Under five seconds the code will roll mid-entry, so
                        // the caption goes red: the bar alone reads as "some
                        // left" right up until it is gone.
                        let caption = widget::text::caption(if remaining == 1 {
                            "expires in 1 second".to_owned()
                        } else {
                            format!("expires in {remaining} seconds")
                        });
                        let caption = if remaining <= 5 {
                            caption.class(cosmic::theme::Text::Color(
                                cosmic::theme::active().cosmic().destructive_color().into(),
                            ))
                        } else {
                            caption
                        };
                        column = column.push(
                            widget::column::with_capacity(2)
                                .spacing(spacing.space_xxxs)
                                .push(bar)
                                .push(caption),
                        );

                        // Enrolling the same account on a phone needs the
                        // seed, not the code — so this is a secret going on
                        // screen, and it hides again with everything else.
                        let showing = self
                            .qr
                            .as_ref()
                            .is_some_and(|(shown, _)| *shown == field.name);
                        column = column.push(
                            widget::button::standard(if showing {
                                "Hide QR code"
                            } else {
                                "Show QR code"
                            })
                            .on_press(Message::ToggleQr(field.name.clone())),
                        );
                        if let Some((_, data)) = self.qr.as_ref().filter(|(shown, _)| {
                            *shown == field.name
                        }) {
                            column = column.push(
                                widget::column::with_capacity(2)
                                    .spacing(spacing.space_xxs)
                                    .align_x(Alignment::Center)
                                    .width(Length::Fill)
                                    .push(widget::qr_code::QRCode::new(data).cell_size(5.0))
                                    .push(
                                        widget::text::caption(
                                            "Scan to add this account to an authenticator \
                                             app. Anyone who photographs this can generate \
                                             your codes.",
                                        )
                                        .center(),
                                    ),
                            );
                        }
                    }
                    Err(e) => {
                        column = column
                            .push(widget::text::caption(format!("Invalid TOTP seed: {e}")));
                    }
                }
                continue;
            }

            column = column.push(self.field_row(
                field.name.clone(),
                field.name.clone(),
                field.value.expose(),
                field.kind,
            ));
        }

        if !item.attributes.is_empty() {
            let mut attrs = widget::column::with_capacity(item.attributes.len() + 1)
                .spacing(spacing.space_xxxs)
                .push(widget::text::caption_heading("Secret Service attributes"));
            for (k, v) in &item.attributes {
                attrs = attrs.push(widget::text::caption(format!("{k} = {v}")));
            }
            column = column.push(attrs);
        }

        Some(column.into())
    }
}

impl cosmic::Application for App {
    type Executor = cosmic::executor::Default;
    type Flags = Flags;
    type Message = Message;

    const APP_ID: &'static str = "io.github.idominikos.Passman";

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, flags: Self::Flags) -> (Self, Task<Self::Message>) {
        let mut nav = nav_bar::Model::default();
        for category in [
            Category::All,
            Category::Favorites,
            Category::Kind(ItemKind::Login),
            Category::Kind(ItemKind::Note),
            Category::Kind(ItemKind::SshKey),
            Category::Kind(ItemKind::ApiToken),
            Category::Kind(ItemKind::OAuth),
            Category::Kind(ItemKind::Card),
            Category::Kind(ItemKind::WifiNetwork),
            Category::Kind(ItemKind::Application),
            Category::Security,
            Category::Settings,
        ] {
            nav.insert()
                .text(category.label())
                .icon(widget::icon::from_name(category.icon_name()).icon())
                .data(category);
        }
        nav.activate_position(0);

        let config = config::config();
        let settings = config.as_ref().map(Settings::load).unwrap_or_default();
        let vault_exists = flags.vault_path.is_file();

        let app = App {
            core,
            nav,
            vault_path: flags.vault_path,
            vault_exists,
            vault: None,
            screen: Screen::Locked,
            passphrase: String::new(),
            confirm: String::new(),
            show_passphrase: false,
            passphrase_focused: false,
            confirm_focused: false,
            error: None,
            search: String::new(),
            selected: None,
            revealed: HashSet::new(),
            settings,
            config,
            toasts: widget::Toasts::new(Message::CloseToast),
            editor: None,
            import: None,
            last_activity: std::time::Instant::now(),
            status: None,
            pending_delete: None,
            security: Security::default(),
            unlock_requested_by_app: false,
            clipboard_copy: None,
            pending_confirm: None,
            qr: None,
            about: about(),
        };

        // Focus the passphrase field, but not before the window exists.
        //
        // A widget operation is applied against the *current* widget tree, and
        // at `init` there is none — returning `text_input::focus(..)` here, or
        // even bouncing it through one message, lands too early and is
        // silently dropped. Both were tried; neither produced a focus ring.
        // Waiting a beat lets the first frame render, after which the
        // operation finds the field. Verified against the accent ring the
        // COSMIC theme draws on a focused input.
        (
            app,
            cosmic::task::future(async {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                Message::FocusPassphrase
            }),
        )
    }

    fn nav_model(&self) -> Option<&nav_bar::Model> {
        // Hidden while locked: the sidebar is meaningless then, and it leaks a
        // little about which categories hold data.
        //
        // Hidden while editing too, because the editor owns the content area.
        // Leaving it visible gave you controls that silently did nothing when
        // clicked, which is worse than not offering them: the window now
        // commits to the form until you save or cancel.
        (self.screen == Screen::Browsing && self.editor.is_none() && self.import.is_none())
            .then_some(&self.nav)
    }

    fn on_nav_select(&mut self, id: nav_bar::Id) -> Task<Self::Message> {
        self.nav.activate(id);
        self.selected = None;
        self.conceal();
        self.core.window.show_context = false;

        // Read the integration state each time the screen is opened rather
        // than caching it for the session: the whole point is to notice when
        // something else has taken the bus name or the portal away.
        if self.category() == Category::Settings {
            self.status = None;
            return Task::batch([self.update_title(), Self::refresh_status()]);
        }
        self.update_title()
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        // Anything that is not the clock ticking counts as the user being
        // here. Without this the idle timer would fire mid-session, because
        // `Tick` and `IdleCheck` arrive every second regardless.
        if !matches!(
            message,
            Message::Tick | Message::IdleCheck | Message::Daemon(_) | Message::CloseToast(_)
        ) {
            self.last_activity = std::time::Instant::now();
        }

        match message {
            Message::PassphraseChanged(v) => {
                self.passphrase = v;
                self.error = None;
            }
            Message::ConfirmChanged(v) => {
                self.confirm = v;
                self.error = None;
            }
            Message::ToggleShowPassphrase => self.show_passphrase = !self.show_passphrase,

            Message::UnlockSubmit => {
                if self.screen == Screen::Unlocking {
                    return Task::none();
                }
                let creating = !self.vault_exists;
                if self.passphrase.is_empty() {
                    self.error = Some("Enter a passphrase.".into());
                    return Task::none();
                }
                if creating && self.passphrase != self.confirm {
                    self.error = Some("The two passphrases do not match.".into());
                    return Task::none();
                }

                let path = self.vault_path.clone();
                let passphrase = std::mem::take(&mut self.passphrase);
                // Kept only long enough to forward to the daemon, so one entry
                // unlocks the GUI and every libsecret client together.
                let for_daemon = passphrase.clone();
                self.confirm.clear();
                self.screen = Screen::Unlocking;
                self.error = None;

                // Argon2id is intentionally slow; running it on the UI thread
                // would freeze the window for the duration.
                return cosmic::task::future(async move {
                    let outcome = tokio::task::spawn_blocking(move || {
                        if creating {
                            Vault::create(&path, &passphrase, KdfParams::default())
                        } else {
                            Vault::open(&path, &passphrase)
                        }
                    })
                    .await;

                    match outcome {
                        Ok(Ok(vault)) => {
                            // Best effort: no daemon is a supported setup.
                            let _ = daemon::unlock(for_daemon).await;
                            Message::VaultOpened(Arc::new(Mutex::new(Some(vault))), None)
                        }
                        Ok(Err(e)) => {
                            Message::VaultOpened(Arc::new(Mutex::new(None)), Some(e.to_string()))
                        }
                        Err(e) => Message::VaultOpened(
                            Arc::new(Mutex::new(None)),
                            Some(format!("unlock task failed: {e}")),
                        ),
                    }
                });
            }

            Message::VaultOpened(slot, error) => {
                let vault = slot.lock().ok().and_then(|mut g| g.take());
                match vault {
                    Some(v) => {
                        self.vault = Some(v);
                        self.vault_exists = true;
                        self.screen = Screen::Browsing;
                        self.error = None;
                        return self.update_title();
                    }
                    None => {
                        self.screen = Screen::Locked;
                        self.error = error.or_else(|| Some("Could not open the vault.".into()));
                        self.passphrase_focused = true;
                        return widget::text_input::focus(PASSPHRASE_ID.clone());
                    }
                }
            }

            Message::Lock => {
                // Dropping the vault drops the data-encryption key with it.
                self.vault = None;
                self.screen = Screen::Locked;
                self.selected = None;
                self.conceal();
                self.search.clear();
                self.core.window.show_context = false;
                self.unlock_requested_by_app = false;
                self.passphrase_focused = true;
                let title = self.update_title();
                return Task::batch([
                    title,
                    widget::text_input::focus(PASSPHRASE_ID.clone()),
                    cosmic::task::future(async {
                        daemon::lock().await;
                        Message::DaemonUnlocked(false)
                    }),
                ]);
            }

            Message::SearchChanged(v) => {
                self.search = v;
                self.selected = None;
            }

            Message::Select(id) => {
                self.selected = Some(id);
                self.conceal();
                self.core.window.show_context = true;
            }

            Message::ToggleReveal(name) => {
                if !self.revealed.remove(&name) {
                    self.revealed.insert(name);
                }
            }

            Message::ToggleQr(name) => {
                if self.qr.as_ref().is_some_and(|(shown, _)| *shown == name) {
                    self.qr = None;
                    return Task::none();
                }
                // Built from the parsed seed rather than passed through
                // verbatim: a bare base32 secret is not a URI, and a phone
                // given one would fall back to SHA-1 and 30 seconds whatever
                // this account actually uses.
                let uri = {
                    let Some(item) = self.selected_item() else {
                        return Task::none();
                    };
                    let Some(field) = item.fields.iter().find(|f| f.name == name) else {
                        return Task::none();
                    };
                    match Totp::parse(field.value.expose()) {
                        Ok(mut totp) => {
                            // An unlabelled seed would arrive on the phone as
                            // an anonymous entry; the item's own name is the
                            // only thing here that says which account it is.
                            if totp.issuer.is_none() && totp.account.is_none() {
                                totp.account = Some(item.label.clone());
                            }
                            totp.to_uri()
                        }
                        Err(e) => return self.toast(format!("Invalid TOTP seed: {e}")),
                    }
                };
                match widget::qr_code::Data::new(uri) {
                    Ok(data) => self.qr = Some((name, data)),
                    Err(e) => return self.toast(format!("Could not build a QR code: {e}")),
                }
            }

            Message::CopyValue(what, value) => {
                let clear_after = self.settings.clipboard_clear_seconds;
                // Kept so the timer can tell "our secret is still there" from
                // "the user has copied something else since".
                self.clipboard_copy = Some(value.clone());
                let copy = cosmic::iced::clipboard::write::<cosmic::Action<Message>>(value);
                let notice = self.toast(if clear_after > 0 {
                    format!("{what} copied — clipboard clears in {clear_after}s")
                } else {
                    format!("{what} copied")
                });

                if clear_after == 0 {
                    return Task::batch([copy, notice]);
                }
                let clear = cosmic::task::future(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(clear_after)).await;
                    Message::ClearClipboard
                });
                return Task::batch([copy, notice, clear]);
            }

            Message::ClearClipboard => {
                // Look before wiping: between the copy and this timer the user
                // may well have copied something of their own, and clearing
                // the clipboard out from under them is its own small disaster.
                return cosmic::iced::clipboard::read()
                    .map(|current| cosmic::Action::App(Message::ClipboardChecked(current)));
            }

            Message::ClipboardChecked(current) => {
                let ours = self.clipboard_copy.take();
                if current.is_some() && current == ours {
                    // Overwrite rather than clear: some clipboard managers
                    // treat an empty payload as "no change" and keep serving
                    // the old value.
                    return cosmic::iced::clipboard::write::<cosmic::Action<Message>>(
                        String::new(),
                    );
                }
                tracing::debug!("clipboard holds something else now; leaving it alone");
            }

            Message::ToggleFavorite(id) => {
                self.reload_if_changed();
                if let Some(vault) = self.vault.as_mut() {
                    if let Some(item) = vault.item_mut(id) {
                        item.favorite = !item.favorite;
                        item.touch();
                    }
                    match self.save_vault() {
                        Ok(task) => return task,
                        Err(e) => return self.toast(e),
                    }
                }
            }

            Message::CloseContext => {
                self.core.window.show_context = false;
                self.selected = None;
                self.conceal();
            }

            Message::Tick => {}

            Message::AnswerConfirm(allow) => {
                let Some((id, key)) = self.pending_confirm.take() else {
                    return Task::none();
                };
                let notice = self.toast(if allow {
                    format!("Allowed one signature with {key}")
                } else {
                    format!("Refused a signature with {key}")
                });
                return Task::batch([
                    cosmic::task::future(async move {
                        daemon::answer_confirm(id, allow).await;
                        Message::Tick
                    }),
                    notice,
                ]);
            }

            Message::SettingsChanged(settings) => {
                if settings == self.settings {
                    return Task::none();
                }
                let auto_lock_changed = settings.auto_lock_seconds != self.settings.auto_lock_seconds;
                self.settings = settings;
                // Anything already on screen was rendered against the old
                // values; re-conceal rather than leave a secret revealed under
                // a setting that now says not to.
                if self.settings.conceal_on_blur {
                    self.revealed.clear();
                }
                if auto_lock_changed {
                    return self.push_auto_lock();
                }
            }

            Message::ReloadVaultFile => {
                if self.reload_if_changed() {
                    return self.update_title();
                }
            }

            Message::CloseToast(id) => self.toasts.remove(id),

            Message::NewItem => {
                let kind = match self.category() {
                    Category::Kind(k) => k,
                    _ => ItemKind::Login,
                };
                self.editor = Some(Editor::new(kind));
                self.core.window.show_context = false;
                return self.update_title();
            }

            Message::EditSelected => {
                if let Some(item) = self.selected_item() {
                    self.editor = Some(Editor::from_item(item));
                    self.core.window.show_context = false;
                    return self.update_title();
                }
            }

            Message::Editor(msg) => {
                let Some(editor) = self.editor.as_mut() else {
                    return Task::none();
                };
                match editor.update(msg) {
                    Outcome::Continue => {}
                    Outcome::Cancel => {
                        self.editor = None;
                        return self.update_title();
                    }
                    Outcome::Save { id, item } => {
                        let item = *item;
                        let label = item.label.clone();
                        let new_id = item.id;
                        let Some(vault) = self.vault.as_mut() else {
                            return Task::none();
                        };
                        match id {
                            // Replace in place so the item keeps its position
                            // and its D-Bus object path stays meaningful.
                            Some(existing) => {
                                if let Some(slot) = vault.item_mut(existing) {
                                    let created = slot.created;
                                    *slot = item;
                                    slot.created = created;
                                    slot.touch();
                                }
                            }
                            None => {
                                vault.add_item_default(item);
                            }
                        }
                        let saved = match self.save_vault() {
                            Ok(task) => task,
                            Err(e) => return self.toast(e),
                        };
                        self.editor = None;
                        self.selected = Some(new_id);
                        let title = self.update_title();
                        return Task::batch([
                            title,
                            saved,
                            self.toast(format!("Saved {label}")),
                        ]);
                    }
                }
            }

            Message::Daemon(event) => match event {
                DaemonEvent::Connected { locked } => {
                    if !locked {
                        self.unlock_requested_by_app = false;
                    }
                    // A daemon that just appeared is running on its own
                    // default; hand it the setting the user actually chose.
                    return self.push_auto_lock();
                }
                DaemonEvent::UnlockRequested => {
                    // Surface it wherever the user is: if the GUI is already
                    // unlocked we still cannot help, because the passphrase is
                    // not retained — so ask again, explaining why.
                    self.unlock_requested_by_app = true;
                    self.editor = None;
                    self.core.window.show_context = false;
                    if self.screen == Screen::Browsing {
                        self.vault = None;
                        self.screen = Screen::Locked;
                    }
                }
                DaemonEvent::ConfirmRequested { id, key } => {
                    // Raise the window: this is a question, and one nobody can
                    // answer from behind whatever they were looking at.
                    self.pending_confirm = Some((id, key));
                }
                // Nothing to do: the next call simply finds no daemon and the
                // frontend falls back to the vault file, which is a supported
                // way to run.
                DaemonEvent::Unavailable => {}
            },

            Message::DaemonUnlocked(ok) => {
                if ok {
                    self.unlock_requested_by_app = false;
                    return self.toast("Unlocked for other applications too");
                }
            }

            Message::FocusSearch => {
                return widget::text_input::focus(SEARCH_ID.clone());
            }

            Message::Preferences(msg) => {
                let mut changed = true;
                match msg {
                    preferences::Message::AutoLockSelected(i) => {
                        match preferences::AUTO_LOCK.get(i) {
                            Some(v) => self.settings.auto_lock_seconds = *v,
                            None => changed = false,
                        }
                    }
                    preferences::Message::ClipboardSelected(i) => {
                        match preferences::CLIPBOARD.get(i) {
                            Some(v) => self.settings.clipboard_clear_seconds = *v,
                            None => changed = false,
                        }
                    }
                    preferences::Message::ConcealToggled(v) => self.settings.conceal_on_blur = v,
                    preferences::Message::CompactListToggled(v) => {
                        self.settings.compact_list = v;
                    }
                    preferences::Message::Loaded(status) => {
                        self.status = Some(status);
                        changed = false;
                    }
                    preferences::Message::Refresh => {
                        self.status = None;
                        return Task::batch([Self::refresh_status()]);
                    }
                    preferences::Message::OpenUrl(url) => return open_url(url),
                }
                if changed {
                    if let Some(config) = self.config.as_ref() {
                        // Written straight through: a preferences screen with a
                        // Save button is a preferences screen you forget to save.
                        self.settings.store(config);
                    }
                    // The daemon holds the key, so the setting has to reach it
                    // too — not only the window it was changed in.
                    return self.push_auto_lock();
                }
            }

            Message::IdleCheck => {
                let limit = self.settings.auto_lock_seconds;
                // Zero disables it; a locked vault has nothing left to lock.
                if limit > 0
                    && self.screen == Screen::Browsing
                    && self.last_activity.elapsed().as_secs() >= limit
                {
                    return self.update(Message::Lock);
                }
            }

            Message::WindowUnfocused => {
                if self.settings.conceal_on_blur {
                    // Only the on-screen reveal is undone; nothing is locked,
                    // because alt-tabbing away is not a request to re-type a
                    // passphrase.
                    self.conceal();
                }
            }

            Message::OpenImport => {
                self.import = Some(import::Import::default());
                self.selected = None;
                self.core.window.show_context = false;
                return self.update_title();
            }

            Message::Import(msg) => return self.update_import(msg),

            Message::ImportFinished(slot, outcome) => {
                // The vault always comes home, whether or not the import
                // worked; losing it here would strand an unlocked session.
                if let Some(vault) = slot.lock().ok().and_then(|mut g| g.take()) {
                    self.vault = Some(vault);
                } else {
                    // Only reachable if the worker died mid-import. The file
                    // on disk is untouched, so re-unlocking recovers.
                    self.screen = Screen::Locked;
                    self.import = None;
                    self.error = Some("The import task failed; unlock again.".into());
                    return self.update_title();
                }

                match outcome {
                    Ok(summary) => {
                        self.import = None;
                        // Notes are things the counts cannot say — a key that
                        // only signs with hardware present, say. One toast per
                        // note, so none of them is buried in a summary line.
                        let mut tasks = vec![self.update_title()];
                        tasks.push(self.toast(format!("Imported {summary}")));
                        for note in &summary.notes {
                            tasks.push(self.toast(note.clone()));
                        }
                        return Task::batch(tasks);
                    }
                    Err(e) => {
                        if let Some(form) = self.import.as_mut() {
                            form.busy = false;
                            form.error = Some(e);
                        }
                    }
                }
            }

            Message::FocusPassphrase => {
                // Focusing through the widget operation does not run the
                // click path, so `on_focus` never fires; say so ourselves.
                self.passphrase_focused = true;
                self.confirm_focused = false;
                return widget::text_input::focus(PASSPHRASE_ID.clone());
            }

            Message::PassphraseFocus(focused) => {
                self.passphrase_focused = focused;
                if focused {
                    self.confirm_focused = false;
                }
            }

            Message::ConfirmFocus(focused) => {
                self.confirm_focused = focused;
                if focused {
                    self.passphrase_focused = false;
                }
            }

            Message::Security(msg) => match msg {
                security::Message::PinChanged(v) => {
                    self.security.pin = v;
                    self.security.error = None;
                }
                security::Message::Dismiss => {
                    self.security.error = None;
                    self.security.notice = None;
                }
                security::Message::Remove(id) => {
                    let Some(vault) = self.vault.as_mut() else {
                        return Task::none();
                    };
                    match vault.remove_slot(id) {
                        Ok(()) => self.security.notice = Some("Factor removed.".into()),
                        Err(e) => self.security.error = Some(e.to_string()),
                    }
                }
                security::Message::Enroll(factor) => {
                    if self.security.busy.is_some() {
                        return Task::none();
                    }
                    // Enrolment blocks — the TPM for the better part of a
                    // second, a security key until somebody touches it. Move
                    // the vault into a worker so the window keeps painting.
                    let Some(vault) = self.vault.take() else {
                        return Task::none();
                    };
                    let pin = std::mem::take(&mut self.security.pin);
                    self.security.busy = Some(factor);
                    self.security.error = None;
                    self.security.notice = None;

                    return cosmic::task::future(async move {
                        let outcome = tokio::task::spawn_blocking(move || {
                            let mut vault = vault;
                            let result = match factor {
                                security::Factor::TpmPin => {
                                    security::enroll_tpm(&mut vault, &pin)
                                }
                                security::Factor::SecurityKey => {
                                    security::enroll_fido(&mut vault, &pin)
                                }
                            };
                            (vault, result)
                        })
                        .await;

                        match outcome {
                            Ok((vault, result)) => Message::SecurityEnrolled(
                                Arc::new(Mutex::new(Some(vault))),
                                result.err(),
                            ),
                            // The vault is gone with the panicked worker; say
                            // so rather than pretending it is merely locked.
                            Err(e) => Message::SecurityEnrolled(
                                Arc::new(Mutex::new(None)),
                                Some(format!("enrolment task failed: {e}")),
                            ),
                        }
                    });
                }
            },

            Message::SecurityEnrolled(slot, error) => {
                self.security.busy = None;
                self.vault = slot.lock().ok().and_then(|mut g| g.take());
                match error {
                    Some(e) => self.security.error = Some(e),
                    None => {
                        self.security.notice =
                            Some("Factor added. Your passphrase still works.".into())
                    }
                }
                if self.vault.is_none() {
                    // Failing safe: without a vault there is nothing to show.
                    self.screen = Screen::Locked;
                }
            }

            Message::RequestDelete(id) => self.pending_delete = Some(id),
            Message::CancelDelete => self.pending_delete = None,

            Message::ConfirmDelete => {
                let Some(id) = self.pending_delete.take() else {
                    return Task::none();
                };
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                let removed = vault.remove_item(id).map(|i| i.label);
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                if self.selected == Some(id) {
                    self.selected = None;
                    self.core.window.show_context = false;
                }
                if let Some(label) = removed {
                    return Task::batch([saved, self.toast(format!("Deleted {label}"))]);
                }
                return saved;
            }
        }

        Task::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let content = match self.screen {
            Screen::Locked | Screen::Unlocking => self.unlock_view(),
            Screen::Browsing => match &self.editor {
                _ if self.import.is_some() => self
                    .import
                    .as_ref()
                    .expect("just checked")
                    .view()
                    .map(Message::Import),
                Some(editor) => editor.view().map(Message::Editor),
                None if self.category() == Category::Security => self
                    .security
                    .view(self.vault.as_ref())
                    .map(Message::Security),
                None if self.category() == Category::Settings => {
                    preferences::view(&self.settings, self.status.as_ref(), &self.about)
                        .map(Message::Preferences)
                }
                None => self.browse_view(),
            },
        };
        widget::toaster(&self.toasts, content)
    }

    fn context_drawer(&self) -> Option<ContextDrawer<'_, Self::Message>> {
        if !self.core.window.show_context || self.editor.is_some() {
            return None;
        }
        let item = self.selected_item()?;
        let title = item.label.clone();
        Some(context_drawer::context_drawer(self.detail_view()?, Message::CloseContext).title(title))
    }

    fn header_end(&self) -> Vec<Element<'_, Self::Message>> {
        if self.screen != Screen::Browsing {
            return Vec::new();
        }
        let mut actions = Vec::new();
        // Security manages unlock factors, not items — offering "New item"
        // there would be a button that lands you somewhere unrelated.
        if self.editor.is_none() && self.import.is_none() {
            if !matches!(self.category(), Category::Security | Category::Settings) {
                actions.push(
                    widget::button::suggested("New item")
                        .on_press(Message::NewItem)
                        .into(),
                );
            }
            actions.push(
                widget::button::standard("Import")
                    .on_press(Message::OpenImport)
                    .into(),
            );
        }
        actions.push(
            widget::button::standard("Lock")
                .on_press(Message::Lock)
                .into(),
        );
        actions
    }

    fn dialog(&self) -> Option<Element<'_, Self::Message>> {
        // A signing request is somebody waiting on the other end of an ssh
        // connection, so it goes in front of anything else.
        if let Some((_, key)) = &self.pending_confirm {
            return Some(
                widget::dialog()
                    .title("Allow this SSH signature?")
                    .body(format!(
                        "Something on this machine is asking to authenticate with \u{201c}{key}\u{201d}.                          This key is set to ask every time, so nothing happens unless you allow it.",
                    ))
                    .primary_action(
                        widget::button::suggested("Allow once")
                            .on_press(Message::AnswerConfirm(true)),
                    )
                    .secondary_action(
                        widget::button::destructive("Refuse")
                            .on_press(Message::AnswerConfirm(false)),
                    )
                    .into(),
            );
        }

        let id = self.pending_delete?;
        let label = self
            .vault
            .as_ref()
            .and_then(|v| v.item(id))
            .map(|i| i.label.clone())
            .unwrap_or_else(|| "this item".to_owned());

        Some(
            widget::dialog()
                .title("Delete item?")
                .body(format!(
                    "\u{201c}{label}\u{201d} will be removed from the vault. \
                     This cannot be undone, and any application that reads it \
                     through the Secret Service will stop finding it."
                ))
                .primary_action(
                    widget::button::destructive("Delete").on_press(Message::ConfirmDelete),
                )
                .secondary_action(
                    widget::button::standard("Cancel").on_press(Message::CancelDelete),
                )
                .into(),
        )
    }

    /// A second `passman` — usually the applet's "Unlock in passman" — asking
    /// this one to come forward.
    ///
    /// libcosmic has already unminimised and raised the window by the time
    /// this runs; all that is left is to put the caret where the person who
    /// clicked is about to type.
    fn dbus_activation(
        &mut self,
        _message: cosmic::dbus_activation::Message,
    ) -> Task<Self::Message> {
        if self.screen == Screen::Locked {
            return self.update(Message::FocusPassphrase);
        }
        Task::none()
    }

    /// Escape backs out of the innermost thing, in the order they stack.
    fn on_escape(&mut self) -> Task<Self::Message> {
        if self.pending_delete.is_some() {
            self.pending_delete = None;
        } else if self.import.as_ref().is_some_and(|i| !i.busy) {
            // Not while it is running: the vault is out of the app's hands
            // until the task returns it, and there would be nothing to go
            // back to.
            self.import = None;
        } else if self.editor.is_some() {
            // Same path as Cancel, so there is one way to abandon an edit.
            self.editor = None;
        } else if self.core.window.show_context {
            self.core.window.show_context = false;
            self.selected = None;
            self.conceal();
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        let daemon = daemon::subscription().map(Message::Daemon);
        // The settings store is shared with the rest of the desktop, so it can
        // change without this window doing anything.
        let settings = config::subscription().map(Message::SettingsChanged);

        // Only bind shortcuts while browsing: they would fight the passphrase
        // field on the unlock screen, and the editor owns its own typing.
        let shortcuts = if self.screen == Screen::Browsing && self.editor.is_none() {
            // `listen_raw` with an Ignored check, the way libcosmic's own
            // keyboard_nav does it: a shortcut must not fire when a widget has
            // already consumed the key, or Ctrl+F would steal focus from a
            // text field mid-word.
            cosmic::iced::event::listen_raw(|event, status, _| {
                if status != cosmic::iced::event::Status::Ignored {
                    return None;
                }
                let cosmic::iced::Event::Keyboard(
                    cosmic::iced::keyboard::Event::KeyPressed { key, modifiers, .. },
                ) = event
                else {
                    return None;
                };
                if !modifiers.control() {
                    return None;
                }
                match key.as_ref() {
                    cosmic::iced::keyboard::Key::Character("n") => Some(Message::NewItem),
                    cosmic::iced::keyboard::Key::Character("l") => Some(Message::Lock),
                    cosmic::iced::keyboard::Key::Character("f") => Some(Message::FocusSearch),
                    _ => None,
                }
            })
        } else {
            Subscription::none()
        };

        let mut subs = vec![daemon, settings, shortcuts];

        if self.screen == Screen::Browsing && self.selected_item().is_some_and(has_totp) {
            // Only tick while a live one-time code is on screen.
            subs.push(
                cosmic::iced::time::every(std::time::Duration::from_secs(1))
                    .map(|_| Message::Tick),
            );
        }

        // Auto-lock. Polled once a second rather than scheduled for the exact
        // deadline, because the deadline moves every time you touch anything.
        if self.screen == Screen::Browsing && self.settings.auto_lock_seconds > 0 {
            subs.push(
                cosmic::iced::time::every(std::time::Duration::from_secs(1))
                    .map(|_| Message::IdleCheck),
            );
        }

        if self.screen == Screen::Browsing {
            // One stat() every few seconds. The daemon rewrites this file
            // whenever a libsecret client stores something, and a list that
            // silently lags behind the truth is worse than a cheap poll.
            subs.push(
                cosmic::iced::time::every(std::time::Duration::from_secs(3))
                    .map(|_| Message::ReloadVaultFile),
            );
        }

        if self.screen == Screen::Browsing && self.settings.conceal_on_blur {
            subs.push(cosmic::iced::event::listen_with(|event, _, _| {
                matches!(
                    event,
                    cosmic::iced::Event::Window(cosmic::iced::window::Event::Unfocused)
                )
                .then_some(Message::WindowUnfocused)
            }));
        }

        Subscription::batch(subs)
    }
}

fn has_totp(item: &Item) -> bool {
    item.fields.iter().any(|f| f.kind == FieldKind::Totp)
}

/// What the About section says. Everything here comes from the manifest, so a
/// release cannot ship a version string that disagrees with the crate.
fn about() -> widget::about::About {
    let repository = env!("CARGO_PKG_REPOSITORY");
    widget::about::About::default()
        .name("passman")
        .icon(widget::icon::from_name(
            <App as cosmic::Application>::APP_ID,
        ))
        .version(env!("CARGO_PKG_VERSION"))
        // The same line the desktop entry shows, so the app describes itself
        // the same way wherever you meet it.
        .comments("Passwords, keys and secrets for the COSMIC desktop")
        .license(env!("CARGO_PKG_LICENSE"))
        .license_url("https://www.gnu.org/licenses/gpl-3.0.html")
        .links([
            ("Source code", repository.to_owned()),
            ("Report an issue", format!("{repository}/issues")),
        ])
}

/// Hand a URL to the desktop's browser.
///
/// Double-forked and detached by `cosmic::process`, so the browser does not
/// die with passman and passman does not inherit its output.
fn open_url(url: String) -> Task<Message> {
    cosmic::iced::Task::future(async move {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        cosmic::process::spawn(command).await;
    })
    .discard()
}

impl App {
    /// Drive the import screen.
    ///
    /// The vault is moved *out* of the app for the duration of a run rather
    /// than borrowed: importing a password-store shells out to gpg once per
    /// entry, and doing that on the UI thread would freeze the window for as
    /// long as it takes. `ImportFinished` puts it back.
    fn refresh_status() -> Task<Message> {
        cosmic::task::future(async {
            Message::Preferences(preferences::Message::Loaded(Status::gather().await))
        })
    }

    fn update_import(&mut self, msg: import::Message) -> Task<Message> {
        let Some(form) = self.import.as_mut() else {
            return Task::none();
        };

        match msg {
            import::Message::SourceSelected(i) => form.select_source(i),
            import::Message::CollectionChanged(v) => form.collection = v,
            import::Message::GroupingSelected(i) => {
                if let Some(g) = import::GROUPINGS.get(i) {
                    form.grouping = *g;
                }
            }
            import::Message::DatabasePasswordChanged(v) => form.database_password = v,
            import::Message::ToggleShowDatabasePassword => {
                form.show_database_password = !form.show_database_password;
            }
            import::Message::Picked(path) => {
                if path.is_some() {
                    form.path = path;
                    form.error = None;
                }
            }
            import::Message::Cancel => {
                if !form.busy {
                    self.import = None;
                    return self.update_title();
                }
            }

            import::Message::Browse => {
                use cosmic::dialog::file_chooser::{FileFilter, open::Dialog};
                let picker = form.picker();
                return cosmic::task::future(async move {
                    let chosen = match picker {
                        import::Picker::Folder { title } => {
                            Dialog::new().title(title).open_folder().await.ok()
                        }
                        import::Picker::File { title, filter } => {
                            let mut dialog = Dialog::new().title(title);
                            if let Some((label, ext)) = filter {
                                // Glob rather than MIME: a .kdbx has no
                                // registered type on most systems, and a .csv
                                // is reported inconsistently.
                                dialog = dialog.filter(
                                    FileFilter::new(label).glob(&format!("*.{ext}")),
                                );
                            }
                            dialog.open_file().await.ok()
                        }
                    };
                    // A cancelled dialog is not an error; it just leaves the
                    // previous choice, if any, alone.
                    Message::Import(import::Message::Picked(
                        chosen.and_then(|r| r.url().to_file_path().ok()),
                    ))
                });
            }

            import::Message::Run => {
                if !form.is_runnable() {
                    return Task::none();
                }
                let Some(vault) = self.vault.take() else {
                    form.error = Some("The vault is locked.".into());
                    return Task::none();
                };
                let job = import::Job::from(form);
                form.busy = true;
                form.error = None;

                return cosmic::task::future(async move {
                    if job.is_async() {
                        let mut vault = vault;
                        let outcome = import::run_keyring(&mut vault, &job).await;
                        return Message::ImportFinished(
                            Arc::new(Mutex::new(Some(vault))),
                            outcome,
                        );
                    }
                    // Back onto a blocking thread: gpg, Argon2 and a few
                    // thousand file reads have no business on the executor's
                    // core threads.
                    match tokio::task::spawn_blocking(move || {
                        let mut vault = vault;
                        let outcome = import::run_blocking(&mut vault, &job);
                        (vault, outcome)
                    })
                    .await
                    {
                        Ok((vault, outcome)) => {
                            Message::ImportFinished(Arc::new(Mutex::new(Some(vault))), outcome)
                        }
                        // The vault died with the worker. `ImportFinished`
                        // treats an empty slot as "re-unlock"; the file on
                        // disk is untouched.
                        Err(e) => Message::ImportFinished(
                            Arc::new(Mutex::new(None)),
                            Err(format!("the import task failed: {e}")),
                        ),
                    }
                });
            }
        }
        Task::none()
    }

    fn update_title(&mut self) -> Task<Message> {
        // With the sidebar hidden during an edit, the title bar is the only
        // thing left saying where you are.
        let title = match self.screen {
            Screen::Browsing => match &self.editor {
                Some(e) if e.is_new() => "New item — passman".to_owned(),
                Some(_) => "Editing — passman".to_owned(),
                None => format!("{} — passman", self.category().label()),
            },
            Screen::Unlocking => "Unlocking… — passman".to_owned(),
            Screen::Locked => "Locked — passman".to_owned(),
        };
        self.set_header_title(title.clone());
        match self.core.main_window_id() {
            Some(id) => self.set_window_title(title, id),
            None => Task::none(),
        }
    }
}

/// Suggest a strong password for new items.
#[allow(dead_code)]
pub fn suggest_password() -> String {
    generator::password(&PasswordRecipe::default())
        .map(|s| s.expose().to_owned())
        .unwrap_or_default()
}

/// Well-known field display order, so a login always reads
/// username → password → URL rather than in insertion order.
#[allow(dead_code)]
pub const FIELD_ORDER: &[&str] = &[
    field_names::USERNAME,
    field_names::PASSWORD,
    field_names::TOTP,
    field_names::URL,
    field_names::NOTES,
];
