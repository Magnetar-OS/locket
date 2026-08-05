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

use crate::config::{self, Settings};
use crate::daemon::{self, DaemonEvent};
use crate::editor::{Editor, EditorMessage, Outcome};

/// Sidebar entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    All,
    Favorites,
    Kind(ItemKind),
}

impl Category {
    fn label(self) -> String {
        match self {
            Category::All => "All Items".to_owned(),
            Category::Favorites => "Favorites".to_owned(),
            Category::Kind(k) => format!("{}s", k.label()),
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            Category::All => "view-grid-symbolic",
            Category::Favorites => "starred-symbolic",
            Category::Kind(k) => k.icon_name(),
        }
    }

    fn matches(self, item: &Item) -> bool {
        match self {
            Category::All => true,
            Category::Favorites => item.favorite,
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
    CopyValue(&'static str, String),
    ClearClipboard,
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
    error: Option<String>,

    search: String,
    selected: Option<Uuid>,
    revealed: HashSet<String>,

    settings: Settings,
    /// Retained for the write path; nothing mutates settings until there is a
    /// preferences UI, so this is read-only for now.
    #[allow(dead_code)]
    config: Option<cosmic_config::Config>,
    toasts: widget::Toasts<Message>,

    /// `Some` while the item editor is open.
    editor: Option<Editor>,
    /// Item awaiting a delete confirmation.
    pending_delete: Option<Uuid>,

    /// Set when the daemon asked for an unlock on an application's behalf, so
    /// the unlock screen can say why it appeared.
    unlock_requested_by_app: bool,
    /// Whether a passmand is reachable at all.
    daemon_present: bool,
}

impl App {
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
                widget::text_input::secure_input(
                    "Passphrase",
                    &self.passphrase,
                    Some(Message::ToggleShowPassphrase),
                    !self.show_passphrase,
                )
                .on_input(Message::PassphraseChanged)
                .on_submit(|_| Message::UnlockSubmit),
            );

        if creating {
            form = form.push(
                widget::text_input::secure_input(
                    "Confirm passphrase",
                    &self.confirm,
                    Some(Message::ToggleShowPassphrase),
                    !self.show_passphrase,
                )
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

        let search = widget::search_input("Search secrets", &self.search)
            .on_input(Message::SearchChanged)
            .on_clear(Message::SearchChanged(String::new()));

        let list: Element<'_, Message> = if items.is_empty() {
            widget::container(
                widget::column::with_capacity(2)
                    .spacing(spacing.space_xs)
                    .align_x(Alignment::Center)
                    .push(widget::icon::from_name("system-search-symbolic").size(48))
                    .push(widget::text::body(if self.search.is_empty() {
                        "Nothing here yet."
                    } else {
                        "No secrets match your search."
                    })),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .into()
        } else {
            let mut column = widget::list_column();
            for item in items {
                let selected = self.selected == Some(item.id);
                let row = widget::row::with_capacity(3)
                    .spacing(spacing.space_s)
                    .align_y(Alignment::Center)
                    .push(widget::icon::from_name(item.kind.icon_name()).size(24))
                    .push(
                        widget::column::with_capacity(2)
                            .push(widget::text::body(item.label.clone()))
                            .push(widget::text::caption(item.subtitle().to_owned()))
                            .width(Length::Fill),
                    )
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
                    .and_then(|t| t.code().map(|c| (c, t.seconds_remaining())));
                match code {
                    Ok((code, remaining)) => {
                        column = column.push(self.field_row(
                            field.name.clone(),
                            format!("One-time code ({remaining}s)"),
                            &code,
                            FieldKind::Text,
                        ));
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
            error: None,
            search: String::new(),
            selected: None,
            revealed: HashSet::new(),
            settings,
            config,
            toasts: widget::Toasts::new(Message::CloseToast),
            editor: None,
            pending_delete: None,
            unlock_requested_by_app: false,
            daemon_present: false,
        };

        (app, Task::none())
    }

    fn nav_model(&self) -> Option<&nav_bar::Model> {
        // The sidebar is meaningless — and a small information leak about how
        // many categories hold data — while locked.
        (self.screen == Screen::Browsing).then_some(&self.nav)
    }

    fn on_nav_select(&mut self, id: nav_bar::Id) -> Task<Self::Message> {
        self.nav.activate(id);
        self.selected = None;
        self.revealed.clear();
        self.core.window.show_context = false;
        Task::none()
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
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
                    }
                }
            }

            Message::Lock => {
                // Dropping the vault drops the data-encryption key with it.
                self.vault = None;
                self.screen = Screen::Locked;
                self.selected = None;
                self.revealed.clear();
                self.search.clear();
                self.core.window.show_context = false;
                self.unlock_requested_by_app = false;
                let title = self.update_title();
                return Task::batch([
                    title,
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
                self.revealed.clear();
                self.core.window.show_context = true;
            }

            Message::ToggleReveal(name) => {
                if !self.revealed.remove(&name) {
                    self.revealed.insert(name);
                }
            }

            Message::CopyValue(what, value) => {
                let clear_after = self.settings.clipboard_clear_seconds;
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
                // Overwrite rather than clear: some clipboard managers treat an
                // empty payload as "no change" and keep serving the old value.
                return cosmic::iced::clipboard::write::<cosmic::Action<Message>>(String::new());
            }

            Message::ToggleFavorite(id) => {
                if let Some(vault) = self.vault.as_mut() {
                    if let Some(item) = vault.item_mut(id) {
                        item.favorite = !item.favorite;
                        item.touch();
                    }
                    if let Err(e) = vault.save() {
                        return self.toast(format!("Could not save: {e}"));
                    }
                }
            }

            Message::CloseContext => {
                self.core.window.show_context = false;
                self.selected = None;
                self.revealed.clear();
            }

            Message::Tick => {}

            Message::CloseToast(id) => self.toasts.remove(id),

            Message::NewItem => {
                let kind = match self.category() {
                    Category::Kind(k) => k,
                    _ => ItemKind::Login,
                };
                self.editor = Some(Editor::new(kind));
                self.core.window.show_context = false;
            }

            Message::EditSelected => {
                if let Some(item) = self.selected_item() {
                    self.editor = Some(Editor::from_item(item));
                    self.core.window.show_context = false;
                }
            }

            Message::Editor(msg) => {
                let Some(editor) = self.editor.as_mut() else {
                    return Task::none();
                };
                match editor.update(msg) {
                    Outcome::Continue => {}
                    Outcome::Cancel => self.editor = None,
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
                        if let Err(e) = vault.save() {
                            return self.toast(format!("Could not save: {e}"));
                        }
                        self.editor = None;
                        self.selected = Some(new_id);
                        return self.toast(format!("Saved {label}"));
                    }
                }
            }

            Message::Daemon(event) => match event {
                DaemonEvent::Connected { locked } => {
                    self.daemon_present = true;
                    if !locked {
                        self.unlock_requested_by_app = false;
                    }
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
                DaemonEvent::Unavailable => self.daemon_present = false,
            },

            Message::DaemonUnlocked(ok) => {
                if ok {
                    self.unlock_requested_by_app = false;
                    return self.toast("Unlocked for other applications too");
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
                if let Err(e) = vault.save() {
                    return self.toast(format!("Could not save: {e}"));
                }
                if self.selected == Some(id) {
                    self.selected = None;
                    self.core.window.show_context = false;
                }
                if let Some(label) = removed {
                    return self.toast(format!("Deleted {label}"));
                }
            }
        }

        Task::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let content = match self.screen {
            Screen::Locked | Screen::Unlocking => self.unlock_view(),
            Screen::Browsing => match &self.editor {
                Some(editor) => editor.view().map(Message::Editor),
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
        if self.editor.is_none() {
            actions.push(
                widget::button::suggested("New item")
                    .on_press(Message::NewItem)
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

    fn subscription(&self) -> Subscription<Self::Message> {
        let daemon = daemon::subscription().map(Message::Daemon);

        if self.screen == Screen::Browsing && self.selected_item().is_some_and(has_totp) {
            // Only tick while a live one-time code is on screen.
            Subscription::batch([
                daemon,
                cosmic::iced::time::every(std::time::Duration::from_secs(1))
                    .map(|_| Message::Tick),
            ])
        } else {
            daemon
        }
    }
}

fn has_totp(item: &Item) -> bool {
    item.fields.iter().any(|f| f.kind == FieldKind::Totp)
}

impl App {
    fn update_title(&mut self) -> Task<Message> {
        let title = match self.screen {
            Screen::Browsing => "passman".to_owned(),
            _ => "passman — Locked".to_owned(),
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
