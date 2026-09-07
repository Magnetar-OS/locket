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
use cosmic::iced::core::text::Wrapping;
use cosmic::iced::keyboard::{Key, Modifiers, key::Physical};
use cosmic::iced::{Alignment, Length, Subscription};
use cosmic::prelude::*;
use cosmic::widget::{self, menu, nav_bar};
use locket_core::{
    Totp, Vault,
    crypto::KdfParams,
    generator::{self, PasswordRecipe},
    model::{FieldKind, Item, ItemKind, field_names},
};
use uuid::Uuid;

use std::sync::LazyLock;

use crate::config::{self, Settings};
use crate::fl;
use crate::labels;
use crate::daemon::{self, DaemonEvent};
use crate::import;
use crate::preferences::{self, Status};
use crate::editor::{Editor, EditorMessage, Outcome};
use crate::security::{self, Security};

/// The application icon, for the About page.
///
/// Embedded rather than looked up by name so it is there in an uninstalled
/// build, where nothing has been written into an icon theme yet.
const APP_ICON: &[u8] =
    include_bytes!("../../../res/icons/hicolor/scalable/apps/io.github.entro314labs.Locket.svg");

/// Id of the search box, so a shortcut can focus it.
static SEARCH_ID: LazyLock<widget::Id> = LazyLock::new(|| widget::Id::new("locket-search"));
/// The unlock screen's passphrase field.
///
/// Focused whenever that screen appears. Without it the window opens with
/// nothing focused: there is no focus ring to show where typing would land,
/// and the placeholder reads like a label that refuses to clear because the
/// user has not actually typed into anything yet.
static PASSPHRASE_ID: LazyLock<widget::Id> =
    LazyLock::new(|| widget::Id::new("locket-passphrase"));

/// Sidebar entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    All,
    Favorites,
    Kind(ItemKind),
    /// Soft-deleted items, restorable until purged.
    Trash,
    /// The password health report: weak, reused, old, expiring.
    Health,
    /// Unlock factors: passphrase, TPM PIN, security key.
    Security,
    /// Preferences, and whether the desktop integration is actually working.
    Settings,
}

impl Category {
    fn label(self) -> String {
        match self {
            Category::All => fl!("category-all"),
            Category::Favorites => fl!("category-favorites"),
            Category::Trash => fl!("category-trash"),
            Category::Health => fl!("category-health"),
            Category::Security => fl!("category-security"),
            Category::Settings => fl!("category-settings"),
            // A category is the plural of its kind, and the plural is its own
            // string: appending an "s" only ever worked in English.
            Category::Kind(k) => labels::kind_plural(k),
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            Category::All => "view-grid-symbolic",
            Category::Favorites => "starred-symbolic",
            Category::Trash => "user-trash-symbolic",
            Category::Health => "emblem-default-symbolic",
            Category::Security => "security-high-symbolic",
            Category::Settings => "preferences-system-symbolic",
            Category::Kind(k) => k.icon_name(),
        }
    }

    fn matches(self, item: &Item) -> bool {
        match self {
            Category::All => true,
            Category::Favorites => item.favorite,
            // None of these screens list live items: Trash and Health draw
            // their own lists rather than filtering this one.
            Category::Trash | Category::Health | Category::Security | Category::Settings => false,
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
    CopyValue(String, String),
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
    // -- trash --
    RestoreTrashed(Uuid),
    RetentionSelected(usize),
    RequestPurge(PurgeTarget),
    ConfirmPurge,
    CancelPurge,
    // -- history --
    RestoreRevision(usize),
    RequestForgetHistory,
    ConfirmForgetHistory,
    CancelForgetHistory,
    // -- attachments --
    AttachmentAdd,
    /// The picked file, read off the UI thread: name and bytes, or `None`
    /// when the dialog was cancelled, or an error string.
    AttachmentLoaded(Option<Result<(String, Vec<u8>), String>>),
    AttachmentSave(Uuid),
    /// Where to write attachment `0`, or `None` when cancelled.
    AttachmentWrite(Uuid, Option<PathBuf>),
    /// The write finished: the path on success, the error otherwise.
    AttachmentWritten(Result<String, String>),
    AttachmentRemove(Uuid),
    // -- vaults and merging --
    OpenVaultDialog,
    VaultPicked(Option<PathBuf>),
    MergeDialog,
    MergePicked(Option<PathBuf>),
    DismissConflict,
    MergeConflict,
    // -- export --
    /// A format was picked from the menu; plaintext ones detour through a
    /// warning dialog, kdbx through a passphrase dialog.
    ExportRequest(ExportFormat),
    /// The warning/passphrase dialog was accepted; open the save dialog.
    ExportContinue,
    ExportCancel,
    ExportKdbxPassphrase(String),
    ExportKdbxConfirm(String),
    /// Where to write, or `None` when the save dialog was cancelled.
    ExportPicked(ExportFormat, Option<PathBuf>),
    /// A kdbx export finished off-thread; the vault comes home in the slot,
    /// the result carries (count, path) or the error.
    ExportFinished(Arc<Mutex<Option<Vault>>>, Result<(usize, String), String>),
    // -- auto-type --
    AutoType,
    AutoTyped(Result<String, String>),
    // -- health --
    /// The report finished on its worker thread.
    HealthReady(Box<locket_core::health::HealthReport>),
    CheckBreaches,
    /// The breach check finished: per item, how often its secret appears in
    /// known breaches (zero-count items are omitted); or the error.
    BreachesChecked(Result<Vec<(Uuid, u64)>, String>),
    // -- daemon --
    Daemon(DaemonEvent),
    DaemonUnlocked(bool),
    // -- unlock factors --
    Security(security::Message),
    /// Move focus to the search box.
    FocusSearch,
    /// A key was pressed while no widget wanted it.
    Key(Modifiers, Physical, Key),
    /// Show the About section, which lives at the foot of Settings.
    OpenAbout,
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
    /// The passphrase change finished; same shared-slot arrangement — the
    /// vault was in a worker for the Argon2 work.
    PassphraseRotated(Arc<Mutex<Option<Vault>>>, Option<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Locked,
    Unlocking,
    Browsing,
}

/// What a purge confirmation is about to destroy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeTarget {
    One(Uuid),
    All,
}

pub use locket_import::export::Format as ExportFormat;

/// The retention windows the trash screen offers, parallel to
/// [`RETENTION_LABELS`]. `None` keeps trash until emptied by hand.
const RETENTION: &[Option<u32>] = &[Some(7), Some(30), Some(90), None];

static RETENTION_LABELS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        fl!("retention-7d"),
        fl!("retention-30d"),
        fl!("retention-90d"),
        fl!("retention-never"),
    ]
});

/// The export flow's dialog state.
#[derive(Default)]
struct ExportFlow {
    /// The format awaiting its warning (plaintext) or passphrase (kdbx)
    /// dialog. `None` when no export is in flight.
    pending: Option<ExportFormat>,
    kdbx_passphrase: String,
    kdbx_confirm: String,
    error: Option<String>,
}

pub struct Flags {
    pub vault_path: PathBuf,
}

/// What a second `locket` forwards to the instance already running.
///
/// Nothing: there are no subcommands, and the vault path is not worth passing
/// because switching an unlocked window to another vault mid-session is not
/// something the app can do. A bare activation just raises the window.
impl cosmic::app::CosmicFlags for Flags {
    type SubCommand = String;
    type Args = Vec<String>;
}

/// What the menu bar and the keyboard can ask for.
///
/// Actions rather than messages because `menu::items` looks an action up in
/// the key-bind table to print its shortcut beside the item — which is the
/// only way anybody discovers a shortcut exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MenuAction {
    NewItem,
    Import,
    ExportJson,
    ExportCsv,
    ExportKdbx,
    OpenVault,
    MergeCopy,
    Lock,
    Search,
    About,
}

impl menu::action::MenuAction for MenuAction {
    type Message = Message;

    fn message(&self) -> Self::Message {
        match self {
            MenuAction::NewItem => Message::NewItem,
            MenuAction::Import => Message::OpenImport,
            MenuAction::ExportJson => Message::ExportRequest(ExportFormat::Json),
            MenuAction::ExportCsv => Message::ExportRequest(ExportFormat::Csv),
            MenuAction::ExportKdbx => Message::ExportRequest(ExportFormat::Kdbx),
            MenuAction::OpenVault => Message::OpenVaultDialog,
            MenuAction::MergeCopy => Message::MergeDialog,
            MenuAction::Lock => Message::Lock,
            MenuAction::Search => Message::FocusSearch,
            MenuAction::About => Message::OpenAbout,
        }
    }
}

/// The shortcuts, in one table.
///
/// `KeyBind::matches` compares the whole modifier set and falls back to the
/// physical key, so Ctrl+N is Ctrl+N on a Greek or Cyrillic layout too — where
/// matching `Key::Character("n")` by hand matches nothing at all.
fn key_binds() -> std::collections::HashMap<menu::KeyBind, MenuAction> {
    use menu::key_bind::{KeyBind, Modifier};

    let mut binds = std::collections::HashMap::new();
    let mut bind = |modifiers: Vec<Modifier>, key: &str, action| {
        binds.insert(
            KeyBind {
                modifiers,
                key: Key::Character(key.into()),
            },
            action,
        );
    };
    bind(vec![Modifier::Ctrl], "n", MenuAction::NewItem);
    bind(vec![Modifier::Ctrl], "i", MenuAction::Import);
    bind(vec![Modifier::Ctrl], "l", MenuAction::Lock);
    // Ctrl+F is also delivered by libcosmic's own keyboard navigation, which
    // calls `on_search`; it is in the table so the menu can print it.
    bind(vec![Modifier::Ctrl], "f", MenuAction::Search);
    binds
}

pub struct App {
    core: Core,
    nav: nav_bar::Model,
    key_binds: std::collections::HashMap<menu::KeyBind, MenuAction>,
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
    config: Option<cosmic::cosmic_config::Config>,
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
    /// Trash awaiting a permanent-delete confirmation.
    pending_purge: Option<PurgeTarget>,
    /// An item whose history is about to be dropped for good.
    pending_forget: Option<Uuid>,
    /// A synchroniser's fork found beside the vault, awaiting a decision.
    sync_conflict: Option<PathBuf>,
    /// Forks the user said "not now" to, so the dialog does not nag every
    /// unlock of this session.
    conflict_dismissed: HashSet<PathBuf>,
    /// The export flow's dialogs, when one is open.
    export: ExportFlow,
    /// The health report, computed when the Health screen is opened rather
    /// than per frame — zxcvbn over a whole vault is not redraw-priced work.
    health: Option<locket_core::health::HealthReport>,
    /// Breach-check outcome: item id → occurrence count. `None` until the
    /// user explicitly runs it; it is the one thing here that goes online.
    breaches: Option<Result<Vec<(Uuid, u64)>, String>>,
    checking_breaches: bool,

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
                self.error = Some(fl!("error-changed-elsewhere"));
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
        let saved = match vault.save() {
            Ok(()) => Ok(cosmic::task::future(async {
                daemon::reload().await;
                Message::Tick
            })),
            Err(locket_core::Error::ChangedOnDisk { .. }) => Err(fl!("error-save-conflict")),
            Err(e) => Err(fl!("error-save-failed", error = e.to_string())),
        };
        // A save while the Health screen is up means its numbers may have
        // just changed — an edit from the drawer, a restored revision. The
        // recomputation rides along with the save's own task.
        if saved.is_ok() && self.category() == Category::Health {
            let recompute = self.refresh_health();
            return saved.map(|task| Task::batch([task, recompute]));
        }
        saved
    }

    /// Recompute the health report from the vault as it stands, dropping any
    /// breach results with it — they described the previous state.
    ///
    /// Off the UI thread: zxcvbn over every secret is 1.7 seconds on a
    /// 10,000-item vault (`cargo run --release -p locket-core --example
    /// bench`), which as a synchronous call is a frozen window. The data is
    /// cloned rather than the vault moved, because the clone costs
    /// milliseconds and leaves every other screen usable while the report
    /// runs.
    fn refresh_health(&mut self) -> Task<Message> {
        self.breaches = None;
        let Some(vault) = self.vault.as_ref() else {
            self.health = None;
            return Task::none();
        };
        let data = vault.data().clone();
        cosmic::task::future(async move {
            let report = tokio::task::spawn_blocking(move || {
                locket_core::health::report(&data, locket_core::model::now())
            })
            .await
            .unwrap_or_default();
            Message::HealthReady(Box::new(report))
        })
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

    /// Fold a diverged copy of the open vault into it, using the DEK already
    /// held — two forks of one vault share a key, so nobody is asked for a
    /// second passphrase. A file that does not decrypt is not a fork, and the
    /// toast says as much.
    fn merge_sibling(&mut self, path: &std::path::Path) -> Task<Message> {
        self.reload_if_changed();
        let Some(vault) = self.vault.as_mut() else {
            return Task::none();
        };
        let other = match vault.open_sibling(path) {
            Ok(data) => data,
            Err(e) => {
                return self.toast(fl!("toast-merge-failed", error = e.to_string()));
            }
        };
        let report = vault.merge_from(other);
        if !report.changed() {
            return self.toast(fl!("toast-merge-nothing"));
        }
        let saved = match self.save_vault() {
            Ok(task) => task,
            Err(e) => return self.toast(e),
        };
        let mut tasks = vec![saved, self.toast(fl!("toast-merged", report = report.to_string()))];
        if report.attachments_dropped > 0 {
            tasks.push(self.toast(fl!(
                "toast-merge-attachments",
                count = report.attachments_dropped
            )));
        }
        Task::batch(tasks)
    }

    // -- views --------------------------------------------------------------

    fn unlock_view(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();
        let creating = !self.vault_exists;

        let heading = if creating {
            fl!("unlock-create-title")
        } else {
            fl!("unlock-title")
        };
        let blurb = if creating {
            fl!("unlock-create-blurb")
        } else if self.unlock_requested_by_app {
            fl!("unlock-app-blurb")
        } else {
            fl!("unlock-blurb")
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
                    if self.passphrase_focused {
                        String::new()
                    } else {
                        fl!("unlock-passphrase")
                    },
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
                        String::new()
                    } else {
                        fl!("unlock-confirm")
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

        // Creating is the one moment this passphrase can still be changed
        // for free, so it is the one moment worth estimating it out loud.
        // Scored against the application's own name, because "locket" is the
        // first thing an attacker would try.
        if creating && !self.passphrase.is_empty() {
            use locket_core::health::Strength;
            let strength = locket_core::health::strength(&self.passphrase, &["locket", "vault"]);
            let named = match strength {
                Strength::VeryWeak => fl!("strength-label-very-weak"),
                Strength::Weak => fl!("strength-label-weak"),
                Strength::Fair => fl!("strength-label-fair"),
                Strength::Good => fl!("strength-label-good"),
                Strength::Strong => fl!("strength-label-strong"),
            };
            let caption = widget::text::caption(fl!("strength-meter", strength = named));
            form = form
                .push(
                    widget::determinate_linear(strength.fraction()).width(Length::Fill),
                )
                .push(if strength.is_flagged() {
                    caption.class(cosmic::theme::Text::Color(
                        cosmic::theme::active().cosmic().destructive_color().into(),
                    ))
                } else {
                    caption
                });
            if strength.is_flagged() {
                form = form.push(
                    widget::text::caption(fl!("unlock-weak-warning"))
                        .wrapping(Wrapping::WordOrGlyph)
                        .center(),
                );
            }
        }

        if let Some(error) = &self.error {
            form = form.push(widget::text::body(error.clone()).class(cosmic::theme::Text::Color(
                cosmic::theme::active().cosmic().destructive_color().into(),
            )));
        }

        let busy = self.screen == Screen::Unlocking;
        let action = widget::button::suggested(if creating {
            fl!("unlock-create-button")
        } else if busy {
            fl!("unlock-working")
        } else {
            fl!("unlock-button")
        });
        form = form.push(if busy {
            action.into()
        } else {
            Element::from(action.on_press(Message::UnlockSubmit))
        });

        // The menu bar is hidden while locked, so without this there is no
        // way to reach a vault that lives somewhere else — the screen would
        // ask forever for the passphrase of a file the person does not have.
        form = form.push(
            widget::button::text(fl!("unlock-open-other")).on_press(Message::OpenVaultDialog),
        );

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
        let search = widget::search_input(
            fl!("search-placeholder", category = category.label()),
            &self.search,
        )
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
                    fl!("empty-no-match", query = self.search.clone()),
                    match category {
                        Category::All => fl!("empty-no-match-all"),
                        other => fl!("empty-no-match-category", category = other.label()),
                    },
                )
            } else if total == 0 {
                (
                    "dialog-password-symbolic",
                    fl!("empty-vault"),
                    fl!("empty-vault-detail"),
                )
            } else {
                (
                    category.icon_name(),
                    fl!("empty-category", category = category.label().to_lowercase()),
                    fl!("empty-category-detail", count = total),
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
                    widget::button::standard(fl!("clear-search"))
                        .on_press(Message::SearchChanged(String::new())),
                );
            } else if category != Category::Security {
                empty = empty
                    .push(widget::button::suggested(fl!("new-item")).on_press(Message::NewItem));
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
                    .push_maybe({
                        // Expired or expiring within 30 days: a credential
                        // about to stop working deserves a mark in the list,
                        // not only in the detail pane.
                        let now = locket_core::model::now();
                        (item.is_expired(now) || item.expires_within(now, 30 * 86_400)).then(
                            || widget::icon::from_name("appointment-missed-symbolic").size(16),
                        )
                    })
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
                widget::button::standard(if revealed {
                    fl!("detail-hide")
                } else {
                    fl!("detail-reveal")
                })
                    .on_press(Message::ToggleReveal(name.clone())),
            );
        }
        let what = if sensitive {
            fl!("copied-kind-secret")
        } else {
            fl!("copied-kind-value")
        };
        controls = controls.push(
            widget::button::standard(fl!("detail-copy"))
                .on_press(Message::CopyValue(what, value.to_owned())),
        );

        widget::column::with_capacity(3)
            .spacing(spacing.space_xxs)
            .push(widget::text::caption_heading(display_name))
            .push(
                widget::row::with_capacity(2)
                    .align_y(Alignment::Center)
                    .spacing(spacing.space_s)
                    .push(if sensitive && revealed {
                        // WordOrGlyph, not Word: a token or a base64 blob has
                        // no word boundaries, and unwrapped it runs under the
                        // buttons beside it.
                        Element::from(
                            widget::text::monotext(shown)
                                .wrapping(Wrapping::WordOrGlyph)
                                .width(Length::Fill),
                        )
                    } else {
                        Element::from(
                            widget::text::body(shown)
                                .wrapping(Wrapping::WordOrGlyph)
                                .width(Length::Fill),
                        )
                    })
                    .push(controls),
            )
            .push(widget::divider::horizontal::default())
            .into()
    }

    /// The health report: weak, reused, old, expiring — and, on request,
    /// breached.
    fn health_view(&self) -> Element<'_, Message> {
        use locket_core::health::Strength;
        let spacing = cosmic::theme::spacing();
        let Some(report) = &self.health else {
            return widget::container(widget::text::body(""))
                .width(Length::Fill)
                .height(Length::Fill)
                .into();
        };

        let breach_count = |id: Uuid| -> Option<u64> {
            match &self.breaches {
                Some(Ok(found)) => found.iter().find(|(i, _)| *i == id).map(|(_, n)| *n),
                _ => None,
            }
        };

        let mut column = widget::column::with_capacity(6)
            .spacing(spacing.space_s)
            .padding(spacing.space_s);

        column = column.push(widget::text::body(fl!(
            "health-summary",
            scanned = report.scanned,
            weak = report.weak,
            reused = report.reused,
            old = report.old,
            expiring = report.expiring,
            expired = report.expired
        )));

        // Items breached but otherwise unflagged still need a row: a strong,
        // unique password sitting in a breach corpus is the finding that
        // matters most. Collect them after the report's own entries.
        let breached_only: Vec<(Uuid, u64)> = match &self.breaches {
            Some(Ok(found)) => found
                .iter()
                .filter(|(id, _)| !report.entries.iter().any(|e| e.id == *id))
                .copied()
                .collect(),
            _ => Vec::new(),
        };

        if report.is_clean() && breached_only.is_empty() {
            let clean = widget::column::with_capacity(3)
                .spacing(spacing.space_xs)
                .align_x(Alignment::Center)
                .push(widget::icon::from_name("emblem-default-symbolic").size(48))
                .push(widget::text::title4(fl!("health-clean")))
                .push(widget::text::body(fl!("health-clean-detail")).center());
            column = column.push(
                widget::container(clean)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .align_x(Alignment::Center)
                    .align_y(Alignment::Center),
            );
        } else {
            let mut list = widget::list_column();
            for e in &report.entries {
                let mut reasons: Vec<String> = Vec::new();
                match e.strength {
                    Some(Strength::VeryWeak) => reasons.push(fl!("strength-very-weak")),
                    Some(Strength::Weak) => reasons.push(fl!("strength-weak")),
                    Some(Strength::Fair) => reasons.push(fl!("strength-fair")),
                    _ => {}
                }
                if e.reused_with > 0 {
                    reasons.push(fl!("health-reason-reused", count = e.reused_with));
                }
                if e.old {
                    reasons.push(fl!("health-reason-old", days = e.age_days));
                }
                if e.expired {
                    reasons.push(fl!("health-reason-expired"));
                } else if e.expiring {
                    reasons.push(fl!("health-reason-expiring"));
                }
                if let Some(count) = breach_count(e.id) {
                    reasons.push(fl!("health-breached", count = count.to_string()));
                }
                list = list.add(self.health_row(e.id, e.kind.icon_name(), &e.label, reasons));
            }
            for (id, count) in &breached_only {
                let Some(item) = self.vault.as_ref().and_then(|v| v.item(*id)) else {
                    continue;
                };
                let finding: String = fl!("health-breached", count = count.to_string());
                list = list.add(self.health_row(
                    *id,
                    item.kind.icon_name(),
                    &item.label,
                    vec![finding],
                ));
            }
            column = column.push(widget::scrollable(list).height(Length::Fill));
        }

        // The one deliberate network affordance in the application, labelled
        // with exactly what leaves the machine.
        column = column.push(
            widget::text::caption(fl!("health-breach-blurb")).wrapping(Wrapping::WordOrGlyph),
        );
        match &self.breaches {
            Some(Ok(found)) if found.is_empty() => {
                column = column.push(widget::text::body(fl!("health-no-breaches")));
            }
            Some(Err(e)) => {
                column = column.push(
                    widget::text::body(fl!("health-breach-failed", error = e.clone())).class(
                        cosmic::theme::Text::Color(
                            cosmic::theme::active().cosmic().destructive_color().into(),
                        ),
                    ),
                );
            }
            _ => {}
        }
        let check = widget::button::standard(if self.checking_breaches {
            fl!("health-checking")
        } else {
            fl!("health-check-breaches")
        });
        column = column.push(if self.checking_breaches {
            Element::from(check)
        } else {
            check.on_press(Message::CheckBreaches).into()
        });

        column.into()
    }

    /// One report row; clicking opens the item so it can be fixed there.
    fn health_row(
        &self,
        id: Uuid,
        icon: &'static str,
        label: &str,
        reasons: Vec<String>,
    ) -> Element<'static, Message> {
        let spacing = cosmic::theme::spacing();
        let row = widget::row::with_capacity(2)
            .spacing(spacing.space_s)
            .align_y(Alignment::Center)
            .push(widget::icon::from_name(icon).size(24))
            .push(
                widget::column::with_capacity(2)
                    .push(widget::text::body(label.to_owned()))
                    .push(widget::text::caption(reasons.join(" · ")))
                    .width(Length::Fill),
            );
        widget::button::custom(row)
            .width(Length::Fill)
            .class(cosmic::theme::Button::Text)
            .on_press(Message::Select(id))
            .into()
    }

    /// The trash: what waits here, when it arrived, and the two ways out.
    fn trash_view(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();
        let Some(vault) = &self.vault else {
            return widget::container(widget::text::body(""))
                .width(Length::Fill)
                .height(Length::Fill)
                .into();
        };
        let trash = &vault.data().trash;

        if trash.is_empty() {
            let empty = widget::column::with_capacity(3)
                .spacing(spacing.space_xs)
                .align_x(Alignment::Center)
                .push(widget::icon::from_name("user-trash-symbolic").size(48))
                .push(widget::text::title4(fl!("empty-trash")))
                .push(widget::text::body(fl!("empty-trash-detail")).center());
            return widget::container(empty)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Alignment::Center)
                .align_y(Alignment::Center)
                .into();
        }

        let mut column = widget::list_column();
        for t in trash {
            let row = widget::row::with_capacity(4)
                .spacing(spacing.space_s)
                .align_y(Alignment::Center)
                .push(widget::icon::from_name(t.item.kind.icon_name()).size(24))
                .push(
                    widget::column::with_capacity(2)
                        .push(widget::text::body(t.item.label.clone()))
                        .push(widget::text::caption(fl!(
                            "trash-deleted-on",
                            date = locket_core::model::format_date(t.deleted)
                        )))
                        .width(Length::Fill),
                )
                .push(
                    widget::button::standard(fl!("trash-restore"))
                        .on_press(Message::RestoreTrashed(t.item.id)),
                )
                .push(
                    widget::button::destructive(fl!("trash-delete-forever"))
                        .on_press(Message::RequestPurge(PurgeTarget::One(t.item.id))),
                );
            column = column.add(row);
        }

        let selected = RETENTION
            .iter()
            .position(|r| *r == vault.data().settings.trash_retention_days);

        widget::column::with_capacity(4)
            .spacing(spacing.space_s)
            .padding(spacing.space_s)
            .push(widget::scrollable(column).height(Length::Fill))
            .push(
                widget::settings::section().add(widget::settings::item(
                    fl!("trash-retention-label"),
                    widget::dropdown(
                        RETENTION_LABELS.as_slice(),
                        selected,
                        Message::RetentionSelected,
                    ),
                )),
            )
            .push(widget::text::caption(fl!("trash-retention-detail")))
            .push(
                widget::button::destructive(fl!("trash-empty-button"))
                    .on_press(Message::RequestPurge(PurgeTarget::All)),
            )
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
                        .push(widget::text::caption(labels::kind(item.kind))),
                ),
        );

        column = column.push(
            widget::row::with_capacity(4)
                .spacing(spacing.space_xxs)
                .push(widget::button::standard(fl!("detail-edit")).on_press(Message::EditSelected))
                // Auto-type wants something to type: a secret, at least.
                .push_maybe((!item.secret.is_empty()).then(|| {
                    widget::button::standard(fl!("detail-autotype"))
                        .on_press(Message::AutoType)
                }))
                .push(
                    widget::button::standard(if item.favorite {
                        fl!("detail-unfavorite")
                    } else {
                        fl!("detail-favorite")
                    })
                    .on_press(Message::ToggleFavorite(item.id)),
                )
                .push(
                    widget::button::destructive(fl!("detail-delete"))
                        .on_press(Message::RequestDelete(item.id)),
                ),
        );

        // Item-level expiry, red once it has passed. Placed above the fields
        // because an expired credential changes how everything below reads.
        if let Some(expires) = item.expires {
            let now = locket_core::model::now();
            let date = locket_core::model::format_date(expires);
            let caption = if item.is_expired(now) {
                widget::text::caption(fl!("detail-expired-on", date = date)).class(
                    cosmic::theme::Text::Color(
                        cosmic::theme::active().cosmic().destructive_color().into(),
                    ),
                )
            } else {
                widget::text::caption(fl!("detail-expires-on", date = date))
            };
            column = column.push(caption);
        }

        // The primary secret, as other applications see it over the
        // Secret Service.
        if !item.secret.is_empty() {
            // A binary secret is base64 at rest; presenting that as the
            // password would be a lie twice over — it is neither text nor,
            // decoded to a lossy string, the secret. Say what it is, and let
            // reveal/copy work on the one faithful text form it has.
            let heading = if item.secret_is_binary() {
                let bytes = item.secret_bytes().len();
                fl!("detail-binary-secret", bytes = bytes)
            } else {
                fl!("detail-password")
            };
            column = column.push(self.field_row(
                "__secret".to_owned(),
                heading,
                item.secret.expose(),
                FieldKind::Secret,
            ));
            if item.secret_is_binary() {
                column = column.push(
                    widget::text::caption(fl!("detail-binary-hint"))
                        .wrapping(Wrapping::WordOrGlyph),
                );
            } else if item.secret_is_mangled() {
                // The replacement characters are stored; the original bytes
                // are gone from the vault. Point at the recovery path rather
                // than presenting damage as if it were the secret.
                column = column.push(
                    widget::text::caption(fl!("detail-mangled-hint"))
                        .wrapping(Wrapping::WordOrGlyph),
                );
            }
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
                            fl!("detail-otp"),
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
                            fl!("detail-expires-one")
                        } else {
                            fl!("detail-expires", seconds = remaining)
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
                                fl!("qr-hide")
                            } else {
                                fl!("qr-show")
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
                                        widget::text::caption(fl!("qr-caption")).center(),
                                    ),
                            );
                        }
                    }
                    Err(e) => {
                        column = column.push(widget::text::caption(fl!(
                            "invalid-totp",
                            error = e.to_string()
                        )));
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
                .push(widget::text::caption_heading(fl!("detail-attributes")));
            for (k, v) in &item.attributes {
                attrs = attrs.push(widget::text::caption(format!("{k} = {v}")));
            }
            column = column.push(attrs);
        }

        // -- attachments ----------------------------------------------------
        column = column
            .push(widget::divider::horizontal::default())
            .push(widget::text::caption_heading(fl!("detail-attachments")));
        for a in &item.attachments {
            column = column.push(
                widget::row::with_capacity(4)
                    .spacing(spacing.space_xxs)
                    .align_y(Alignment::Center)
                    .push(
                        widget::column::with_capacity(2)
                            .push(widget::text::body(a.name.clone()))
                            .push(widget::text::caption(format_size(a.size())))
                            .width(Length::Fill),
                    )
                    .push(
                        widget::button::standard(fl!("attachment-save"))
                            .on_press(Message::AttachmentSave(a.id)),
                    )
                    .push(
                        widget::button::destructive(fl!("attachment-remove"))
                            .on_press(Message::AttachmentRemove(a.id)),
                    ),
            );
        }
        column = column.push(
            widget::button::standard(fl!("attachment-add")).on_press(Message::AttachmentAdd),
        );
        if !item.attachments.is_empty() {
            column = column.push(
                widget::text::caption(fl!("attachment-note")).wrapping(Wrapping::WordOrGlyph),
            );
        }

        // -- history --------------------------------------------------------
        if !item.history.is_empty() {
            column = column
                .push(widget::divider::horizontal::default())
                .push(widget::text::caption_heading(fl!("detail-history")))
                .push(
                    widget::text::caption(fl!("detail-history-note"))
                        .wrapping(Wrapping::WordOrGlyph),
                );
            // Newest first: the revision someone wants is almost always the
            // one their last edit replaced.
            for (index, revision) in item.history.iter().enumerate().rev() {
                column = column.push(
                    widget::row::with_capacity(2)
                        .spacing(spacing.space_xxs)
                        .align_y(Alignment::Center)
                        .push(
                            widget::text::body(fl!(
                                "history-entry",
                                date = locket_core::model::format_date(revision.saved),
                                subtitle = revision.item.subtitle().to_owned()
                            ))
                            .width(Length::Fill),
                        )
                        .push(
                            widget::button::standard(fl!("detail-history-restore"))
                                .on_press(Message::RestoreRevision(index)),
                        ),
                );
            }
            column = column.push(
                widget::button::destructive(fl!("detail-history-forget"))
                    .on_press(Message::RequestForgetHistory),
            );
        }

        Some(column.into())
    }
}

impl cosmic::Application for App {
    type Executor = cosmic::executor::Default;
    type Flags = Flags;
    type Message = Message;

    const APP_ID: &'static str = "io.github.entro314labs.Locket";

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
            Category::Health,
            Category::Trash,
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
            key_binds: key_binds(),
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
            pending_purge: None,
            pending_forget: None,
            sync_conflict: None,
            conflict_dismissed: HashSet::new(),
            export: ExportFlow::default(),
            health: None,
            breaches: None,
            checking_breaches: false,
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
        // Recomputed on entry so the report reflects the vault as it is now;
        // stale breach results from a previous visit are dropped with it.
        if self.category() == Category::Health {
            return Task::batch([self.update_title(), self.refresh_health()]);
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
                    self.error = Some(fl!("error-enter-passphrase"));
                    return Task::none();
                }
                if creating && self.passphrase != self.confirm {
                    self.error = Some(fl!("error-passphrases-differ"));
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
                            Some(fl!("error-unlock-task", error = e.to_string())),
                        ),
                    }
                });
            }

            Message::VaultOpened(slot, error) => {
                let vault = slot.lock().ok().and_then(|mut g| g.take());
                match vault {
                    Some(v) => {
                        // Look for a synchroniser's fork while the directory
                        // listing is cheap and the person is right here to
                        // decide about it.
                        let conflict = v
                            .sync_conflict_siblings()
                            .into_iter()
                            .find(|p| !self.conflict_dismissed.contains(p));
                        self.vault = Some(v);
                        self.vault_exists = true;
                        self.screen = Screen::Browsing;
                        self.error = None;
                        let title = self.update_title();
                        if conflict.is_some() {
                            self.sync_conflict = conflict;
                        }
                        return title;
                    }
                    None => {
                        self.screen = Screen::Locked;
                        self.error = error.or_else(|| Some(fl!("error-open-failed")));
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
                        Err(e) => {
                            return self.toast(fl!("invalid-totp", error = e.to_string()));
                        }
                    }
                };
                match widget::qr_code::Data::new(uri) {
                    Ok(data) => self.qr = Some((name, data)),
                    Err(e) => {
                        return self.toast(fl!("toast-qr-failed", error = e.to_string()));
                    }
                }
            }

            Message::CopyValue(what, value) => {
                let clear_after = self.settings.clipboard_clear_seconds;
                // Kept so the timer can tell "our secret is still there" from
                // "the user has copied something else since".
                self.clipboard_copy = Some(value.clone());
                let copy = cosmic::iced::clipboard::write::<cosmic::Action<Message>>(value);
                let notice = self.toast(if clear_after > 0 {
                    fl!("toast-copied-clearing", what = what, seconds = clear_after)
                } else {
                    fl!("toast-copied", what = what)
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
                    fl!("toast-allowed-signature", key = key)
                } else {
                    fl!("toast-refused-signature", key = key)
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
                            // Applied field by field rather than replaced
                            // wholesale: the editor only speaks for what its
                            // form shows, and a whole-item overwrite silently
                            // destroyed everything it does not — tags,
                            // attachments, history. `edit_item` also files
                            // the state being replaced into history first.
                            Some(existing) => {
                                let _ = vault.edit_item(existing, move |slot| {
                                    slot.label = item.label;
                                    slot.kind = item.kind;
                                    slot.secret = item.secret;
                                    slot.attributes = item.attributes;
                                    slot.fields = item.fields;
                                    slot.favorite = item.favorite;
                                    slot.expires = item.expires;
                                });
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
                            self.toast(fl!("toast-saved", label = label)),
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
                    return self.toast(fl!("toast-unlocked-others"));
                }
            }

            Message::FocusSearch => {
                return widget::text_input::focus(SEARCH_ID.clone());
            }

            Message::Key(modifiers, physical, key) => {
                for (bind, action) in &self.key_binds {
                    if bind.matches(modifiers, &key, Some(&physical)) {
                        return self.update(menu::action::MenuAction::message(action));
                    }
                }
            }

            Message::OpenAbout => {
                // About lives at the foot of Settings rather than in a drawer
                // of its own; take the user there.
                let settings = self
                    .nav
                    .iter()
                    .find(|id| self.nav.data::<Category>(*id) == Some(&Category::Settings));
                if let Some(id) = settings {
                    return self.on_nav_select(id);
                }
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
                    self.error = Some(fl!("error-import-task"));
                    return self.update_title();
                }

                match outcome {
                    Ok(summary) => {
                        self.import = None;
                        // Notes are things the counts cannot say — a key that
                        // only signs with hardware present, say. One toast per
                        // note, so none of them is buried in a summary line.
                        let mut tasks = vec![self.update_title()];
                        tasks.push(self.toast(fl!("toast-imported", summary = summary.to_string())));
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
                security::Message::CurrentPassphrase(v) => {
                    self.security.current = v;
                    self.security.error = None;
                }
                security::Message::NewPassphrase(v) => {
                    self.security.new1 = v;
                    self.security.error = None;
                }
                security::Message::ConfirmPassphrase(v) => {
                    self.security.new2 = v;
                    self.security.error = None;
                }
                security::Message::KdfSelected(i) => {
                    if i < security::KDF_PRESETS.len() {
                        self.security.kdf_index = i;
                    }
                }
                security::Message::ChangePassphrase => {
                    if self.security.changing {
                        return Task::none();
                    }
                    if self.security.new1.is_empty() {
                        self.security.error = Some(fl!("error-new-passphrase-empty"));
                        return Task::none();
                    }
                    if self.security.new1 != self.security.new2 {
                        self.security.error = Some(fl!("error-new-passphrases-differ"));
                        return Task::none();
                    }
                    let Some(vault) = self.vault.take() else {
                        return Task::none();
                    };
                    let params = security::KDF_PRESETS[self.security.kdf_index]();
                    let current = std::mem::take(&mut self.security.current);
                    let new = std::mem::take(&mut self.security.new1);
                    self.security.new2.clear();
                    self.security.changing = true;
                    self.security.error = None;
                    self.security.notice = None;
                    let path = self.vault_path.clone();

                    // Argon2 twice over — verifying the current passphrase,
                    // then deriving the new slot — has no business on the UI
                    // thread.
                    return cosmic::task::future(async move {
                        let outcome = tokio::task::spawn_blocking(move || {
                            let mut vault = vault;
                            // Proof of knowledge first: an unlocked window is
                            // not authority to rotate the owner's passphrase.
                            let result = match Vault::open(&path, &current) {
                                Err(locket_core::Error::WrongPassphrase) => {
                                    Err(fl!("error-current-passphrase-wrong"))
                                }
                                Err(e) => Err(e.to_string()),
                                Ok(_) => vault
                                    .change_passphrase(&new, params)
                                    .map_err(|e| e.to_string()),
                            };
                            (vault, result)
                        })
                        .await;

                        match outcome {
                            Ok((vault, result)) => Message::PassphraseRotated(
                                Arc::new(Mutex::new(Some(vault))),
                                result.err(),
                            ),
                            Err(e) => Message::PassphraseRotated(
                                Arc::new(Mutex::new(None)),
                                Some(fl!("error-enrolment-task", error = e.to_string())),
                            ),
                        }
                    });
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
                        Ok(()) => self.security.notice = Some(fl!("toast-factor-removed")),
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
                                Some(fl!("error-enrolment-task", error = e.to_string())),
                            ),
                        }
                    });
                }
            },

            Message::PassphraseRotated(slot, error) => {
                self.security.changing = false;
                self.security.clear_passphrase_form();
                self.vault = slot.lock().ok().and_then(|mut g| g.take());
                match error {
                    Some(e) => self.security.error = Some(e),
                    None => {
                        self.security.notice = Some(fl!("security-passphrase-changed"));
                        // The daemon's copy of the file just changed under it.
                        return cosmic::task::future(async {
                            daemon::reload().await;
                            Message::Tick
                        });
                    }
                }
                if self.vault.is_none() {
                    self.screen = Screen::Locked;
                }
            }

            Message::SecurityEnrolled(slot, error) => {
                self.security.busy = None;
                self.vault = slot.lock().ok().and_then(|mut g| g.take());
                match error {
                    Some(e) => self.security.error = Some(e),
                    None => {
                        self.security.notice = Some(fl!("toast-factor-added"))
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
                // Soft-delete: the trash keeps it recoverable, and the dialog
                // that got us here already said so.
                let label = vault.item(id).map(|i| i.label.clone());
                let trashed = vault.trash_item(id).is_some();
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                if self.selected == Some(id) {
                    self.selected = None;
                    self.core.window.show_context = false;
                }
                if let Some(label) = label.filter(|_| trashed) {
                    return Task::batch([saved, self.toast(fl!("toast-trashed", label = label))]);
                }
                return saved;
            }

            Message::RestoreTrashed(id) => {
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                let label = vault
                    .data()
                    .trashed(id)
                    .map(|t| t.item.label.clone());
                if vault.restore_item(id).is_none() {
                    return Task::none();
                }
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                let label = label.unwrap_or_default();
                return Task::batch([saved, self.toast(fl!("toast-restored", label = label))]);
            }

            Message::RetentionSelected(index) => {
                let Some(&retention) = RETENTION.get(index) else {
                    return Task::none();
                };
                self.reload_if_changed();
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                if vault.data().settings.trash_retention_days == retention {
                    return Task::none();
                }
                vault.data_mut().settings.trash_retention_days = retention;
                match self.save_vault() {
                    Ok(task) => return task,
                    Err(e) => return self.toast(e),
                }
            }

            Message::RequestPurge(target) => self.pending_purge = Some(target),
            Message::CancelPurge => self.pending_purge = None,

            Message::ConfirmPurge => {
                let Some(target) = self.pending_purge.take() else {
                    return Task::none();
                };
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                let notice = match target {
                    PurgeTarget::One(id) => vault
                        .purge_item(id)
                        .map(|item| fl!("toast-purged", label = item.label)),
                    PurgeTarget::All => {
                        let count = vault.data().trash.len();
                        vault.data_mut().trash.clear();
                        (count > 0).then(|| fl!("toast-trash-emptied", count = count))
                    }
                };
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                if let Some(notice) = notice {
                    return Task::batch([saved, self.toast(notice)]);
                }
                return saved;
            }

            Message::RestoreRevision(index) => {
                let Some(id) = self.selected else {
                    return Task::none();
                };
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                let restored = vault.edit_item(id, |item| {
                    item.restore_revision(index).map(|()| item.label.clone())
                });
                match restored {
                    Ok(Ok(label)) => {
                        self.conceal();
                        let saved = match self.save_vault() {
                            Ok(task) => task,
                            Err(e) => return self.toast(e),
                        };
                        return Task::batch([
                            saved,
                            self.toast(fl!("toast-revision-restored", label = label)),
                        ]);
                    }
                    Ok(Err(e)) | Err(e) => return self.toast(e.to_string()),
                }
            }

            Message::RequestForgetHistory => self.pending_forget = self.selected,
            Message::CancelForgetHistory => self.pending_forget = None,

            Message::ConfirmForgetHistory => {
                let Some(id) = self.pending_forget.take() else {
                    return Task::none();
                };
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                // Not through `edit_item`: recording a revision of the state
                // whose whole point is to have no revisions would be absurd.
                let Some(item) = vault.item_mut(id) else {
                    return Task::none();
                };
                let dropped = item.forget_history();
                let label = item.label.clone();
                if dropped == 0 {
                    return Task::none();
                }
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                return Task::batch([
                    saved,
                    self.toast(fl!(
                        "toast-history-forgotten",
                        count = dropped,
                        label = label
                    )),
                ]);
            }

            Message::AttachmentAdd => {
                if self.selected.is_none() {
                    return Task::none();
                }
                use cosmic::dialog::file_chooser::open::Dialog;
                return cosmic::task::future(async move {
                    let chosen = Dialog::new()
                        .title(fl!("attachment-picker-title"))
                        .open_file()
                        .await
                        .ok()
                        .and_then(|r| r.url().to_file_path().ok());
                    let Some(path) = chosen else {
                        return Message::AttachmentLoaded(None);
                    };
                    // Read off the UI thread; an attachment can be megabytes.
                    let loaded = tokio::fs::read(&path).await.map_err(|e| e.to_string());
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "attachment".to_owned());
                    Message::AttachmentLoaded(Some(loaded.map(|data| (name, data))))
                });
            }

            Message::AttachmentLoaded(outcome) => {
                let Some(outcome) = outcome else {
                    return Task::none(); // cancelled
                };
                let (name, data) = match outcome {
                    Ok(pair) => pair,
                    Err(e) => return self.toast(fl!("toast-attachment-failed", error = e)),
                };
                let Some(id) = self.selected else {
                    return Task::none();
                };
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                let Some(item) = vault.item_mut(id) else {
                    return Task::none();
                };
                let mime = mime_for(&name);
                if let Err(e) = item.add_attachment(&name, mime, data) {
                    return self.toast(fl!("toast-attachment-failed", error = e.to_string()));
                }
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                return Task::batch([saved, self.toast(fl!("toast-attachment-added", name = name))]);
            }

            Message::AttachmentSave(attachment_id) => {
                let Some(item) = self.selected_item() else {
                    return Task::none();
                };
                let Some(attachment) = item.attachment(attachment_id) else {
                    return Task::none();
                };
                let name = attachment.name.clone();
                use cosmic::dialog::file_chooser::save::Dialog;
                return cosmic::task::future(async move {
                    let chosen = Dialog::new()
                        .title(fl!("attachment-save-title"))
                        .file_name(name)
                        .save_file()
                        .await
                        .ok()
                        .and_then(|r| r.url().and_then(|u| u.to_file_path().ok()));
                    Message::AttachmentWrite(attachment_id, chosen)
                });
            }

            Message::AttachmentWrite(attachment_id, path) => {
                let Some(path) = path else {
                    return Task::none(); // cancelled
                };
                let Some(item) = self.selected_item() else {
                    return Task::none();
                };
                let Some(attachment) = item.attachment(attachment_id) else {
                    return Task::none();
                };
                // Cloned so the write can leave the UI thread; wiped with the
                // task. The dialog vouched for the destination, so an existing
                // file there is a choice, not an accident.
                let data = attachment.data.expose().to_vec();
                return cosmic::task::future(async move {
                    let outcome = write_attachment(&path, &data)
                        .await
                        .map(|()| path.display().to_string())
                        .map_err(|e| e.to_string());
                    Message::AttachmentWritten(outcome)
                });
            }

            Message::AttachmentWritten(outcome) => {
                return match outcome {
                    Ok(path) => self.toast(fl!("toast-attachment-saved", path = path)),
                    Err(e) => self.toast(fl!("toast-attachment-failed", error = e)),
                };
            }

            Message::AttachmentRemove(attachment_id) => {
                let Some(id) = self.selected else {
                    return Task::none();
                };
                let Some(vault) = self.vault.as_mut() else {
                    return Task::none();
                };
                let Some(item) = vault.item_mut(id) else {
                    return Task::none();
                };
                let Some(removed) = item.remove_attachment(attachment_id) else {
                    return Task::none();
                };
                let name = removed.name.clone();
                let saved = match self.save_vault() {
                    Ok(task) => task,
                    Err(e) => return self.toast(e),
                };
                return Task::batch([
                    saved,
                    self.toast(fl!("toast-attachment-removed", name = name)),
                ]);
            }

            Message::OpenVaultDialog => {
                use cosmic::dialog::file_chooser::{FileFilter, open::Dialog};
                return cosmic::task::future(async {
                    let chosen = Dialog::new()
                        .title(fl!("vault-picker-title"))
                        .filter(FileFilter::new("locket vault").glob("*.vault"))
                        .open_file()
                        .await
                        .ok()
                        .and_then(|r| r.url().to_file_path().ok());
                    Message::VaultPicked(chosen)
                });
            }

            Message::VaultPicked(path) => {
                let Some(path) = path else {
                    return Task::none(); // cancelled
                };
                if path == self.vault_path {
                    return Task::none();
                }
                // Switching vaults is a lock plus a different unlock target.
                // The daemon keeps serving the system vault regardless; the
                // Settings panel is where that distinction is reported.
                self.vault = None;
                self.vault_path = path;
                self.vault_exists = self.vault_path.is_file();
                self.screen = Screen::Locked;
                self.selected = None;
                self.conceal();
                self.search.clear();
                self.core.window.show_context = false;
                self.passphrase_focused = true;
                let title = self.update_title();
                return Task::batch([title, widget::text_input::focus(PASSPHRASE_ID.clone())]);
            }

            Message::MergeDialog => {
                use cosmic::dialog::file_chooser::{FileFilter, open::Dialog};
                return cosmic::task::future(async {
                    let chosen = Dialog::new()
                        .title(fl!("merge-picker-title"))
                        .filter(FileFilter::new("locket vault").glob("*.vault"))
                        .open_file()
                        .await
                        .ok()
                        .and_then(|r| r.url().to_file_path().ok());
                    Message::MergePicked(chosen)
                });
            }

            Message::MergePicked(path) => {
                let Some(path) = path else {
                    return Task::none(); // cancelled
                };
                return self.merge_sibling(&path);
            }

            Message::ExportRequest(format) => {
                if self.vault.is_none() {
                    return Task::none();
                }
                self.export = ExportFlow {
                    pending: Some(format),
                    ..ExportFlow::default()
                };
            }

            Message::ExportCancel => self.export = ExportFlow::default(),

            Message::ExportKdbxPassphrase(v) => {
                self.export.kdbx_passphrase = v;
                self.export.error = None;
            }
            Message::ExportKdbxConfirm(v) => {
                self.export.kdbx_confirm = v;
                self.export.error = None;
            }

            Message::ExportContinue => {
                let Some(format) = self.export.pending else {
                    return Task::none();
                };
                if format == ExportFormat::Kdbx {
                    if self.export.kdbx_passphrase.is_empty() {
                        self.export.error = Some(fl!("error-new-passphrase-empty"));
                        return Task::none();
                    }
                    if self.export.kdbx_passphrase != self.export.kdbx_confirm {
                        self.export.error = Some(fl!("error-new-passphrases-differ"));
                        return Task::none();
                    }
                }
                let name = match format {
                    ExportFormat::Json => "locket-export.json",
                    ExportFormat::Csv => "locket-export.csv",
                    ExportFormat::Kdbx => "locket-export.kdbx",
                };
                use cosmic::dialog::file_chooser::save::Dialog;
                return cosmic::task::future(async move {
                    let chosen = Dialog::new()
                        .title(fl!("export-save-title"))
                        .file_name(name.to_owned())
                        .save_file()
                        .await
                        .ok()
                        .and_then(|r| r.url().and_then(|u| u.to_file_path().ok()));
                    Message::ExportPicked(format, chosen)
                });
            }

            Message::ExportPicked(format, path) => {
                let Some(path) = path else {
                    self.export = ExportFlow::default();
                    return Task::none(); // cancelled at the save dialog
                };
                // The save dialog already asked about replacing; the module's
                // own refuse-to-overwrite would second-guess an answered
                // question.
                let _ = std::fs::remove_file(&path);

                match format {
                    ExportFormat::Json | ExportFormat::Csv => {
                        self.export = ExportFlow::default();
                        let Some(vault) = self.vault.as_ref() else {
                            return Task::none();
                        };
                        let outcome = match format {
                            ExportFormat::Json => {
                                locket_import::export::to_json(vault, &path).map(|n| (n, 0))
                            }
                            ExportFormat::Csv => locket_import::export::to_csv(vault, &path),
                            ExportFormat::Kdbx => unreachable!("handled below"),
                        };
                        return match outcome {
                            Ok((count, lossy)) => {
                                let mut tasks = vec![self.toast(fl!(
                                    "toast-exported",
                                    count = count,
                                    path = path.display().to_string()
                                ))];
                                if lossy > 0 {
                                    tasks.push(
                                        self.toast(fl!("toast-exported-lossy", count = lossy)),
                                    );
                                }
                                Task::batch(tasks)
                            }
                            Err(e) => {
                                self.toast(fl!("toast-export-failed", error = e.to_string()))
                            }
                        };
                    }
                    ExportFormat::Kdbx => {
                        // The kdbx KDF is deliberately slow; move the vault
                        // into a worker so the window keeps painting.
                        let passphrase = std::mem::take(&mut self.export.kdbx_passphrase);
                        self.export = ExportFlow::default();
                        let Some(vault) = self.vault.take() else {
                            return Task::none();
                        };
                        return cosmic::task::future(async move {
                            let outcome = tokio::task::spawn_blocking(move || {
                                let result =
                                    locket_import::export::to_kdbx(&vault, &path, &passphrase)
                                        .map(|count| (count, path.display().to_string()))
                                        .map_err(|e| e.to_string());
                                (vault, result)
                            })
                            .await;
                            match outcome {
                                Ok((vault, result)) => Message::ExportFinished(
                                    Arc::new(Mutex::new(Some(vault))),
                                    result,
                                ),
                                Err(e) => Message::ExportFinished(
                                    Arc::new(Mutex::new(None)),
                                    Err(e.to_string()),
                                ),
                            }
                        });
                    }
                }
            }

            Message::ExportFinished(slot, outcome) => {
                self.vault = slot.lock().ok().and_then(|mut g| g.take());
                if self.vault.is_none() {
                    self.screen = Screen::Locked;
                }
                return match outcome {
                    Ok((count, path)) => {
                        self.toast(fl!("toast-exported", count = count, path = path))
                    }
                    Err(e) => self.toast(fl!("toast-export-failed", error = e)),
                };
            }

            Message::AutoType => {
                let Some(item) = self.selected_item() else {
                    return Task::none();
                };
                let label = item.label.clone();
                let username = item
                    .field_value(locket_core::model::field_names::USERNAME)
                    .map(str::to_owned);
                let secret = item.secret.clone();
                let armed = self.toast(fl!(
                    "toast-autotype-armed",
                    seconds = crate::autotype::COUNTDOWN_SECS
                ));
                let typing = cosmic::task::future(async move {
                    Message::AutoTyped(
                        crate::autotype::type_credentials(username, secret)
                            .await
                            .map(|()| label),
                    )
                });
                return Task::batch([armed, typing]);
            }

            Message::AutoTyped(outcome) => {
                return match outcome {
                    Ok(label) => self.toast(fl!("toast-autotype-done", label = label)),
                    Err(e) => self.toast(fl!("toast-autotype-failed", error = e)),
                };
            }

            Message::HealthReady(report) => self.health = Some(*report),

            Message::CheckBreaches => {
                if self.checking_breaches {
                    return Task::none();
                }
                let Some(vault) = self.vault.as_ref() else {
                    return Task::none();
                };
                // Clone what the check needs; the request loop must not hold
                // the vault, and the copies are wiped with the task.
                let secrets: Vec<(Uuid, String)> = vault
                    .data()
                    .all_items()
                    .filter(|(_, i)| !i.secret.is_empty() && !i.secret_is_binary())
                    .map(|(_, i)| (i.id, i.secret.expose().to_owned()))
                    .collect();
                self.checking_breaches = true;
                self.breaches = None;
                return cosmic::task::future(async move {
                    let outcome = async {
                        let client = locket_hibp::client().map_err(|e| e.to_string())?;
                        let mut found = Vec::new();
                        for (id, secret) in &secrets {
                            match locket_hibp::pwned_count(&client, secret).await {
                                Ok(0) => {}
                                Ok(count) => found.push((*id, count)),
                                Err(e) => return Err(e.to_string()),
                            }
                        }
                        Ok(found)
                    }
                    .await;
                    Message::BreachesChecked(outcome)
                });
            }

            Message::BreachesChecked(outcome) => {
                self.checking_breaches = false;
                self.breaches = Some(outcome);
            }

            Message::DismissConflict => {
                if let Some(path) = self.sync_conflict.take() {
                    self.conflict_dismissed.insert(path);
                }
            }

            Message::MergeConflict => {
                let Some(path) = self.sync_conflict.take() else {
                    return Task::none();
                };
                self.conflict_dismissed.insert(path.clone());
                return self.merge_sibling(&path);
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
                None if self.category() == Category::Trash => self.trash_view(),
                None if self.category() == Category::Health => self.health_view(),
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

    /// The menu bar.
    ///
    /// The same actions the header buttons offer, but with their shortcuts
    /// printed beside them — a shortcut nothing names is a shortcut nobody
    /// finds. Hidden while locked, where none of it would work.
    fn header_start(&self) -> Vec<Element<'_, Self::Message>> {
        if self.screen != Screen::Browsing {
            return Vec::new();
        }
        let file = menu::Tree::with_children(
            menu::root(fl!("menu-file")).apply(Element::from),
            menu::items(
                &self.key_binds,
                vec![
                    menu::Item::Button(fl!("new-item"), None, MenuAction::NewItem),
                    menu::Item::Button(fl!("import"), None, MenuAction::Import),
                    menu::Item::Folder(
                        fl!("menu-export"),
                        vec![
                            menu::Item::Button(
                                fl!("menu-export-kdbx"),
                                None,
                                MenuAction::ExportKdbx,
                            ),
                            menu::Item::Button(
                                fl!("menu-export-json"),
                                None,
                                MenuAction::ExportJson,
                            ),
                            menu::Item::Button(fl!("menu-export-csv"), None, MenuAction::ExportCsv),
                        ],
                    ),
                    menu::Item::Divider,
                    menu::Item::Button(fl!("menu-open-vault"), None, MenuAction::OpenVault),
                    menu::Item::Button(fl!("menu-merge-copy"), None, MenuAction::MergeCopy),
                    menu::Item::Divider,
                    menu::Item::Button(fl!("lock"), None, MenuAction::Lock),
                ],
            ),
        );
        let view = menu::Tree::with_children(
            menu::root(fl!("menu-view")).apply(Element::from),
            menu::items(
                &self.key_binds,
                vec![
                    menu::Item::Button(fl!("menu-search"), None, MenuAction::Search),
                    menu::Item::Divider,
                    menu::Item::Button(fl!("menu-about"), None, MenuAction::About),
                ],
            ),
        );
        vec![menu::bar(vec![file, view]).into()]
    }

    fn header_end(&self) -> Vec<Element<'_, Self::Message>> {
        if self.screen != Screen::Browsing {
            return Vec::new();
        }
        let mut actions = Vec::new();
        // Security manages unlock factors, not items — offering "New item"
        // there would be a button that lands you somewhere unrelated.
        if self.editor.is_none() && self.import.is_none() {
            if !matches!(
                self.category(),
                Category::Trash | Category::Health | Category::Security | Category::Settings
            ) {
                actions.push(
                    widget::button::suggested(fl!("new-item"))
                        .on_press(Message::NewItem)
                        .into(),
                );
            }
            actions.push(
                widget::button::standard(fl!("import"))
                    .on_press(Message::OpenImport)
                    .into(),
            );
        }
        actions.push(
            widget::button::standard(fl!("lock"))
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
                    .title(fl!("dialog-ssh-title"))
                    .body(fl!("dialog-ssh-body", key = key.clone()))
                    .primary_action(
                        widget::button::suggested(fl!("dialog-allow-once"))
                            .on_press(Message::AnswerConfirm(true)),
                    )
                    .secondary_action(
                        widget::button::destructive(fl!("dialog-refuse"))
                            .on_press(Message::AnswerConfirm(false)),
                    )
                    .into(),
            );
        }

        if let Some(format) = self.export.pending {
            // The plaintext warning, or the kdbx passphrase form.
            let dialog = if format == ExportFormat::Kdbx {
                let spacing = cosmic::theme::spacing();
                let mut form = widget::column::with_capacity(4)
                    .spacing(spacing.space_s)
                    .push(
                        widget::text_input::secure_input(
                            fl!("dialog-kdbx-passphrase"),
                            &self.export.kdbx_passphrase,
                            None,
                            true,
                        )
                        .on_input(Message::ExportKdbxPassphrase),
                    )
                    .push(
                        widget::text_input::secure_input(
                            fl!("dialog-kdbx-confirm"),
                            &self.export.kdbx_confirm,
                            None,
                            true,
                        )
                        .on_input(Message::ExportKdbxConfirm)
                        .on_submit(|_| Message::ExportContinue),
                    );
                if let Some(error) = &self.export.error {
                    form = form.push(widget::text::body(error.clone()).class(
                        cosmic::theme::Text::Color(
                            cosmic::theme::active().cosmic().destructive_color().into(),
                        ),
                    ));
                }
                widget::dialog()
                    .title(fl!("dialog-kdbx-title"))
                    .body(fl!("dialog-kdbx-body"))
                    .control(form)
                    .primary_action(
                        widget::button::suggested(fl!("dialog-kdbx-continue"))
                            .on_press(Message::ExportContinue),
                    )
            } else {
                widget::dialog()
                    .title(fl!("dialog-export-title"))
                    .body(fl!("dialog-export-body"))
                    .primary_action(
                        widget::button::destructive(fl!("dialog-export-continue"))
                            .on_press(Message::ExportContinue),
                    )
            };
            return Some(
                dialog
                    .secondary_action(
                        widget::button::standard(fl!("dialog-cancel"))
                            .on_press(Message::ExportCancel),
                    )
                    .into(),
            );
        }

        if let Some(target) = self.pending_purge {
            let (title, body) = match target {
                PurgeTarget::One(id) => {
                    let label = self
                        .vault
                        .as_ref()
                        .and_then(|v| v.data().trashed(id))
                        .map(|t| t.item.label.clone())
                        .unwrap_or_else(|| fl!("dialog-delete-fallback-label"));
                    (fl!("dialog-purge-title"), fl!("dialog-purge-body", label = label))
                }
                PurgeTarget::All => {
                    let count = self
                        .vault
                        .as_ref()
                        .map(|v| v.data().trash.len())
                        .unwrap_or(0);
                    (
                        fl!("dialog-empty-trash-title"),
                        fl!("dialog-empty-trash-body", count = count),
                    )
                }
            };
            return Some(
                widget::dialog()
                    .title(title)
                    .body(body)
                    .primary_action(
                        widget::button::destructive(fl!("dialog-purge"))
                            .on_press(Message::ConfirmPurge),
                    )
                    .secondary_action(
                        widget::button::standard(fl!("dialog-cancel"))
                            .on_press(Message::CancelPurge),
                    )
                    .into(),
            );
        }

        if let Some(id) = self.pending_forget {
            let label = self
                .vault
                .as_ref()
                .and_then(|v| v.item(id))
                .map(|i| i.label.clone())
                .unwrap_or_else(|| fl!("dialog-delete-fallback-label"));
            return Some(
                widget::dialog()
                    .title(fl!("dialog-forget-history-title"))
                    .body(fl!("dialog-forget-history-body", label = label))
                    .primary_action(
                        widget::button::destructive(fl!("dialog-forget"))
                            .on_press(Message::ConfirmForgetHistory),
                    )
                    .secondary_action(
                        widget::button::standard(fl!("dialog-cancel"))
                            .on_press(Message::CancelForgetHistory),
                    )
                    .into(),
            );
        }

        if let Some(id) = self.pending_delete {
            let label = self
                .vault
                .as_ref()
                .and_then(|v| v.item(id))
                .map(|i| i.label.clone())
                .unwrap_or_else(|| fl!("dialog-delete-fallback-label"));

            return Some(
                widget::dialog()
                    .title(fl!("dialog-delete-title"))
                    .body(fl!("dialog-delete-body", label = label))
                    .primary_action(
                        widget::button::destructive(fl!("dialog-delete"))
                            .on_press(Message::ConfirmDelete),
                    )
                    .secondary_action(
                        widget::button::standard(fl!("dialog-cancel"))
                            .on_press(Message::CancelDelete),
                    )
                    .into(),
            );
        }

        // Last, because it is the least urgent: a sync conflict waited on
        // disk already and can wait through a delete dialog too.
        let conflict = self.sync_conflict.as_ref()?;
        if self.screen != Screen::Browsing {
            return None;
        }
        let name = conflict
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Some(
            widget::dialog()
                .title(fl!("dialog-conflict-title"))
                .body(fl!("dialog-conflict-body", name = name))
                .primary_action(
                    widget::button::suggested(fl!("dialog-merge"))
                        .on_press(Message::MergeConflict),
                )
                .secondary_action(
                    widget::button::standard(fl!("dialog-later"))
                        .on_press(Message::DismissConflict),
                )
                .into(),
        )
    }

    /// A second `locket` — usually the applet's "Unlock in locket" — asking
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

    /// Ctrl+F, delivered by libcosmic's own keyboard navigation.
    ///
    /// Implementing this rather than listening for the key again means one
    /// handler instead of two racing ones.
    fn on_search(&mut self) -> Task<Self::Message> {
        if self.screen == Screen::Browsing && self.editor.is_none() && self.import.is_none() {
            return widget::text_input::focus(SEARCH_ID.clone());
        }
        Task::none()
    }

    /// Escape backs out of the innermost thing, in the order they stack.
    fn on_escape(&mut self) -> Task<Self::Message> {
        if self.export.pending.is_some() {
            self.export = ExportFlow::default();
        } else if self.pending_forget.is_some() {
            self.pending_forget = None;
        } else if self.pending_purge.is_some() {
            self.pending_purge = None;
        } else if self.pending_delete.is_some() {
            self.pending_delete = None;
        } else if self.sync_conflict.is_some() {
            // Escape means "not now", and "not now" is remembered.
            return self.update(Message::DismissConflict);
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
        // change without this window doing anything. libcosmic's own watcher
        // already filters to the keys `Settings` owns and only fires when one
        // of them actually changed.
        let settings = self
            .core()
            .watch_config::<Settings>(Self::APP_ID)
            .map(|update| {
                for e in &update.errors {
                    tracing::debug!("settings watch: {e}");
                }
                Message::SettingsChanged(update.config)
            });

        // Only bind shortcuts while browsing: they would fight the passphrase
        // field on the unlock screen, and the editor owns its own typing.
        let shortcuts = if self.screen == Screen::Browsing && self.editor.is_none() {
            // `listen_raw` with an Ignored check, the way libcosmic's own
            // keyboard_nav does it: a shortcut must not fire when a widget has
            // already consumed the key, or Ctrl+N would fire while somebody is
            // typing an `n` into the search box.
            //
            // The key travels as it arrived — logical key, physical key and
            // modifiers — because deciding what it means is `KeyBind`'s job,
            // and it is the part that knows about keyboard layouts.
            cosmic::iced::event::listen_raw(|event, status, _| {
                if status != cosmic::iced::event::Status::Ignored {
                    return None;
                }
                let cosmic::iced::Event::Keyboard(
                    cosmic::iced::keyboard::Event::KeyPressed {
                        key,
                        physical_key,
                        modifiers,
                        ..
                    },
                ) = event
                else {
                    return None;
                };
                Some(Message::Key(modifiers, physical_key, key))
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

/// Human-readable size, the way a file manager prints it.
fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// A best-effort MIME type from the file extension; the fallback is honest.
fn mime_for(name: &str) -> &'static str {
    match name.rsplit('.').next().map(str::to_lowercase).as_deref() {
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Write attachment bytes where the save dialog pointed, 0600 first.
///
/// The mode is set at open rather than after the write, so the plaintext is
/// never sitting there world-readable even for a moment.
async fn write_attachment(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path).await?;
    use tokio::io::AsyncWriteExt as _;
    file.write_all(data).await?;
    file.sync_all().await
}

/// What the About section says. Everything here comes from the manifest, so a
/// release cannot ship a version string that disagrees with the crate.
fn about() -> widget::about::About {
    let repository = env!("CARGO_PKG_REPOSITORY");
    widget::about::About::default()
        .name(fl!("app-title"))
        // From the file rather than from the icon theme: an uninstalled build
        // has nothing under `hicolor`, and a missing icon on the About page is
        // the first thing anyone running `cargo run` would see.
        .icon(widget::icon::from_svg_bytes(APP_ICON))
        .version(env!("CARGO_PKG_VERSION"))
        // The same line the desktop entry shows, so the app describes itself
        // the same way wherever you meet it.
        .comments(fl!("app-comment"))
        .license(env!("CARGO_PKG_LICENSE"))
        .license_url("https://www.gnu.org/licenses/gpl-3.0.html")
        .links([
            (fl!("about-source-code"), repository.to_owned()),
            (fl!("about-report-issue"), format!("{repository}/issues")),
        ])
}

/// Hand a URL to the desktop's browser.
///
/// Double-forked and detached by `cosmic::process`, so the browser does not
/// die with locket and locket does not inherit its output.
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
                                    FileFilter::new(&label).glob(&format!("*.{ext}")),
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
                Some(e) if e.is_new() => fl!("title-new-item"),
                Some(_) => fl!("title-editing"),
                None => fl!("title-page", page = self.category().label()),
            },
            Screen::Unlocking => fl!("title-unlocking"),
            Screen::Locked => fl!("title-locked"),
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
