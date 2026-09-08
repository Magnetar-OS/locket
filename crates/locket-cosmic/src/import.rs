//! The import screen.
//!
//! Every importer locket has is reachable from the CLI, but a migration is a
//! one-off thing you do on the day you switch — which is exactly when you are
//! least likely to be reading `--help`. This puts the same four file-based
//! sources behind a file picker, plus the live Secret Service import that
//! makes gnome-keyring hand over what it is holding.
//!
//! The screen deliberately does not offer to delete the source afterwards.
//! Every one of these formats is a plaintext copy of your credentials and
//! should be destroyed, but doing it *for* you means a bug here loses the
//! original before you have confirmed the copy is good.

use std::path::PathBuf;
use std::sync::LazyLock;

use cosmic::widget;
use cosmic::{Apply, Element};
use locket_core::Vault;
use locket_import::{ImportSummary, dotenv};

use crate::fl;

/// Where the secrets are coming from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    BrowserCsv,
    Bitwarden,
    OnePassword,
    ProtonPass,
    DotEnv,
    SshKeys,
    CloudClis,
    Totp,
    PasswordStore,
    KeePass,
    Keyring,
}

impl Source {
    pub const ALL: &'static [Source] = &[
        Source::BrowserCsv,
        Source::Bitwarden,
        Source::OnePassword,
        Source::ProtonPass,
        Source::DotEnv,
        Source::SshKeys,
        Source::CloudClis,
        Source::Totp,
        Source::PasswordStore,
        Source::KeePass,
        Source::Keyring,
    ];

    fn blurb(self) -> String {
        match self {
            Source::BrowserCsv => fl!("source-browser-csv-blurb"),
            Source::Bitwarden => fl!("source-bitwarden-blurb"),
            Source::OnePassword => fl!("source-onepassword-blurb"),
            Source::ProtonPass => fl!("source-protonpass-blurb"),
            Source::DotEnv => fl!("source-dotenv-blurb"),
            Source::PasswordStore => fl!("source-pass-blurb"),
            Source::KeePass => fl!("source-keepass-blurb"),
            Source::SshKeys => fl!("source-ssh-blurb"),
            Source::CloudClis => fl!("source-cloud-blurb"),
            Source::Totp => fl!("source-totp-blurb"),
            Source::Keyring => fl!("source-keyring-blurb"),
        }
    }

    /// Whether this source is a directory rather than a single file.
    fn wants_directory(self) -> bool {
        matches!(
            self,
            Source::DotEnv | Source::PasswordStore | Source::SshKeys
        )
    }

    /// Sources that read a path at all.
    ///
    /// The keyring is reached over D-Bus, and the cloud CLIs are found at
    /// fixed locations under the home directory — asking for a path there
    /// would be asking the user to tell us something we already know.
    fn wants_path(self) -> bool {
        !matches!(self, Source::Keyring | Source::CloudClis)
    }

    fn default_collection(self) -> &'static str {
        match self {
            Source::DotEnv => "Environment",
            Source::SshKeys => "SSH",
            Source::CloudClis => "Cloud",
            Source::Totp => "2FA",
            Source::PasswordStore => "pass",
            Source::KeePass => "KeePass",
            Source::Bitwarden => "Bitwarden",
            Source::OnePassword => "1Password",
            Source::ProtonPass => "Proton Pass",
            _ => "Login",
        }
    }

    /// A path to start the picker in, where there is an obvious one.
    fn default_path(self) -> Option<PathBuf> {
        match self {
            Source::SshKeys => locket_import::ssh::default_dir(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    SourceSelected(usize),
    Browse,
    Picked(Option<PathBuf>),
    CollectionChanged(String),
    GroupingSelected(usize),
    DatabasePasswordChanged(String),
    ToggleShowDatabasePassword,
    Run,
    Cancel,
}

/// A finished import, handed back to the app so it can save and toast.
pub type Outcome = Result<ImportSummary, String>;

pub struct Import {
    pub source: Source,
    pub path: Option<PathBuf>,
    pub collection: String,
    pub grouping: dotenv::Grouping,
    pub database_password: String,
    pub show_database_password: bool,
    /// Set while the import runs; the vault is moved out of the app for the
    /// duration, so nothing else may touch it.
    pub busy: bool,
    pub error: Option<String>,
}

impl Default for Import {
    fn default() -> Self {
        Self {
            source: Source::BrowserCsv,
            path: None,
            collection: Source::BrowserCsv.default_collection().to_owned(),
            grouping: dotenv::Grouping::PerFile,
            database_password: String::new(),
            show_database_password: false,
            busy: false,
            error: None,
        }
    }
}

/// Parallel to [`Source::ALL`]. Resolved once and kept for the life of the
/// process because a dropdown borrows its labels for the lifetime of the view,
/// which a `Vec` built inside `view` cannot satisfy.
static SOURCE_LABELS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        fl!("source-browser-csv"),
        fl!("source-bitwarden"),
        fl!("source-onepassword"),
        fl!("source-protonpass"),
        fl!("source-dotenv"),
        fl!("source-ssh"),
        fl!("source-cloud"),
        fl!("source-totp"),
        fl!("source-pass"),
        fl!("source-keepass"),
        fl!("source-keyring"),
    ]
});

pub const GROUPINGS: &[dotenv::Grouping] = &[
    dotenv::Grouping::PerFile,
    dotenv::Grouping::PerService,
    dotenv::Grouping::PerVariable,
];

static GROUPING_LABELS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        fl!("grouping-per-file"),
        fl!("grouping-per-service"),
        fl!("grouping-per-variable"),
    ]
});

impl Import {
    /// Whether the form has everything the chosen source needs.
    pub fn is_runnable(&self) -> bool {
        !self.busy && (!self.source.wants_path() || self.path.is_some())
    }

    pub fn select_source(&mut self, index: usize) {
        let Some(&source) = Source::ALL.get(index) else {
            return;
        };
        if source == self.source {
            return;
        }
        // A path chosen for one source is meaningless for another, and a
        // stale one left in the field is worse than an empty one.
        self.source = source;
        self.path = source.default_path();
        self.error = None;
        self.collection = source.default_collection().to_owned();
    }

    /// The picker configuration this source needs.
    pub fn picker(&self) -> Picker {
        match self.source {
            Source::DotEnv => Picker::Folder {
                title: fl!("picker-projects"),
            },
            Source::PasswordStore => Picker::Folder {
                title: fl!("picker-password-store"),
            },
            Source::BrowserCsv => Picker::File {
                title: fl!("picker-csv"),
                filter: Some((fl!("picker-csv-filter"), "csv")),
            },
            Source::KeePass => Picker::File {
                title: fl!("picker-kdbx"),
                filter: Some((fl!("picker-kdbx-filter"), "kdbx")),
            },
            Source::Bitwarden => Picker::File {
                title: fl!("picker-bitwarden"),
                filter: Some((fl!("picker-bitwarden-filter"), "json")),
            },
            Source::OnePassword => Picker::File {
                title: fl!("picker-onepassword"),
                filter: Some((fl!("picker-onepassword-filter"), "1pux")),
            },
            Source::ProtonPass => Picker::File {
                title: fl!("picker-protonpass"),
                filter: Some((fl!("picker-protonpass-filter"), "zip")),
            },
            Source::SshKeys => Picker::Folder {
                title: fl!("picker-ssh"),
            },
            Source::Totp => Picker::File {
                title: fl!("picker-totp"),
                filter: None,
            },
            Source::Keyring | Source::CloudClis => Picker::File {
                title: fl!("picker-file"),
                filter: None,
            },
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::active().cosmic().spacing;

        let selected = Source::ALL.iter().position(|s| *s == self.source);

        let mut form = widget::column::with_capacity(10)
            .spacing(spacing.space_m)
            .max_width(620.0)
            .push(widget::text::title3(fl!("import-title")))
            .push(
                widget::dropdown(SOURCE_LABELS.as_slice(), selected, Message::SourceSelected)
                    .apply(widget::container)
                    .width(cosmic::iced::Length::Fill),
            )
            .push(widget::text::body(self.source.blurb()));

        if self.source.wants_path() {
            let chosen = match &self.path {
                Some(p) => p.display().to_string(),
                None if self.source.wants_directory() => fl!("import-no-folder"),
                None => fl!("import-no-file"),
            };
            form = form.push(
                widget::row::with_capacity(2)
                    .spacing(spacing.space_s)
                    .align_y(cosmic::iced::Alignment::Center)
                    .push(widget::text::body(chosen).width(cosmic::iced::Length::Fill))
                    .push(
                        widget::button::standard(if self.source.wants_directory() {
                            fl!("import-choose-folder")
                        } else {
                            fl!("import-choose-file")
                        })
                        .on_press(Message::Browse),
                    ),
            );
        }

        if self.source == Source::DotEnv {
            let selected = GROUPINGS.iter().position(|g| *g == self.grouping);
            form = form.push(widget::settings::section().add(widget::settings::item(
                fl!("import-group-variables"),
                widget::dropdown(
                    GROUPING_LABELS.as_slice(),
                    selected,
                    Message::GroupingSelected,
                ),
            )));
        }

        if self.source == Source::KeePass {
            form = form.push(
                widget::text_input::secure_input(
                    "",
                    &self.database_password,
                    Some(Message::ToggleShowDatabasePassword),
                    !self.show_database_password,
                )
                .label(fl!("import-database-password"))
                .on_input(Message::DatabasePasswordChanged),
            );
        }

        form = form.push(
            widget::text_input(fl!("import-collection-placeholder"), &self.collection)
                .label(fl!("import-into"))
                .on_input(Message::CollectionChanged),
        );

        if let Some(error) = &self.error {
            form = form.push(
                widget::text::body(error.clone()).class(cosmic::theme::Text::Color(
                    cosmic::theme::active().cosmic().destructive_color().into(),
                )),
            );
        }

        let run = widget::button::suggested(if self.busy {
            fl!("import-running")
        } else {
            fl!("import-run")
        });
        let run = if self.is_runnable() {
            run.on_press(Message::Run)
        } else {
            run
        };

        form = form.push(
            widget::row::with_capacity(2)
                .spacing(spacing.space_s)
                .push(run)
                .push(widget::button::standard(fl!("import-cancel")).on_press(Message::Cancel)),
        );

        widget::container(form)
            .padding(spacing.space_l)
            .width(cosmic::iced::Length::Fill)
            .into()
    }
}

/// What kind of file dialog a source needs.
pub enum Picker {
    File {
        title: String,
        /// Label and glob extension for the dialog's file filter.
        filter: Option<(String, &'static str)>,
    },
    Folder {
        title: String,
    },
}

/// Everything an import needs, detached from the UI so it can move into a
/// blocking task along with the vault.
#[derive(Debug, Clone)]
pub struct Job {
    pub source: Source,
    pub path: Option<PathBuf>,
    pub collection: String,
    pub grouping: dotenv::Grouping,
    pub database_password: String,
}

impl Job {
    pub fn from(form: &Import) -> Self {
        Self {
            source: form.source,
            path: form.path.clone(),
            collection: form.collection.clone(),
            grouping: form.grouping,
            database_password: form.database_password.clone(),
        }
    }

    /// Whether this job has to run on an async executor rather than a
    /// blocking thread. Only the keyring import talks D-Bus.
    pub fn is_async(&self) -> bool {
        self.source == Source::Keyring
    }
}

/// Run a file-based import. Saves on success, so a crash afterwards cannot
/// lose what was just imported.
pub fn run_blocking(vault: &mut Vault, job: &Job) -> Outcome {
    refresh(vault);
    let into = (!job.collection.trim().is_empty()).then(|| job.collection.trim());
    let path = job.path.as_deref();

    let summary = match job.source {
        Source::BrowserCsv => {
            let path = path.ok_or_else(|| fl!("import-error-no-file"))?;
            locket_import::csv::import_file(vault, path, into)
        }
        Source::DotEnv => {
            let path = path.ok_or_else(|| fl!("import-error-no-folder"))?;
            locket_import::dotenv::import_dir(vault, path, job.grouping, into)
        }
        Source::PasswordStore => {
            let path = path.ok_or_else(|| fl!("import-error-no-folder"))?;
            locket_import::pass::import_store(vault, path, "gpg", into)
        }
        Source::KeePass => {
            let path = path.ok_or_else(|| fl!("import-error-no-database"))?;
            locket_import::keepass::import_kdbx(vault, path, &job.database_password, None, into)
        }
        Source::SshKeys => {
            let path = path.ok_or_else(|| fl!("import-error-no-folder"))?;
            locket_import::ssh::import_dir(vault, path, into)
        }
        Source::CloudClis => {
            let home = locket_import::cloud::home().ok_or_else(|| fl!("import-error-no-home"))?;
            locket_import::cloud::import_home(vault, &home, "sqlite3", into)
        }
        Source::Totp => {
            let path = path.ok_or_else(|| fl!("import-error-no-file"))?;
            locket_import::totp::import_file(vault, path, into)
        }
        Source::Bitwarden => {
            let path = path.ok_or_else(|| fl!("import-error-no-file"))?;
            locket_import::bitwarden::import_file(vault, path, into)
        }
        Source::OnePassword => {
            let path = path.ok_or_else(|| fl!("import-error-no-file"))?;
            locket_import::onepassword::import_file(vault, path, into)
        }
        Source::ProtonPass => {
            let path = path.ok_or_else(|| fl!("import-error-no-file"))?;
            locket_import::protonpass::import_file(vault, path, into)
        }
        Source::Keyring => {
            return Err(fl!("import-error-keyring-elsewhere"));
        }
    }
    .map_err(|e| e.to_string())?;

    vault.save().map_err(|e| e.to_string())?;
    Ok(summary)
}

/// Bring the vault in line with the file before a long import.
///
/// An import can take a while, and the daemon writes the same file whenever a
/// `libsecret` client stores something. Starting from stale data would mean
/// the save at the end is refused and the whole import is lost.
fn refresh(vault: &mut Vault) {
    if vault.changed_on_disk()
        && let Err(e) = vault.reload()
    {
        tracing::warn!("could not refresh the vault before importing: {e}");
    }
}

/// Run the live Secret Service import.
pub async fn run_keyring(vault: &mut Vault, job: &Job) -> Outcome {
    refresh(vault);
    let into = (!job.collection.trim().is_empty()).then(|| job.collection.trim());
    let summary =
        locket_secret::import::import_from(vault, locket_secret::WELL_KNOWN_NAME, into, false)
            .await
            .map_err(|e| e.to_string())?;
    vault.save().map_err(|e| e.to_string())?;
    // Same fields, different crate: locket-secret cannot depend on
    // locket-import without a cycle, so the two summaries are separate types.
    Ok(ImportSummary {
        collections: summary.collections,
        imported: summary.imported + summary.replaced,
        skipped_duplicate: summary.skipped_duplicate,
        skipped_unreadable: summary.skipped_unreadable,
        notes: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_required_before_a_file_import_can_run() {
        let mut form = Import::default();
        assert!(!form.is_runnable(), "ran without a file");
        form.path = Some(PathBuf::from("/tmp/x.csv"));
        assert!(form.is_runnable());
    }

    #[test]
    fn the_keyring_import_needs_no_path() {
        let mut form = Import::default();
        form.select_source(
            Source::ALL
                .iter()
                .position(|s| *s == Source::Keyring)
                .unwrap(),
        );
        assert!(form.is_runnable(), "the keyring import demanded a file");
    }

    #[test]
    fn switching_source_drops_a_path_chosen_for_the_previous_one() {
        let mut form = Import {
            path: Some(PathBuf::from("/tmp/export.csv")),
            ..Default::default()
        };
        form.select_source(
            Source::ALL
                .iter()
                .position(|s| *s == Source::DotEnv)
                .unwrap(),
        );
        assert_eq!(
            form.path, None,
            "a .csv path survived into a directory import"
        );
        assert_eq!(form.collection, "Environment");
    }

    #[test]
    fn each_source_asks_for_the_right_kind_of_dialog() {
        let mut form = Import::default();
        assert!(matches!(form.picker(), Picker::File { .. }));
        form.select_source(
            Source::ALL
                .iter()
                .position(|s| *s == Source::DotEnv)
                .unwrap(),
        );
        assert!(matches!(form.picker(), Picker::Folder { .. }));
        form.select_source(
            Source::ALL
                .iter()
                .position(|s| *s == Source::PasswordStore)
                .unwrap(),
        );
        assert!(matches!(form.picker(), Picker::Folder { .. }));
    }

    #[test]
    fn a_blank_collection_falls_back_to_the_importers_default() {
        let form = Import {
            collection: "   ".into(),
            ..Default::default()
        };
        let job = Job::from(&form);
        assert!(
            job.collection.trim().is_empty(),
            "the job should carry the blank through; run_blocking maps it to None"
        );
    }
}
