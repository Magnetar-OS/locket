//! The import screen.
//!
//! Every importer passman has is reachable from the CLI, but a migration is a
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

use cosmic::widget;
use cosmic::{Apply, Element};
use passman_core::Vault;
use passman_import::{ImportSummary, dotenv};

/// Where the secrets are coming from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    BrowserCsv,
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
        Source::DotEnv,
        Source::SshKeys,
        Source::CloudClis,
        Source::Totp,
        Source::PasswordStore,
        Source::KeePass,
        Source::Keyring,
    ];

    fn blurb(self) -> &'static str {
        match self {
            Source::BrowserCsv => {
                "A .csv exported from Chrome, Edge, Brave, Firefox, Safari, \
                 Bitwarden, 1Password or KeePassXC. Columns are matched by \
                 name, so a renamed header still imports."
            }
            Source::DotEnv => {
                "Walks a directory of projects and imports every .env file, \
                 skipping node_modules, build output, and .env.example \
                 templates. Your files are left where they are."
            }
            Source::PasswordStore => {
                "A ~/.password-store tree. Each entry is decrypted with gpg, \
                 so the key it was encrypted to has to be available; entries \
                 that cannot be decrypted are counted and skipped."
            }
            Source::KeePass => {
                "A .kdbx database. Groups become tags and TOTP seeds are \
                 carried across."
            }
            Source::SshKeys => {
                "Copies the private keys out of ~/.ssh into the vault, in the \
                 shape passman's own SSH agent reads. Your key files stay \
                 where they are; OpenSSH keeps working exactly as before."
            }
            Source::CloudClis => {
                "Reads the credentials the aws, gcloud, az, gh, docker and \
                 npm tools leave unencrypted in your home directory. Only the \
                 stores you actually have are touched."
            }
            Source::Totp => {
                "A list of otpauth:// URIs, or a plain-text Aegis or andOTP \
                 export. Encrypted backups are refused rather than \
                 half-read — export again without a password."
            }
            Source::Keyring => {
                "Reads everything the keyring currently serving this session \
                 will hand over. Only useful before you take the \
                 org.freedesktop.secrets name away from it."
            }
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
            _ => "Login",
        }
    }

    /// A path to start the picker in, where there is an obvious one.
    fn default_path(self) -> Option<PathBuf> {
        match self {
            Source::SshKeys => passman_import::ssh::default_dir(),
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

/// Parallel to [`Source::ALL`]. Kept as a `'static` table because a dropdown
/// borrows its labels for the lifetime of the view, which a `Vec` built inside
/// `view` cannot satisfy.
const SOURCE_LABELS: &[&str] = &[
    "Browser or password manager export",
    "Project .env files",
    "SSH private keys",
    "Cloud CLI credentials",
    "Authenticator export (TOTP)",
    "pass (password-store)",
    "KeePass database",
    "Running keyring (gnome-keyring)",
];

pub const GROUPINGS: &[dotenv::Grouping] = &[
    dotenv::Grouping::PerFile,
    dotenv::Grouping::PerService,
    dotenv::Grouping::PerVariable,
];

const GROUPING_LABELS: &[&str] = &[
    "One item per .env file",
    "One item per service",
    "One item per variable",
];

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
                title: "Choose a directory of projects",
            },
            Source::PasswordStore => Picker::Folder {
                title: "Choose a password-store directory",
            },
            Source::BrowserCsv => Picker::File {
                title: "Choose an exported .csv",
                filter: Some(("CSV export", "csv")),
            },
            Source::KeePass => Picker::File {
                title: "Choose a .kdbx database",
                filter: Some(("KeePass database", "kdbx")),
            },
            Source::SshKeys => Picker::Folder {
                title: "Choose an SSH directory",
            },
            Source::Totp => Picker::File {
                title: "Choose an authenticator export",
                filter: None,
            },
            Source::Keyring | Source::CloudClis => Picker::File {
                title: "Choose a file",
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
            .push(widget::text::title3("Import secrets"))
            .push(
                widget::dropdown(SOURCE_LABELS, selected, Message::SourceSelected)
                    .apply(widget::container)
                    .width(cosmic::iced::Length::Fill),
            )
            .push(widget::text::body(self.source.blurb()));

        if self.source.wants_path() {
            let chosen = match &self.path {
                Some(p) => p.display().to_string(),
                None if self.source.wants_directory() => "No directory chosen".to_owned(),
                None => "No file chosen".to_owned(),
            };
            form = form.push(
                widget::row::with_capacity(2)
                    .spacing(spacing.space_s)
                    .align_y(cosmic::iced::Alignment::Center)
                    .push(widget::text::body(chosen).width(cosmic::iced::Length::Fill))
                    .push(
                        widget::button::standard(if self.source.wants_directory() {
                            "Choose folder…"
                        } else {
                            "Choose file…"
                        })
                        .on_press(Message::Browse),
                    ),
            );
        }

        if self.source == Source::DotEnv {
            let selected = GROUPINGS.iter().position(|g| *g == self.grouping);
            form = form.push(
                widget::settings::section().add(widget::settings::item(
                    "Group variables",
                    widget::dropdown(GROUPING_LABELS, selected, Message::GroupingSelected),
                )),
            );
        }

        if self.source == Source::KeePass {
            form = form.push(
                widget::text_input::secure_input(
                    "",
                    &self.database_password,
                    Some(Message::ToggleShowDatabasePassword),
                    !self.show_database_password,
                )
                .label("Database password")
                .on_input(Message::DatabasePasswordChanged),
            );
        }

        form = form.push(
            widget::text_input("Collection", &self.collection)
                .label("Import into")
                .on_input(Message::CollectionChanged),
        );

        if let Some(error) = &self.error {
            form = form.push(widget::text::body(error.clone()).class(
                cosmic::theme::Text::Color(
                    cosmic::theme::active().cosmic().destructive_color().into(),
                ),
            ));
        }

        let run = widget::button::suggested(if self.busy { "Importing…" } else { "Import" });
        let run = if self.is_runnable() {
            run.on_press(Message::Run)
        } else {
            run
        };

        form = form.push(
            widget::row::with_capacity(2)
                .spacing(spacing.space_s)
                .push(run)
                .push(widget::button::standard("Cancel").on_press(Message::Cancel)),
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
        title: &'static str,
        filter: Option<(&'static str, &'static str)>,
    },
    Folder {
        title: &'static str,
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
    let into = (!job.collection.trim().is_empty()).then(|| job.collection.trim());
    let path = job.path.as_deref();

    let summary = match job.source {
        Source::BrowserCsv => {
            let path = path.ok_or_else(|| "no file chosen".to_owned())?;
            passman_import::csv::import_file(vault, path, into)
        }
        Source::DotEnv => {
            let path = path.ok_or_else(|| "no directory chosen".to_owned())?;
            passman_import::dotenv::import_dir(vault, path, job.grouping, into)
        }
        Source::PasswordStore => {
            let path = path.ok_or_else(|| "no directory chosen".to_owned())?;
            passman_import::pass::import_store(vault, path, "gpg", into)
        }
        Source::KeePass => {
            let path = path.ok_or_else(|| "no database chosen".to_owned())?;
            passman_import::keepass::import_kdbx(
                vault,
                path,
                &job.database_password,
                None,
                into,
            )
        }
        Source::SshKeys => {
            let path = path.ok_or_else(|| "no directory chosen".to_owned())?;
            passman_import::ssh::import_dir(vault, path, into)
        }
        Source::CloudClis => {
            let home = passman_import::cloud::home()
                .ok_or_else(|| "cannot find your home directory".to_owned())?;
            passman_import::cloud::import_home(vault, &home, "sqlite3", into)
        }
        Source::Totp => {
            let path = path.ok_or_else(|| "no file chosen".to_owned())?;
            passman_import::totp::import_file(vault, path, into)
        }
        Source::Keyring => {
            return Err("the keyring import does not run here".to_owned());
        }
    }
    .map_err(|e| e.to_string())?;

    vault.save().map_err(|e| e.to_string())?;
    Ok(summary)
}

/// Run the live Secret Service import.
pub async fn run_keyring(vault: &mut Vault, job: &Job) -> Outcome {
    let into = (!job.collection.trim().is_empty()).then(|| job.collection.trim());
    let summary =
        passman_secret::import::import_from(vault, passman_secret::WELL_KNOWN_NAME, into, false)
            .await
            .map_err(|e| e.to_string())?;
    vault.save().map_err(|e| e.to_string())?;
    // Same fields, different crate: passman-secret cannot depend on
    // passman-import without a cycle, so the two summaries are separate types.
    Ok(ImportSummary {
        collections: summary.collections,
        imported: summary.imported + summary.replaced,
        skipped_duplicate: summary.skipped_duplicate,
        skipped_unreadable: summary.skipped_unreadable,
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
            Source::ALL.iter().position(|s| *s == Source::Keyring).unwrap(),
        );
        assert!(form.is_runnable(), "the keyring import demanded a file");
    }

    #[test]
    fn switching_source_drops_a_path_chosen_for_the_previous_one() {
        let mut form = Import {
            path: Some(PathBuf::from("/tmp/export.csv")),
            ..Default::default()
        };
        form.select_source(Source::ALL.iter().position(|s| *s == Source::DotEnv).unwrap());
        assert_eq!(form.path, None, "a .csv path survived into a directory import");
        assert_eq!(form.collection, "Environment");
    }

    #[test]
    fn each_source_asks_for_the_right_kind_of_dialog() {
        let mut form = Import::default();
        assert!(matches!(form.picker(), Picker::File { .. }));
        form.select_source(Source::ALL.iter().position(|s| *s == Source::DotEnv).unwrap());
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
