//! Application settings, stored through `cosmic-config`.
//!
//! Using `cosmic-config` rather than a private dotfile means locket's settings
//! live in the same store as the rest of the desktop and — because libcosmic is
//! built with `dbus-config` — are mediated by `cosmic-settings-daemon` when it
//! is running.
//!
//! The store is *watched*, which is what makes it worth having: a change made
//! anywhere else — a second locket window, the settings daemon, someone editing
//! the file — lands in this one without a restart. That watch is
//! [`cosmic::app::ApplicationExt::watch_config`], which already filters to the
//! keys this struct owns and only emits when a value actually changed.

// `APP_ID` is an associated const on the `Application` trait.
use cosmic::Application as _;
use cosmic::cosmic_config::{
    self, Config, CosmicConfigEntry, cosmic_config_derive::CosmicConfigEntry,
};

pub const CONFIG_VERSION: u64 = 1;

/// Everything the preferences screen writes.
///
/// The derive stores one file per field, named after the field, so a rename
/// here is a migration — see [`migrate`].
#[derive(Debug, Clone, PartialEq, Eq, CosmicConfigEntry)]
#[version = 1]
pub struct Settings {
    /// Lock the vault after this many seconds idle. Zero disables auto-lock.
    pub auto_lock_seconds: u64,
    /// Wipe a copied secret from the clipboard after this many seconds.
    /// Zero leaves it there.
    pub clipboard_clear_seconds: u64,
    /// Re-conceal revealed secrets when the window loses focus.
    pub conceal_on_blur: bool,
    /// Drop the subtitle line and tighten the rows, so more items fit on
    /// screen. Worth having once a vault holds a few hundred.
    pub compact_list: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_seconds: 15 * 60,
            clipboard_clear_seconds: 30,
            conceal_on_blur: true,
            compact_list: false,
        }
    }
}

impl Settings {
    /// Load, falling back to the defaults for anything unset or corrupt.
    ///
    /// A missing key is the normal first-run case; a malformed one is logged
    /// and replaced rather than refused.
    pub fn load(config: &Config) -> Self {
        match Self::get_entry(config) {
            Ok(settings) => settings,
            Err((errors, settings)) => {
                for e in errors {
                    tracing::debug!("settings key unavailable ({e}); using the default");
                }
                settings
            }
        }
    }

    /// The write half, driven by the preferences screen.
    pub fn store(&self, config: &Config) {
        if let Err(e) = self.write_entry(config) {
            tracing::warn!("could not persist the settings: {e}");
        }
    }
}

/// Application ids this configuration has been stored under before.
///
/// Oldest first. `cosmic-config` keys are files under `cosmic/<app id>/v<n>`,
/// so a rename moves the whole store and every preference silently reverts to
/// its default.
const LEGACY_APP_IDS: &[&str] = &[
    "io.github.idominikos.Passman",
    "io.github.idominikos.Locket",
];

/// Keys that used to be spelled differently, oldest name first.
///
/// The hand-written store used kebab-case; the derive names each file after
/// its Rust field. Same values, different filenames — so the migration is a
/// copy, not a parse.
const RENAMED_KEYS: &[(&str, &str)] = &[
    ("auto-lock-seconds", "auto_lock_seconds"),
    ("clipboard-clear-seconds", "clipboard_clear_seconds"),
    ("conceal-on-blur", "conceal_on_blur"),
    ("compact-list", "compact_list"),
];

/// Carry settings across from every name they have been stored under.
///
/// Copied rather than moved, so going back to a previous build finds its own
/// settings intact, and only where there is nothing at the new location to
/// overwrite.
fn migrate() {
    let Some(base) = dirs::config_dir().map(|d| d.join("cosmic")) else {
        return;
    };
    let new = base
        .join(crate::app::App::APP_ID)
        .join(format!("v{CONFIG_VERSION}"));

    for legacy in LEGACY_APP_IDS {
        let old = base.join(legacy).join(format!("v{CONFIG_VERSION}"));
        if !old.is_dir() {
            continue;
        }
        copy_missing(&old, &new);
    }

    // Within the store, the keys themselves were renamed.
    for (old_key, new_key) in RENAMED_KEYS {
        let (from, to) = (new.join(old_key), new.join(new_key));
        if from.is_file()
            && !to.exists()
            && let Err(e) = std::fs::copy(&from, &to)
        {
            tracing::warn!("could not carry `{old_key}` over to `{new_key}`: {e}");
        }
    }
}

/// Copy every file in `from` that `to` does not already have.
fn copy_missing(from: &std::path::Path, to: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    let entries: Vec<_> = entries
        .flatten()
        .filter(|e| e.path().is_file())
        .filter(|e| !to.join(e.file_name()).exists())
        .collect();
    if entries.is_empty() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(to) {
        tracing::warn!("could not create the settings directory: {e}");
        return;
    }
    for entry in entries {
        if let Err(e) = std::fs::copy(entry.path(), to.join(entry.file_name())) {
            tracing::warn!("could not carry over {:?}: {e}", entry.file_name());
        }
    }
    tracing::info!("carried settings over from {}", from.display());
}

/// Open the application's config store.
pub fn config() -> Option<Config> {
    migrate();
    match Config::new(crate::app::App::APP_ID, CONFIG_VERSION) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("cosmic-config unavailable ({e}); settings will not persist");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_renamed_key_names_a_field_that_still_exists() {
        // The derive names each file after its field, so a field renamed
        // without a line here silently loses whatever the user had set.
        let defaults = Settings::default();
        let fields = [
            ("auto_lock_seconds", defaults.auto_lock_seconds.to_string()),
            (
                "clipboard_clear_seconds",
                defaults.clipboard_clear_seconds.to_string(),
            ),
            ("conceal_on_blur", defaults.conceal_on_blur.to_string()),
            ("compact_list", defaults.compact_list.to_string()),
        ];
        for (_, new) in RENAMED_KEYS {
            assert!(
                fields.iter().any(|(name, _)| name == new),
                "`{new}` is not a field of Settings"
            );
        }
        assert_eq!(RENAMED_KEYS.len(), fields.len());
    }

    #[test]
    fn a_migration_never_overwrites_what_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (dir.path().join("old"), dir.path().join("new"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join("compact_list"), "true").unwrap();
        std::fs::write(old.join("conceal_on_blur"), "false").unwrap();
        std::fs::write(new.join("compact_list"), "false").unwrap();

        copy_missing(&old, &new);

        assert_eq!(
            std::fs::read_to_string(new.join("compact_list")).unwrap(),
            "false",
            "a value already set at the new location was overwritten"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("conceal_on_blur")).unwrap(),
            "false",
            "a value only the old location had was not carried over"
        );
    }
}
