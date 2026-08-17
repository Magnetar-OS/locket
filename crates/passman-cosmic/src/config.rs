//! Application settings, stored through `cosmic-config`.
//!
//! Using `cosmic-config` rather than a private dotfile means passman's
//! settings live in the same store as the rest of the desktop and — because
//! libcosmic is built with `dbus-config` — are mediated by
//! `cosmic-settings-daemon` when it is running.
//!
//! [`subscription`] is what makes that worth having: the store is watched, so
//! a change made anywhere else — a second passman window, the settings daemon,
//! someone editing the file — lands in this one without a restart.

// `APP_ID` is an associated const on the `Application` trait.
use cosmic::Application as _;
use cosmic::iced::Subscription;
use cosmic::iced::futures::{SinkExt, StreamExt, channel::mpsc};
use cosmic::iced::stream;
use cosmic_config::{Config, ConfigGet, ConfigSet};

pub const CONFIG_VERSION: u64 = 1;

mod key {
    pub const AUTO_LOCK_SECONDS: &str = "auto-lock-seconds";
    pub const CLIPBOARD_CLEAR_SECONDS: &str = "clipboard-clear-seconds";
    pub const CONCEAL_ON_BLUR: &str = "conceal-on-blur";
    pub const COMPACT_LIST: &str = "compact-list";

    /// Every key this application owns, for filtering watch notifications.
    pub const ALL: &[&str] = &[
        AUTO_LOCK_SECONDS,
        CLIPBOARD_CLEAR_SECONDS,
        CONCEAL_ON_BLUR,
        COMPACT_LIST,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Load settings, falling back to defaults for anything unset or corrupt.
    ///
    /// A missing key is the normal first-run case, so it is not worth an error
    /// path; a malformed one is logged and replaced.
    pub fn load(config: &Config) -> Self {
        let defaults = Settings::default();
        Self {
            auto_lock_seconds: get_or(config, key::AUTO_LOCK_SECONDS, defaults.auto_lock_seconds),
            clipboard_clear_seconds: get_or(
                config,
                key::CLIPBOARD_CLEAR_SECONDS,
                defaults.clipboard_clear_seconds,
            ),
            conceal_on_blur: get_or(config, key::CONCEAL_ON_BLUR, defaults.conceal_on_blur),
            compact_list: get_or(config, key::COMPACT_LIST, defaults.compact_list),
        }
    }

    /// The write half, driven by the preferences screen.
    pub fn store(&self, config: &Config) {
        set(config, key::AUTO_LOCK_SECONDS, self.auto_lock_seconds);
        set(
            config,
            key::CLIPBOARD_CLEAR_SECONDS,
            self.clipboard_clear_seconds,
        );
        set(config, key::CONCEAL_ON_BLUR, self.conceal_on_blur);
        set(config, key::COMPACT_LIST, self.compact_list);
    }
}

fn get_or<T>(config: &Config, key: &str, fallback: T) -> T
where
    T: serde::de::DeserializeOwned,
{
    match config.get::<T>(key) {
        Ok(v) => v,
        Err(cosmic_config::Error::NoConfigDirectory) => fallback,
        Err(e) => {
            tracing::debug!("config key `{key}` unavailable ({e}); using default");
            fallback
        }
    }
}

#[allow(dead_code)]
fn set<T>(config: &Config, key: &str, value: T)
where
    T: serde::Serialize,
{
    if let Err(e) = config.set(key, value) {
        tracing::warn!("could not persist config key `{key}`: {e}");
    }
}

/// Watch the store, and emit the settings whenever they change elsewhere.
///
/// The watcher's callback runs on `notify`'s own thread, so it hands the
/// reloaded settings across a channel rather than doing anything with them
/// there. The watcher itself is held for the life of the subscription: drop it
/// and the notifications stop, silently.
///
/// A machine with no `cosmic-config` at all parks forever instead of ending —
/// a subscription that returns is one iced will not restart, and settings
/// simply stay at whatever this window has.
pub fn subscription() -> Subscription<Settings> {
    Subscription::run(|| {
        stream::channel(4, |mut output: mpsc::Sender<Settings>| async move {
            let Some(config) = config() else {
                std::future::pending::<()>().await;
                unreachable!("pending never resolves");
            };

            let (tx, mut rx) = mpsc::channel(4);
            let watcher = config.watch(move |config, keys| {
                // Only our own keys are worth a reload; the store holds every
                // application's settings.
                if !keys.iter().any(|k| key::ALL.contains(&k.as_str())) {
                    return;
                }
                let _ = tx.clone().try_send(Settings::load(config));
            });

            let _watcher = match watcher {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("cannot watch the settings store: {e}");
                    std::future::pending::<()>().await;
                    unreachable!("pending never resolves");
                }
            };

            while let Some(settings) = rx.next().await {
                tracing::debug!("settings changed elsewhere; picking them up");
                if output.send(settings).await.is_err() {
                    break;
                }
            }
        })
    })
}

/// Open the application's config store.
pub fn config() -> Option<Config> {
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
    fn every_key_the_settings_use_is_in_the_watch_filter() {
        // A key missing from ALL is a setting that silently stops reloading:
        // the watcher fires, the filter drops it, nothing happens.
        for key in [
            key::AUTO_LOCK_SECONDS,
            key::CLIPBOARD_CLEAR_SECONDS,
            key::CONCEAL_ON_BLUR,
            key::COMPACT_LIST,
        ] {
            assert!(key::ALL.contains(&key), "`{key}` is not watched");
        }
        assert_eq!(key::ALL.len(), 4, "a key was added without watching it");
    }
}
