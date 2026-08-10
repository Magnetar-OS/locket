//! Settings, and a straight answer to "is passman actually my keyring?".
//!
//! The preferences themselves are few on purpose — every one of them changes
//! behaviour that exists, and there is nothing here that only writes a config
//! key. The more useful half of this screen is the status panel: the same
//! information `passman-setup --status` prints, in the place you would look
//! after an update or a reboot.
//!
//! That panel matters because passman's integration is made of pieces that
//! can each fail silently. A D-Bus name can be taken back by gnome-keyring, a
//! portal can be routed elsewhere by a desktop upgrade, a PAM line can be
//! dropped by a distribution's own tooling. None of those announce
//! themselves; applications just quietly stop finding their secrets.

use cosmic::widget;
use cosmic::{Apply, Element};

use crate::config::Settings;

#[derive(Debug, Clone)]
pub enum Message {
    AutoLockSelected(usize),
    ClipboardSelected(usize),
    ConcealToggled(bool),
    Refresh,
    Loaded(Status),
}

/// Auto-lock choices, in seconds. Zero is "never".
pub const AUTO_LOCK: &[u64] = &[0, 60, 5 * 60, 15 * 60, 30 * 60, 60 * 60];
const AUTO_LOCK_LABELS: &[&str] = &[
    "Never",
    "After 1 minute",
    "After 5 minutes",
    "After 15 minutes",
    "After 30 minutes",
    "After 1 hour",
];

/// Clipboard clear choices, in seconds. Zero leaves the secret there.
pub const CLIPBOARD: &[u64] = &[0, 10, 30, 60];
const CLIPBOARD_LABELS: &[&str] = &[
    "Never — leave it on the clipboard",
    "After 10 seconds",
    "After 30 seconds",
    "After 1 minute",
];

/// How the desktop is currently wired up. Every field is observed, not
/// assumed: this is the panel people will use to decide whether something is
/// broken, so a hopeful guess here would be worse than no panel at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// Process name owning `org.freedesktop.secrets`, if anyone does.
    pub secrets_owner: Option<String>,
    /// Whether that owner is us.
    pub secrets_is_passman: bool,
    /// The `.portal` backend file is installed where the portal scans.
    pub portal_installed: bool,
    /// The effective `portals.conf` names passman for the Secret interface.
    pub portal_routed: bool,
    /// `pam_passman.so` appears in the login stack.
    pub pam_wired: bool,
    /// gnome-keyring is running, which usually means it is contending with us.
    pub gnome_keyring_running: bool,
}

/// A tick, a cross, or a warning triangle, with its explanation.
fn row<'a>(good: bool, warn: bool, title: &'a str, detail: String) -> Element<'a, Message> {
    let icon = if warn {
        "dialog-warning-symbolic"
    } else if good {
        "emblem-ok-symbolic"
    } else {
        "window-close-symbolic"
    };
    widget::settings::item::builder(title)
        .description(detail)
        .icon(widget::icon::from_name(icon).size(16))
        .control(widget::text::body(""))
        .into()
}

pub fn view<'a>(settings: &Settings, status: Option<&'a Status>) -> Element<'a, Message> {
    let spacing = cosmic::theme::active().cosmic().spacing;

    let auto_lock = AUTO_LOCK
        .iter()
        .position(|s| *s == settings.auto_lock_seconds);
    let clipboard = CLIPBOARD
        .iter()
        .position(|s| *s == settings.clipboard_clear_seconds);

    let prefs = widget::settings::section()
        .title("Security")
        .add(widget::settings::item(
            "Lock the vault when idle",
            widget::dropdown(AUTO_LOCK_LABELS, auto_lock, Message::AutoLockSelected),
        ))
        .add(widget::settings::item(
            "Clear copied secrets",
            widget::dropdown(CLIPBOARD_LABELS, clipboard, Message::ClipboardSelected),
        ))
        .add(widget::settings::item(
            "Hide revealed secrets when the window loses focus",
            widget::toggler(settings.conceal_on_blur).on_toggle(Message::ConcealToggled),
        ));

    let integration = match status {
        None => widget::settings::section()
            .title("Desktop integration")
            .add(widget::settings::item(
                "Checking…",
                widget::text::body(""),
            )),
        Some(s) => {
            let owner = match (&s.secrets_owner, s.secrets_is_passman) {
                (Some(_), true) => (
                    true,
                    false,
                    "passman is serving org.freedesktop.secrets".to_owned(),
                ),
                (Some(other), false) => (
                    false,
                    true,
                    format!("{other} owns org.freedesktop.secrets, not passman"),
                ),
                (None, _) => (
                    false,
                    false,
                    "nothing owns org.freedesktop.secrets".to_owned(),
                ),
            };

            widget::settings::section()
                .title("Desktop integration")
                .add(row(owner.0, owner.1, "Secret Service", owner.2))
                .add(row(
                    s.portal_installed && s.portal_routed,
                    s.portal_installed && !s.portal_routed,
                    "Flatpak apps",
                    if !s.portal_installed {
                        "The Secret portal backend is not installed. Run \
                         passman-setup to install it."
                            .to_owned()
                    } else if !s.portal_routed {
                        "The backend is installed but the desktop prefers \
                         another one, so Flatpak apps will not use passman."
                            .to_owned()
                    } else {
                        "Sandboxed applications get their secrets from passman"
                            .to_owned()
                    },
                ))
                .add(row(
                    s.pam_wired,
                    false,
                    "Unlock at login",
                    if s.pam_wired {
                        "pam_passman.so is in the login stack".to_owned()
                    } else {
                        "Not configured; you unlock manually each session"
                            .to_owned()
                    },
                ))
                .add(row(
                    !s.gnome_keyring_running,
                    s.gnome_keyring_running,
                    "gnome-keyring",
                    if s.gnome_keyring_running {
                        "Still running, and will contend with passman for the \
                         Secret Service name"
                            .to_owned()
                    } else {
                        "Not running".to_owned()
                    },
                ))
        }
    };

    widget::column::with_capacity(4)
        .spacing(spacing.space_m)
        .max_width(720.0)
        .push(widget::text::title3("Settings"))
        .push(prefs)
        .push(integration)
        .push(
            widget::button::standard("Re-check")
                .on_press(Message::Refresh)
                .apply(widget::container)
                .align_x(cosmic::iced::alignment::Horizontal::Left),
        )
        .apply(widget::container)
        .padding(spacing.space_l)
        .width(cosmic::iced::Length::Fill)
        .into()
}

impl Status {
    /// Observe the current state of the integration.
    ///
    /// Reads are best-effort and independent: a failure to answer one question
    /// must not stop the others, because a partly-broken setup is exactly when
    /// this panel is worth looking at.
    pub async fn gather() -> Self {
        let (secrets_owner, secrets_is_passman) = Self::secrets_owner().await;
        Self {
            secrets_owner,
            secrets_is_passman,
            portal_installed: std::path::Path::new(
                "/usr/share/xdg-desktop-portal/portals/passman.portal",
            )
            .is_file(),
            portal_routed: Self::portal_routed(),
            pam_wired: std::fs::read_to_string("/etc/pam.d/system-login")
                .map(|s| s.contains("pam_passman.so"))
                .unwrap_or(false),
            gnome_keyring_running: Self::gnome_keyring_running(),
        }
    }

    /// Ask the bus who owns the Secret Service, then who that process is.
    async fn secrets_owner() -> (Option<String>, bool) {
        let Ok(connection) = zbus::Connection::session().await else {
            return (None, false);
        };
        let Ok(dbus) = zbus::fdo::DBusProxy::new(&connection).await else {
            return (None, false);
        };
        let name = match zbus::names::BusName::try_from(passman_secret::WELL_KNOWN_NAME) {
            Ok(n) => n,
            Err(_) => return (None, false),
        };
        let Ok(pid) = dbus.get_connection_unix_process_id(name).await else {
            return (None, false);
        };

        // /proc/<pid>/comm is the process name; good enough to tell "passmand"
        // from "gnome-keyring-d", which is the only distinction that matters.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| format!("pid {pid}"));
        let is_passman = comm.starts_with("passmand");
        (Some(comm), is_passman)
    }

    /// Whether the effective portals.conf prefers passman for Secret.
    ///
    /// The files are not merged: the first one found, searching the user's
    /// config directory before the system's and the desktop-specific name
    /// before the generic one, wins outright.
    fn portal_routed() -> bool {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let mut candidates = Vec::new();
        if let Some(config) = dirs::config_dir() {
            let dir = config.join("xdg-desktop-portal");
            if !desktop.is_empty() {
                candidates.push(dir.join(format!("{desktop}-portals.conf")));
            }
            candidates.push(dir.join("portals.conf"));
        }
        let system = std::path::Path::new("/usr/share/xdg-desktop-portal");
        if !desktop.is_empty() {
            candidates.push(system.join(format!("{desktop}-portals.conf")));
        }
        candidates.push(system.join("portals.conf"));

        for path in candidates {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            return text
                .lines()
                .find_map(|l| l.trim().strip_prefix("org.freedesktop.impl.portal.Secret="))
                .is_some_and(|v| v.trim().starts_with("passman"));
        }
        false
    }

    fn gnome_keyring_running() -> bool {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return false;
        };
        entries.flatten().any(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))
                && std::fs::read_to_string(e.path().join("comm"))
                    .map(|c| c.trim().starts_with("gnome-keyring"))
                    .unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_choice_has_exactly_one_label() {
        assert_eq!(AUTO_LOCK.len(), AUTO_LOCK_LABELS.len());
        assert_eq!(CLIPBOARD.len(), CLIPBOARD_LABELS.len());
    }

    #[test]
    fn the_defaults_are_selectable() {
        let defaults = Settings::default();
        assert!(
            AUTO_LOCK.contains(&defaults.auto_lock_seconds),
            "the default auto-lock is not one of the offered choices, so the \
             dropdown would open with nothing selected"
        );
        assert!(CLIPBOARD.contains(&defaults.clipboard_clear_seconds));
    }

    #[test]
    fn never_is_zero_in_both_lists() {
        assert_eq!(AUTO_LOCK[0], 0);
        assert_eq!(CLIPBOARD[0], 0);
    }
}
