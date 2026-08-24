//! Settings, and a straight answer to "is locket actually my keyring?".
//!
//! The preferences themselves are few on purpose — every one of them changes
//! behaviour that exists, and there is nothing here that only writes a config
//! key. The more useful half of this screen is the status panel: the same
//! information `locket-setup --status` prints, in the place you would look
//! after an update or a reboot.
//!
//! That panel matters because locket's integration is made of pieces that
//! can each fail silently. A D-Bus name can be taken back by gnome-keyring, a
//! portal can be routed elsewhere by a desktop upgrade, a PAM line can be
//! dropped by a distribution's own tooling. None of those announce
//! themselves; applications just quietly stop finding their secrets.

use std::sync::LazyLock;

use cosmic::widget;
use cosmic::{Apply, Element};

use crate::config::Settings;
use crate::fl;

#[derive(Debug, Clone)]
pub enum Message {
    AutoLockSelected(usize),
    ClipboardSelected(usize),
    ConcealToggled(bool),
    CompactListToggled(bool),
    Refresh,
    Loaded(Status),
    /// A link in the About section was clicked.
    OpenUrl(String),
}

/// Auto-lock choices, in seconds. Zero is "never".
pub const AUTO_LOCK: &[u64] = &[0, 60, 5 * 60, 15 * 60, 30 * 60, 60 * 60];

/// The labels for those choices.
///
/// Built once rather than per frame, and `'static` because `dropdown` borrows
/// the slice for as long as the element it returns. Resolved after
/// `i18n::init`, which runs before the first view.
static AUTO_LOCK_LABELS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        fl!("auto-lock-never"),
        fl!("auto-lock-1m"),
        fl!("auto-lock-5m"),
        fl!("auto-lock-15m"),
        fl!("auto-lock-30m"),
        fl!("auto-lock-1h"),
    ]
});

/// Clipboard clear choices, in seconds. Zero leaves the secret there.
pub const CLIPBOARD: &[u64] = &[0, 10, 30, 60];
static CLIPBOARD_LABELS: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        fl!("clipboard-never"),
        fl!("clipboard-10s"),
        fl!("clipboard-30s"),
        fl!("clipboard-1m"),
    ]
});

/// How the desktop is currently wired up. Every field is observed, not
/// assumed: this is the panel people will use to decide whether something is
/// broken, so a hopeful guess here would be worse than no panel at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// Process name owning `org.freedesktop.secrets`, if anyone does.
    pub secrets_owner: Option<String>,
    /// Whether that owner is us.
    pub secrets_is_locket: bool,
    /// The `.portal` backend file is installed where the portal scans.
    pub portal_installed: bool,
    /// The effective `portals.conf` names locket for the Secret interface.
    pub portal_routed: bool,
    /// `pam_locket.so` appears in the login stack.
    pub pam_wired: bool,
    /// …and on the `password` line, which is what keeps the vault's passphrase
    /// in step when the login password changes. Reported separately because
    /// having one without the other is a real state people end up in, and it
    /// fails silently months later.
    pub pam_rekeys: bool,
    /// gnome-keyring is running, which usually means it is contending with us.
    pub gnome_keyring_running: bool,
}

/// A tick, a cross, or a warning triangle, with its explanation.
fn row<'a>(good: bool, warn: bool, title: String, detail: String) -> Element<'a, Message> {
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

pub fn view<'a>(
    settings: &Settings,
    status: Option<&'a Status>,
    about: &'a widget::about::About,
) -> Element<'a, Message> {
    let spacing = cosmic::theme::active().cosmic().spacing;

    let auto_lock = AUTO_LOCK
        .iter()
        .position(|s| *s == settings.auto_lock_seconds);
    let clipboard = CLIPBOARD
        .iter()
        .position(|s| *s == settings.clipboard_clear_seconds);

    let prefs = widget::settings::section()
        .title(fl!("settings-section-security"))
        .add(widget::settings::item(
            fl!("settings-auto-lock"),
            widget::dropdown(AUTO_LOCK_LABELS.as_slice(), auto_lock, Message::AutoLockSelected),
        ))
        .add(widget::settings::item(
            fl!("settings-clipboard"),
            widget::dropdown(CLIPBOARD_LABELS.as_slice(), clipboard, Message::ClipboardSelected),
        ))
        .add(widget::settings::item(
            fl!("settings-conceal-on-blur"),
            widget::toggler(settings.conceal_on_blur).on_toggle(Message::ConcealToggled),
        ));

    let appearance = widget::settings::section()
        .title(fl!("settings-section-appearance"))
        .add(
            widget::settings::item::builder(fl!("settings-compact-list"))
                .description(fl!("settings-compact-list-detail"))
                .control(
                    widget::toggler(settings.compact_list)
                        .on_toggle(Message::CompactListToggled),
                ),
        );

    let integration = match status {
        None => widget::settings::section()
            .title(fl!("integration-title"))
            .add(widget::settings::item(
                fl!("integration-checking"),
                widget::text::body(""),
            )),
        Some(s) => {
            let owner = match (&s.secrets_owner, s.secrets_is_locket) {
                (Some(_), true) => (true, false, fl!("integration-secrets-ours")),
                (Some(other), false) => (
                    false,
                    true,
                    fl!("integration-secrets-other", owner = other.clone()),
                ),
                (None, _) => (false, false, fl!("integration-secrets-none")),
            };

            widget::settings::section()
                .title(fl!("integration-title"))
                .add(row(owner.0, owner.1, fl!("integration-secrets"), owner.2))
                .add(row(
                    s.portal_installed && s.portal_routed,
                    s.portal_installed && !s.portal_routed,
                    fl!("integration-flatpak"),
                    if !s.portal_installed {
                        fl!("integration-flatpak-missing")
                    } else if !s.portal_routed {
                        fl!("integration-flatpak-unrouted")
                    } else {
                        fl!("integration-flatpak-ok")
                    },
                ))
                .add(row(
                    s.pam_wired && s.pam_rekeys,
                    // Half-wired is a warning, not a failure: it works today
                    // and breaks the day you change your password.
                    s.pam_wired && !s.pam_rekeys,
                    fl!("integration-pam"),
                    if s.pam_wired && s.pam_rekeys {
                        fl!("integration-pam-ok")
                    } else if s.pam_wired {
                        fl!("integration-pam-partial")
                    } else {
                        fl!("integration-pam-missing")
                    },
                ))
                .add(row(
                    !s.gnome_keyring_running,
                    s.gnome_keyring_running,
                    fl!("integration-keyring"),
                    if s.gnome_keyring_running {
                        fl!("integration-keyring-running")
                    } else {
                        fl!("integration-keyring-stopped")
                    },
                ))
        }
    };

    widget::column::with_capacity(7)
        .spacing(spacing.space_m)
        .max_width(720.0)
        .push(widget::text::title3(fl!("settings-title")))
        .push(prefs)
        .push(appearance)
        .push(integration)
        .push(
            widget::button::standard(fl!("settings-recheck"))
                .on_press(Message::Refresh)
                .apply(widget::container)
                .align_x(cosmic::iced::alignment::Horizontal::Left),
        )
        // Last, because it is the thing you come here for least often — but
        // here rather than nowhere, since a version number is the first thing
        // a bug report asks for.
        .push(widget::divider::horizontal::default())
        .push(widget::about::about(about, |url| {
            Message::OpenUrl(url.to_owned())
        }))
        .apply(widget::container)
        .padding(spacing.space_l)
        .width(cosmic::iced::Length::Fill)
        .apply(widget::scrollable)
        .into()
}

impl Status {
    /// Observe the current state of the integration.
    ///
    /// Reads are best-effort and independent: a failure to answer one question
    /// must not stop the others, because a partly-broken setup is exactly when
    /// this panel is worth looking at.
    pub async fn gather() -> Self {
        let (secrets_owner, secrets_is_locket) = Self::secrets_owner().await;
        Self {
            secrets_owner,
            secrets_is_locket,
            portal_installed: std::path::Path::new(
                "/usr/share/xdg-desktop-portal/portals/locket.portal",
            )
            .is_file(),
            portal_routed: Self::portal_routed(),
            pam_wired: Self::pam_line("auth"),
            pam_rekeys: Self::pam_line("password"),
            gnome_keyring_running: Self::gnome_keyring_running(),
        }
    }

    /// Whether the login stack has `pam_locket.so` on the given line.
    fn pam_line(kind: &str) -> bool {
        std::fs::read_to_string("/etc/pam.d/system-login")
            .map(|stack| {
                stack.lines().any(|line| {
                    let line = line.trim_start();
                    !line.starts_with('#')
                        && line.starts_with(kind)
                        && line.contains("pam_locket.so")
                })
            })
            .unwrap_or(false)
    }

    /// Ask the bus who owns the Secret Service, then who that process is.
    async fn secrets_owner() -> (Option<String>, bool) {
        let Ok(connection) = zbus::Connection::session().await else {
            return (None, false);
        };
        let Ok(dbus) = zbus::fdo::DBusProxy::new(&connection).await else {
            return (None, false);
        };
        let name = match zbus::names::BusName::try_from(locket_secret::WELL_KNOWN_NAME) {
            Ok(n) => n,
            Err(_) => return (None, false),
        };
        let Ok(pid) = dbus.get_connection_unix_process_id(name).await else {
            return (None, false);
        };

        // /proc/<pid>/comm is the process name; good enough to tell "locketd"
        // from "gnome-keyring-d", which is the only distinction that matters.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| format!("pid {pid}"));
        let is_locket = comm.starts_with("locketd");
        (Some(comm), is_locket)
    }

    /// Whether the effective portals.conf prefers locket for Secret.
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
                .is_some_and(|v| v.trim().starts_with("locket"));
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
