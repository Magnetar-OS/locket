//! `org.freedesktop.secrets` — the freedesktop Secret Service, served from a
//! locket vault.
//!
//! This is the crate that lets locket stand in for `gnome-keyring-daemon`.
//! Anything that speaks `libsecret` — GNOME Online Accounts, Chromium,
//! Evolution, NetworkManager, `secret-tool` — talks to this.

#![forbid(unsafe_code)]

pub mod client;
pub mod dh;
pub mod error;
pub mod import;
pub mod manager;
pub mod portal;
pub mod service;
pub mod session;
pub mod unlock_socket;

pub use error::{Error, Result};
pub use service::{SecretService, ServiceConfig};
pub use session::{Session, SessionStore};

/// The well-known name gnome-keyring currently owns.
pub const WELL_KNOWN_NAME: &str = "org.freedesktop.secrets";

/// A parallel name, so locket can be exercised against real clients without
/// evicting the running keyring first.
pub const DEV_NAME: &str = "org.locket.secrets";

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection";
/// Aliased collections are *also* published here.
///
/// `libsecret` resolves the default collection by constructing
/// `/org/freedesktop/secrets/aliases/default` directly rather than calling
/// `ReadAlias`, so a service that only implements `ReadAlias` fails every
/// `secret-tool store`. gnome-keyring serves this path without advertising it
/// as a child node during introspection; locket matches that behaviour.
pub const ALIAS_PREFIX: &str = "/org/freedesktop/secrets/aliases";
pub const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session";
pub const PROMPT_PREFIX: &str = "/org/freedesktop/secrets/prompt";
