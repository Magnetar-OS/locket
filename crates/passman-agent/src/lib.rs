//! SSH agent protocol, backed by passman vault items of kind
//! [`ItemKind::SshKey`](passman_core::ItemKind::SshKey).
//!
//! Implements `draft-miller-ssh-agent` well enough for OpenSSH: listing
//! identities and signing with them. It is deliberately **read-only** with
//! respect to the vault — `ADD_IDENTITY` and `REMOVE_IDENTITY` are refused,
//! because an agent socket is reachable by every process running as you, and
//! letting it mutate the vault would make a compromised process able to
//! silently swap the key you authenticate with.
//!
//! This fills a slot nothing currently owns: on a stock COSMIC session
//! `gnome-keyring-daemon` runs as `--components=pkcs11,secrets` and
//! `SSH_AUTH_SOCK` is unset.

#![forbid(unsafe_code)]

pub mod agent;
pub mod error;
pub mod listener;
pub mod protocol;
pub mod wire;

pub use agent::{Agent, AgentKey};
pub use error::{Error, Result};

/// Upper bound on a single agent message.
///
/// OpenSSH uses 256 KiB; anything larger is a client bug or an attempt to make
/// the daemon allocate without bound.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;
