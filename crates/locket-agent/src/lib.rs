//! SSH agent protocol, backed by locket vault items of kind
//! [`ItemKind::SshKey`](locket_core::ItemKind::SshKey).
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
//!
//! # Security keys
//!
//! `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`
//! identities are served too, by asking the token for a FIDO2 assertion per
//! signature — see [`sk`]. Those keys hold no signing scalar, so an agent that
//! merely listed them would advertise identities it could never use; without a
//! token backend they are dropped at load instead.

#![forbid(unsafe_code)]

pub mod agent;
pub mod confirm;
pub mod error;
#[cfg(feature = "fido")]
pub mod fido;
pub mod listener;
pub mod protocol;
pub mod signing;
pub mod sk;
pub mod wire;

pub use agent::{Agent, AgentKey};
pub use error::{Error, Result};

/// Upper bound on a single agent message.
///
/// OpenSSH uses 256 KiB; anything larger is a client bug or an attempt to make
/// the daemon allocate without bound.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;
