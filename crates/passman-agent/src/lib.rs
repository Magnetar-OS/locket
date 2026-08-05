//! SSH agent protocol (RFC 4251 framing, `draft-miller-ssh-agent`) backed by
//! passman vault items of kind [`ItemKind::SshKey`].
//!
//! Not yet implemented — this crate is a placeholder so the workspace and the
//! daemon's wiring are in place. On this machine `SSH_AUTH_SOCK` is currently
//! unset and `gnome-keyring-daemon` runs without its `ssh` component, so
//! nothing owns the agent socket; that is the slot this will fill.
//!
//! [`ItemKind::SshKey`]: passman_core::ItemKind::SshKey

#![forbid(unsafe_code)]
