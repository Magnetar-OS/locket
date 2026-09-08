# locket-core

Vault format, cryptography and item model for locket.

This crate is deliberately free of D-Bus, UI and async: it is the piece
that the daemon, the CLI and the COSMIC frontend all agree on, and the
piece worth auditing closely.

## Part of locket

`locket-core` is one crate of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
