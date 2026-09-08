# locket-secret

`org.freedesktop.secrets` — the freedesktop Secret Service, served from a
locket vault.

This is the crate that lets locket stand in for `gnome-keyring-daemon`.
Anything that speaks `libsecret` — GNOME Online Accounts, Chromium,
Evolution, NetworkManager, `secret-tool` — talks to this.

## Part of locket

`locket-secret` is one crate of [locket](https://github.com/entro314-labs/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/entro314-labs/locket/blob/main/LICENSE).
