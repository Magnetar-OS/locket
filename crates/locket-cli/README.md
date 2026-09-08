# locket-cli

`locket-cli` — scriptable access to a locket vault.

Operates directly on the vault file. It deliberately does not talk to
`locketd`, so it keeps working for recovery when the daemon will not start.

## Part of locket

`locket-cli` is the command line interface of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
