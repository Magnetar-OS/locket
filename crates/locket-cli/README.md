# locket-cli

`locket-cli` — scriptable access to a locket vault.

Operates directly on the vault file. It deliberately does not go through
`locketd`, so it keeps working for recovery when the daemon will not start.
After a write it tells a daemon that is already running to re-read the file;
it never starts one, and is silent when there is none.

## Part of locket

`locket-cli` is the command line interface of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
