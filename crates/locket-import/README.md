# locket-import

Importers for other password managers.

Each importer maps a foreign format onto locket's item model and hands the
result to a vault. They share two rules:

* **Read-only against the source.** Nothing here writes to a password-store
  or a `.kdbx`; a failed import must leave you exactly where you started.
* **Idempotent against the target.** An item whose attribute set already
  exists is skipped, so re-running after adding a few secrets does not
  duplicate anything.

Importing from a running Secret Service (gnome-keyring, KWallet) lives in
`locket-secret` instead, because it needs D-Bus rather than a file format.

## Part of locket

`locket-import` is one crate of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
