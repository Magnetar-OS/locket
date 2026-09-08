# locket-ipc

The unlock socket: how a passphrase reaches `locketd` from outside.

Used by the PAM module at login, and by anything else that legitimately
holds the user's passphrase and wants the daemon unlocked. The protocol is
deliberately trivial — one length-prefixed passphrase in, one status byte
back — because the *interesting* security properties are in where the
socket lives, not in what is spoken over it:

* The socket sits in `/run/user/<uid>/locket/`, a directory the kernel
  gives that user alone (mode 0700, owned by them). Only that uid and root
  can reach it, so no bus policy or peer-credential dance is needed.
* The socket itself is 0600, so a stray relaxation of the parent directory
  is not immediately fatal.
* Nothing is ever written to disk. A passphrase that arrives here goes into
  the daemon's memory and nowhere else.

This crate has no dependencies beyond `zeroize` on purpose: it is linked
into a PAM module that loads on **every** login, including `sudo` and `su`.
Pulling an async runtime or a D-Bus client into that path would be
irresponsible.

## Part of locket

`locket-ipc` is one crate of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
