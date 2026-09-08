# locket-hibp

Have I Been Pwned range queries, the k-anonymity way.

This is the only crate in the workspace that talks to the network, and it
exists so that fact stays legible: locket-core does no I/O, and anything
wanting a breach check has to reach for this crate on purpose, behind an
explicit user opt-in.

What actually leaves the machine: the first five hex characters of the
SHA-1 of a password — 20 bits, shared by every one of the ~16 million
passwords per bucket — never the password, never its full hash. The
server returns the whole bucket and the matching is done here. The
`Add-Padding` header is sent so even the response length does not say
whether anything matched.

SHA-1 is fine here: it is the dataset's index, not a security boundary.

## Part of locket

`locket-hibp` is one crate of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
