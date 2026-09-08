# locket-fido

FIDO2 `hmac-secret` key slots.

Enrols a `SlotFactor::Fido2` slot whose key-encryption key comes from a
hardware security key.

What makes this different from a fingerprint reader is that `hmac-secret`
returns **key material**, not a verdict. `fprintd` can only tell you "yes,
that was them", which means a daemon must already hold the key and merely
gates releasing it. A FIDO2 token given a salt returns
`HMAC-SHA256(credential_secret, salt)` — 32 bytes that exist nowhere but on
the token. So the vault key genuinely cannot be reconstructed without the
physical device, and "attacker has your disk image" is not enough.

With user verification on, the token additionally requires its own PIN or
on-device biometric, and enforces its own retry limit — the same
hardware-rate-limited property the TPM slot relies on, but portable between
machines.

# Testing

Everything that talks to a token is `#[ignore]`d and gated on
`LOCKET_FIDO_TESTS=1`, because it needs a physical key *and* a human to
touch it. The derivation and factor logic is tested unconditionally.

## Part of locket

`locket-fido` is one crate of [locket](https://github.com/Magnetar-OS/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/Magnetar-OS/locket/blob/main/LICENSE).
