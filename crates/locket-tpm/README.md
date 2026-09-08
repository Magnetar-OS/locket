# locket-tpm

TPM 2.0 sealed key slots.

Enrols a `SlotFactor::Tpm2` slot whose key-encryption key is a random
secret *sealed to this machine's TPM*, optionally behind a PIN. The PIN is
not a password and is never used to derive anything: it is a TPM
`authValue` that releases a hardware-held secret, so its own entropy is not
what stands between an attacker and the key. The dictionary-attack lockout
on the chip is what makes a short PIN defensible — six digits are fine when
the hardware allows a handful of guesses, and indefensible when an attacker
can try them offline at GPU speed.

Because the slot only *adds* a way in, losing the machine does not lose the
vault: the passphrase slot still opens it.

# A note on `noDA`

`tss-esapi`'s own sealing example builds the object with `with_no_da(true)`,
which **exempts it from dictionary-attack protection**. That is fine for a
test fixture and completely wrong here: it would turn the PIN into an
unlimited-guess secret with roughly 20 bits of entropy. This crate clears
`noDA` whenever a PIN is in use, and that choice is load-bearing — there is
a test asserting it.

# Testing

Anything that talks to hardware needs a TPM the caller can open
(`/dev/tpmrm0` is `root:tss 0660`, or point the TCTI at an `swtpm`
simulator), so those tests are `#[ignore]`d and additionally gated on
`LOCKET_TPM_TESTS=1`. The pure logic — blob framing, template attributes,
factor handling — is tested unconditionally.

## Part of locket

`locket-tpm` is one crate of [locket](https://github.com/entro314-labs/locket), a
password and secret manager for the Linux desktop that serves
`org.freedesktop.secrets` and an SSH agent from a single encrypted vault.

The repository README covers installation, the architecture, and how the
crates fit together.

## Licence

GPL-3.0-or-later. See [LICENSE](https://github.com/entro314-labs/locket/blob/main/LICENSE).
