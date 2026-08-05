# passman

A password and secrets manager for Linux, built for COSMIC — aiming to be what
Passwords + Keychain Access are on macOS, and to replace `gnome-keyring` as the
system's secret store rather than sit beside it.

Status: **early, but real.** The vault, the cryptography, the freedesktop
Secret Service, the Secret portal and the SSH agent are implemented and
verified against actual `libsecret` and OpenSSH clients. The GUI browses and
reveals; it does not yet edit. See [Roadmap](#roadmap).

## Why replace gnome-keyring rather than wrap it

On a stock COSMIC session `gnome-keyring-daemon` is doing three jobs that
nothing in COSMIC does:

- it owns `org.freedesktop.secrets`, so every `libsecret` client depends on it;
- it is the **only** installed backend for `org.freedesktop.impl.portal.Secret`,
  which is how sandboxed Flatpak apps get a per-application encryption key —
  `xdg-desktop-portal-cosmic` implements `Access`, `FileChooser`, `Screenshot`,
  `Settings` and `ScreenCast`, but not `Secret`;
- it can serve the SSH agent, though on this machine it is started
  `--components=pkcs11,secrets` and `SSH_AUTH_SOCK` is empty, so nothing does.

Wrapping it would mean inheriting its storage format and its lock semantics.
passman implements the same D-Bus contracts on top of a modern vault instead.

## Architecture

```
crates/
  passman-core     vault format, Argon2id + XChaCha20-Poly1305, item model  (no I/O, no D-Bus, no UI)
  passman-secret   org.freedesktop.secrets + org.freedesktop.impl.portal.Secret
  passman-daemon   passmand — owns the unlocked vault, serves D-Bus and the agent
  passman-agent    SSH agent protocol
  passman-cli      command line interface
  passman-cosmic   libcosmic GUI (binary: `passman`)
  passman-tpm      TPM 2.0 sealed key slots (tss-esapi)
  passman-fido     FIDO2 hmac-secret key slots (ctap-hid-fido2)
```

The daemon holds the only copy of the data-encryption key. The GUI, the CLI and
every `libsecret` client are clients of it, so the vault is unlocked once per
session rather than once per application.

### Key slots

The body is encrypted once, under a random data-encryption key. Each *slot*
stores that same DEK wrapped under a different factor — a passphrase
(Argon2id), a TPM-sealed secret, or a FIDO2 token's `hmac-secret` output.
Enrolling hardware therefore **adds** a way in rather than replacing the
passphrase, so a dead motherboard is not a dead vault. `Vault::remove_slot`
refuses to remove the last one.

`SlotOpener` is the seam: a factor only has to produce 32 bytes, which is why
`passman-core` has no hardware dependencies.

### Vault format

JSON envelope with base64 fields — inspectable on purpose, so a recovery tool
never has to reverse a binary format.

- **Argon2id** (64 MiB, t=3, p=4 by default; parameters stored in the file)
  derives a key-encryption key from the passphrase.
- The body is encrypted under a random **data-encryption key**, which is
  wrapped by the KEK. Changing the passphrase rewraps 32 bytes instead of
  re-encrypting the vault, and the daemon never retains the passphrase.
- **XChaCha20-Poly1305** for both. The 192-bit nonce makes random nonces safe
  without a counter, which matters when a vault is synced between machines.
- The header is fed to both AEADs as associated data, so downgrading the KDF
  cost fails authentication instead of silently weakening the file.

### Secret Service transport

`libsecret` negotiates `dh-ietf1024-sha256-aes128-cbc-pkcs7` before falling
back to `plain`, so passman implements it: Diffie-Hellman over the RFC 2409
Second Oakley Group, HKDF-SHA256 to a 128-bit key, AES-128-CBC/PKCS#7. The
1024-bit group is weak by 2026 standards but is fixed by the wire format; it
protects secrets in transit on the session bus only, never the vault at rest.

Two compatibility details that are not in the spec but are required in practice:

- aliased collections must **also** be published at
  `/org/freedesktop/secrets/aliases/<alias>`; libsecret constructs that path
  directly instead of calling `ReadAlias`, and gnome-keyring serves it without
  advertising it during introspection.
- `Item.GetSecret` must return a 1-tuple. zbus uses a returned struct *as* the
  message body, which yields `(oayays)` where the spec wants `((oayays))`.

## Try it

```sh
cargo build

# A vault with representative items, passphrase "hunter2".
cargo run -p passman-core --example seed -- /tmp/dev.vault hunter2

# The GUI.
PASSMAN_VAULT=/tmp/dev.vault ./target/debug/passman
```

The daemon defaults to `org.passman.secrets` so that starting it never silently
displaces a running gnome-keyring. To exercise it as a real drop-in, give it a
private bus:

```sh
PW=hunter2 dbus-run-session -- bash -c '
  ./target/debug/passmand --vault /tmp/dev.vault --replace-keyring --passphrase-env PW &
  sleep 1
  printf "s3cret" | secret-tool store --label=Demo service example.com username ada
  secret-tool lookup service example.com username ada
'
```

Only pass `--replace-keyring` on your real session bus when you actually mean
to take over from gnome-keyring.

## Verified

`cargo test` covers the crypto (tamper, downgrade, wrong-key, key-wrapping),
the vault (round-trip, passphrase change, no-plaintext-on-disk, 0600 perms),
RFC 6238 TOTP vectors for SHA-1/256/512, the password generator's bias and
composition properties, and the DH session against a simulated libsecret peer.

End-to-end against real `libsecret` on a private bus: store, lookup, search
(single and multi-attribute, narrowing and contradictory), replace-on-store
without duplicates, delete, unicode secrets, both session algorithms, and
`ReadAlias`. The vault file was checked for plaintext leakage after each.

## Roadmap

Implemented: vault + crypto, Secret Service (Service/Collection/Item/Session,
Prompt objects), the Secret portal backend, an SSH agent, the daemon, the CLI,
and a GUI that browses/searches/reveals/copies with clipboard auto-clear.

**SSH agent** (`passmand --ssh-agent`) serves vault items of kind `SshKey`.
Verified with real OpenSSH: `ssh-add -l` lists the key with a matching
fingerprint, `ssh-keygen -Y sign` signs through the agent, and `-Y verify`
accepts the result. It refuses `ADD_IDENTITY`/`REMOVE_IDENTITY` on purpose —
every process running as you can reach that socket.

**Secret portal** (`passmand --portal`) implements
`org.freedesktop.impl.portal.Secret`. App secrets are *derived*, not stored:
`HKDF-SHA256(portal_master, info = "org.freedesktop.portal.Secret\0" || app_id)`,
so they are reproducible from a vault backup and no two apps can collide.
Install `res/passman.portal` into `/usr/share/xdg-desktop-portal/portals/` to
make xdg-desktop-portal route to it.

Next:

1. **Import** — from gnome-keyring (via its own Secret Service), `pass`,
   KeePassXC, Bitwarden.
3. **COSMIC applet** — panel indicator with lock state and quick copy.
4. **PAM module** — unlock at login and authorise `sudo`, on top of the TPM
   slot below.
5. **PKCS#11** — for consumers of gnome-keyring's certificate store.

## Unlocking on demand

The Secret Service spec has no way to *unlock* a service — its `Prompt` objects
say "ask the user" without saying how, because on GNOME the answer is a
gnome-keyring-specific dialog. `org.passman.Manager1` is that missing half:
`Unlock(passphrase) -> bool`, `Lock()`, and `Locked`/`ItemCount`/`VaultPath`
properties, plus an `UnlockRequested` signal.

A locked passman vault cannot be enumerated at all — labels and attributes live
inside the sealed body, which is the point, but it means gnome-keyring's trick
of listing locked items is unavailable. Returning "no matches" would be a lie
clients believe, reporting a secret as *missing* rather than locked. So
`SearchItems` on a locked vault emits `UnlockRequested` and waits.

Verified end to end on a private bus: with the vault locked, `secret-tool
lookup` blocks, `UnlockRequested` fires, a frontend answering with `Unlock`
releases the pending call, and the client gets its secret. A wrong passphrase
returns `false` rather than a D-Bus error, since a typo is an expected outcome
and not a fault.

## Security keys (FIDO2)

`passman-fido` enrols a slot whose key comes from a token's `hmac-secret`
extension. The distinction from a fingerprint reader matters: `fprintd` returns
a *verdict*, so a daemon must already hold the key and merely gates releasing
it. A FIDO2 token given a salt returns `HMAC-SHA256(credential_secret, salt)` —
32 bytes that exist nowhere but on the device. The vault key therefore cannot
be reconstructed from a stolen disk image at all.

Credentials are created under the relying-party id `passman.local`, which is
deliberately not a real domain: `hmac-secret` is scoped per (rp_id, credential),
so a passman credential cannot be exercised by a website.

**Not verified on hardware** — no FIDO2 token is attached to this machine. The
two round-trip tests are `#[ignore]`d behind `PASSMAN_FIDO_TESTS=1` (plus
`PASSMAN_FIDO_PIN` if your token has one); they need a physical touch.

## On authorising `sudo`

A PAM module that accepts "the user's daemon said yes" is *weaker* than typing
a password: any process running as you could claim the bus name and mint root
for itself. The fix is to anchor the decision in something your own uid cannot
forge, which is exactly what Windows Hello does — the PIN is not a password,
it unlocks a TPM-bound key, and the TPM's dictionary-attack lockout is what
makes a 6-digit PIN viable.

`passman-tpm` implements that: a random 32-byte secret sealed to the TPM under
an `authValue`, enrolled as a key slot. One detail is load-bearing —
`tss-esapi`'s own sealing example builds the object with `no_da(true)`, which
**exempts it from dictionary-attack lockout**. That would reduce the PIN to a
~20-bit password with unlimited guesses. `passman-tpm` clears `noDA` whenever a
PIN is set, and there is a test asserting it.

PCR binding is deliberately *not* used: binding to firmware measurements means
a BIOS update locks you out of your own vault, and the PIN is what provides the
security here.

**Verified against a TPM 2.0 simulator** (`swtpm`, rev 1.83) — seal/unseal
round trip, wrong-PIN rejection, and a TPM slot opening a real vault. The tests
are `#[ignore]`d behind `PASSMAN_TPM_TESTS=1` and a TCTI:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/tpm --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --flags not-need-init,startup-clear &
TCTI="swtpm:host=localhost,port=2321" PASSMAN_TPM_TESTS=1 \
  cargo test -p passman-tpm -- --ignored
```

The lockout claim is verified too, by `examples/da_probe.rs`. With the
simulator's `MAX_AUTH_FAIL = 3`, two wrong PINs increment the DA counter and
the third puts the TPM in lockout mode — after which **the correct PIN is also
refused** until the recovery interval expires. Lockout is device-wide, so this
is not free: it is exactly why a passphrase slot must always remain enrolled.

Still to do before `pam_passman.so`: confirm the same behaviour on the discrete
TPM rather than the simulator, since `MAX_AUTH_FAIL` and the recovery interval
are vendor-set.

## Licence

GPL-3.0-or-later.
