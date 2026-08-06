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
  passman-import   pass, KeePass/.kdbx and browser CSV importers
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

## Migrating off gnome-keyring

```sh
passman-cli import --dry-run          # see what would come across
passman-cli import                    # from org.freedesktop.secrets
passman-cli import --from org.passman.secrets --into Imported
```

There are importers for the other common escape routes too:

```sh
passman-cli import-csv chrome-passwords.csv     # Chrome, Edge, Brave, Firefox,
                                                # Safari, Bitwarden, 1Password
passman-cli import-pass                         # ~/.password-store
passman-cli import-keepass secrets.kdbx
```

The CSV importer matches *column aliases* rather than detecting a vendor
dialect, because every exporter names things differently and renames them
between releases. Chrome's `name,url,username,password,note` and Bitwarden's
`login_uri,login_username,login_password,login_totp` fall out of one table, and
columns nothing recognises are kept as custom fields instead of being dropped.
A browser export is a plaintext copy of every credential you own, so the CLI
tells you to delete it afterwards.

`import-pass` shells out to `gpg` rather than linking OpenPGP: the entries are
encrypted to your own key, which lives in your `gpg-agent` behind its own
pinentry and possibly a smartcard. It is tolerant by design — an unrecognised
line becomes notes rather than being lost, and `note to self: rotate in June`
stays prose instead of becoming a field called `note to self`.

The Secret Service importer is a *client*, not a file parser: gnome-keyring's
on-disk format is undocumented and version-specific, but its D-Bus surface is a
standard passman already implements the other half of. The same code therefore
imports from KWallet or anything else conforming.

It is read-only against the source and idempotent against the target — an item
whose attribute set already exists is skipped, since attribute identity is what
the Secret Service itself uses for replace-on-store. Re-running after adding a
few secrets does not duplicate anything.

Verified end to end: 9 items across 2 collections transfer with byte-identical
secrets, a dry run writes nothing, and a second run imports 0 while recognising
all 9 as already present.

**One thing does not survive, by construction.** The Secret Service carries a
label, an `a{ss}` attribute map and a schema string — it has no concept of item
*kind*. Logins, notes and Wi-Fi passwords are recovered because they have
recognisable schema or attribute signatures; an SSH key or a payment card
arrives as a generic application secret and needs retyping in the UI. That is a
limit of the source format, not of the importer, and it is why moving a passman
vault between machines should be a file copy rather than an import.

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

The GUI closes the loop in both directions: it subscribes to `UnlockRequested`
and raises its unlock screen saying *why* it appeared, and when you unlock it
forwards the same passphrase to the daemon — otherwise the GUI would show your
secrets while every `libsecret` app still saw a locked vault. Locking the GUI
locks the daemon too. A missing daemon is a supported configuration, not an
error; the GUI falls back to editing the vault file directly.

Verified end to end on a private bus: with the vault locked, `secret-tool
lookup` blocks, `UnlockRequested` fires, a frontend answering with `Unlock`
releases the pending call, and the client gets its secret. A wrong passphrase
returns `false` rather than a D-Bus error, since a typo is an expected outcome
and not a fault.

Also verified across two real processes on a live COSMIC session: `passmand`
logs *"asked the frontend to unlock"*, the GUI logs *"daemon asked for an
unlock"*, and the unlock screen appears reading "An application asked for a
secret from your vault."

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

**Verified on real hardware** — an AMD firmware TPM — as well as against
`swtpm`. Seal/unseal round trip, wrong-PIN rejection, and a TPM slot opening a
real vault all pass, and the chip's dictionary-attack counter incremented
exactly once per wrong PIN, which is the property the whole design rests on.

The tests are `#[ignore]`d behind `PASSMAN_TPM_TESTS=1` and a TCTI:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/tpm --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --flags not-need-init,startup-clear &
TCTI="swtpm:host=localhost,port=2321" PASSMAN_TPM_TESTS=1 \
  cargo test -p passman-tpm -- --ignored
```

The lockout claim is demonstrated by `examples/da_probe.rs`. With the
simulator's `MAX_AUTH_FAIL = 3`, two wrong PINs increment the DA counter and
the third puts the TPM in lockout — after which **the correct PIN is also
refused** until recovery. Lockout is device-wide, so this is not free: it is
exactly why a passphrase slot must always remain enrolled.

**Vendor variance is large, so read your own chip's numbers before trusting
any of this.** `tpm2_getcap properties-variable` reports them. The AMD fTPM
tested here allows 32 failures with a 2-hour decay and a 24-hour lockout
recovery; the simulator allows 3. Run `da_probe` only after confirming nothing
else on the machine depends on the TPM — on a dual-boot system that plausibly
includes BitLocker.

### Why the parent key is ECC

The storage parent is regenerated from a fixed template on *every* unlock
rather than occupying a persistent handle. Firmware TPMs are slow at RSA key
generation, and it shows: on the AMD fTPM here the hardware tests took 12.15 s
with an RSA-2048 parent and **2.51 s** with NIST P-256 — roughly 3 s versus
0.6 s per unlock. At three seconds a `sudo` prompt is unusable.

A sealed blob is only loadable under the exact template that sealed it, so the
choice is recorded per slot (`TpmParent`) and defaults to RSA for anything
enrolled before this change. Changing the default cannot silently brick an
enrolled factor.

## Licence

GPL-3.0-or-later.
