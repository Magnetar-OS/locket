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
```

The daemon holds the only copy of the data-encryption key. The GUI, the CLI and
every `libsecret` client are clients of it, so the vault is unlocked once per
session rather than once per application.

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

1. **GUI editing** — create/edit/delete items, password generator UI.
2. **Prompt UI** — the daemon exposes `Prompt` objects and a channel; the
   frontend needs to answer them so a locked vault can unlock on demand.
3. **Import** — from gnome-keyring (via its own Secret Service), `pass`,
   KeePassXC, Bitwarden.
4. **COSMIC applet** — panel indicator with lock state and quick copy.
5. **TPM2 sealing + PIN** — see below; the prerequisite for a credible
   `pam_passman.so`.
6. **PAM module** — unlock at login and authorise `sudo`.
7. **PKCS#11** — for consumers of gnome-keyring's certificate store.

## On authorising `sudo`

A PAM module that accepts "the user's daemon said yes" is *weaker* than typing
a password: any process running as you could claim the bus name and mint root
for itself. The fix is to anchor the decision in something your own uid cannot
forge, which is exactly what Windows Hello does — the PIN is not a password,
it unlocks a TPM-bound key, and the TPM's dictionary-attack lockout is what
makes a 6-digit PIN viable.

The same primitive exists here. This machine has a TPM 2.0 (`/dev/tpmrm0`),
`tpm2-tss`, and `systemd-cryptenroll --tpm2-with-pin` as a reference
implementation; `tss-esapi` is the Rust binding. Sealing a secret under a
TPM policy with an `authValue` gives a PIN that is rate-limited in hardware.
Note the device node is `root:tss 0660` and your user is not in `tss` — which
is the right shape, since the PAM module runs as root.

Ordering matters: TPM sealing first, `pam_passman.so` only after.

## Licence

GPL-3.0-or-later.
