# passman

A password and secrets manager for Linux, built for COSMIC — aiming to be what
Passwords + Keychain Access are on macOS, and to replace `gnome-keyring` as the
system's secret store rather than sit beside it.

Status: **early, but real.** The vault, the cryptography and the freedesktop
Secret Service are implemented and verified against actual `libsecret` clients.
The GUI browses and reveals; it does not yet edit. See [Roadmap](#roadmap).

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
  passman-secret   org.freedesktop.secrets: Service/Collection/Item/Session/Prompt
  passman-daemon   passmand — owns the unlocked vault, serves D-Bus
  passman-agent    SSH agent protocol                                       (placeholder)
  passman-cli      command line interface                                   (placeholder)
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
Prompt objects), daemon, GUI browse/search/reveal/copy with clipboard
auto-clear, `cosmic-config` settings.

Next, roughly in order of how much each unties you from gnome-keyring:

1. **SSH agent** — `passman-agent` is a placeholder; the socket is unclaimed on
   this machine, so this is free ground.
2. **`org.freedesktop.impl.portal.Secret` backend** — makes passman the Flatpak
   per-app key provider. Single method, `RetrieveSecret`, over a pipe FD.
3. **GUI editing** — create/edit/delete items, password generator UI, import.
4. **Prompt UI** — the daemon exposes `Prompt` objects and a channel; the
   frontend needs to answer them so a locked vault can be unlocked on demand.
5. **Import** — from gnome-keyring (via its own Secret Service), `pass`,
   KeePassXC, Bitwarden, macOS Keychain.
6. **COSMIC applet** — panel indicator with lock state and quick copy.
7. **PAM module** — unlock at login, the last thing tying a session to
   gnome-keyring.
8. **PKCS#11** — for consumers of gnome-keyring's certificate store.

## Licence

GPL-3.0-or-later.
