# Locket

A password and secrets manager for the COSMIC desktop. It keeps logins, keys,
tokens and notes in an encrypted vault, and it is also the process the rest of
the system asks for secrets: it owns `org.freedesktop.secrets`, serves the
`org.freedesktop.impl.portal.Secret` backend that sandboxed Flatpak
applications get their per-application key from, and runs an SSH agent. On a
stock session `gnome-keyring-daemon` holds those; installing locket takes
them over rather than sitting beside it.

The desktop application creates, edits and deletes items, generates passwords,
shows live TOTP codes, imports from eight sources and enrols TPM and FIDO2
unlock factors. There is a CLI, a panel applet, a PAM module that unlocks at
login, and a browser extension with its native messaging host.

Each of those has been exercised against the software that actually calls it —
`libsecret`, a sandboxed Flatpak through `xdg-desktop-portal`, OpenSSH,
`pamtester` — and the results are recorded in [Verified](#verified) and in the
section covering each piece.

It runs on one machine, its author's, as that machine's only secret store. It
has no other users, has never been tried against a FIDO2 token, and has been
reviewed by nobody — see [SECURITY.md](SECURITY.md) before trusting it with
anything you cannot afford to lose. There is an Arch package under
`packaging/`; no distribution ships it. See [Roadmap](#roadmap).

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
locket implements the same D-Bus contracts on top of its own vault instead.

## The application

`locket` is the desktop application: a COSMIC nav bar of categories, a
search-filtered list, and the selected item in a context drawer. The vault
models twelve kinds of item — logins, notes, cards, identities, SSH and GPG
keys, API tokens, OAuth registrations, certificates, environment bundles, Wi-Fi
passphrases, and *application* secrets, which is where anything a `libsecret`
client stored lands: a secret another application wrote is an item you can
open, edit and delete like the ones you typed in yourself.

Every item has a primary secret — the one the Secret Service hands out — plus
any number of extra fields, each with a kind: text, secret, URL, TOTP seed,
note, email, phone, date, private key, public key. The kind is what decides
whether a value is masked, excluded from search, or turned into a live code, so
the editor lets you set it per field rather than guessing from the name.

- **TOTP** fields render the current code with a bar that drains over the
  period, and the caption turns into a warning under five seconds. The
  question while typing a code into a form is "have I got long enough", and a
  number you have to read and subtract from is a poor way to answer it. **Show
  QR code** puts the seed back on screen as the `otpauth://` URI a phone
  authenticator expects, rebuilt from the parsed seed so the algorithm, digits
  and period travel with it rather than being guessed at the other end. It is
  a secret on display, so it hides again with everything else — on lock, on
  changing item, and on losing focus if you asked for that.
- **Copying** clears the clipboard afterwards — 30 seconds by default,
  configurable, or never.
- **Auto-lock** after 15 minutes idle by default. Revealed secrets also
  re-conceal when the window loses focus, which is a display change and not a
  lock: it costs nothing and covers the screenshot-and-screen-share case.
- **Deleting** asks first, then moves the item to the **trash**: gone for any
  application reading it over the Secret Service, restorable from the Trash
  category until a retention window stored in the vault itself purges it —
  30 days by default, enforced on unlock by whichever process gets there
  first. This covers deletes arriving over the bus too, so a misbehaving
  `libsecret` client can no longer destroy anything outright.
- **Every edit files the state it replaced** into the item's bounded history —
  including a `SetSecret` or replace-on-store from another application — and
  the detail pane restores any revision, itself undoably. **Attachments**
  (encrypted, 10 MiB each) and an **expiry date** with list badges ride on
  items; **two diverged copies of one vault merge** by id and timestamp, the
  losing side of each conflict filed into history rather than discarded, and
  a `.sync-conflict` sibling left by a file synchroniser is noticed and
  offered for merge on unlock.
- **Health** reports weak passwords (zxcvbn, seeded with the item's own
  label and username), secrets reused across items, secrets unchanged for a
  year, and expiring items — offline. Checking against Have I Been Pwned is
  a separate button that says exactly what leaves the machine: five hex
  characters of each secret's SHA-1, by k-anonymity range, from the one
  crate in the workspace allowed to touch the network.
- **The passphrase changes from the Security screen** — current passphrase
  required first, Argon2id cost selectable — and `locket-cli passwd
  --rederive-only` re-wraps at new parameters without changing what you
  type.
- `Ctrl+N` new item, `Ctrl+F` search, `Ctrl+L` lock. Shortcuts are only
  claimed when no text field has already consumed the key.
- **Settings live in `cosmic-config`**, the desktop's own store, mediated by
  `cosmic-settings-daemon`. They are watched, so a change made anywhere else —
  a second window, the settings daemon — lands here without a restart. That is
  as close to control-center integration as COSMIC currently offers: there is
  no third-party panel mechanism in `cosmic-settings` to plug into.
- The **Settings** page is a status panel as much as a preferences screen: who
  owns `org.freedesktop.secrets` right now, whether the portal backend is
  installed *and* routed, whether the PAM line is in the login stack, whether
  gnome-keyring is running against you. Every one of those can be undone by a
  desktop upgrade without announcing itself, and the failure mode is
  applications quietly not finding their secrets. It ends with the About
  section, because the version number is the first thing a bug report asks
  for.

A running daemon is the normal case but not a requirement: with no `locketd`
on the bus the GUI opens the vault file directly. The Settings panel is where
you find out which of the two you are in, since it reports the actual owner of
`org.freedesktop.secrets` rather than assuming.

## Architecture

```
crates/
  locket-core     vault format, Argon2id + XChaCha20-Poly1305, item model, health  (no I/O, no D-Bus, no UI)
  locket-hibp     Have I Been Pwned range queries — the only crate that touches the network
  locket-secret   org.freedesktop.secrets + org.freedesktop.impl.portal.Secret, quick lookup
  locket-daemon   locketd — owns the unlocked vault, serves D-Bus and the agent
  locket-agent    SSH agent protocol, including security-key (`sk-`) signing
  locket-cli      command line interface
  locket-cosmic   libcosmic GUI (binary: `locket`)
  locket-applet   COSMIC panel indicator
  locket-tpm      TPM 2.0 sealed key slots (tss-esapi)
  locket-fido     FIDO2: hmac-secret key slots and assertions (ctap-hid-fido2)
  locket-import   importers: browser CSV, .env trees, SSH keys, cloud CLIs, TOTP exports, pass, KeePass
  locket-ipc      the unlock-socket protocol (no deps; linked into PAM)
  locket-pam      pam_locket.so — unlocks the vault at login
  locket-nmh      native messaging host for the browser extension
extension/         the browser extension itself (Chrome/Firefox, MV3)
res/               desktop entries, metainfo, systemd unit, .portal file, PAM notes
scripts/           locket-setup (install/uninstall/status) and the keyring re-import
justfile           build, install and metadata checks — the packager's path
packaging/arch/    PKGBUILD
docs/              cosmic-conventions.md, threat-model.md, performance.md, autotype-wayland.md
```

The two COSMIC crates carry their own fluent catalogue under
`crates/<crate>/i18n/`; `fl!("id")` resolves against it at compile time, so a
message id that does not exist is a build error rather than a label reading
`id` at runtime.

While `locketd` is running it holds the only unlocked copy of the
data-encryption key, and the GUI, the browser host and every `libsecret` client
go through it — so the vault is unlocked once per session rather than once per
application.

`locket-cli` is the exception, on purpose: it opens the vault file itself and
never talks to the daemon, so it still works when the daemon will not start.
The GUI does the same as a fallback when no daemon is on the bus.

### Key slots

The body is encrypted once, under a random data-encryption key. Each *slot*
stores that same DEK wrapped under a different factor — a passphrase
(Argon2id), a TPM-sealed secret, or a FIDO2 token's `hmac-secret` output.
Enrolling hardware therefore **adds** a way in rather than replacing the
passphrase, so a dead motherboard is not a dead vault. `Vault::remove_slot`
refuses to remove the last one.

`SlotOpener` is the seam: a factor only has to produce 32 bytes, which is why
`locket-core` has no hardware dependencies.

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

One thing is deliberately *outside* the sealed body: a plaintext index of
which collections exist — id, label and alias, nothing else. A locked Secret
Service still has to answer `ReadAlias` and the `Collections` property, and
answering "none" does not read as *locked* to `libsecret`, it reads as *there
is no keyring installed here*. Item labels, usernames, attributes and secrets
all stay inside the body. gnome-keyring draws the same line — keyring names are
in the clear there too — and the index is covered by the body's AEAD, so
relabelling a collection on disk invalidates the vault rather than silently
succeeding.

Older files are read and upgraded in place, the next time the vault is saved:
format 1 (a single inline KDF descriptor) becomes a one-slot format 2 file,
format 2 gains the collection index, and format 3 becomes format 4 — the
envelope unchanged, the version raised so a build that predates trash, item
history and attachments refuses the file instead of opening it and silently
stripping what it does not know about on save.

### Secret Service transport

`libsecret` negotiates `dh-ietf1024-sha256-aes128-cbc-pkcs7` before falling
back to `plain`, so locket implements it: Diffie-Hellman over the RFC 2409
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
cargo run -p locket-core --example seed -- /tmp/dev.vault hunter2

# The GUI.
LOCKET_VAULT=/tmp/dev.vault ./target/debug/locket
```

The daemon defaults to `org.locket.secrets` so that starting it never silently
displaces a running gnome-keyring. To exercise it as a real drop-in, give it a
private bus:

```sh
PW=hunter2 dbus-run-session -- bash -c '
  ./target/debug/locketd --vault /tmp/dev.vault --replace-keyring --passphrase-env PW &
  sleep 1
  printf "s3cret" | secret-tool store --label=Demo service example.com username ada
  secret-tool lookup service example.com username ada
'
```

Only pass `--replace-keyring` on your real session bus when you actually mean
to take over from gnome-keyring.

## Verified

`cargo test` covers the crypto (tamper, downgrade, wrong-key, key-wrapping),
the vault (round-trip, passphrase change, format upgrade, no-plaintext-on-disk,
0600 perms, a tampered collection index failing authentication), key slots and
the rule that the last one cannot be removed, RFC 6238 TOTP vectors for
SHA-1/256/512, the password generator's bias and composition properties, the DH
session against a simulated libsecret peer, the SSH agent's wire format, its
lock/unlock round trip, the RSA hash the client asks for, certificate
identities and the confirm-each-use gate, the security-key signature encoding
against a software token, two writers racing for the vault
file, the unlock socket's rekey framing, the portal's key derivation, every importer's parsing and classification, the
browser host's origin matching, and the GUI's editor and import state machines.
All of that runs without hardware. The TPM and FIDO2 round trips are
`#[ignore]`d behind environment variables because they need a chip and a touch
— the TPM ones have been run against a real AMD fTPM and `swtpm` (see
[On authorising `sudo`](#on-authorising-sudo)); the FIDO2 ones have not been
run at all.

End-to-end against real `libsecret` on a private bus: store, lookup, search
(single and multi-attribute, narrowing and contradictory), replace-on-store
without duplicates, delete, unicode secrets, both session algorithms, and
`ReadAlias`. The vault file was checked for plaintext leakage after each,
including a 64-byte non-UTF-8 secret stored through `CreateItem` and read
back byte-identical through `GetSecret` — the case that a lossy string
conversion used to destroy silently.

End-to-end through `xdg-desktop-portal` with a real sandboxed application
(Authenticator, a Flatpak that encrypts its database with a portal-derived
key). The app requested its secret over `org.freedesktop.portal.Secret`, the
portal routed it to locket's backend, and the app's own log confirms `oo7`
took the sandboxed file-backend path and loaded its keyring. Restarting it
decrypted the keyring written under the previous run's key, which is the
property that matters: an app whose derived key moved would lose everything
it had stored.

## Roadmap

Implemented: the vault and its cryptography, key slots (passphrase, TPM 2.0,
FIDO2), the Secret Service (Service/Collection/Item/Session and Prompt
objects), `org.locket.Manager1` for lock state, the Secret portal backend, the
SSH agent, the daemon, the CLI, eight importers, the PAM module, the browser
extension and its native messaging host, the panel applet, the installer, and a
GUI that creates, edits, deletes, generates, imports and enrols factors.

**SSH agent** (`locketd --ssh-agent`) serves vault items of kind `SshKey`,
including security-key (`sk-`) identities — see
[Security keys over SSH](#security-keys-over-ssh). Verified with real OpenSSH:
`ssh-add -l` lists the keys with matching fingerprints, `ssh-keygen -Y sign`
signs through the agent, and `-Y verify` accepts the result. It refuses
`ADD_IDENTITY`/`REMOVE_IDENTITY` on purpose — every process running as you can
reach that socket. `ssh-add -x` and `-X` work, with the passphrase compared in
constant time.

Its identities follow the vault rather than the process: they are loaded when
the vault unlocks and **dropped when it locks**. Both halves matter. The
installed unit starts `--locked` so that PAM can unlock it, so keys loaded once
at startup would be no keys at all; and the keys the agent holds are decrypted
copies, so keeping them after a lock would leave anything that can reach the
socket able to authenticate as you.

RSA keys sign under the hash the client asks for — `rsa-sha2-256`,
`rsa-sha2-512`, or `ssh-rsa` when a client explicitly wants the old one.
OpenSSH rejects a signature that comes back under a different name than it
requested, and `ssh-key` cannot choose a hash for a key loaded from a file at
all, so locket does that part itself.

**Certificates.** A key with an OpenSSH certificate is advertised twice, the
certificate first, exactly as `ssh-add` does — a host configured for
certificate authentication will not accept the bare key, so a vault holding
only the key is useless there. `import-ssh` picks up `<key>-cert.pub`
alongside the key. A certificate for a different key, or one outside its
validity window, is dropped with a log line rather than offered: every server
would reject it while it still cost the client one of its permitted attempts.

```console
$ ssh-add -l
256 SHA256:ORWwGI7n… user@host (ED25519-CERT)
256 SHA256:ORWwGI7n… user@host (ED25519)
```

**Confirm each use.** An agent socket is reachable by every process running as
you — which is why `ADD_IDENTITY` is refused — but a key that signs silently is
still a key any of them can use. Setting a `confirm-each-use` field on an item
makes every signature with it wait for a dialog naming the key:

> Something on this machine is asking to authenticate with "deploy@prod". This
> key is set to ask every time, so nothing happens unless you allow it.

This is OpenSSH's `ssh-add -c`, kept in the vault so it survives a restart and
travels with the key. It fails closed: no frontend, no answer within 30
seconds, or no graphical session at all, and the signature is refused — the
last of those immediately rather than after a timeout, since an `ssh` in a
script is waiting on the other end. Deliberately per key: confirming every
signature trains people to click yes, and the keys worth gating are the few
that authorise something expensive.

Three fields on an `SSH Key` item drive all of this, and the editor sets them
like any other field:

| Field | What it does |
|---|---|
| `certificate` | The `*-cert.pub` text, advertised as a second identity |
| `confirm-each-use` | `yes` to require a confirmation for every signature |
| `token-pin` | The security key's PIN, for a `verify-required` `sk-` key |

**Secret portal** (`locketd --portal`) implements
`org.freedesktop.impl.portal.Secret`. App secrets are *derived*, not stored:
`HKDF-SHA256(portal_master, info = "org.freedesktop.portal.Secret\0" || app_id)`,
so they are reproducible from a vault backup and no two apps can collide.
Install `res/locket.portal` into `/usr/share/xdg-desktop-portal/portals/` to
make xdg-desktop-portal route to it.

What comes next lives in [ROADMAP.md](ROADMAP.md): six milestones from
vault-format parity with KeePassXC (trash, history, attachments, merge)
through passkeys and password health, Wayland-portal auto-type, the polish
and accessibility bar, desktop-wide COSMIC integration, and finally
distribution beyond one machine. The items previously listed here — FIDO2 on
real hardware, packaging beyond Arch, PAM for `sudo`, conditional PKCS#11 —
are carried there with their reasoning intact.

## Building

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` picks the right
one on its own. The system libraries are not optional — these are what the
binaries actually link against, read off `ldd` rather than guessed:

| Provides | Arch | Debian/Ubuntu |
|---|---|---|
| TPM key slots | `tpm2-tss` | `libtss2-dev` |
| Security keys (hidapi's Linux backend) | `systemd-libs` | `libudev-dev` |
| The GUI's keyboard handling | `libxkbcommon` | `libxkbcommon-dev`, `libwayland-dev` |
| Everything | `openssl`, `zlib`, `zstd`, `brotli`, `pkgconf` | `libssl-dev`, `pkg-config` |
| The PAM module | `pam` | `libpam0g-dev` |

```sh
cargo build --release          # ~4 minutes cold, ~75 MB of binaries
cargo test --workspace         # no hardware needed; TPM and FIDO2 tests are #[ignore]d
```

Both hardware factors are cargo features (`tpm`, `fido`, on by default).
Without them neither library is needed, the GUI still builds, and it says the
factor is unavailable in this build rather than pretending otherwise.

For packaging there is a `justfile`, the same shape every COSMIC application
ships:

```sh
just build-release
just rootdir=$DESTDIR prefix=/usr install
just validate-metadata          # desktop entries and AppStream, against their specs
```

`packaging/arch/PKGBUILD` builds an Arch package. Both paths install the pieces
and stop there: claiming `org.freedesktop.secrets`, enabling the unit and
editing a PAM stack are decisions for the person using the machine, taken after
they have imported whatever their current keyring holds.

## Installing as your secret store

```sh
scripts/locket-setup            # build, install, and report what is left to do
scripts/locket-setup --pam      # also unlock the vault at login (needs root)
scripts/locket-setup --status   # who currently owns what
scripts/locket-setup --uninstall
```

Three properties it is built around, because this replaces authentication
infrastructure:

**It imports before it switches.** Your secrets are in gnome-keyring. Taking
the `org.freedesktop.secrets` name first would point every application at an
empty vault, so the script counts both stores and refuses to switch until the
import has happened:

```
gnome-keyring holds 27 item(s); the locket vault holds 0
! Switching now would point every application at an empty store.
```

**It is reversible.** Everything except the PAM module is a *user-level
override* that shadows the system file rather than editing it — a D-Bus service
file in `~/.local/share/dbus-1/services`, a `Hidden=true` autostart entry, a
masked user unit. `--uninstall` deletes them and gnome-keyring comes straight
back. No file under `/usr` is modified.

**It guards the login path.** The PAM step backs up the stack, proves the
module loads against a throwaway service *before* going near `system-login`,
adds the lines as `optional`, and then checks `sudo` still works — restoring
the backup automatically if it does not. Keep a root shell open anyway; that
is the advice for editing any PAM stack and this is no exception.

Two things the switch gets wrong if you do it by hand, both of which make it a
silent no-op:

* **The session bus caches `.service` files at startup.** Writing an override
  into `~/.local/share/dbus-1/services` does nothing until `ReloadConfig`, so
  the bus keeps activating gnome-keyring from `/usr/share`.
* **D-Bus delegates activation to systemd** when the service file carries
  `SystemdService=`, which means the *unit's* `ExecStart` is what runs and the
  `Exec=` line is ignored. The unit must therefore pass `--replace-keyring`, or
  the daemon comes up on `org.locket.secrets` and **nothing** owns
  `org.freedesktop.secrets`. The installer refuses to write a unit missing that
  flag.

A gnome-keyring already holding the name is also not displaced by any of this —
it has to be stopped.

The installer leaves gnome-keyring's **pkcs11** component alone. See below for
why replacing it is probably unnecessary.

## Migrating off gnome-keyring

```sh
locket-cli import --dry-run          # see what would come across
locket-cli import                    # from org.freedesktop.secrets
locket-cli import --from org.locket.secrets --into Imported
locket-cli import --replace          # overwrite rather than skip duplicates
```

There are importers for the other common escape routes too:

```sh
locket-cli import-csv chrome-passwords.csv     # Chrome, Edge, Brave, Firefox,
                                                # Safari, Bitwarden, 1Password
locket-cli import-pass                         # ~/.password-store
locket-cli import-keepass secrets.kdbx
locket-cli import-env ~/GitHub                 # .env files across a tree
locket-cli import-ssh                          # ~/.ssh private keys
locket-cli import-cloud                        # aws, gcloud, az, gh, docker, npm
locket-cli import-totp aegis-export.json       # otpauth:// URIs, Aegis, andOTP
```

And the way out, because a manager you cannot leave is a trap:

```sh
locket-cli export everything.json --i-understand-this-is-plaintext
locket-cli passwd                              # change the vault passphrase
```

The CLI edits too, so the documented recovery tool can actually repair things
when the daemon will not start:

```sh
locket-cli edit github --set username=ada --secret --generate
locket-cli edit github --label "GitHub (work)" --unset old-field --favorite true
locket-cli rm gitlab
```

An ambiguous query lists the candidates and stops rather than guessing, since
these two overwrite and delete.

The export includes the secrets — an export that leaves them out is not a
migration path — so it is written 0600, refuses to overwrite, and tells you to
delete it. The flag is mandatory for the same reason the importers nag: this
file is every credential you own, in the clear.

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
standard locket already implements the other half of. The same code therefore
imports from KWallet or anything else conforming.

It is read-only against the source and idempotent against the target — an item
whose attribute set already exists is skipped, since attribute identity is what
the Secret Service itself uses for replace-on-store. Re-running after adding a
few secrets does not duplicate anything.

Verified end to end: 9 items across 2 collections transfer with byte-identical
secrets, a dry run writes nothing, and a second run imports 0 while recognising
all 9 as already present.

### Repairing an import that went wrong

Skipping duplicates is the right default and the wrong behaviour for a repair:
the attributes match, but the secret in the vault is not the secret the source
holds. `import --replace` overwrites in place instead, keeping the item's id so
anything referring to it still resolves, and counts replacements separately
from new items.

```sh
scripts/locket-reimport-keyring --dry-run
scripts/locket-reimport-keyring
```

That script exists because the obvious way to read gnome-keyring again — stop
locket, start gnome-keyring, import, swap back — takes `org.freedesktop.secrets`
away from every running application for the duration, and they do not all cope:
some cache the name owner, some quietly fall back to storing secrets in the
clear. So it runs gnome-keyring on a *private* bus against the same
`~/.local/share/keyrings` files and imports from that, while your session keeps
locket throughout.

It checks that the keyring actually *unlocked* rather than that gnome-keyring
started, because gnome-keyring starts happily on a wrong password and simply
leaves the collection locked — at which point an import would read zero items
and report success.

**One thing does not survive, by construction.** The Secret Service carries a
label, an `a{ss}` attribute map and a schema string — it has no concept of item
*kind*. Logins, notes and Wi-Fi passwords are recovered because they have
recognisable schema or attribute signatures; an SSH key or a payment card
arrives as a generic application secret and needs retyping in the UI. That is a
limit of the source format, not of the importer, and it is why moving a locket
vault between machines should be a file copy rather than an import.

## Unlocking on demand

The Secret Service spec has no way to *unlock* a service — its `Prompt` objects
say "ask the user" without saying how, because on GNOME the answer is a
gnome-keyring-specific dialog. `org.locket.Manager1` is that missing half:
`Unlock(passphrase) -> bool`, `Lock()`, and `Locked`/`ItemCount`/`VaultPath`
properties, plus an `UnlockRequested` signal.

A locked locket vault cannot have its *items* enumerated — labels and
attributes live inside the sealed body, which is the point, but it means
gnome-keyring's trick of listing locked items is unavailable. Returning "no
matches" would be a lie clients believe, reporting a secret as *missing* rather
than locked. So `SearchItems` on a locked vault emits `UnlockRequested` and
waits.

Its *collections* are a different matter, and that is why the vault keeps a
plaintext index of them: a service that cannot answer `ReadAlias` or
`Collections` while locked does not look locked to `libsecret`, it looks like a
machine with no keyring on it.

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

Also verified across two real processes on a live COSMIC session: `locketd`
logs *"asked the frontend to unlock"*, the GUI logs *"daemon asked for an
unlock"*, and the unlock screen appears reading "An application asked for a
secret from your vault."

## Unlocking at login

`pam_locket.so` takes the password you have already typed at the login screen
and hands it to the daemon. When that password is also your vault passphrase,
logging in unlocks the vault and every `libsecret` application finds its
secrets without a second prompt. See [res/pam-install.md](res/pam-install.md).

It is an **auth/password/session** module and nothing more. `sm_authenticate`
returns `PAM_IGNORE`, so it takes no part in the authentication decision — it
only observes a token PAM already accepted. Every failure path returns success:
a password manager that stops you logging in is worse than one that does not
auto-unlock. There is deliberately no `sudo` entry; authorising privilege
escalation is a different module with a much higher bar.

The `password` line is what survives `passwd`. Change your login password
without it and the vault keeps the old passphrase: auto-unlock quietly stops
working and nothing anywhere explains why. With it, PAM hands the daemon both
the old and the new password, and the daemon re-wraps the vault key under the
new one — after proving the old one opens the vault, so this cannot be used to
change a passphrase nobody knew.

The passphrase reaches the daemon over a socket in `/run/user/<uid>/locket/`,
a directory the kernel already restricts to that user (0700), with the socket
itself 0600. The path is derived from the uid rather than `$XDG_RUNTIME_DIR`,
because a PAM module runs as root in a process whose environment belongs to
nobody. `locket-ipc` carries this protocol and has no dependencies beyond
`zeroize` — it is linked into a module that loads on every login, so pulling in
an async runtime or a D-Bus client there would be irresponsible.

`locketd --locked` starts without a passphrase and waits, which is what the
login case needs: at boot nobody has typed anything yet.

Verified end to end with `pamtester` against a throwaway user, on a stack that
touched no system PAM config:

* daemon starts locked → correct login password → daemon logs *"vault unlocked
  over the unlock socket"* and the module logs *"vault unlocked for the
  session"*;
* wrong login password → `pam_unix` rejects it, vault untouched;
* correct login password but a *different* vault passphrase → **the session
  still opens**, the vault stays locked, and the module says so once.

## Importing what you already have

Every importer is available from the GUI's **Import** button and from the CLI.
None of them modify or delete the source — a migration you cannot reverse is
not a migration, it is a gamble.

| Source | GUI | CLI |
|---|---|---|
| Browser / manager `.csv` | Browser or password manager export | `locket-cli import-csv FILE` |
| Project `.env` files | Project .env files | `locket-cli import-env DIR` |
| SSH private keys | SSH private keys | `locket-cli import-ssh` |
| Cloud CLI credentials | Cloud CLI credentials | `locket-cli import-cloud` |
| Authenticator export | Authenticator export (TOTP) | `locket-cli import-totp FILE` |
| `pass` store | pass (password-store) | `locket-cli import-pass` |
| KeePass `.kdbx` | KeePass database | `locket-cli import-keepass FILE` |
| Running keyring | Running keyring | `locket-cli import` |

### Project `.env` files

Walks a tree of projects, skipping `node_modules`, build output and
`.env.example`-style templates. `--group-by` decides the shape: one item per
file (the default, preserving "these belong together"), one per inferred
service (`STRIPE_*` in one item, `AWS_*` in another), or one per variable —
which puts the value in the Secret Service secret itself, so
`secret-tool lookup env:key STRIPE_SECRET_KEY` returns it directly.

`--dry-run` reads the files but never the vault, so it needs no passphrase:

```console
$ locket-cli import-env ~/GitHub --dry-run
...
191 file(s), 2512 variable(s), 991 credential(s) under /home/you/GitHub
```

Variables are classified rather than blanket-encrypted: `PORT=3000` stays a
plain field while `STRIPE_SECRET_KEY` is masked. The classifier errs towards
"secret" — a needlessly-masked field costs a click, a missed one leaves a live
credential in plaintext metadata.

### SSH private keys

Copies the keys from `~/.ssh` into `ItemKind::SshKey` items, which is the
shape locket's own SSH agent already reads. Keys are found by their PEM
banner rather than the `id_*` naming convention, so `deploy-key-prod` is not
missed. The private key goes in the `private-key` field and the item's secret
is reserved for the key's *passphrase*, which is what an encrypted key needs
to be usable.

Your key files stay exactly where they are; OpenSSH keeps reading them.
Confirm `ssh-add -l` lists them through locket's agent before removing
anything.

A security-key file — `sk-ssh-ed25519@openssh.com` or
`sk-ecdsa-sha2-nistp256@openssh.com` — is imported like any other, but it is
not the same kind of thing and the import says so:

```console
$ locket-cli import-ssh
imported 2 item(s); 0 already present, 0 unreadable from /home/you/.ssh

1 of these sign on a security key: id_ed25519_sk. The files hold credential
handles rather than private keys, so importing them is not a backup — they
authenticate only with the token present.
```

The item carries the same warning in a note, because months later the vault is
the only thing anyone reads, and "I have a copy of the key" is the wrong
conclusion to be left with. The algorithm is recorded as an attribute either
way.

### Cloud CLI credentials

`aws`, `gcloud`, `az`, `gh`, `docker` and `npm` all cache long-lived
credentials in your home directory with no encryption. Unlike `.env` files
they are not project-scoped: one of them authorises everything the account
behind it can do.

```console
$ locket-cli import-cloud --dry-run
Google Cloud CLI     /home/you/.config/gcloud/credentials.db
GitHub CLI           /home/you/.config/gh/hosts.yml
```

gcloud's store is a SQLite database, read through the `sqlite3` binary rather
than a linked library — the same choice the `pass` importer makes in shelling
out to `gpg`. It keeps a C dependency out of the build for one file, and if
`sqlite3` is missing that store is reported as skipped instead of silently
contributing nothing. Only the refresh token is kept; access tokens expire
within the hour and are not worth storing.

Importing does not make the originals safe. Rotate them, or remove them once
the tools read from locket.

### Authenticator exports

Accepts a list of `otpauth://` URIs, or a plain-text Aegis or andOTP export;
the format is sniffed from the content, since both are `.json`. Encrypted
Aegis and andOTP backups are refused with an explanation rather than
half-read. Every seed is parsed as a real TOTP before it is stored, so an
import that reports success cannot have written a code that will never
generate.

Google Authenticator and Authy are not supported because they do not export
the seed in any readable form.

## Flatpak apps and the Secret portal

A sandboxed application cannot reach `org.freedesktop.secrets` directly. It
asks `org.freedesktop.portal.Secret` for a per-application key instead, and
xdg-desktop-portal forwards that to whichever *backend* the desktop prefers.
locket implements that backend (`locketd --portal`), but being implemented
is not enough — two separate things have to line up, and neither does by
default:

1. **The `.portal` file has to be somewhere xdg-desktop-portal looks.** It
   scans `XDG_DATA_DIRS` only, which does not include `~/.local/share`. A
   backend installed under your home directory is never seen, with no error
   anywhere. It has to go in `/usr/share/xdg-desktop-portal/portals/`, which
   is the one part of the install that needs root.

2. **The desktop's `portals.conf` has to name it.** COSMIC ships

   ```ini
   [preferred]
   org.freedesktop.impl.portal.Secret=oo7-portal;gnome-keyring;
   ```

   and a backend that is merely present but unlisted is never chosen. Worse,
   the fallback is a D-Bus-activatable gnome-keyring, so a Flatpak app asking
   for a secret will *start* the daemon locket just replaced, and the two then
   contend for `org.freedesktop.secrets`.

`locket-setup` does both: it installs the `.portal` file system-wide and
writes a user-level `portals.conf` preferring locket. Because these files are
not merged across directories — the first one found wins outright — the user
copy is derived from the desktop's own file so the rest of its preferences
survive:

```console
$ locket-setup            # includes the portal step; will ask for sudo
$ locket-setup --status
:: Flatpak apps (Secret portal)
 ✓ portal backend installed
 ✓ Secret portal routed to locket (via ~/.config/xdg-desktop-portal/cosmic-portals.conf)
```

If the portal step is skipped, everything else still works — only Flatpak
applications are affected. `--status` says so explicitly rather than leaving
you to find out when an app silently fails to remember a password.

## Why there is no PKCS#11 module

The plan was to replace gnome-keyring's PKCS#11 provider, on the assumption it
was the last thing keeping the package alive. Checking rather than assuming
showed otherwise. gnome-keyring's own registration says:

```
# This module is obsolete and only exposed to specific programs that
# rely on it through gcr's certificate pinning API.
enable-in: geary, midori
```

It is enabled for exactly two programs, upstream calls it obsolete, and on the
machine this was developed against:

* neither `geary` nor `midori` is installed;
* `p11-kit-trust` provides the certificate trust store at priority 1, not
  gnome-keyring;
* `p11tool --list-tokens` lists p11-kit's two trust tokens and the TPM — **no
  gnome-keyring token at all**;
* browsers keep client certificates in their own NSS databases
  (`~/.pki/nssdb`, `cert9.db`), never in gnome-keyring;
* nothing outside its own `.module` file references it.

So a locket PKCS#11 provider would be a module nothing loads: a large C ABI
surface — around 68 function pointers — with no caller. It is not written.

It becomes worth revisiting if you install one of those two programs, or want
to expose vault certificates to a PKCS#11 consumer such as an EAP-TLS VPN
client. SSH is already covered by the agent, which is the path SSH actually
prefers.

## Browser autofill

```sh
# load extension/ unpacked, then pass the id chrome://extensions shows you
scripts/locket-setup --browser <extension-id>
```

Chrome and Firefox get separate manifests — see
[extension/README.md](extension/README.md). MDN suggests declaring both
`background.service_worker` and `background.scripts` in one file for
cross-browser use, but Chrome 151 warns on that
(`'background.scripts' requires manifest version of 2 or lower`) and flags the
extension, so they are kept apart. Firefox needs the split regardless:
`background.service_worker` is still unimplemented there.

The design assumption is that **a browser extension is not trusted** — it runs
alongside every page you visit and is one supply-chain compromise away from
hostile. So the host never exposes the vault wholesale:

* `search` returns metadata only — labels and usernames, never a password —
  and only for entries matching the origin the caller names.
* `get` returns exactly one secret, and re-checks the origin at that moment
  against the page the secret is about to be typed into. The id is not the
  authorisation: a tab can navigate between the popup opening and the click,
  and an extension is assumed hostile. The extension checks the tab too, but
  the host does not rely on that.
* A secret that is not text is refused rather than converted lossily — some
  genuinely are binary, and none of those belong in a login form.
* Nothing unlocks the vault. A locked vault answers `locked` and stops; the
  passphrase is typed into locket's own window, never into a web page.
* Filling happens only on an explicit click in the popup, never automatically
  on page load — automatic autofill is how a password manager becomes a
  credential-harvesting bug on a hostile page.

Origin matching is on suffix boundaries, so `mail.example.com` matches an entry
saved for `example.com`, while `notexample.com` and `example.com.evil.test` do
not, and a credential saved for a subdomain never leaks up to the parent.
Getting that wrong is how a manager hands passwords to a lookalike domain, so
it is tested directly.

Verified against the live daemon: `status` reports the daemon and lock state,
and while locked both `search` and `get` return `locked` without leaking
anything.

## Panel applet

`locket-applet` shows lock state in the COSMIC panel: a secure icon when the
vault is open, an insecure one when it is not, and a neutral one when no daemon
is running — it does not claim "locked" for a vault it cannot see.

It can **lock** in one click but deliberately cannot **unlock**: that button
opens the main window instead. A panel popup is a poor place to type a master
passphrase — small, undecorated, untitled, and appearing exactly where users
are trained to expect system prompts, which is the shape a spoofed prompt would
take. Locking is safe to expose because a fake "lock" button costs nothing.

The applet and the GUI share one `ManagerProxy` definition in
`locket-secret::client`; a drifting copy is the kind of bug that surfaces as
"the applet says locked but the window says unlocked".

Opening the window from the panel asks the compositor for an XDG activation
token first. Without one, a window launched from a panel button comes up
unfocused behind it — and if locket is already running there is nothing to
raise it with. The launch itself goes through `spawn_desktop_exec`, which
double-forks it out of the panel process and into its own systemd scope, so
restarting the panel does not take the vault window with it.

Clicking the button twice does not give you two vault windows: a second
`locket` hands its activation over D-Bus to the one already running and exits.
Two windows would each hold their own vault handle, so locking one would leave
the other unlocked. Set `COSMIC_SINGLE_INSTANCE=0` to opt out — needed if you
want two vaults side by side with `LOCKET_VAULT`, since the hand-off carries
no arguments.

## When the vault locks

Locking is the whole security story of a session daemon, so it happens on more
than a button:

* **The GUI locks it** with `Ctrl+L`, and that locks the daemon too — otherwise
  the window would look locked while every `libsecret` client carried on
  reading secrets.
* **Idle**: the frontend has a 15-minute default for its own window, and
  `locketd --auto-lock SECONDS` covers the session, because closing the window
  is not the same as ending the session. Both Secret Service traffic and SSH
  agent requests count as use — being locked out mid-`ssh` because no secret
  had been read would be its own bug. The installed unit passes
  `--auto-lock 900`.
* **The session locks**, or the machine suspends. `locketd` watches logind for
  both `Lock` and the `LockedHint` a screen locker sets, plus
  `PrepareForSleep`, because different lockers announce themselves differently
  and a locked screen with a readable vault behind it is not a locked screen.
  `--no-lock-on-idle-session` turns that off.

In every case the SSH agent's identities go with it.

## Two processes, one file

The daemon holds the vault, and the GUI opens the same file directly whenever
it is not going through a daemon — so two writers is the normal arrangement,
not an exotic one. Saving is done under an advisory lock on a sibling
`.vault.lock`, and a file that changed since it was read is refused with
`ChangedOnDisk` rather than overwritten:

* the daemon reloads before it writes, and after an external write it is told
  to catch up by whoever wrote it (`org.locket.Manager1.Reload`);
* the frontend reloads before it edits, polls for external changes while it is
  open, and calls `Reload` after saving so the daemon is never left serving
  what it read ten minutes ago.

A conflict that survives all that loses one write and says so. It does not
silently discard the other side's, which is what the previous arrangement did
every time the two processes were both open.

## Managing unlock factors

The **Security** page in the GUI lists every slot and adds or removes them. Two
rules are enforced there rather than left to judgement:

* A passphrase slot can never be the last one removed. Hardware is additive, so
  a dead motherboard or a lost token must not be a lost vault — the button says
  "Required" rather than silently failing.
* The screen states what a TPM PIN actually rests on: the chip's lockout, not
  the PIN's length, and that lockout is device-wide.

Enrolment runs on a worker thread. A TPM seal takes the better part of a second
and a security key takes as long as it takes someone to touch it, so the vault
is moved into the worker and the screen says *"Waiting for you to touch your
security key…"* rather than freezing or claiming to be locked.

Hardware support is behind cargo features (`tpm`, `fido`, both on by default),
because `tss-esapi` needs libtss2 and `ctap-hid-fido2` needs hidapi. Without
them the GUI still builds and says the factor is unavailable in this build.

Verified against the real AMD fTPM, through the same code path the GUI calls:

```
slots before:  Passphrase        argon2id m=65536KiB t=3 p=4
slots after:   Passphrase        argon2id m=65536KiB t=3 p=4
               TPM 2.0 (PIN)     TPM 2.0 + PIN

correct PIN, no passphrase -> OPENED via TPM: 2 slots
wrong PIN                  -> refused (one DA strike, 0x2 -> 0x3)
passphrase                 -> still opens it
```

## Security keys (FIDO2)

`locket-fido` enrols a slot whose key comes from a token's `hmac-secret`
extension. The distinction from a fingerprint reader matters: `fprintd` returns
a *verdict*, so a daemon must already hold the key and merely gates releasing
it. A FIDO2 token given a salt returns `HMAC-SHA256(credential_secret, salt)` —
32 bytes that exist nowhere but on the device. The vault key therefore cannot
be reconstructed from a stolen disk image at all.

Credentials are created under the relying-party id `locket.local`, which is
deliberately not a real domain: `hmac-secret` is scoped per (rp_id, credential),
so a locket credential cannot be exercised by a website.

**Not verified on hardware** — no FIDO2 token is attached to this machine. The
round-trip tests are `#[ignore]`d behind `LOCKET_FIDO_TESTS=1` (plus
`LOCKET_FIDO_PIN` if your token has one); they need a physical touch.

## Security keys over SSH

A security-key SSH identity is a different animal from the vault slot above,
and the agent serves it. `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com` private key files contain no signing
scalar at all: a public key, an *application* string (`ssh:`), a flags byte and
a credential handle. Signing means asking the token for a FIDO2 assertion over

```
SHA256(application) ‖ flags ‖ counter ‖ SHA256(message)
└─────────── authenticator data ──────┘  └ client data hash ┘
```

and dressing the result in SSH's clothing: `string algorithm, string signature,
byte flags, uint32 counter`, with the trailer *outside* the signature string.

Three things there are easy to get wrong, so each is checked rather than
assumed:

* **The trailer's position.** `ssh_key::Signature` keeps flags and counter
  inside its own byte array and splits them back out only for Ed25519, not for
  ECDSA — so locket writes the blob itself, and the tests hand what it wrote
  back to `ssh-key`'s decoder and verifier to prove the two agree.
* **ECDSA integer encoding.** A token returns ES256 signatures in ASN.1 DER;
  SSH wants `mpint r ‖ mpint s`. A component with its high bit set needs a
  leading zero byte or it reads as negative, and the failure would surface only
  as a server rejecting a signature that looked fine here.
* **Extension data.** The verifier reconstructs exactly 37 bytes of
  authenticator data. A token that appended extension output would sign
  something no server rebuilds, so an oversized assertion is refused locally
  with an explanation instead of becoming an unexplainable auth failure.

A `verify-required` key needs the token's PIN as well as a touch; store it in
the item's `token-pin` field and the agent passes it through. Without it the
assertion asks for user verification and the token decides how to get it —
its own PIN entry, or a fingerprint.

The hardware call is a blocking one that waits for a human, so it runs on a
blocking thread rather than a runtime worker, and the daemon logs *"touch your
security key to sign with `<key>`"* at its default log level. A signature that
waits silently for hardware is indistinguishable from a hang.

Verified end to end against real OpenSSH, with a key file `ssh-keygen -l`
reports as `ED25519-SK`:

```console
$ ssh-add -l
256 SHA256:xypkA6tk… ordinary@key (ED25519)
256 SHA256:0ErLWxzF… token@laptop (ED25519-SK)
```

and, with no token plugged in, `ssh-keygen -Y sign` fails in about a second
with the agent logging *"no FIDO2 security key found; plug one in and try
again"* rather than hanging. The signature encoding itself is covered by unit
tests driving a software token that produces assertions the way real hardware
does; **the hardware path has never run against an actual token**, for the same
reason the slot above has not.

Support is behind the `fido` cargo feature (on by default) because it needs
`hidapi`. Built without it, `sk-` identities are dropped at load with a log
line saying why — an identity the agent cannot sign for is worse than a missing
one, since the client still spends one of the server's permitted
authentication attempts offering it.

## On authorising `sudo`

A PAM module that accepts "the user's daemon said yes" is *weaker* than typing
a password: any process running as you could claim the bus name and mint root
for itself. The decision has to be anchored in something your own uid cannot
forge. A short PIN can do that when it is not acting as a password but as the
`authValue` on a TPM-bound key: the entropy is nowhere near enough on its own,
and what makes it viable is the chip refusing further attempts after a handful
of wrong ones.

`locket-tpm` implements that: a random 32-byte secret sealed to the TPM under
an `authValue`, enrolled as a key slot. One detail is load-bearing —
`tss-esapi`'s own sealing example builds the object with `no_da(true)`, which
**exempts it from dictionary-attack lockout**. That would reduce the PIN to a
~20-bit password with unlimited guesses. `locket-tpm` clears `noDA` whenever a
PIN is set, and there is a test asserting it.

PCR binding is deliberately *not* used: binding to firmware measurements means
a BIOS update locks you out of your own vault, and the PIN is what provides the
security here.

**Verified on real hardware** — an AMD firmware TPM — as well as against
`swtpm`. Seal/unseal round trip, wrong-PIN rejection, and a TPM slot opening a
real vault all pass, and the chip's dictionary-attack counter incremented
exactly once per wrong PIN, which is the property the whole design rests on.

The tests are `#[ignore]`d behind `LOCKET_TPM_TESTS=1` and a TCTI:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/tpm --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --flags not-need-init,startup-clear &
TCTI="swtpm:host=localhost,port=2321" LOCKET_TPM_TESTS=1 \
  cargo test -p locket-tpm -- --ignored
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
