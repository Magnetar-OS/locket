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
  passman-applet   COSMIC panel indicator
  passman-tpm      TPM 2.0 sealed key slots (tss-esapi)
  passman-fido     FIDO2 hmac-secret key slots (ctap-hid-fido2)
  passman-import   pass, KeePass/.kdbx and browser CSV importers
  passman-ipc      the unlock-socket protocol (no deps; linked into PAM)
  passman-pam      pam_passman.so — unlocks the vault at login
  passman-nmh      native messaging host for the browser extension
extension/         the browser extension itself (Chrome/Firefox, MV3)
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
4. **PKCS#11** — for consumers of gnome-keyring's certificate store.
5. **PAM for `sudo`** — a *different* module from the session one below, and
   still gated on the reasoning in the TPM section.

## Installing as your secret store

```sh
scripts/passman-setup            # build, install, and report what is left to do
scripts/passman-setup --pam      # also unlock the vault at login (needs root)
scripts/passman-setup --status   # who currently owns what
scripts/passman-setup --uninstall
```

Three properties it is built around, because this replaces authentication
infrastructure:

**It imports before it switches.** Your secrets are in gnome-keyring. Taking
the `org.freedesktop.secrets` name first would point every application at an
empty vault, so the script counts both stores and refuses to switch until the
import has happened:

```
gnome-keyring holds 27 item(s); the passman vault holds 0
! Switching now would point every application at an empty store.
```

**It is reversible.** Everything except the PAM module is a *user-level
override* that shadows the system file rather than editing it — a D-Bus service
file in `~/.local/share/dbus-1/services`, a `Hidden=true` autostart entry, a
masked user unit. `--uninstall` deletes them and gnome-keyring comes straight
back. No file under `/usr` is modified.

**It cannot lock you out.** The PAM step backs up the stack, proves the module
loads against a throwaway service *before* going near `system-login`, adds the
lines as `optional`, and then checks `sudo` still works — restoring the backup
automatically if it does not.

Two things the switch gets wrong if you do it by hand, both of which make it a
silent no-op:

* **The session bus caches `.service` files at startup.** Writing an override
  into `~/.local/share/dbus-1/services` does nothing until `ReloadConfig`, so
  the bus keeps activating gnome-keyring from `/usr/share`.
* **D-Bus delegates activation to systemd** when the service file carries
  `SystemdService=`, which means the *unit's* `ExecStart` is what runs and the
  `Exec=` line is ignored. The unit must therefore pass `--replace-keyring`, or
  the daemon comes up on `org.passman.secrets` and **nothing** owns
  `org.freedesktop.secrets`. The installer refuses to write a unit missing that
  flag.

A gnome-keyring already holding the name is also not displaced by any of this —
it has to be stopped.

The installer leaves gnome-keyring's **pkcs11** component alone. See below for
why replacing it is probably unnecessary.

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

## Unlocking at login

`pam_passman.so` is the `pam_gnome_keyring` equivalent: when your login
password is also your vault passphrase, logging in unlocks the vault and every
`libsecret` application finds its secrets without a second prompt. See
[res/pam-install.md](res/pam-install.md).

It is a **session** module and nothing more. `sm_authenticate` returns
`PAM_IGNORE`, so it takes no part in the authentication decision — it only
observes a token PAM already accepted. Every failure path returns success: a
password manager that stops you logging in is worse than one that does not
auto-unlock. There is deliberately no `sudo` entry; authorising privilege
escalation is a different module with a much higher bar.

The passphrase reaches the daemon over a socket in `/run/user/<uid>/passman/`,
a directory the kernel already restricts to that user (0700), with the socket
itself 0600. The path is derived from the uid rather than `$XDG_RUNTIME_DIR`,
because a PAM module runs as root in a process whose environment belongs to
nobody. `passman-ipc` carries this protocol and has no dependencies beyond
`zeroize` — it is linked into a module that loads on every login, so pulling in
an async runtime or a D-Bus client there would be irresponsible.

`passmand --locked` starts without a passphrase and waits, which is what the
login case needs: at boot nobody has typed anything yet.

Verified end to end with `pamtester` against a throwaway user, on a stack that
touched no system PAM config:

* daemon starts locked → correct login password → daemon logs *"vault unlocked
  over the unlock socket"* and the module logs *"vault unlocked for the
  session"*;
* wrong login password → `pam_unix` rejects it, vault untouched;
* correct login password but a *different* vault passphrase → **the session
  still opens**, the vault stays locked, and the module says so once.

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

So a passman PKCS#11 provider would be a module nothing loads. Writing one
would be a large C ABI surface — around 68 function pointers — serving no
caller, and the honest engineering answer is not to write it.

It becomes worth revisiting if you install one of those two programs, or want
to expose vault certificates to a PKCS#11 consumer such as an EAP-TLS VPN
client. SSH is already covered by the agent, which is the path SSH actually
prefers.

## Browser autofill

```sh
# load extension/ unpacked, then pass the id chrome://extensions shows you
scripts/passman-setup --browser <extension-id>
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
* `get` returns exactly one secret, for an id the extension had to learn from a
  matching `search`.
* Nothing unlocks the vault. A locked vault answers `locked` and stops; the
  passphrase is typed into passman's own window, never into a web page.
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

`passman-applet` shows lock state in the COSMIC panel: a secure icon when the
vault is open, an insecure one when it is not, and a neutral one when no daemon
is running — it does not claim "locked" for a vault it cannot see.

It can **lock** in one click but deliberately cannot **unlock**: that button
opens the main window instead. A panel popup is a poor place to type a master
passphrase — small, undecorated, untitled, and appearing exactly where users
are trained to expect system prompts, which is the shape a spoofed prompt would
take. Locking is safe to expose because a fake "lock" button costs nothing.

The applet and the GUI share one `ManagerProxy` definition in
`passman-secret::client`; a drifting copy is the kind of bug that surfaces as
"the applet says locked but the window says unlocked".

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
