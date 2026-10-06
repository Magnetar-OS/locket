# Threat model

**October 2026 · vault format 4**

What each piece of locket trusts, what can reach it, and what an attacker in
each position can and cannot do. Written to be the document an external
reviewer starts from — and to be falsifiable: where a claim rests on
something that was measured or tested, it says so, and where it rests on an
assumption, it says that too.

The [security policy](../SECURITY.md) covers reporting and scope. This is the
model underneath it.

## The assets

1. **The data-encryption key (DEK).** 32 bytes. Everything else is a way of
   getting to it or a consequence of having it.
2. **The vault body** — item labels, usernames, attributes, secrets,
   attachments, history — sealed under the DEK.
3. **The collection index** — collection ids, labels and aliases. Plaintext,
   deliberately; see [Deliberate exposures](#deliberate-exposures).
4. **Derived per-application portal keys.** Not stored: recomputed as
   `HKDF-SHA256(portal_master, "org.freedesktop.portal.Secret\0" || app_id)`.
   Compromise of the portal master compromises every sandboxed app's store.

## The components, and what each trusts

| Component | Holds the DEK? | Trusts | Reached by |
|---|---|---|---|
| `locket-core` | in memory, while open | nothing — no I/O, no D-Bus, no UI | linked into everything below |
| `locketd` | **yes**, while unlocked | the vault file, the session bus; it talks to no TPM and no security key | every client below |
| `locket` (GUI) | yes, while its window is unlocked — it opens the vault file itself, with or without a daemon | the vault file, `cosmic-config`, the daemon's `VaultLocked` announcements, and the TPM or token it asks for a slot's key | the person at the keyboard |
| `locket-cli` | yes, while it runs | the vault file only, and the TPM or token when told to unlock with one; it reads nothing from the daemon, and tells a running one to re-read the file after a write | a terminal |
| `pam_locket.so` | no | the unlock socket's location — a 0700 directory in the user's 0700 `XDG_RUNTIME_DIR`; no peer credentials are checked | the login stack, as root |
| SSH agent (in `locketd`) | via the daemon | nothing about its callers | any process running as you |
| Secret portal backend | via the daemon | `xdg-desktop-portal` to name the app id | sandboxed applications |
| `locket-native-host` | **no** | nothing — treats the extension as hostile; a person's "Allow" in locket's own dialog gates every password | the browser, one process per connection |
| Browser extension | no | nothing it is given | every page you visit |
| `locket-applet` | no | nothing — an ordinary Secret Service client | the panel |

The shape to notice: **the daemon holds the key for the session, and the
window holds a copy only while it is unlocked** — it locks itself on its own
idle timer, on `Ctrl+L`, and when the daemon announces a lock from the panel,
the screen locking or suspend. The pieces most exposed to hostile input — the
extension, its host, the applet — hold none of it and cannot unlock anything.
The window writes no core dump (it sets its core limit to zero at start),
but unlike the daemon and the confirmation dialogs it does not make itself
non-dumpable: xdg-desktop-portal identifies a caller by opening
`/proc/<pid>/root`, which a non-dumpable process refuses, and every file
dialog and auto-type go through the portal. So while it is unlocked, whether
another process running as you can attach to it or read its memory rests on
the kernel's Yama `ptrace_scope` (1, "descendants only", on Arch and most
distributions). Its passphrases, PINs, the item editor's values (the
secret and every field, whatever its kind) and the copy kept for clearing
the clipboard are held in wiping buffers. The text-input widget's own copies
are beyond its reach: one per frame, and one in the widget's state that
follows the form's value and is emptied when the form is — on save, cancel
or lock — but freed rather than wiped. What goes on the clipboard is a plain
string from there on, held by the compositor and whatever reads it; the
clear timer is the defence.

## Attacker positions

### A. Someone with the vault file

A backup, a synced copy, a stolen disk. They have the ciphertext and the
plaintext collection index.

**Cannot** read any item without a factor: the body is XChaCha20-Poly1305
under the DEK, and the DEK is wrapped per slot — Argon2id (64 MiB, t=3 by
default) from the passphrase, or a TPM/FIDO2 secret. Tested: wrong
passphrase, wrong device key, and tampering with the slot table, the
collection index or the body all fail closed rather than degrade.

**Cannot** downgrade the KDF: the header is fed to both AEADs as associated
data, so editing the cost parameters breaks authentication instead of
weakening the file.

**Can** learn how many collections exist and what they are called, that the
vault exists at all, its approximate size, and when it was last written.

**Can** brute-force a weak passphrase, at Argon2id's price. This is the
attack the strength meter on vault creation exists to make less likely.

**Cannot** do anything with a TPM factor's sealed blob, which is in the file:
it unseals only on the TPM that made it (tested: a second software TPM
refuses it). **Can** see that the vault has a TPM or security-key factor,
and the token's credential id and salt — the slots are in the header, in the
clear, because the unlock screen has to offer them before anything is
unlocked.

With the file *and the machine* the TPM factor is a PIN and a counter. The
chip counts wrong PINs — one strike each, tested against `swtpm` — and stops
answering at its limit, the right PIN included, until its recovery time has
passed. How many guesses that leaves an attacker is the chip's number, not
locket's: 3 on `swtpm`, 32 with a two-hour decay on the AMD fTPM this was
developed on. A PIN-less TPM factor cannot be made; nothing would stand
behind it. PCR binding is not used, so the factor does not notice a changed
boot chain.

### B. A process running as you, vault **locked**

**Cannot** get a secret. The daemon holds no key; the Secret Service answers
`IsLocked`, the agent has dropped every identity, the portal backend has
nothing to derive from.

**Can** ask for an unlock, which surfaces as a dialog in a titled window of
locket's own — not a keystroke the asking process can see, and not a surface it
can position or dress up. One dialog serves every request made while it is up,
so asking repeatedly does not stack them; behind a locked screen no dialog is
raised at all and the request is refused.
**Can** see the collection index and the fact that a vault exists.

**Can**, if you are in the `tss` group, try TPM PINs against the chip itself
with the sealed blob from the vault file — locket is not in that path and
cannot rate-limit it. The chip does: each wrong PIN is a strike, and the
price of the protection is that such a process can spend your strikes and
put the TPM into lockout for everything that uses it. That is the reason
the passphrase factor can never be removed.

### C. A process running as you, vault **unlocked**

This is the position the design does *not* defend against, and saying so
plainly matters more than any mitigation listed here: a session secret store
that is unlocked serves the session. Anything running as you can call
`GetSecret` over `org.freedesktop.secrets`, exactly as `libsecret` would.

What is still true in this position:

- **The key is not readable out of the daemon's memory.** `locketd` sets
  `PR_SET_DUMPABLE(0)` at startup, so `ptrace`, `process_vm_readv` and core
  dumps are refused even to the same user. Verified: `/proc/<pid>/mem` is
  root-owned and `/proc/<pid>/environ` unreadable while it runs.
- **The key does not reach swap** where `RLIMIT_MEMLOCK` allows `mlockall`;
  the shipped unit grants `LimitMEMLOCK=infinity`, and the daemon logs when
  it could not lock.
- **SSH keys cannot be added or removed** through the agent socket
  (`ADD_IDENTITY`/`REMOVE_IDENTITY` are refused), and a key marked
  `confirm-each-use` will not sign without a dialog — which fails closed on
  no frontend, no answer in 30 seconds, or no graphical session. The dialog
  is a separate `locket --confirm-signing` process the daemon starts and
  reads the answer from over a pipe only it holds: the question is not
  broadcast on the bus and no bus method answers it (tested over a private
  bus). The dialog sets `PR_SET_DUMPABLE(0)`, so another process running as
  you cannot attach to it and press "Allow". **Not** covered: a process that
  rewrites the user manager's environment (`systemctl --user
  set-environment LD_PRELOAD=…`) before the dialog starts — which subverts
  the daemon itself at its next start just as well — or one that can inject
  input into the compositor.
- **A hardware factor's key crosses the session bus once per unlock.** The
  window or the dialog has the TPM or the token release the slot's key and
  hands it to the daemon through `Manager1.UnlockWithKey`, as it hands a
  passphrase through `Unlock`. Whatever can watch that bus learns a key that
  opens this vault file, as it would learn the passphrase; a PIN never
  crosses it.
- **Locking is the defence**, which is why it happens on idle, on session
  lock, on the compositor raising `LockedHint`, and on suspend. **Unlocking
  the screen does not undo it.** The lock screen's password never reaches
  locket — `pam_locket` acts when a session opens, and a screen locker opens
  none — so after any of these the vault stays locked until the person
  answers locket's own unlock dialog, raised by the first application that
  needs a secret. The cost is that applications ask again after every screen
  lock; what it buys is that a process in this position finds a locked vault
  (position B) for as long as nothing has needed it.
- **The control interface is not a boundary.** `org.locket.Manager1`
  authenticates no caller: a process running as you can turn the idle lock
  off (`SetAutoLock(0)`), lock the vault, refuse a pending unlock
  (`CancelUnlock`), and try passphrases through `Unlock` or the unlock
  socket at Argon2id's cost per guess, unthrottled — or 256-bit slot keys
  through `UnlockWithKey`, to no purpose. Locking on session lock
  and suspend is not a setting and cannot be turned off this way. None of
  this reveals a secret it could not already read in this position.

### D. A hostile browser extension

Assumed hostile by construction — it runs beside every page and is one
supply-chain compromise away. What makes that hard is that the native host
has **no independent view of the browser**: the page URL in every request is
a field the extension fills in. So the host's guarantees are the ones that
hold whatever the extension claims:

- **No password leaves without the person.** `Get` puts up a locket dialog
  (`locket --confirm-fill <site> <entry>`, the same private-pipe mechanism as
  SSH confirmation) naming the entry and the site, and releases the one
  secret only on "Allow once"; a refusal, a closed dialog, 30 seconds of
  silence or no graphical session all answer `Refused`. The extension can
  ask, and cannot answer. A hostile extension naming `github.com` gets a
  dialog saying so — not the password. The allowance is for that one fill:
  nothing is remembered per site or for a while afterwards, so every
  password a compromised extension obtains is one a person clicked through.
- **Metadata is not protected against it.** `Search` returns labels and
  usernames — never passwords — for whatever origin it is asked about, and
  a hostile extension can ask about every site it can think of. That the
  vault holds a login for a site, and under which username, is disclosed to
  a compromised extension without asking.
- **The origin check protects an honest extension from a page**, not the
  vault from the extension: `Get` re-checks the entry against the page it is
  going into, so a tab that navigated between the listing and the click is
  not filled with the previous site's password. Origin matching is on suffix
  boundaries, so `example.com.evil.test` and `notexample.com` do not match a
  credential for `example.com`, a subdomain credential does not leak to its
  parent, and a URL without a host (`data:`, `file:`) matches nothing.
- **Nothing unlocks the vault.** A locked vault answers `Locked` and stops.

Writing is deliberately less guarded than reading — an attacker gains
nothing by *adding* secrets — with one rule: an update lands only on an item
already saved for that origin *and* username, so a write can never silently
retarget another site's credential, and the value it replaces goes into the
item's history. Saving the value already stored is a no-op; the comparison
happens in the host and nothing about the stored value is returned.

### E. A sandboxed Flatpak application

Gets `HKDF(portal_master, app_id)` and nothing else. Two applications cannot
collide, no application sees another's key, and the key is reproducible from
a vault backup — verified end to end with a real Flatpak through
`xdg-desktop-portal`.

The backend answers only the connection that owns
`org.freedesktop.portal.Desktop`, because that is what vouches for the
`app_id` (tested over a private bus). This does not protect one application's
key from a sandboxed app granted `--talk-name=org.freedesktop.secrets`: such
an app is an ordinary Secret Service client, and in position C it can read
the portal master item itself (locket keeps that item from being changed or
deleted over the bus, not from being read).

### F. Someone on the network

Only one thing reaches the network, only when asked: the Have I Been Pwned
check sends the first five hex characters of a secret's SHA-1 — twenty bits,
one of about a million prefixes, each shared by some two thousand of the
breached passwords the service knows (measured September 2026) and by one in
a million of every password there could be — over HTTPS, with response
padding requested. The password, and its full hash, do not leave
the machine. Everything else in locket is local.

## Deliberate exposures

Each of these is a decision, not an oversight.

- **The collection index is plaintext** (ids, labels, aliases). A locked
  Secret Service must still answer `ReadAlias` and `Collections`, and
  answering "none" reads to `libsecret` as *no keyring is installed*, not as
  *locked*. gnome-keyring draws the same line. The index is covered by the
  body's AEAD, so it cannot be edited without invalidating the vault.
- **The 1024-bit DH group** in the Secret Service session transport is weak
  by 2026 standards and fixed by the wire format. It protects secrets in
  transit on your own session bus only — never the vault at rest — and the
  alternative clients negotiate otherwise is `plain`.
- **`locket-cli` never goes through the daemon.** It opens the vault file
  directly so recovery still works when the daemon will not start. It
  therefore needs the passphrase every time, and holds the key for its own
  lifetime only. Its one call to a daemon is `Manager1.Reload` after it has
  written the file — to one that is already running and serving that file,
  found by asking the bus who owns the name, so that nothing is started. The
  call carries no data and any process running as you could make it.
- **Auto-type sends keystrokes to whatever has focus.** No portal names the
  focused window (measured — see
  [autotype-wayland.md](autotype-wayland.md)), so locket cannot check where
  the text is going. The countdown-and-click flow makes the person the
  targeting step; no Enter is ever sent.

## What trash and history changed

Vault format 4 keeps data the user asked to remove, and that is a real
change to the model:

- **A deleted item stays in the vault** until the retention window purges it
  (30 days by default, settable per vault, enforced on unlock). "Delete" now
  means *invisible to every reader* — the Secret Service, search, the agent
  — not *gone from the file*. Emptying the trash is the operation that
  destroys.
- **A replaced password stays in the item's history** — bounded at 10
  revisions and 256 KiB, evicted oldest-first. This is the point of history,
  but it means **rotating a compromised password leaves the compromised one
  in the vault** until it is evicted. Somebody rotating after a breach
  should delete the item's history, or delete and recreate the item.
- Both live inside the encrypted body, so attacker A gains nothing from
  them. They matter for someone who assumed deletion was immediate.

## Known unverified

Carried from the security policy, and the honest limit of everything above:

- **No FIDO2 hardware has ever been attached.** Slot and `sk-` agent paths
  are implemented and unit-tested against a software token only; a
  security-key factor can therefore unlock but not be added.
- **Unlocking with a TPM factor has only met `swtpm`.** The enrolment path
  ran against a real AMD fTPM when it was written; the unlock path added
  since was run against the software TPM, and the buttons that reach it in
  the window and the unlock dialog have not been driven by anyone.
- **RSA timing (RUSTSEC-2023-0071).** The advisory is open against every
  release of the `rsa` crate, the release candidate locket builds with
  included, so `cargo audit` reports it and will until upstream closes it.
  The crate is used for one thing here, the SSH agent's RSA signatures. Of
  what the advisory lists as outstanding (read 2026-10-06), two items —
  PKCS#1 v1.5 padding checks that are not constant-time, and implicit
  rejection — concern RSA *decryption*, which locket never performs; the
  third, blinding on the crate's default code path, is why the agent signs
  through the randomised signer, which blinds every private-key operation
  with a fresh factor. That has not been measured here, only read in the
  crate's source. An Ed25519 or ECDSA key is not affected at all.
- **No external review.** One author, no audit.
- **Fuzzing is bounded, not a campaign.** Five targets over the vault
  parser, the agent wire protocol, the session transport and two importers,
  run for a minute each on every CI pass. No overnight soak has been done.
- **No reproducible-build story.**
