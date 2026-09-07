# Threat model

**September 2026 · vault format 4**

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
| `locketd` | **yes**, while unlocked | the vault file, the session bus | every client below |
| `locket` (GUI) | yes, when running daemonless | the vault file, `cosmic-config` | the person at the keyboard |
| `locket-cli` | yes, while it runs | the vault file only — never the daemon | a terminal |
| `pam_locket.so` | no | the unlock socket's peer credentials | the login stack, as root |
| SSH agent (in `locketd`) | via the daemon | nothing about its callers | any process running as you |
| Secret portal backend | via the daemon | `xdg-desktop-portal` to name the app id | sandboxed applications |
| `locket-native-host` | **no** | nothing — treats the extension as hostile | the browser, one process per connection |
| Browser extension | no | nothing it is given | every page you visit |
| `locket-applet` | no | nothing — an ordinary Secret Service client | the panel |

The shape to notice: **exactly one process holds the key at a time**, and
the pieces most exposed to hostile input — the extension, its host, the
applet — hold none of it and cannot unlock anything.

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

### B. A process running as you, vault **locked**

**Cannot** get a secret. The daemon holds no key; the Secret Service answers
`IsLocked`, the agent has dropped every identity, the portal backend has
nothing to derive from.

**Can** ask for an unlock, which surfaces as a prompt in locket's own window.
**Can** see the collection index and the fact that a vault exists.

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
  no frontend, no answer in 30 seconds, or no graphical session.
- **Locking is the defence**, which is why it happens on idle, on session
  lock, on the compositor raising `LockedHint`, and on suspend.

### D. A hostile browser extension

Assumed hostile by construction. The native host never exposes the vault:
`Search` returns labels and usernames for the requested origin only,
`Get` releases one secret and **re-checks the origin at release time**
against the page it is going into — the id from a previous search is not an
authorisation, because a tab can navigate in between. Origin matching is on
suffix boundaries, so `example.com.evil.test` and `notexample.com` do not
match a credential for `example.com`, and a subdomain credential does not
leak to its parent. Nothing unlocks the vault; a locked vault answers
`Locked` and stops.

Writing is deliberately less guarded than reading — an attacker gains
nothing by *adding* secrets — with one rule: an update lands only on an item
already saved for that origin *and* username, so a write can never silently
retarget another site's credential, and the value it replaces goes into the
item's history.

### E. A sandboxed Flatpak application

Gets `HKDF(portal_master, app_id)` and nothing else. Two applications cannot
collide, no application sees another's key, and the key is reproducible from
a vault backup — verified end to end with a real Flatpak through
`xdg-desktop-portal`.

### F. Someone on the network

Only one thing reaches the network, only when asked: the Have I Been Pwned
check sends the first five hex characters of a secret's SHA-1 — twenty bits,
shared with roughly sixteen million other passwords — over HTTPS, with
response padding requested. The password, and its full hash, do not leave
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
- **`locket-cli` never talks to the daemon.** It opens the vault file
  directly so recovery still works when the daemon will not start. It
  therefore needs the passphrase every time, and holds the key for its own
  lifetime only.
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
  are implemented and unit-tested against a software token only.
- **No external review.** One author, no audit.
- **Fuzzing is bounded, not a campaign.** Five targets over the vault
  parser, the agent wire protocol, the session transport and two importers,
  run for a minute each on every CI pass. No overnight soak has been done.
- **No reproducible-build story.**
