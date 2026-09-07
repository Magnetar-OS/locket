# Roadmap

The direction: an application that can stand 1:1 against the most complete
desktop password manager that exists, while being the most COSMIC-native
application in its class — and staying honest about what has actually been
verified, in the spirit of the README's [Verified](README.md#verified) section.

**The benchmark is KeePassXC.** It is the closest existing application in
scope — local encrypted vault, SSH agent, browser extension, TOTP, hardware
keys, CLI, Secret Service — and the feature-richest, so parity with it is a
meaningful claim where parity with a simpler app would not be. Bitwarden and
1Password serve as UX references in places, not as feature targets: their
defining feature is a sync service, and Locket deliberately has none (see
[Non-goals](#non-goals)).

Nothing here carries a date. Milestones are ordered by dependency and by risk:
vault-format changes first, because everything else builds on them and because
format churn late in the roadmap would invalidate earlier verification.

## Where Locket stands against the benchmark

Ahead — things KeePassXC does not do, or does less deeply:

- Owns `org.freedesktop.secrets` natively rather than emulating it as a
  side-feature; verified against real `libsecret`.
- The only `org.freedesktop.impl.portal.Secret` backend besides gnome-keyring;
  verified through a real sandboxed Flatpak.
- PAM unlock at login; a panel applet; per-field kinds driving masking, search
  exclusion and live TOTP; derived (not stored) portal app secrets; multi-slot
  key wrapping where hardware *adds* a factor instead of replacing one.

At parity: TOTP (with QR round-trip), password + Diceware generation, SSH
agent (arguably ahead: certificates, `sk-` keys, per-key confirm), CLI,
browser extension basics, import from eight sources, tags, favorites,
auto-lock, clipboard clearing.

Behind — and the substance of this roadmap:

| KeePassXC has | Locket today | Milestone |
|---|---|---|
| Recycle bin | **Landed** — trash with retention, bus deletes included | 1 ✓ |
| Entry history with restore | **Landed** — bounded revisions, every edit path | 1 ✓ |
| File attachments | **Landed** — encrypted, capped, GUI + CLI | 1 ✓ |
| Expiry dates | **Landed** — editor, badges, CLI | 1 ✓ |
| Multiple databases open | **Landed** — open/switch from the File menu | 1 ✓ |
| Database merge (sync via file sync) | **Landed** — id/timestamp merge, conflict detection | 1 ✓ |
| Password health report + HIBP | **Landed** — offline report + opt-in k-anonymity check | 2 ✓ |
| Passkeys (WebAuthn) | None | 2 |
| KDF re-tuning from the UI | **Landed** — GUI presets + CLI `passwd --rederive-only` | 2 ✓ |
| Export from the GUI, multiple formats | **Landed** — JSON/CSV/KDBX, GUI + CLI | 3 ✓ |
| Bitwarden / 1Password importers | **Landed** — plus Proton Pass | 3 ✓ |
| Auto-type | **Landed** — RemoteDesktop portal, keysym path | 3 ✓ |
| Save-new-login prompt in the browser | **Landed** — offer-only, history-backed | 3 ✓ |

## Milestone 1 — the vault holds more, and forgives more

**Status: landed.** Format 4 carries trash, history, attachments and expiry;
format 3 files upgrade in place; the merge folds forks back together and the
GUI notices `.sync-conflict` siblings on unlock. The done-criteria below all
hold — the format-3 upgrade, the round-trip/no-plaintext tests and the
two-way-fork merge are in `locket-core`'s suite. The retention window is
settable from both the Trash screen's dropdown and
`locket-cli trash retain`.

Everything here touches the vault format, which is why it comes first: format
4 should be the *last* format change this roadmap needs, landing trash,
history, attachments and expiry together with one upgrade path, the same way
formats 2 and 3 upgrade in place today.

- **Trash.** Soft-delete with restore; permanent delete is a second, separate
  action. Purge after a configurable period. The subtlety is the Secret
  Service: an item deleted by a `libsecret` client goes to the trash too, but
  a trashed item must be invisible to `SearchItems` — to every other
  application it is gone, which is what the delete dialog already promises.
- **Item history.** Bounded revisions per item (count and total size), stored
  inside the encrypted body. The editor shows what changed and restores a
  revision as a new write, so history never rewrites itself.
- **Attachments.** Encrypted blobs on an item — a recovery-codes PDF, a key
  backup. Bounded size with the limit stated in the UI, decrypted to memory
  and handed over via the FileChooser portal on save, never spooled to a
  temporary file in plaintext.
- **Expiry.** A date field kind (the field-kind seam already exists) plus an
  expired/expiring badge in the list and a filter for it. Certificates and API
  tokens are the items that want this, not just passwords.
- **Multiple vaults.** Open, create and switch between vault files in the GUI.
  One vault remains *the* system vault — the one the daemon serves on the bus;
  the others are just open files. The distinction is surfaced, not implied.
- **Merge.** Two divergent copies of a vault — the file-sync case the
  XChaCha20 nonce choice was made for — merge by item id and modification
  time, with history (above) absorbing the losing side instead of discarding
  it. Detects `.sync-conflict` siblings and offers the merge.

Done when: a format-3 vault upgrades in place; every feature above has the
tamper/round-trip/no-plaintext-on-disk tests the existing format has; a
seeded vault forked two ways merges without losing either side's edit.

## Milestone 2 — security features that face the user

**Status: landed, with three open ends.** The health report (offline, plus
the opt-in HIBP range check in its own network-only crate), KDF re-tuning
from both the GUI and the CLI, GUI passphrase change gated on the current
passphrase, daemon hardening (`PR_SET_DUMPABLE`, `mlockall` with the unit
granting `LimitMEMLOCK`), and the fuzz targets with a bounded CI run have
all shipped. Open: **passkeys** (unstarted — the largest single feature in
this milestone), **true `memfd_secret` residence** for the DEK (the
dumpable/mlock fallback landed; moving the key itself into a secret memfd
means restructuring `SymKey` and stays open), and the **overnight fuzz
soak** plus **FIDO2 on real hardware**, which need time and a token
respectively rather than code.

- **Password health.** A report page: weak (zxcvbn), reused across items,
  old, expiring. Runs entirely offline. **Have I Been Pwned** checking is
  opt-in, clearly labelled as a network feature, and uses the k-anonymity
  range API so no full hash ever leaves the machine.
- **Passkeys.** The largest single feature in the roadmap. A WebAuthn
  credential becomes an item kind; the browser extension implements
  create/get so sites see a platform authenticator backed by the vault.
  Parity target is KeePassXC's passkey support; the extension's "never fills
  automatically, never asks for your passphrase" stance carries over —
  a passkey assertion is a click in the popup, not a silent grant.
- **KDF re-tuning.** The Argon2id parameters are stored per slot; add the UI
  and CLI to re-derive at new cost, which is a 32-byte rewrap, not a vault
  re-encryption. Surface the current parameters in Settings the way the
  bus-ownership status is surfaced today.
- **Key material hardening in the daemon.** The unlocked DEK moves into
  `memfd_secret` (with an `mlock` fallback for kernels without it), so it is
  absent from core dumps and inaccessible to other processes even via
  `process_vm_readv`. `zeroize` already covers drop; this covers residence.
- **Fuzzing.** `cargo-fuzz` targets for the vault parser, the Secret Service
  DH session, the SSH agent wire protocol and every importer — the four
  places untrusted bytes enter. Corpora committed, a bounded run in CI.
- **FIDO2 on hardware.** Carried from the README: the code paths exist and
  are unit-tested against a software token, but no physical token has ever
  been attached. Until one has, the hardware half stays labelled untested.

Done when: the health report agrees with KeePassXC's on the same imported
vault; a passkey registered on webauthn.io round-trips through a browser
restart; the fuzz targets have each run a night without a finding; the FIDO2
`#[ignore]`d tests have passed against a real token.

## Milestone 3 — parity in interop

**Status: landed.** The three importers (Bitwarden JSON, 1Password 1PUX,
Proton Pass), the three export formats (lossless JSON, flat CSV that counts
what it drops, encrypted KDBX 4 verified by round-trip through our own
KeePass importer), the extension's offer-only save prompt with its
history-backed update rule, and auto-type over the RemoteDesktop portal's
keysym path. The portal investigation this milestone demanded is in
[docs/autotype-wayland.md](docs/autotype-wayland.md), measured on a live
session; two of its findings amend this milestone's original text: there is
no routed GlobalShortcuts backend on COSMIC yet (so the trigger lives in
locket until there is), and no portal names the focused window (so the
"show the target window title" idea is unimplementable — the
countdown-and-click flow makes the person the targeting step instead).
The KDBX export deliberately does not carry attachments or item history —
the JSON export is the lossless one, and the CSV/KDBX paths say what they
leave behind.

- **Export.** GUI export with the same friction the CLI has (the
  `--i-understand-this-is-plaintext` gate becomes a dialog that means it),
  plus formats something can actually ingest: generic CSV, and KeePass KDBX
  so leaving Locket is as supported as arriving.
- **Importers.** Bitwarden (JSON), 1Password (1PUX), Proton Pass — the three
  most common migration sources not yet covered. Same contract as the
  existing eight: parsing and classification unit-tested from real export
  samples, secrets never logged.
- **Auto-type, the Wayland way.** There is no XTest on Wayland; synthetic
  input goes through the `RemoteDesktop` portal (libei) and a hotkey through
  the `GlobalShortcuts` portal. Step one is an investigation with a recorded
  outcome: which of those `xdg-desktop-portal-cosmic` actually implements
  today, measured, not assumed — the conventions doc exists precisely
  because this ecosystem is documented by reading it. If the portals are
  there, auto-type lands behind per-item opt-in with the target window title
  shown before a single key is sent. If not, that becomes an upstream
  contribution or a documented **gap with a reason**, not a silent absence.
- **Browser extension: save and update.** The extension notices a submitted
  login it does not hold — or holds with a different password — and offers to
  save through the popup. Fill-on-click stays as designed; the save prompt is
  the missing half of the loop. Passkey support arrives here from
  milestone 2.

Done when: a vault exported to KDBX opens in KeePassXC with items, groups,
TOTP seeds and attachments intact; each new importer round-trips a real
export; auto-type's portal investigation is written down in `docs/` with the
same measured/inferred honesty as `cosmic-conventions.md`.

## Milestone 4 — pixel-perfect, reactive, humane

**Status: the measurable half has landed.** `docs/performance.md` records
real numbers from `cargo run --release -p locket-core --example bench` on a
10,000-item vault, with a budget per operation — and the benchmark earned
its place on the first run by finding that the health report was blocking
the UI thread for 1.6 seconds at that size (now on a worker). First-run also
improved: a zxcvbn strength meter while the vault passphrase is being
chosen, and *Open a different vault…* on the unlock screen. Still open, and
genuinely needing an interactive session rather than more code: the
screen-reader pass, keyboard-completeness audit, responsive-layout work at
narrow widths, and frame-level profiling inside the compositor — which
`docs/performance.md` names as the half its harness cannot see.

The bar: put Locket beside cosmic-edit and cosmic-settings and find no seam.
The conventions checklist in
[docs/cosmic-conventions.md](docs/cosmic-conventions.md) is the reference;
Locket already **follows** on most rows, so this milestone is the remainder
plus the polish that no checklist captures.

- **Close the adoption-table gaps.** A second language (which unblocks the
  deferred xdgen adoption), then more — the catalogue structure is already
  there; `debian/`, `flake.nix`, `hooks/` alongside the existing CI.
- **First-run.** A fresh start currently assumes you know what a vault is.
  First launch offers create/import/open, explains the passphrase's role in
  one paragraph, and lands in a seeded-empty state that shows what the app
  will look like full — an empty state that teaches, for every category.
- **Keyboard-complete.** Every action reachable without a pointer, focus
  always visible, list navigation with arrows and type-ahead. The KeyBind
  table and the claimed-only-when-unconsumed rule already exist; this
  extends them to the whole surface.
- **Accessibility.** AccessKit (already in iced) exercised end-to-end with a
  screen reader: masked fields announce as concealed rather than reading
  asterisks, the TOTP countdown is announced at the warning threshold, every
  icon-only button has a label.
- **Reactivity as a measured property.** The TOTP ring already animates;
  extend that standard: no operation blocks the frame loop, unlock shows
  progress (Argon2id at 64 MiB is *supposed* to take a moment — say so),
  list scrolling stays smooth on a 10,000-item vault, search results update
  per keystroke under a stated latency budget. These become benchmarks in
  the repo, run on real hardware, with the numbers recorded the way
  `Verified` records behaviour.
- **Responsive layout.** The nav-bar/list/context-drawer triptych collapses
  gracefully at narrow widths and in the applet popup, using libcosmic's
  breakpoints rather than invented ones.

Done when: the conventions checklist passes every applicable row; the
benchmarks exist with recorded numbers; a screen-reader pass of every screen
is written down, gaps included.

## Milestone 5 — COSMIC everywhere

**Status: the session integration turned out to already exist** — the daemon
has followed logind's `PrepareForSleep`, the session's `Lock` signal *and*
the compositor's `LockedHint` since before this roadmap was written
(`locket-daemon/src/idle.rs`); this milestone's first bullet was a gap in
the roadmap's knowledge, not the code's. What this milestone actually
added so far: **lock notifications** — the daemon now says, through
`org.freedesktop.Notifications`, that the vault locked and why (idle,
session lock, suspend), because an application "forgetting" its login half
an hour after a resume was the silent failure; the body carries the reason
and nothing from the vault. The **applet's quick search** has landed too — search, copy, clipboard
clearing, popup-close forgetting the query — built on a shared
`locket-secret::quick` client that the launcher plugin can reuse when it
comes. Still open: the launcher plugin itself, and clipboard-cleared
notifications when the window is unfocused.

Locket is already infrastructure (bus, portal, PAM, agent). This milestone is
about the desktop *noticing*: every place COSMIC shows or asks for something,
Locket is there natively.

- **Session lock integration.** Locking the session locks the vault
  (configurable, on by default), wired to logind's lock signal and
  `PrepareForSleep` — a laptop lid closing should not leave the DEK unlocked
  overnight. The applet reflects the state transition immediately.
- **Notifications.** Clipboard cleared, vault auto-locked, agent
  confirmation missed — the events that currently happen silently — through
  `org.freedesktop.Notifications`, each individually opt-outable, none
  containing a secret or an item label.
- **Launcher integration.** A pop-launcher plugin: type an item's name,
  copy its secret. The security shape is fixed before the feature: the
  plugin process sees labels only, matching happens in the daemon, the
  secret goes straight to the clipboard with the standard clearing rules,
  and a locked vault yields a single "unlock Locket" row rather than a
  search that quietly returns nothing.
- **The applet grows up.** Quick search and copy, live TOTP for favorites,
  the lock toggle it already has — the 90% of interactions that do not
  deserve a full window, in the panel where COSMIC puts them.
- **Toolkit currency.** libcosmic stays tracked from its branch with
  `Cargo.lock` as the reproducibility line, per the conventions doc. The
  renderer is iced-on-wgpu and stays that way — Wayland-native, GPU-drawn,
  no X11 path. Newer libcosmic APIs (`surface_task`, `LiveSettings`) are
  adopted as they stabilise rather than worked around.

Done when: a locked session means a locked vault, verified against a real
suspend/resume cycle; the launcher flow works with the vault locked and
unlocked; the applet covers search-copy-lock without opening the window.

## Milestone 6 — distribution and trust

The README says it plainly: one machine, one user, reviewed by nobody. This
milestone is what changes that sentence.

- **Release automation.** Finish what `release.config.json` and the release
  workflow start: tagged releases with changelog, checksummed artifacts and
  the vendored-source tarball `just vendor` already supports.
- **Packaging.** Debian and Fedora packages next to the Arch one; AUR
  publication. Flatpak ships the frontend only and *says so* — a sandboxed
  app cannot own the bus name or install PAM, and pretending otherwise
  would be worse than absence.
- **A threat model in writing.** SECURITY.md grows into a real model: what
  each component trusts, what reaches it, what an attacker on the session
  bus / with the socket / with the file can and cannot do. This is the
  document an external reviewer starts from — and the prerequisite for
  soliciting that review, which is the actual goal.
- **sudo PAM and PKCS#11.** Carried, still gated on their README reasoning:
  the first on the authorisation argument, the second on a caller existing.

Done when: a release installs from a package on all three distributions and
`locket-setup --status` reports a correct takeover on each; the threat model
is published; at least one person who is not the author runs it as their
secret store.

## Non-goals

- **A sync service.** The vault is a file; nonce design already assumes file
  sync (Syncthing, a git repo), and milestone 1's merge makes it safe.
  Running servers is a different product.
- **Telemetry of any kind.** The only network features in this roadmap —
  HIBP, favicon fetching if it ever comes — are opt-in and individually
  labelled.
- **X11.** Wayland-native via libcosmic. Anything reaching Locket over the
  network of protocols above it (Secret Service, portal, PAM, agent) is
  display-server-agnostic anyway.
- **Auto-fill without a click.** The extension's stance is a decision, not a
  gap.
