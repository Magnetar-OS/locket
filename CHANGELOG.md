# Changelog

Notable changes, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.0] - 2026-09-08

The first release.

### Added

**The vault forgives more, and remembers more.** Vault format 4 — the envelope
is unchanged, and a format 3 file upgrades in place on its next save. The
version exists so an older build refuses the file instead of opening it and
silently stripping the data it does not know about:

- **Trash.** Deleting an item — in the GUI, with `locket-cli rm`, or by any
  application calling `Delete` over the Secret Service — now moves it to the
  trash instead of destroying it. To everything reading the vault the item is
  gone; the Trash category in the GUI and `locket-cli trash list/restore/purge`
  bring it back or finish the job. Trash is purged on unlock after a retention
  window stored in the vault itself (30 days by default;
  `locket-cli trash retain <days>|never`), so every process enforces the same
  number. Deleting a whole collection routes every item through the trash too.
- **Item history.** Every edit files the state it replaced — the GUI editor,
  `locket-cli edit`, a Secret Service `SetSecret` or replace-on-store from any
  application. Bounded per item (10 revisions, 256 KiB); the detail pane and
  `locket-cli history` list and restore them, and a restore is itself an edit,
  so it can be undone the same way.
- **Attachments.** Files ride on an item, encrypted in the vault body — a
  recovery-codes PDF, a key backup. Capped at 10 MiB each, 25 MiB per item,
  with the limit stated rather than discovered. In the GUI (add/save/remove in
  the detail pane, through the file chooser) and the CLI
  (`locket-cli attach add/list/save/rm`). History snapshots deliberately do not
  carry attachments, and the UI says so.
- **Expiry.** An item can carry an expiry date — a certificate's end, a
  token's lifetime. The editor and `locket-cli edit --expires` set it; the
  list badges items expired or expiring within 30 days; the detail pane says
  which and when.
- **Merge.** Two diverged copies of one vault — what a file synchroniser
  leaves after both machines edited — fold back together: matched by id,
  decided by timestamp, the losing side of each conflict filed into the
  winner's history rather than discarded. The GUI notices a
  `.sync-conflict` sibling on unlock and offers the merge (no second
  passphrase: forks share a key), or merge any copy via File → Merge a
  diverged copy…; the CLI grew `locket-cli merge`. Deletions propagate only
  when newer than the other side's last edit, and an edit after a deletion
  resurrects the item.
- **Open another vault** from the File menu. The daemon keeps serving the
  system vault; the Settings panel already reports which is which.

The GUI editor also stopped discarding what its form does not show: tags,
attachments and history now survive an edit, where previously a whole-item
replace dropped them.

**Password health.** A Health page in the GUI and `locket-cli health`: weak
passwords (zxcvbn, with the item's own label and username fed in as the
guesses an attacker tries first), secrets reused across items, secrets
unchanged for over a year, and items expired or expiring. Entirely offline.
Checking against **Have I Been Pwned** is a separate, explicit action — a
button on the page, `--check-breaches` on the CLI — that sends only the
first five characters of each secret's SHA-1 by k-anonymity range, with
response padding requested; it lives in its own crate (`locket-hibp`),
which is the only code in the workspace that touches the network.

**The passphrase can now be changed from the GUI** (Security screen), with
the current passphrase required first — an unlocked window is not authority
to lock its owner out — and an Argon2id cost preset (Balanced / Stronger /
Lighter). `locket-cli passwd` grew the matching knobs (`--memory-mib`,
`--passes`, `--parallelism`) plus `--rederive-only`, which keeps the
passphrase and just rewraps the key at the new cost — how an old vault
catches up with current parameters.

**The daemon hardens itself at startup**: `PR_SET_DUMPABLE(0)`, so no core
dumps and no `ptrace`/`process_vm_readv` from other processes in the
session, and `mlockall` after raising `RLIMIT_MEMLOCK` to its hard limit,
so nothing it maps reaches swap where the limit allows (the installed unit
now grants `LimitMEMLOCK=infinity`; elsewhere the daemon logs what it got).

**Fuzzing.** `cargo fuzz` targets over the four places untrusted bytes
enter — the vault file parser, the SSH agent wire protocol, the Secret
Service session transport (DH peer keys and secret payloads), and the TOTP
and `.env` importers — with a bounded run on every CI pass.

**Three more ways in.** First-class importers for **Bitwarden** (the JSON
export, with custom fields, TOTP seeds, cards, identities and folders),
**1Password** (`.1pux` — trashed items stay deleted, attached documents are
counted rather than silently dropped) and **Proton Pass** (the zip export;
aliases keep their address). All three in the GUI's import screen and as
`locket-cli import-bitwarden / import-onepassword / import-protonpass`;
password-protected and PGP-encrypted exports are refused with directions,
and re-importing never duplicates.

**Three ways out.** `locket-cli export --format json|csv|kdbx` and a File →
Export menu in the GUI: lossless JSON, the flat CSV every manager imports
(it says exactly how many items had fields it could not carry), and an
encrypted **KDBX 4** database KeePassXC opens directly — TOTP seeds, tags
and field protection intact, verified by round-tripping through locket's
own KeePass importer. The plaintext formats keep the CLI's explicit consent
gate; in the GUI they detour through a warning dialog first.

**Auto-type, the Wayland way.** An *Auto-type* button on an item types
username → Tab → password into whatever field is focused, over the
`RemoteDesktop` portal's keysym path — layout-independent, permission
granted through the compositor's own dialog, and a measured investigation
of what the portals actually offer on COSMIC lives in
`docs/autotype-wayland.md`. No Enter is sent, and there is no global hotkey
yet: `GlobalShortcuts` has no routed backend on COSMIC, which the note
records with the commands to re-check.

**The panel applet grew a quick search.** Type into the popup, copy a
secret in one click — the 90% of interactions that do not deserve a window.
It is an ordinary Secret Service client holding no key material: the list
shows labels and usernames only, a secret is fetched at the moment Copy is
pressed, and the clipboard clears after 30 seconds with the same
"is-it-still-ours" check the main window makes. Closing the popup forgets
the query. The lookup lives in `locket-secret::quick` so there is one
definition of it rather than a copy per frontend.

**History can be forgotten.** `locket-cli history <item> --forget` and a
button in the detail pane drop every recorded revision. This is what to run
after rotating a credential that leaked — history exists to make a replaced
value recoverable, which is exactly wrong for the one you just rotated away
from. The [threat model](docs/threat-model.md) now says so in as many words.

**A strength meter on vault creation.** The one passphrase nothing can
recover is the one worth estimating out loud, so the create screen scores it
as you type (zxcvbn, with "locket" and "vault" fed in as the words an
attacker guesses first) and says plainly that four unrelated words outlast a
short line of symbols. The unlock screen also gained *Open a different
vault…*, because the menu bar is hidden while locked and somebody whose
vault lives elsewhere was otherwise stuck.

**Locking with the session actually works now.** Following logind's lock
signal was written, shipped and silently doing nothing in the arrangement
the unit creates: a systemd *user* unit runs under `user@<uid>.service`,
which logind classes as a manager session, so neither `XDG_SESSION_ID` nor
`GetSessionByPID` resolved a session. The daemon logged one warning and
watched suspend only — a locked screen left every secret readable by
anything on the session bus. It now asks logind for the user's display
session as a third fallback, and logs the session it followed, because the
only previous sign of failure was a warning nobody reads.

**The browser host installs without an extension id.** `--browser` used to
demand one, but only Chromium-family browsers key on an id, and that id
does not exist until the extension has been loaded unpacked — so Firefox
users had to invent a value. It is optional now, and the manifest written
without one omits `allowed_origins` rather than claiming an empty origin
a Chromium browser would silently ignore. Vivaldi and Edge were missing
from the list of browsers written to; both are there now.

**The vault says when it locks.** Locking on idle, on session lock and on
suspend already existed; now each sends a desktop notification naming the
reason — nothing from the vault, just why — so an application quietly
losing its secrets after a resume stops being a mystery. The trash's
retention window also gained a control in the Trash screen itself,
alongside the existing `locket-cli trash retain`. Pass
`--no-lock-notifications` to the daemon to turn the notifications off.

**The browser extension saves as well as fills.** A content script notices
a submitted login; if the vault does not hold that value the toolbar icon
gains a badge, and the popup asks before anything is written. Updates land
on the entry already saved for that origin and username — never anything
else — and the replaced password goes into the item's history. The native
host grew the matching `save` request; reading stayed exactly as guarded
as it was.

**Measured, not asserted.** `cargo run --release -p locket-core --example
bench` times the four things a person waits on against a 10,000-item vault,
and [docs/performance.md](docs/performance.md) records the numbers with the
budget each has to fit. It found a real bug on its first run: the health
report is 1.6 seconds at that size and was being computed on the UI thread —
imperceptible on the author's nine-item vault, a frozen window on anyone
else's. It now runs on a worker. Search and sort come in at 1–2 ms, which is
the argument for leaving both implementations naive.

**A written threat model.** [docs/threat-model.md](docs/threat-model.md):
what each component trusts, what reaches it, and what an attacker with the
vault file, with a process on your session, with a hostile browser extension
or inside a Flatpak sandbox can and cannot do — plus the deliberate
exposures (the plaintext collection index, the 1024-bit DH group, auto-type
having no way to name the window it types into) and what trash and history
changed about deletion. `SECURITY.md` points at it.

### Renamed

The project is now **Locket**. Everything moved with it: the binaries
(`locket`, `locketd`, `locket-cli`, `locket-applet`, `locket-native-host`,
`pam_locket.so`), the crates, the application id
(`com.magnetaros.Locket`), the development bus name
(`org.locket.secrets`), the manager interface (`org.locket.Manager1` at
`/org/locket/Manager`), the portal backend, the systemd unit and the scripts.
`org.freedesktop.secrets` is untouched — that name belongs to the
specification, not to us.

Two things follow you across, because losing them to a rename would be absurd:

- **An existing vault keeps working where it is.** If there is nothing at
  `~/.local/share/locket/default.vault` and the old path has a vault, that one
  is opened, and the daemon logs which file it used. Nothing is moved on your
  behalf; move it yourself when you want the tidier path.
- **Settings are carried over** from the old `cosmic-config` store the first
  time the application starts, copied rather than moved so an older build still
  finds its own.

**An existing installation needs migrating by hand**, because the old files
name the old program:

```sh
systemctl --user disable --now passman-daemon.service
rm -f ~/.config/systemd/user/passman-daemon.service
rm -f ~/.local/bin/passman ~/.local/bin/passmand ~/.local/bin/passman-cli \
      ~/.local/bin/passman-applet ~/.local/bin/passman-native-host
scripts/locket-setup            # installs the new names and rewrites the D-Bus override
sudo sed -i 's/pam_passman.so/pam_locket.so/' /etc/pam.d/system-login
sudo rm -f /usr/lib/security/pam_passman.so
```

The PAM line matters more than it looks: the unlock socket moved to
`/run/user/<uid>/locket/`, so the old module would keep being loaded at every
login and keep finding nothing there — the exact silent failure this release
spent its time removing elsewhere.

**The application id moved to the namespace the rest of the suite uses**:
`com.magnetaros.Locket`, with `com.magnetaros.LocketApplet` for
the panel indicator, `com.magnetaros.locket` for the browser's native
messaging host and `locket@magnetaros.com` for the Firefox extension.
Slate, Circle and Envelope are all `com.magnetaros.*`; Locket was the
one that was not, while its own `Cargo.toml` pointed at that organisation.

Settings are carried across again, from both older ids, and the keys inside the
store were renamed with them — `auto-lock-seconds` is now `auto_lock_seconds`,
because `cosmic-config`'s derive names each key after its field. Copied, not
moved, so an older build still finds its own.

An installed copy of a previous build leaves files behind under the old id:

```sh
rm -f ~/.local/share/applications/io.github.idominikos.Locket*.desktop
rm -f ~/.local/share/icons/hicolor/*/apps/io.github.idominikos.Locket*.svg
rm -f ~/.local/share/metainfo/io.github.idominikos.Locket.metainfo.xml
scripts/locket-setup            # reinstalls under the new id
```

### Fixed

- **A vault from before the rename would not open.** The file records its
  magic as `passman-vault`, the check demanded `locket-vault`, and the daemon
  started against an unreadable file — while this changelog promised the old
  vault kept working where it was. The old magic is now accepted and *kept*:
  it is bound into the authenticated data of every slot and of the body, so
  rewriting it would have locked the vault out of its own key. A passphrase
  change or a hardware enrolment on such a vault now seals under the file's
  own magic too, where it used the current constant and would have done the
  same.
- The systemd unit set `ProtectHome=read-write`, which is not a value systemd
  accepts; it logged the line as ignored on every start.
- **Binary secrets displayed as garbage.** The vault stores a non-text secret
  base64-encoded with a marker, but the detail view printed the raw store for
  every item — and for secrets damaged by the older lossy import, printed the
  damage as if it were the password. A binary secret now says what it is
  ("Binary secret · N bytes") and reveals and copies the Base64, the one
  faithful text form it has; a damaged one is called out, with a pointer to
  `locket-reimport-keyring` as the recovery path.
- **Editing a binary secret silently corrupted it.** The editor showed the
  Base64 store with nothing saying so, and a value typed over it kept the
  binary marker — so every reader would base64-decode the new text, or fail to
  and hand back its raw bytes. The editor now says what the field holds
  ("Binary secret · N bytes, shown as Base64"), warns when the value has been
  replaced, and saves a typed replacement as the text it is. An untouched
  field still round-trips the original bytes exactly.
- **Long revealed values ran underneath the Reveal/Copy buttons.** Tokens,
  JSON blobs and Base64 have no word boundaries, so word-wrapping never broke
  them; values now wrap at the glyph level when they must.
- **Keyboard shortcuts did nothing on a non-Latin layout.** Ctrl+N, Ctrl+L and
  Ctrl+F were matched against `Key::Character("n")`, which a Greek or Cyrillic
  layout never produces. They go through libcosmic's `KeyBind` now, which falls
  back to the physical key — and which compares the whole modifier set, so
  Ctrl+Shift+N no longer creates an item either.
- **Payment cards had no icon.** `credit-card-symbolic` is in no icon theme
  COSMIC falls back through; the name COSMIC and Pop both ship is
  `payment-card-symbolic`.
- **The AppStream metadata failed validation** and named a repository that does
  not exist, which also meant `makepkg` could not clone the source. The release
  it advertised (0.1.0) disagreed with the version the About page shows.
- **RSA keys could not sign at all through the SSH agent.** A key loaded from
  a file carries no hash choice, and in that state `ssh-key` refused. The hash
  now comes from the client's sign-request flags, which were previously parsed
  and discarded — so a server asking for `rsa-sha2-512` gets one.
- **The agent's identities never reloaded.** They were read once at startup,
  and the installed unit starts `--locked` so that PAM can unlock it, which
  meant the agent served nothing at all for the rest of the session.
- **Locking the vault left the SSH keys usable.** The agent held decrypted
  copies with nothing connecting them to lock state, so anything that could
  reach the socket could go on authenticating as you.
- **Two processes writing the vault lost edits.** The daemon holds the vault
  while the frontend edits the same file directly; whichever wrote second
  silently discarded the other's changes.
- **A secret could be filled into the wrong site.** The browser host handed
  over any item by id and the extension never re-checked the tab, so a page
  that navigated between the popup opening and the click was filled with the
  previous origin's password.
- Changing your login password left the vault behind, silently and for good.
- Clearing the clipboard wiped whatever you had copied since, not only the
  secret locket put there.
- Creating a vault raced: two creates could both decide the file was absent.
- A non-text secret was mangled into replacement characters on its way to a
  browser instead of being refused.

### Added

- **The interface is translatable.** Every string the GUI and the panel applet
  show now comes from a fluent catalogue (`crates/*/i18n/`), selected from the
  languages the desktop asks for. `fl!()` checks ids at compile time, so a typo
  is a build error rather than a label reading `some-id`.
- **A menu bar**, with the shortcuts printed beside the actions they run —
  which is the only place anyone was ever going to find out that Ctrl+N exists.
- **A `justfile`**, the shape every COSMIC application ships: `build-release`,
  `install` with `rootdir`/`prefix`, `validate-metadata`, `vendor`. The
  interactive installer (`scripts/locket-setup`) is unchanged and still the way
  to take over the session's secret store.
- **Security keys over SSH** — `sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256`
  identities, signed by driving a FIDO2 assertion per signature.
- **SSH certificates** — advertised alongside the key they belong to, since a
  host configured for certificate authentication will not take the bare key.
- **Confirm each use** — an item can require a dialog before every signature
  with it. Fails closed: nothing to ask means no signature.
- **The vault locks itself**: after an idle timeout, when the session locks,
  and when the machine suspends.
- `locket-cli edit`, `rm`, `export` and `passwd` — the recovery tool can now
  repair and leave, not only add.
- `pam_locket.so` follows a password change through to the vault, given a
  `password optional pam_locket.so` line.
- Settings are watched, so a change made anywhere else lands without a
  restart, and the idle timeout is shared with the daemon rather than being
  two settings with one name.
- The SSH importer picks up a key's certificate, and marks the keys whose
  signing happens on hardware — those files are credential handles, so
  importing one is not a backup.

### Changed

- **libcosmic is no longer pinned to a revision.** Every COSMIC application
  tracks the default branch and pins the commit in `Cargo.lock`; a `rev` on top
  of that bought nothing and cost a split dependency tree, because libcosmic's
  own `cosmic-panel-config` and `cosmic-settings-config` follow the branch — so
  two copies of `cosmic-config`, `iced_core` and `iced_futures` were being
  compiled. The separate `cosmic-config` dependency is gone with it;
  `cosmic::cosmic_config` is the same crate, re-exported.
- Settings use `cosmic-config`'s `CosmicConfigEntry` derive and libcosmic's
  `watch_config`, replacing a hand-written store, watcher and key filter that
  did the same thing.
- Ctrl+F is handled once. libcosmic's keyboard navigation already delivers it
  as `on_search`; the second listener has been removed.
- The About page loads its icon from the binary rather than from the icon
  theme, so it is there in an uninstalled build too.
- `Vault::save` refuses to overwrite a file that changed since it was read.
  Use `reload` to pick the other writer up, or `save_force` to mean it.
- `locketd` gained `--auto-lock` and `--no-lock-on-idle-session`; the
  installed unit turns the idle lock on at 15 minutes.
- `ssh-add -x` and `-X` work: the lock passphrase is kept and compared in
  constant time.
