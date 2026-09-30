# Changelog

Notable changes, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `org.locket.Manager1.VaultLocked(reason)`: the daemon now says when the
  vault has locked and why — `request`, `idle`, `session`, `suspend`,
  `shutdown` or `error` — so a window holding its own copy of the key can
  follow.

### Changed

- A locked vault no longer keeps an application waiting past the point where
  the application stops listening. `git push`, `secret-tool` and anything else
  on libsecret used to hang for 25 seconds per call and then report "Timeout
  was reached" when nobody unlocked in time — twice per push, once for the
  lookup and once for the store. Now a lookup waits twenty seconds for the
  unlock dialog and is then told the vault is locked; a store is told at
  once, which sends libsecret through its own unlock prompt, where it waits
  for as long as the dialog is up (two minutes) and then stores. An unlock
  that takes longer than 25 seconds no longer loses the secret being saved.
- One unlock dialog answers every application that asked while it was up.
  Requests used to queue, each with two minutes of dialog of its own, raised
  one after another long after the applications had given up.
- Nothing asks to be unlocked behind a locked screen. A request that would
  raise the dialog there is refused at once and asks again when the screen is
  back.
- `locket-cli` tells a running daemon to re-read the vault after it writes
  it, as the application already did. An item added, edited or removed from
  a terminal is there for libsecret applications, the browser extension and
  the SSH agent straight away, instead of after the daemon's next write or
  unlock. It never starts a daemon to do so and says nothing when there is
  none.

### Fixed

- `locket-cli get` refuses a query that fits more than one item, as the
  commands that change things already did, and lists the candidates. It used
  to print the secret of whichever matching item came first.
- `locket-cli passwd --memory-mib` refuses a value too large to express,
  where a release build used to wrap it round to a small cost and weaken the
  vault while reporting success.
- `locket-cli import-env --dry-run` lists a `.env` file it cannot read as
  unreadable, instead of as a file holding nothing.
- Every `locket-cli import-…` command prints what it left out and why. Only
  the 1Password and SSH imports did; an authenticator export with an entry
  locket cannot generate said nothing about it.
- `locket-cli history --restore N` restores revision N. With a full history
  it restored the one after it and lost the one asked for.
- A search answered the moment the vault unlocked could name items that were
  not on the bus yet, so reading the secret it had just found failed.
- `pam_locket.so` contains a panic in any of its hooks and answers as it
  would with nothing to do, so a defect there cannot fail a login even on a
  stack that lists it as `required`.
- Merging a diverged copy no longer reports "the copies are identical" and
  throws the result away when every conflicting item had been edited more
  recently here. The other copy's edits are filed into each item's history
  and saved, and so are collection renames and trash that only the other
  copy had.
- Merging a diverged copy now says so when an attachment is left behind
  because both copies of an item had gained a different attachment. The
  merge used to keep one side's attachments and drop the other's without a
  word.
- A one-time-code seed set to ten digits now shows the right code. Such a
  seed used to show a wrong code about a third of the time.
- A one-time-code secret written with its trailing `=` padding is now
  accepted, whether typed in or imported. It used to be refused as invalid,
  and imports skipped it.
- A one-time-code seed whose account name was written with escapes, such as
  `My%20Bank:ada%40example.com`, now shows as "My Bank" and
  "ada@example.com". Show QR code used to pass the escapes on to the phone,
  doubled.
- Merging the same diverged copy more than once no longer fills an item's
  history with copies of the same old version, pushing out the revisions it
  held before.
- Merging a diverged copy no longer loses the earlier versions an item went
  through on the side whose edit lost. They are kept in the item's history
  along with its last state there.
- When a merge moves an item to the trash because the other copy deleted it,
  restoring it now brings back its most recent edit. It could bring back an
  older version, with the later edit gone.
- The SSH agent answers a signature request it cannot meet with a small RSA
  key, such as `rsa-sha2-512` on a 512-bit key, with a refusal. It used to
  drop the connection.
- Adding a TPM unlock factor from the Security page now finds the machine's
  TPM. It used to fail with "no TPM available" unless a TCTI environment
  variable had been set by hand.
- Importing a Bitwarden JSON export of a personal vault failed with "not a
  Bitwarden JSON export", because Bitwarden writes `"collectionIds": null`
  on every item and the importer only accepted a list there. Such exports
  now import.
- Re-importing from gnome-keyring with `--replace`, or through
  `locket-reimport-keyring`, did not repair binary secrets damaged by the
  older lossy import: it added a correct copy beside the damaged one, and
  applications could still be handed the damaged one. The re-import now
  overwrites the damaged item in place.
- Importing a list of `otpauth://` URIs crashed when a label held a `%`
  followed by a non-ASCII character, such as `10%優惠`; in the app this also
  locked the vault. Such labels now import as written.
- Importing an authenticator export no longer drops entries without a word.
  HOTP and Steam codes, and seeds that do not parse, used to vanish while
  the summary said nothing was unreadable; they are now counted as
  unreadable and named in a note, so you know which codes are still only on
  the phone.
- Importing SSH keys whose file names contain a dot, such as `deploy.old`,
  could attach the public key and comment of a different key (`deploy.pub`).
  Each key now gets its own `.pub` file, the way OpenSSH names them.
- A `.env` file with an unmatched quote, such as `A="oops`, no longer loses
  every variable after that line: they used to be folded into A's value, and
  large files with such a line took very long to scan. The stray line now
  imports as written and the rest of the file imports normally.
- Unquoted `.env` values with a `#` right after certain non-ASCII letters
  were cut short: `PASSWORD=pà#ss` imported as `pà`. Only a `#` after real
  whitespace starts a comment now.
- Importing `.env` files from a folder of projects failed outright with
  "Permission denied" on the folder itself when any directory inside it
  could not be read, such as a database volume owned by another user. Those
  directories are now skipped and named in the summary, and everything else
  imports.
- A `pass` entry holding binary data was imported with its bytes replaced by
  placeholder characters and counted as a success. It is now reported as
  unreadable and left in the store as it is.
- Importing from another keyring said nothing about collections it could not
  read: a locked collection was skipped while the summary reported "0
  unreadable". Each locked or unreadable collection is now counted as
  unreadable, and an item whose attributes cannot be read is skipped rather
  than imported without them.
- Importing a 1Password export now counts Document items in its note about
  files left inside the `.1pux` archive. They were missed before, so the
  import could say nothing was left behind when documents were.
- Importing a Proton Pass export lost two things: one-time-code seeds stored
  as extra fields on an item, and the address of every alias. Both now come
  across.
- Importing SSH keys now says which ones will not be served straight away.
  Keys in the older PEM formats (`BEGIN RSA PRIVATE KEY` and the like) were
  imported but never offered by locket's agent, and passphrase-protected
  keys waited silently for a passphrase; both are now named in the import
  summary, with how to convert the former.
- Two one-time-code seeds listed under the same name, or two KeePass entries
  with the same title in the same group and no username, no longer collapse
  into one on import. The second was reported as already present and its
  secret was never stored; both now come across, and importing the same file
  again still skips them.
- Importing locket's own CSV export, or a Bitwarden CSV, added a `type`
  field (and `favorite`, `reprompt`) to every item and dropped the favourite
  mark. Favourites now come back as favourites, and those bookkeeping
  columns are not turned into fields.
- KeePass exports and imports lose less. An item with a custom field named
  `Password` (or `Title`, `URL`, and so on) exported that field in place of
  its real password; the field now gets a name of its own. Importing a
  `.kdbx` keeps each entry's tags, and no longer brings back entries from
  KeePass's Recycle Bin.
- Importing GitHub CLI credentials could label a token with the wrong
  account, or with none: with two accounts on one host, the active account's
  token was filed under the other one. Each token is now filed under the
  account gh keeps it for.
- Importing cloud CLI credentials now reports what it could not bring in. An
  Azure or Docker file that could not be read, and Google Cloud
  service-account keys (which are not imported), used to be passed over
  without a word; they are now counted as unreadable and named in the
  summary.
- Importing a Bitwarden JSON export kept less than it should: SSH keys
  arrived as empty logins, only the first website of a login survived, and a
  card's expiry was dropped when only the month or the year was set. SSH
  keys now import as SSH keys the agent can use, every website is kept, and
  a partial expiry is kept as it is.
- Importing a list of `otpauth://` URIs turned a `+` in the account name
  into a space, so `ada+work@example.com` arrived as `ada work@example.com`.
  Plus-addressed accounts now keep their plus.
- The window now locks itself after the idle time chosen in Settings. It
  never did: a check for changes to the vault file, made every few seconds
  while the vault is open, counted as you using the window.
- Restoring an earlier version of an item whose history was full brought
  back the version after the one you clicked, and deleted the one you
  clicked for good. It now restores the version you chose.
- Saving an item that had been deleted elsewhere while you were editing it
  said "Saved" and threw your changes away. The editor now stays open and
  says the item is gone, so you can copy what you typed.
- Turning down the unlock dialog now refuses the application that asked
  straight away. Closing it from the window menu or a keyboard shortcut, or
  cancelling it when locket had been started only to show it, left the
  application waiting two minutes.
- Saving an item you had open in the editor no longer quietly undoes a
  change another application made to it meanwhile, such as a password the
  browser extension updated. locket says the item changed; saving again
  replaces that change, and the replaced version stays in the item's
  history.

### Security

- A vault file whose key-derivation costs were edited to absurd values is
  now refused with an error when unlocked. It used to make the daemon,
  locket or the CLI try to allocate terabytes of memory and crash, or hang
  for good.
- SSH keys imported from `~/.ssh` were stored as an ordinary note field, so
  opening the item showed the private key in the clear and searching could
  match its contents. Newly imported keys are stored as private-key fields,
  masked until revealed. Keys imported earlier keep the old field kind.
- Importing a CSV with no header row showed its first line in the error
  message, password included. The error now says how many columns the first
  row has and that a header row is expected, without repeating its contents.
- KDBX exports were sealed with a key derivation of only 1 MiB of memory, so
  the exported file could be attacked with far less effort than the vault it
  came from. New exports use the same Argon2 cost as a new vault (64 MiB).
  Re-export anything you have already moved out this way.
- Locking the window while an import, a new unlock factor, a passphrase
  change or a KeePass export was still running left the open vault in memory
  behind the lock screen once that work finished. The vault is now dropped
  when it comes back to a locked window.
- Locking the window now clears everything the open vault put in it. An
  unsaved edit, a half-filled passphrase or export form, the health report
  and any open delete dialog used to survive the lock and come back after
  the next unlock, and an auto-type counting down still typed.
- The dialogs that ask before an SSH signature or a browser fill show the
  key, site and entry names on one line and at most 64 characters long. A
  browser extension could send a site name carrying line breaks,
  text-direction controls or enough text to push the real question and its
  buttons out of view.

### Documentation

- How Linux-PAM treats `PAM_ABORT` from an `optional` module is written down
  with the measurement behind it.
- Unlocking the screen does not unlock the vault, and the README, the threat
  model and the PAM notes now say so: applications ask again after a screen
  lock, and locket's own dialog is what reopens it.
- The README and the threat model state that every browser fill is confirmed
  separately — nothing is remembered per site or for a while afterwards.

## [2.0.0] - 2026-09-29

### Changed

- Rebuilt against the current COSMIC libraries (libcosmic `03d7dcb`).

### Added

- Cancelling locket's unlock dialog now refuses the application that
  asked, straight away: its request completes as dismissed, as the Secret
  Service specification provides, instead of waiting out a two-minute
  timeout. New `org.locket.Manager1.CancelUnlock` method.

### Security

- A process running as you can no longer approve its own SSH signature with
  a `confirm-each-use` key. The question used to be broadcast on the session
  bus with a sequential id, and any bus peer could answer it through
  `Manager1.AnswerConfirm` before the dialog appeared. The daemon now starts
  a dedicated dialog (`locket --confirm-signing <key>`) and reads its answer
  from a private pipe; `AnswerConfirm` and `ConfirmRequested` are gone, and
  the question no longer appears in the main window. Two signatures waiting
  at once each get their own dialog, and neither holds up an unlock prompt.
- The browser extension can no longer take a password without you. The
  native host released any saved password for whatever site the extension
  named, so a compromised extension could collect every stored login
  silently. Every fill now puts up a locket dialog naming the entry and the
  site (`locket --confirm-fill`), and nothing is handed over unless you
  allow it; the extension cannot answer that dialog. The extension no longer
  reads a stored password back to decide whether to offer saving a login —
  it remembers what it just filled instead — and saving a password the
  vault already holds changes nothing.

### Fixed

- The daemon no longer hangs for good when the vault locks — screen lock,
  suspend, idle, or Ctrl+L — while an SSH key marked `confirm-each-use` is
  waiting for its confirmation. The question is now asked without holding
  the agent, and a vault that locks while it is open refuses the signature.
- A sandboxed application can no longer be given a Secret portal key that
  was never saved. When another process had written the vault first, the
  key could be handed out from memory and then lost at the next reload,
  leaving the application's data encrypted under a key that no longer
  existed; the daemon now reloads before creating the key and hands out
  nothing it could not save.
- The browser host no longer treats the text of a URL without a host
  (`data:`, `file:`) as a site name, which let such a page match a
  credential saved for a domain its text happened to end in.
- Renaming the Secret portal's master key no longer re-keys every Flatpak
  application. The master was found by its label, so a rename (or an
  unrelated item saved under the same label) made the next request mint a
  new one. It is now found by its `locket:internal` tag; vaults from before
  are migrated to the master applications have actually been using —
  including ones still tagged `passman:internal` — and a damaged master is
  reported instead of silently replaced.
- The portal master key is no longer shown in locket's item list, and the
  Secret Service refuses to delete it, rewrite it, strip its tag, or delete
  the collection holding it.
- A login added in locket while the daemon is unlocked is visible to the
  browser extension and the panel's quick search straight away, not only
  after the next unlock: the daemon now publishes items as they appear,
  whoever wrote them. Locking — by any route, including idle and the
  screen lock — takes the item objects off the bus, so a locked vault no
  longer advertises how many items it holds.
- `/org/freedesktop/secrets/aliases/<name>` now follows its alias:
  `SetAlias` and creating or deleting a collection move or remove it, so
  `secret-tool store` no longer keeps writing to the old default
  collection until the daemon restarts. Creating a collection for an alias
  that already exists returns that collection, as the specification says,
  instead of a second one sharing the alias.
- An application storing a secret is told when the store did not reach
  the disk — because another program wrote the vault at the same moment,
  or the disk failed — instead of being told it succeeded while the change
  was quietly dropped. A desktop notification says so too. Every way of
  locking the vault (idle, screen lock, suspend, shutdown, a client's
  `Lock`) now saves anything pending first.
- Every Secret Service method now answers with the specification's error
  names (`org.freedesktop.Secret.Error.IsLocked`, `NoSession`,
  `NoSuchObject`). Only one method did before; the rest answered a generic
  `Failed` for a locked vault and `UnknownObject` for a missing session,
  which libsecret cannot tell apart from a hard failure.
- An unlock that takes longer than 25 seconds no longer fails in the
  application that asked. The Secret Service `Prompt()` call used to wait
  for the passphrase before returning, and GDBus clients give up on a call
  after 25 seconds; it now returns at once and reports through `Completed`,
  as the specification describes.
- Secret Service sessions, each holding a Diffie-Hellman key, are closed
  when the application that opened them leaves the bus, and
  `LockService` takes them off the bus as well as forgetting them. They
  used to accumulate for the daemon's lifetime. A session can only be used
  by the application that opened it.
- Adding an item after a Secret Service client deleted every collection
  no longer crashes locket, the daemon or the CLI; a new default
  collection is created for it.
- Unlocking at login from PAM and from locket at the same moment no longer
  lets the slower of the two replace the vault the faster one opened,
  losing anything written to it in between.
- Secret Service clients are told when an item or collection is deleted or
  edited (`ItemDeleted`, `ItemChanged`, `CollectionDeleted`,
  `CollectionChanged`), not only when one is created, so a keyring browser
  no longer keeps showing a deleted entry. Deleting an item that is already
  gone is an error rather than a second success.
- The browser extension fills nothing into a tab that navigated away
  between the click and the fill: the injected code checks the page's
  origin itself. A login saved from an `https://` page is no longer
  offered to, or filled into, the `http://` page of the same site.
- The Secret portal backend answers only `xdg-desktop-portal`. Any program
  that could reach the daemon could name any Flatpak application and be
  handed that application's key.

## [1.2.0] - 2026-09-22

### Changed

- Rebuilt against the current COSMIC libraries (libcosmic `03c8f93`).

### Added

- The package ships `locket-setup`. Run as your own user after installing, it
  makes locket your keyring using the packaged binaries: it imports from the
  running keyring, points Secret Service activation at `/usr/bin/locketd`,
  routes the Secret portal, and with `--pam` and `--browser` wires the login
  stack and the browser extension's host. Before, the package installed the
  pieces and left the switch-over to a script that only worked from a source
  checkout; the install prints how to run it.

### Fixed

- The unlock dialog starts outside the daemon's sandbox. Launched as the
  daemon's child it inherited `MemoryDenyWriteExecute`, which blocks Mesa's
  shader compiler ("JIT session error: Permission denied"); under systemd it
  now starts as its own transient unit.
- The daemon no longer leaves a finished dialog behind as a zombie process.
- Menus are laid out like Envelope's: a divider is a thin rule instead of a
  full-height empty row, and the menu is wide enough that labels are not cut
  off and shortcuts have room beside them.
- An SSH signing request brings the locket window forward, or opens it when
  none is open. It used to wait in a window that could be behind the terminal
  asking, or in no window at all.

### Fixed

- The package declares `pam` and `systemd-libs`, which the binaries link directly. Both were
  already present on any Arch system, so nothing failed to start.

## [1.1.0] - 2026-09-16

### Changed

- **An application asking for a secret gets a dialog, not the whole window.**
  When a `libsecret` client reaches a locked vault, locket now asks for the
  passphrase in a small titled window of its own — one field, and an *Open
  locket* button for anyone who wanted the application itself. Before, the
  request took over the main window: it switched to the full-screen unlock
  view and, if the vault was open, locked it first, so an application's
  request could close what you were reading mid-session. It no longer touches
  the window behind it, and unlocking through the dialog still unlocks that
  window too when it is locked, exactly as unlocking in the window has always
  unlocked the daemon.
- When no locket is running, the daemon now starts one with `--prompt`, which
  brings up that dialog and no main window at all. Dismissing it ends the
  process; the Secret Service request then waits out its own timeout, as it
  does when nobody is at the machine.

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

[Unreleased]: https://github.com/Magnetar-OS/locket/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/Magnetar-OS/locket/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/Magnetar-OS/locket/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Magnetar-OS/locket/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Magnetar-OS/locket/releases/tag/v1.0.0
