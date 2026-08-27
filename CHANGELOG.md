# Changelog

Notable changes, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Nothing has been released yet, so everything so far sits under Unreleased.

## Unreleased

### Renamed

The project is now **Locket**. Everything moved with it: the binaries
(`locket`, `locketd`, `locket-cli`, `locket-applet`, `locket-native-host`,
`pam_locket.so`), the crates, the application id
(`io.github.entro314labs.Locket`), the development bus name
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
`io.github.entro314labs.Locket`, with `io.github.entro314labs.LocketApplet` for
the panel indicator, `io.github.entro314labs.locket` for the browser's native
messaging host and `locket@entro314labs.github.io` for the Firefox extension.
Slate, Circle and Envelope are all `io.github.entro314labs.*`; Locket was the
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
