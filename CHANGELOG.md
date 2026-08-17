# Changelog

Notable changes, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Nothing has been released yet, so everything so far sits under Unreleased.

## Unreleased

### Fixed

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
  secret passman put there.
- Creating a vault raced: two creates could both decide the file was absent.
- A non-text secret was mangled into replacement characters on its way to a
  browser instead of being refused.

### Added

- **Security keys over SSH** — `sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256`
  identities, signed by driving a FIDO2 assertion per signature.
- **SSH certificates** — advertised alongside the key they belong to, since a
  host configured for certificate authentication will not take the bare key.
- **Confirm each use** — an item can require a dialog before every signature
  with it. Fails closed: nothing to ask means no signature.
- **The vault locks itself**: after an idle timeout, when the session locks,
  and when the machine suspends.
- `passman-cli edit`, `rm`, `export` and `passwd` — the recovery tool can now
  repair and leave, not only add.
- `pam_passman.so` follows a password change through to the vault, given a
  `password optional pam_passman.so` line.
- Settings are watched, so a change made anywhere else lands without a
  restart, and the idle timeout is shared with the daemon rather than being
  two settings with one name.
- The SSH importer picks up a key's certificate, and marks the keys whose
  signing happens on hardware — those files are credential handles, so
  importing one is not a backup.

### Changed

- `Vault::save` refuses to overwrite a file that changed since it was read.
  Use `reload` to pick the other writer up, or `save_force` to mean it.
- `passmand` gained `--auto-lock` and `--no-lock-on-idle-session`; the
  installed unit turns the idle lock on at 15 minutes.
- `ssh-add -x` and `-X` work: the lock passphrase is kept and compared in
  constant time.
