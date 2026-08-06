# Installing `pam_passman.so`

Unlocks the vault at login when your login password is also your vault
passphrase — the `pam_gnome_keyring` arrangement.

```sh
cargo build --release -p passman-pam
sudo install -m 755 target/release/libpam_passman.so /usr/lib/security/pam_passman.so
```

Add to `/etc/pam.d/system-login`, **after `pam_systemd.so`** — the unlock socket
lives in `/run/user/<uid>`, and `pam_systemd` is what creates that directory:

```
auth     optional  pam_passman.so
session  optional  pam_passman.so
```

Then enable the daemon, which starts locked and waits:

```sh
systemctl --user enable --now passman-daemon.service
```

## Why `optional`, and why only `auth` + `session`

`optional` means a failure here can never stop you logging in. The module is
written to match: every path returns success, and `sm_authenticate` returns
`PAM_IGNORE` so it takes no part in the authentication *decision*. It observes
the token PAM already accepted and hands it to the daemon; it cannot let anyone
in.

There is deliberately no `sudo` entry. Authorising privilege escalation from
passman is a different module with a much higher bar — see the TPM section in
the main README for why that needs hardware-anchored verification first.

## Testing without touching your login stack

Create a throwaway service file rather than editing `system-login`:

```sh
sudo tee /etc/pam.d/passman-test <<'STACK'
auth     required  pam_unix.so
auth     optional  pam_passman.so
account  required  pam_permit.so
session  required  pam_permit.so
session  optional  pam_passman.so
STACK

pamtester -v passman-test "$USER" authenticate open_session
journalctl --since -1min | grep passman:
```

Only programs that ask for the `passman-test` service are affected, so a
mistake cannot lock you out.
