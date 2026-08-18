# Installing `pam_locket.so`

Hands the password PAM already collected at the login screen to the daemon, so
a login password that is also your vault passphrase unlocks the vault without
a second prompt.

```sh
cargo build --release -p locket-pam
sudo install -m 755 target/release/libpam_locket.so /usr/lib/security/pam_locket.so
```

Add to `/etc/pam.d/system-login`, **after `pam_systemd.so`** — the unlock socket
lives in `/run/user/<uid>`, and `pam_systemd` is what creates that directory:

```
auth     optional  pam_locket.so
password optional  pam_locket.so
session  optional  pam_locket.so
```

The `password` line is what keeps the arrangement working when you change your
login password: without it `passwd` succeeds, the vault keeps its old
passphrase, auto-unlock stops happening and nothing says why.

Then enable the daemon, which starts locked and waits:

```sh
systemctl --user enable --now locket-daemon.service
```

## Why `optional`

`optional` means a failure here can never stop you logging in, or block a
password change. The module is written to match: every path returns success or
`PAM_IGNORE`, and `sm_authenticate` takes no part in the authentication
*decision*. It observes the token PAM already accepted and hands it to the
daemon; it cannot let anyone in.

`sm_chauthtok` does nothing on PAM's first (`PAM_PRELIM_CHECK`) pass, and on
the second sends the old and new passwords to the daemon. The daemon proves
the old one opens the vault before re-wrapping the key under the new one, so a
password change by someone who never knew the vault passphrase changes
nothing.

There is deliberately no `sudo` entry. Authorising privilege escalation from
locket is a different module with a much higher bar — see the TPM section in
the main README for why that needs hardware-anchored verification first.

## Testing without touching your login stack

Create a throwaway service file rather than editing `system-login`:

```sh
sudo tee /etc/pam.d/locket-test <<'STACK'
auth     required  pam_unix.so
auth     optional  pam_locket.so
account  required  pam_permit.so
session  required  pam_permit.so
session  optional  pam_locket.so
STACK

pamtester -v locket-test "$USER" authenticate open_session
journalctl --since -1min | grep locket:
```

Only programs that ask for the `locket-test` service are affected, so a
mistake cannot lock you out.
