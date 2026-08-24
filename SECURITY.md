# Security policy

locket holds the credentials of whoever runs it, so the honest starting point
is this: **it has been written and reviewed by one person, and audited by
nobody.** Treat it accordingly. Nothing below is a claim that it is safe; it is
a description of what has been checked and how to tell me when it is not.

## Reporting a vulnerability

Report privately first, via GitHub's [private vulnerability
reporting](https://github.com/entro314-labs/locket/security/advisories/new) on
this repository. If that is unavailable to you, open an issue saying only that
you have a security report and how to reach you — no details in the issue.

Please include what you need to include and nothing you would rather not: a
description, the version or commit, and ideally the steps that reproduce it.

You will get an acknowledgement. If the report is valid you will be credited in
the advisory unless you ask not to be. There is no bounty; this is one person's
project.

## What is in scope

Anything that lets code or a person reach secrets they should not:

* recovering vault contents without a factor that opens it — the passphrase, an
  enrolled TPM, an enrolled security key;
* a `libsecret` client, Flatpak application or browser extension obtaining a
  secret belonging to another origin, application or item;
* the SSH agent signing with a key the caller should not be able to use, or
  after the vault has been locked;
* the PAM module affecting the authentication decision, or leaking a token;
* a local process escalating through the unlock socket, the agent socket or
  `org.locket.Manager1`.

## What is out of scope

* An attacker who is already running code as your user *while the vault is
  unlocked*. The unlocked daemon holds the key in memory and serves any client
  on your session bus; that is what a session secret store is. Locking is the
  defence, which is why the vault locks on idle, on session lock and on
  suspend.
* Physical attacks on an unlocked machine.
* Weak passphrases. Argon2id makes guessing expensive, not impossible.
* The 1024-bit Diffie-Hellman group in the Secret Service transport. It is
  fixed by the wire format `libsecret` implements, it protects secrets in
  transit on your own session bus only, and the alternative that clients
  actually negotiate otherwise is plaintext.

## What has and has not been verified

Verified against the real software that consumes it — `libsecret`, a sandboxed
Flatpak through `xdg-desktop-portal`, OpenSSH, `pamtester`, a real TPM — and
covered by the test suite. See the Verified section of the README, which says
in each case what was actually run.

**Not verified:** anything involving a FIDO2 token on hardware. The code paths
exist and are unit-tested against a software stand-in; no physical token has
ever been attached. There has been no external review, no fuzzing campaign, and
no reproducible-build story.

## Supported versions

Nothing is released yet. Until there is a tag, the supported version is the tip
of `main`.
