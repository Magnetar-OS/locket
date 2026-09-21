#!/bin/sh
# Shown after install and upgrade. A package cannot take over a user's Secret
# Service or edit /etc/pam.d, so it says how instead of doing it.
cat <<'MSG'

locket is installed but not yet your keyring. As your own user (not root):

  locket-setup                  import from the running keyring and switch over
  locket-setup --pam            ...and unlock the vault at login
  locket-setup --browser [ID]   ...and register the browser extension's host
  locket-setup --status         see what is wired up

MSG
