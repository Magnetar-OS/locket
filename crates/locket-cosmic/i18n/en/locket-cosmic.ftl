# locket — English source catalogue.
#
# Ids are grouped by the screen they appear on. A string that is stored in the
# vault file (a slot label, an item's own name) is deliberately absent: those
# are data, not interface, and translating them would rewrite what is on disk.

app-title = locket
app-comment = Passwords, keys and secrets for the COSMIC desktop


## Security — unlock factors

security-title = Unlock factors
security-blurb =
    Any one of these opens the vault. Hardware factors are added alongside your
    passphrase, never instead of it — so losing a device does not lose the vault.
security-dismiss = Dismiss
security-locked = Unlock the vault to manage factors.
security-sealing = Sealing a key to the TPM…
security-touch-key = Waiting for you to touch your security key…
security-required = Required
security-remove = Remove
security-add-heading = Add a factor
security-pin-placeholder = PIN (optional)
security-add-factor = Add { $factor }
security-sealing-short = Sealing…
security-touch-short = Touch your key…
security-build-missing =
    Some factors are unavailable because this build was compiled without support
    for them.
security-tpm-caveat =
    A TPM PIN is protected by the chip's lockout, not by its length — which is
    what makes a short PIN safe. That lockout is device-wide: repeated wrong PINs
    can lock out anything else using the TPM, including disk unlock, until it
    recovers.

factor-tpm-pin = TPM PIN
factor-security-key = Security key

security-passphrase-heading = Passphrase
security-passphrase-blurb =
    Changing the passphrase rewraps the vault's key rather than re-encrypting
    the vault, so it is fast whatever the vault holds — and every other unlock
    factor keeps working.
security-current-passphrase = Current passphrase
security-new-passphrase = New passphrase
security-confirm-passphrase = Confirm new passphrase
security-kdf-cost = Unlock cost
kdf-balanced = Balanced — 64 MiB, 3 passes. The default.
kdf-stronger = Stronger — 256 MiB, 4 passes. Unlocking takes noticeably longer.
kdf-lighter = Lighter — 19 MiB, 2 passes. For hardware where Balanced hurts.
security-change-passphrase = Change passphrase
security-changing-passphrase = Changing…
security-passphrase-changed = Passphrase changed. Other unlock factors keep working.
error-current-passphrase-wrong = The current passphrase is not right.
error-new-passphrases-differ = The two new passphrases do not match.
error-new-passphrase-empty = Enter the new passphrase twice.

slot-passphrase = Argon2id · { $memory } MiB · { $passes } passes
slot-tpm = Sealed to this machine's TPM{ $pin } · { $parent }
slot-tpm-with-pin = , released by PIN
slot-fido = Hardware token{ $verification }
slot-fido-uv = , with user verification
slot-fido-presence = , presence only

error-no-tpm-support = this build has no TPM support
error-no-fido-support = this build has no security-key support


## Settings

settings-title = Settings
settings-section-security = Security
settings-auto-lock = Lock the vault when idle
settings-clipboard = Clear copied secrets
settings-conceal-on-blur = Hide revealed secrets when the window loses focus
settings-section-appearance = Appearance
settings-compact-list = Compact list
settings-compact-list-detail = Fit more items on screen by putting each one on a single line
settings-recheck = Re-check

auto-lock-never = Never
auto-lock-1m = After 1 minute
auto-lock-5m = After 5 minutes
auto-lock-15m = After 15 minutes
auto-lock-30m = After 30 minutes
auto-lock-1h = After 1 hour

clipboard-never = Never — leave it on the clipboard
clipboard-10s = After 10 seconds
clipboard-30s = After 30 seconds
clipboard-1m = After 1 minute

integration-title = Desktop integration
integration-checking = Checking…

integration-secrets = Secret Service
integration-secrets-ours = locket is serving org.freedesktop.secrets
integration-secrets-other = { $owner } owns org.freedesktop.secrets, not locket
integration-secrets-none = nothing owns org.freedesktop.secrets

integration-flatpak = Flatpak apps
integration-flatpak-missing =
    The Secret portal backend is not installed. Run locket-setup to install it.
integration-flatpak-unrouted =
    The backend is installed but the desktop prefers another one, so Flatpak apps
    will not use locket.
integration-flatpak-ok = Sandboxed applications get their secrets from locket

integration-pam = Unlock at login
integration-pam-ok = pam_locket.so is in the login stack
integration-pam-partial =
    Unlocks at login, but has no `password` line — changing your login password
    will quietly stop that working
integration-pam-missing = Not configured; you unlock manually each session

integration-keyring = gnome-keyring
integration-keyring-running =
    Still running, and will contend with locket for the Secret Service name
integration-keyring-stopped = Not running

about-source-code = Source code
about-report-issue = Report an issue


## Item and field kinds
#
# Singular names label one item; the plural forms name a category in the
# sidebar. They are separate ids rather than an "s" appended to the singular,
# because that only ever worked in English.

kind-login = Login
kind-note = Secure Note
kind-card = Payment Card
kind-identity = Identity
kind-ssh-key = SSH Key
kind-gpg-key = GPG Key
kind-api-token = API Token
kind-oauth = OAuth Credential
kind-certificate = Certificate
kind-environment = Environment
kind-wifi = Wi-Fi Network
kind-application = Application Secret

kind-login-plural = Logins
kind-note-plural = Secure Notes
kind-card-plural = Payment Cards
kind-identity-plural = Identities
kind-ssh-key-plural = SSH Keys
kind-gpg-key-plural = GPG Keys
kind-api-token-plural = API Tokens
kind-oauth-plural = OAuth Credentials
kind-certificate-plural = Certificates
kind-environment-plural = Environments
kind-wifi-plural = Wi-Fi Networks
kind-application-plural = Application Secrets

field-text = Text
field-secret = Secret
field-url = URL
field-totp = One-time code
field-note = Note
field-email = Email
field-phone = Phone
field-date = Date
field-private-key = Private key
field-public-key = Public key


## Item editor

editor-new = New item
editor-edit = Edit item
editor-name = Name
editor-name-placeholder = e.g. GitHub
editor-type = Type
editor-secret = Password / secret
editor-generate = Generate
editor-strength = { $length } chars · ~{ $bits } bits
editor-symbols = Symbols
editor-fields = Fields
editor-field-name = Name
editor-field-value = Value
editor-field-remove = Remove
editor-add-field = Add field
editor-attributes-kept = { $count } Secret Service attribute(s) will be preserved
editor-save = Save
editor-cancel = Cancel
editor-needs-name = Give the item a name.
editor-field-needs-name = Every field needs a name.
editor-expires = Expires
editor-expires-placeholder = YYYY-MM-DD, or leave empty
editor-bad-expiry = Expiry wants a YYYY-MM-DD date, or nothing for never.


## Import

import-title = Import secrets
import-run = Import
import-running = Importing…
import-cancel = Cancel
import-into = Import into
import-collection-placeholder = Collection
import-group-variables = Group variables
import-database-password = Database password
import-choose-folder = Choose folder…
import-choose-file = Choose file…
import-no-folder = No directory chosen
import-no-file = No file chosen

source-browser-csv = Browser or password manager export
source-bitwarden = Bitwarden (.json)
source-onepassword = 1Password (.1pux)
source-protonpass = Proton Pass (.zip)
source-dotenv = Project .env files
source-ssh = SSH private keys
source-cloud = Cloud CLI credentials
source-totp = Authenticator export (TOTP)
source-pass = pass (password-store)
source-keepass = KeePass database
source-keyring = Running keyring (gnome-keyring)

source-browser-csv-blurb =
    A .csv exported from Chrome, Edge, Brave, Firefox, Safari, Bitwarden,
    1Password or KeePassXC. Columns are matched by name, so a renamed header
    still imports.
source-bitwarden-blurb =
    Bitwarden's Tools → Export as .json — the format that carries custom
    fields, TOTP seeds, cards, identities and folders. A password-protected
    export is refused; export again without a file password.
source-onepassword-blurb =
    A .1pux export (File → Export). Logins, cards, identities, notes, tags
    and TOTP seeds come across; items in 1Password's trash stay deleted, and
    attached documents are counted rather than silently dropped.
source-protonpass-blurb =
    Proton Pass's non-encrypted zip export. Logins, aliases, cards, notes
    and custom fields come across; a PGP-encrypted export is refused —
    export again without encryption.
source-dotenv-blurb =
    Walks a directory of projects and imports every .env file, skipping
    node_modules, build output, and .env.example templates. Your files are left
    where they are.
source-pass-blurb =
    A ~/.password-store tree. Each entry is decrypted with gpg, so the key it was
    encrypted to has to be available; entries that cannot be decrypted are
    counted and skipped.
source-keepass-blurb =
    A .kdbx database. Groups become tags and TOTP seeds are carried across.
source-ssh-blurb =
    Copies the private keys out of ~/.ssh into the vault, in the shape locket's
    own SSH agent reads. Your key files stay where they are; OpenSSH keeps
    working exactly as before.
source-cloud-blurb =
    Reads the credentials the aws, gcloud, az, gh, docker and npm tools leave
    unencrypted in your home directory. Only the stores you actually have are
    touched.
source-totp-blurb =
    A list of otpauth:// URIs, or a plain-text Aegis or andOTP export. Encrypted
    backups are refused rather than half-read — export again without a password.
source-keyring-blurb =
    Reads everything the keyring currently serving this session will hand over.
    Only useful before you take the org.freedesktop.secrets name away from it.

grouping-per-file = One item per .env file
grouping-per-service = One item per service
grouping-per-variable = One item per variable

picker-projects = Choose a directory of projects
picker-password-store = Choose a password-store directory
picker-csv = Choose an exported .csv
picker-csv-filter = CSV export
picker-kdbx = Choose a .kdbx database
picker-kdbx-filter = KeePass database
picker-bitwarden = Choose a Bitwarden .json export
picker-bitwarden-filter = Bitwarden export
picker-onepassword = Choose a .1pux export
picker-onepassword-filter = 1Password export
picker-protonpass = Choose a Proton Pass export
picker-protonpass-filter = Proton Pass export
picker-ssh = Choose an SSH directory
picker-totp = Choose an authenticator export
picker-file = Choose a file

import-error-no-file = no file chosen
import-error-no-folder = no directory chosen
import-error-no-database = no database chosen
import-error-no-home = cannot find your home directory
import-error-keyring-elsewhere = the keyring import does not run here


## Unlock screen

unlock-create-title = Create your vault
unlock-title = Unlock locket
unlock-create-blurb =
    Choose a strong passphrase. It is the only thing protecting your secrets, and
    it cannot be recovered if you forget it.
unlock-app-blurb =
    An application asked for a secret from your vault. Unlock to let it through.
unlock-blurb = Enter your passphrase to unlock the vault.
unlock-passphrase = Passphrase
unlock-confirm = Confirm passphrase
unlock-create-button = Create vault
unlock-button = Unlock
unlock-working = Unlocking…


## Sidebar categories

category-all = All Items
category-favorites = Favorites
category-trash = Trash
category-health = Health
category-security = Security
category-settings = Settings


## Health report

health-summary =
    { $scanned } items scanned — { $weak } weak, { $reused } reused, { $old } old,
    { $expiring } expiring, { $expired } expired
health-clean = Nothing to report
health-clean-detail = Passwords look strong, unique and current.
health-reason-reused = reused by { $count } other item(s)
health-reason-old = unchanged for { $days } days
health-reason-expired = expired
health-reason-expiring = expiring soon
strength-very-weak = very weak password
strength-weak = weak password
strength-fair = fair password
health-check-breaches = Check against known breaches
health-checking = Checking against known breaches…
health-breach-blurb =
    Asks haveibeenpwned.com whether any of these secrets appear in a known
    breach. Only the first five characters of each secret's SHA-1 hash leave
    this machine — never the secret, never the full hash — and this is the
    only thing in locket that touches the network, only when you press it.
health-breached = In known breaches — seen { $count } time(s)
health-no-breaches = No secret appears in known breaches.
health-breach-failed = The breach check failed: { $error }
health-old-note =
    “Unchanged” is measured from the item's last edit, which is the closest
    thing the vault records to when the secret itself last changed.


## Item list

search-placeholder = Search { $category }
empty-no-match = No match for “{ $query }”
empty-no-match-all = Nothing in the vault matches.
empty-no-match-category = Nothing in { $category } matches. Try All Items.
empty-vault = Your vault is empty
empty-vault-detail = Add something, or import from another password manager.
empty-category = No { $category } yet
empty-category-detail = The vault holds { $count } item(s) in other categories.
clear-search = Clear search
new-item = New item
import = Import
lock = Lock


## Item details

detail-edit = Edit
detail-autotype = Auto-type
toast-autotype-armed =
    After allowing input access, click the field to fill — typing starts
    { $seconds } seconds later. Username, Tab, password; no Enter.
toast-autotype-done = Typed { $label } into the focused field
toast-autotype-failed = Auto-type failed: { $error }
detail-favorite = Favorite
detail-unfavorite = Unfavorite
detail-delete = Delete
detail-password = Password
detail-reveal = Reveal
detail-hide = Hide
detail-copy = Copy
detail-otp = One-time code
detail-expires = expires in { $seconds } seconds
detail-expires-one = expires in 1 second
detail-attributes = Secret Service attributes

# Item-level expiry (a certificate's end date, a token's lifetime) — not the
# TOTP countdown above.
detail-expired-on = Expired { $date }
detail-expires-on = Expires { $date }

detail-attachments = Attachments
attachment-add = Add attachment…
attachment-save = Save…
attachment-remove = Remove
attachment-picker-title = Choose a file to attach
attachment-save-title = Save attachment
attachment-note =
    Stored encrypted in the vault; the original file is untouched. Attachments
    are not carried into edit history.

detail-history = History
detail-history-restore = Restore
detail-history-note =
    Earlier versions of this item, captured each time an edit replaced them.
    Restoring is itself an edit, so it can be undone the same way.
history-entry = { $date } · { $subtitle }
qr-show = Show QR code
qr-hide = Hide QR code
qr-caption =
    Scan to add this account to an authenticator app. Anyone who photographs this
    can generate your codes.
invalid-totp = Invalid TOTP seed: { $error }

# What a copy toast calls the thing it copied.
copied-kind-secret = Secret
copied-kind-value = Value


## Menus

menu-file = File
menu-view = View
menu-about = About
menu-open-vault = Open another vault…
menu-merge-copy = Merge a diverged copy…
vault-picker-title = Open another vault
merge-picker-title = Choose the diverged copy to merge

menu-export = Export
menu-export-json = Everything, as JSON (plaintext)…
menu-export-csv = Flat CSV for another manager (plaintext)…
menu-export-kdbx = Encrypted KeePass database…

dialog-export-title = Export in the clear?
dialog-export-body =
    The file will hold every secret in the vault, unencrypted. It is the most
    dangerous file on the disk while it exists — move the secrets, then delete
    it. The encrypted KeePass export avoids this entirely.
dialog-export-continue = Choose where to write it

dialog-kdbx-title = Encrypt the export
dialog-kdbx-body =
    The database is sealed under its own passphrase — the one KeePassXC will
    ask for when opening it.
dialog-kdbx-passphrase = Database passphrase
dialog-kdbx-confirm = Confirm passphrase
dialog-kdbx-continue = Choose where to write it

export-save-title = Export the vault
toast-exported = Exported { $count } item(s) to { $path }
toast-exported-lossy =
    { $count } item(s) had fields or attachments CSV cannot carry; the JSON
    export is lossless.
toast-export-failed = Export failed: { $error }


## Dialogs

dialog-ssh-title = Allow this SSH signature?
dialog-ssh-body =
    Something on this machine is asking to authenticate with “{ $key }”. This key
    is set to ask every time, so nothing happens unless you allow it.
dialog-allow-once = Allow once
dialog-refuse = Refuse
dialog-delete-title = Move to the trash?
dialog-delete-body =
    “{ $label }” moves to the trash: any application that reads it through the
    Secret Service stops finding it, but you can restore it from Trash until it
    is purged.
dialog-delete = Move to trash
dialog-cancel = Cancel

dialog-purge-title = Delete forever?
dialog-purge-body = “{ $label }” will be gone for good. This cannot be undone.
dialog-purge = Delete forever
dialog-empty-trash-title = Empty the trash?
dialog-empty-trash-body =
    { $count } item(s) will be gone for good. This cannot be undone.

dialog-conflict-title = A diverged copy of this vault exists
dialog-conflict-body =
    Your file synchroniser left “{ $name }” beside this vault — a copy holding
    edits made on another machine. Merging folds both sides together: the newer
    edit of each item wins and the other lands in its history, so nothing is
    lost. The copy itself is only read.
dialog-merge = Merge
dialog-later = Not now


## Trash

empty-trash = The trash is empty
empty-trash-detail = Items you delete wait here before they are gone for good.
trash-deleted-on = Deleted { $date }
trash-restore = Restore
trash-delete-forever = Delete forever
trash-empty-button = Empty trash
trash-retention-label = Delete forever after
retention-7d = 7 days
retention-30d = 30 days
retention-90d = 90 days
retention-never = Never — only when emptied by hand
trash-retention-detail =
    Stored in the vault itself and enforced on unlock, by whichever locket
    process opens it first — so the window means the same thing everywhere
    the vault goes.


## Toasts and messages

toast-copied = { $what } copied
toast-copied-clearing = { $what } copied — clipboard clears in { $seconds }s
toast-allowed-signature = Allowed one signature with { $key }
toast-refused-signature = Refused a signature with { $key }
toast-saved = Saved { $label }
toast-trashed = Moved { $label } to the trash
toast-restored = Restored { $label }
toast-purged = Deleted { $label } forever
toast-trash-emptied = Emptied the trash — { $count } item(s)
toast-revision-restored = Restored an earlier version of { $label }
toast-attachment-added = Attached { $name }
toast-attachment-removed = Removed { $name }
toast-attachment-saved = Wrote { $path }
toast-attachment-failed = Could not handle the attachment: { $error }
toast-merged = Merged — { $report }
toast-merge-nothing = The copies are identical; nothing to merge.
toast-merge-failed =
    Could not merge: { $error }. A copy that does not decrypt with this vault's
    key is not a fork of this vault.
toast-merge-attachments =
    { $count } conflicting edit(s) lost attachments held only by the older side;
    their other changes are in the item's history.
toast-imported = Imported { $summary }
toast-unlocked-others = Unlocked for other applications too
toast-factor-removed = Factor removed.
toast-factor-added = Factor added. Your passphrase still works.
toast-qr-failed = Could not build a QR code: { $error }


## Errors

error-enter-passphrase = Enter a passphrase.
error-passphrases-differ = The two passphrases do not match.
error-open-failed = Could not open the vault.
error-unlock-task = unlock task failed: { $error }
error-enrolment-task = enrolment task failed: { $error }
error-import-task = The import task failed; unlock again.
error-changed-elsewhere = The vault was changed elsewhere. Unlock it again.
error-save-conflict =
    Another locket process wrote the vault a moment ago. Nothing was
    overwritten — try that again.
error-save-failed = Could not save: { $error }


## Window title

title-new-item = New item — locket
title-editing = Editing — locket
title-locked = Locked — locket
title-unlocking = Unlocking… — locket
title-page = { $page } — locket

# Shown in the delete dialog when the item has gone between the click and the
# dialog appearing.
dialog-delete-fallback-label = this item

# The View menu entry that focuses the search box.
menu-search = Search

# The primary secret when it is binary data, base64-encoded at rest.
detail-binary-secret = Binary secret · { $bytes } bytes
detail-binary-hint =
    Not text. Shown and copied as Base64; applications reading it through the
    Secret Service get the original bytes.
# The primary secret when it holds U+FFFD replacement characters: destroyed by
# an import that predates the binary-secret encoding.
detail-mangled-hint =
    This value contains replacement characters (�), which usually means an
    earlier import damaged binary data. If the source keyring still has the
    original, locket-reimport-keyring restores it.

# The editor's secret field when the item holds a binary secret.
editor-binary-secret =
    Binary secret · { $bytes } bytes, shown as Base64. Applications read the
    original bytes; typing here replaces it with a text secret.
editor-binary-replaced =
    The secret has changed and will be saved as the text above, no longer as
    binary data. Cancel to keep the original.

# The strength meter on the create-vault screen. This is the one passphrase
# nothing can recover, so it is the one worth estimating out loud.
strength-meter = Strength: { $strength }
strength-label-very-weak = very weak
strength-label-weak = weak
strength-label-fair = fair
strength-label-good = good
strength-label-strong = strong
unlock-weak-warning =
    A weak passphrase is the whole vault's weakness. Longer beats stranger:
    four unrelated words outlast a short line of symbols.
unlock-open-other = Open a different vault…

detail-history-forget = Forget history
dialog-forget-history-title = Forget this item's history?
dialog-forget-history-body =
    Every earlier version of “{ $label }” is deleted for good. Do this after
    rotating a credential that leaked: history exists to make a replaced value
    recoverable, which is the last thing you want for the one you just rotated
    away from.
dialog-forget = Forget
toast-history-forgotten = Dropped { $count } earlier version(s) of { $label }
