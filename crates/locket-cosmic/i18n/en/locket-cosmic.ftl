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
category-security = Security
category-settings = Settings


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


## Dialogs

dialog-ssh-title = Allow this SSH signature?
dialog-ssh-body =
    Something on this machine is asking to authenticate with “{ $key }”. This key
    is set to ask every time, so nothing happens unless you allow it.
dialog-allow-once = Allow once
dialog-refuse = Refuse
dialog-delete-title = Delete item?
dialog-delete-body =
    “{ $label }” will be removed from the vault. This cannot be undone, and any
    application that reads it through the Secret Service will stop finding it.
dialog-delete = Delete
dialog-cancel = Cancel


## Toasts and messages

toast-copied = { $what } copied
toast-copied-clearing = { $what } copied — clipboard clears in { $seconds }s
toast-allowed-signature = Allowed one signature with { $key }
toast-refused-signature = Refused a signature with { $key }
toast-saved = Saved { $label }
toast-deleted = Deleted { $label }
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
