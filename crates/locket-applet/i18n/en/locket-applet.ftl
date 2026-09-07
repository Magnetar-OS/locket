# The panel indicator. Kept deliberately small: unlocking happens in the
# window, never in a popup, so there is nothing here to translate but state.

summary-unlocked = Unlocked · { $items } items
summary-locked = Locked
summary-no-daemon = locketd is not running

daemon-hint = Start locketd to manage secrets from here.

lock-now = Lock now
open-locket = Open locket
unlock-in-locket = Unlock in locket

# Quick search. Only ever shows labels; a secret leaves the vault when — and
# only when — the copy button is pressed.
search-placeholder = Search secrets
search-no-match = Nothing matches “{ $query }”
search-locked = Unlock to search from here.
copy = Copy
copied = Copied “{ $label }” — clipboard clears in { $seconds }s
copied-forever = Copied “{ $label }”
copy-failed = Could not copy “{ $label }”: it may be binary, or the vault locked.
