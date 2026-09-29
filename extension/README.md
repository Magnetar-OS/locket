# locket browser extension

Two manifests, because the browsers genuinely disagree about MV3 backgrounds:

| | background key | why |
|---|---|---|
| Chrome / Chromium / Brave / Edge | `service_worker` | MV3 requires it |
| Firefox | `scripts` (event page) | `service_worker` is unimplemented — [bug 1573659](https://bugzil.la/1573659) |

MDN suggests declaring both keys in one manifest. Chrome 151 warns on that
(`'background.scripts' requires manifest version of 2 or lower`) and shows the
extension with a warning banner, so they are kept apart.

## Chrome / Chromium / Brave

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
   select this directory.
2. Copy the extension id it shows.
3. Register the native messaging host:

   ```sh
   scripts/locket-setup --browser <extension-id>
   ```

4. Reload the extension.

## Firefox

```sh
cp manifest.firefox.json manifest.json    # in a copy of this directory
```

Then `about:debugging` → **This Firefox** → **Load Temporary Add-on** and pick
the `manifest.json`. Firefox matches on the id baked into
`browser_specific_settings`, so it needs no id from the installer:

```sh
scripts/locket-setup --browser        # no id: Firefox is ready
```

## What it will and will not do

The popup lists credentials matching the current page and fills on click. It
never fills automatically, never asks for your passphrase, and shows nothing
while the vault is locked — unlock in locket itself.

**Every fill is confirmed in locket.** Clicking **Fill** asks the native host
for one password, and the host puts up a locket dialog naming the entry and
the site before it hands anything over. The extension cannot answer that
dialog: a compromised extension can ask for passwords, but each one needs
you to say yes. It can still list the labels and usernames saved for any
site it names, because the host has no independent view of your tabs.

**Saving** is offer-only. A content script notices a login form being
submitted; unless it is the login locket just filled, the toolbar icon gains
a badge and the popup's next opening asks
"Save login for this site?" — nothing is written until you say so, and
"Not now" forgets it. The pending credential waits in the browser's
session storage, which is memory-backed and gone when the browser closes.
An update to an existing entry files the old password into the item's
history in locket, so even a mistaken save is undoable there.

## Version

The extension carries locket's version and is bumped with every release
(`release.config.json` lists both manifests). It speaks to the native host
from the same release: the message set is not versioned separately, and a
host newer than the extension may answer in ways an older extension does
not know — `refused` and `unchanged` arrived that way.
