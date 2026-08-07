# passman browser extension

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
   scripts/passman-setup --browser <extension-id>
   ```

4. Reload the extension.

## Firefox

```sh
cp manifest.firefox.json manifest.json    # in a copy of this directory
```

Then `about:debugging` → **This Firefox** → **Load Temporary Add-on** and pick
the `manifest.json`. Firefox matches on the id baked into
`browser_specific_settings`, so `--browser` takes any value.

## What it will and will not do

The popup lists credentials matching the current page and fills on click. It
never fills automatically, never asks for your passphrase, and shows nothing
while the vault is locked — unlock in passman itself.
