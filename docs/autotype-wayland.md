# Auto-type on Wayland — field notes

**Measured · September 2026 · COSMIC session · xdg-desktop-portal 1.22.1 ·
xdg-desktop-portal-cosmic 1.7.0**

Auto-type is the KeePassXC feature locket lacks with the least obvious
replacement: focus a login form somewhere, press a hotkey, and the manager
types username, Tab, password, Enter into it. On X11 that is XTest. On
Wayland there is no XTest, by design — synthetic input has to come from
something the compositor trusts, and the sanctioned route is the portals.
This note records what the portals actually offer on a live COSMIC session,
measured rather than assumed, and what that means for building the feature.

Everything below was read off a running session with `busctl`, the installed
`.portal` files, and `cosmic-portals.conf`. Package versions are in the
header; re-measure before trusting this on a newer stack.

## What is actually there

**Typing: available.** The portal frontend exposes
`org.freedesktop.portal.RemoteDesktop` at version 2, and — the part that
matters — `xdg-desktop-portal-cosmic` itself implements the backend:

```
$ grep Interfaces /usr/share/xdg-desktop-portal/portals/cosmic.portal
Interfaces=…;org.freedesktop.impl.portal.RemoteDesktop;…

$ busctl --user introspect org.freedesktop.impl.portal.desktop.cosmic \
    /org/freedesktop/portal/desktop | grep Keyboard
.NotifyKeyboardKeycode    method    oa{sv}iu
.NotifyKeyboardKeysym     method    oa{sv}iu
```

`NotifyKeyboardKeysym` is the one to build on: a keysym names a character,
not a physical key, so typing works whatever layout the session runs — where
`NotifyKeyboardKeycode` would need the client to reimplement the keymap and
would still type the wrong thing on anything but the layout it assumed.

Routing is confirmed, not assumed: `cosmic-portals.conf` says
`default=cosmic;gtk;`, gtk does not implement RemoteDesktop, so a
RemoteDesktop session on this desktop is served by cosmic.

**A global hotkey: not available.** `org.freedesktop.portal.GlobalShortcuts`
is absent from the frontend's interface list on this session. The interface
exists in the spec and `xdg-desktop-portal-gnome` (installed here) implements
its backend — but the routing prefers `cosmic;gtk;`, neither of which
implements it, and the frontend hides an interface no routed backend serves.
Until `xdg-desktop-portal-cosmic` grows a GlobalShortcuts backend (or the
COSMIC settings daemon offers its own registration mechanism), nothing can
give locket a system-wide "auto-type into the focused field" key.

**Window targeting: not available, by design.** The RemoteDesktop portal
types into whatever has focus; it does not say what that is, and nothing in
the portal surface names the focused window. A client cannot check "am I
about to type a bank password into a chat box" — the person invoking it is
the targeting mechanism, and the UI has to be built around that fact.

## What locket builds on this

- **Auto-type ships against the RemoteDesktop portal**, keysym path. The
  flow is: the person picks an item and presses *Auto-type*; the portal asks
  for permission (a system dialog, owned by the compositor, first use per
  session); locket then counts down a few seconds while the person clicks
  the field they want filled, and types `username → Tab → password`. No
  Enter — submitting a form nobody has reviewed is a decision, not a
  keystroke.
- **The trigger lives in locket**, not on a hotkey, until GlobalShortcuts is
  routable on COSMIC. When it is, the hotkey becomes a small addition to an
  already-working feature rather than the blocker for it.
- **The roadmap's "show the target window title before typing" is not
  implementable** on this portal surface, and this note supersedes it: the
  countdown-and-click flow makes the person the targeting step instead.

## Re-measuring

All of the above is three commands: `busctl --user introspect
org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop` for what the
frontend offers, the `Interfaces=` lines under
`/usr/share/xdg-desktop-portal/portals/` for what backends exist, and
`cosmic-portals.conf` for which of them the desktop actually routes to.
When a COSMIC release adds `org.freedesktop.impl.portal.GlobalShortcuts` to
`cosmic.portal`, the hotkey work unblocks.