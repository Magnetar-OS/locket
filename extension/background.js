// Talks to locket-native-host. Nothing here caches secrets: a password is
// requested only when the user picks an entry, and is handed straight to the
// content script for that one fill.
const HOST = "com.magnetaros.locket";

async function ask(message) {
  try {
    return await chrome.runtime.sendNativeMessage(HOST, message);
  } catch (e) {
    return { type: "error", message: String(e.message || e) };
  }
}

const origin = (u) => {
  try {
    return new URL(u).origin;
  } catch {
    return null;
  }
};

// A submitted login waiting for the user's decision, keyed so the popup can
// show it for the right site. Session storage only: memory-backed, cleared
// when the browser closes, never written to disk.
const PENDING_KEY = "pending-save";

async function setPending(pending) {
  if (pending) {
    await chrome.storage.session.set({ [PENDING_KEY]: pending });
    chrome.action.setBadgeText({ text: "1" });
    chrome.action.setTitle({ title: "locket — save this login?" });
  } else {
    await chrome.storage.session.remove(PENDING_KEY);
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setTitle({ title: "locket" });
  }
}

// A form was submitted with a password in it. Decide whether it is worth
// offering: a value identical to what the vault already holds is not.
async function submitted(msg) {
  const status = await ask({ type: "status" });
  if (status.type !== "status" || !status.unlocked) return;

  const matches = await ask({ type: "search", url: msg.url });
  if (matches.type === "matches") {
    const existing = matches.items.find((i) => i.username === msg.username);
    if (existing) {
      // Same username: only offer if the password actually changed.
      const current = await ask({ type: "get", id: existing.id, url: msg.url });
      if (current.type === "secret" && current.password === msg.password) return;
    }
  }

  await setPending({
    url: msg.url,
    origin: origin(msg.url),
    username: msg.username,
    password: msg.password,
    at: Date.now(),
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    switch (msg.type) {
      case "status":
        reply(await ask({ type: "status" }));
        break;
      case "submitted":
        await submitted(msg);
        reply({ type: "ok" });
        break;
      case "pending": {
        const stored = await chrome.storage.session.get(PENDING_KEY);
        reply({ type: "pending", pending: stored[PENDING_KEY] || null });
        break;
      }
      case "save-pending": {
        const stored = await chrome.storage.session.get(PENDING_KEY);
        const pending = stored[PENDING_KEY];
        if (!pending) {
          reply({ type: "error", message: "Nothing waiting to be saved." });
          break;
        }
        const saved = await ask({
          type: "save",
          url: pending.url,
          username: pending.username,
          password: pending.password,
        });
        if (saved.type === "saved") await setPending(null);
        reply(saved);
        break;
      }
      case "dismiss-pending":
        await setPending(null);
        reply({ type: "ok" });
        break;
      case "search":
        reply(await ask({ type: "search", url: msg.url }));
        break;
      case "fill": {
        // Where is that tab *now*? The popup listed matches for the page as it
        // was when it opened; a page that navigated in between must not be
        // handed the previous origin's password. The host checks this too —
        // this side cannot be trusted to — but checking here as well means the
        // secret is never even requested for the wrong site.
        const tab = await chrome.tabs.get(msg.tabId).catch(() => null);
        if (!tab || !tab.url || origin(tab.url) !== origin(msg.url)) {
          reply({ type: "error", message: "That tab is no longer on the page you picked." });
          break;
        }

        // Fetch the secret and inject it in one step, so it never sits in the
        // popup's memory or crosses more boundaries than necessary.
        const secret = await ask({ type: "get", id: msg.id, url: tab.url });
        if (secret.type !== "secret") {
          reply(secret);
          break;
        }
        await chrome.scripting.executeScript({
          target: { tabId: msg.tabId },
          func: fillForm,
          args: [msg.username, secret.password],
        });
        reply({ type: "ok" });
        break;
      }
      default:
        reply({ type: "error", message: "unknown request" });
    }
  })();
  return true; // keep the channel open for the async reply
});

// Injected into the page. Deliberately only ever called from an explicit user
// action in the popup — never automatically on page load, which is how
// autofill turns into a credential-harvesting bug on a hostile page.
//
// Runs in the default ISOLATED world, not MAIN. The isolated world shares the
// DOM, which is all this needs, while denying the page any view of this code
// or the value being written. Assigning through the prototype's value setter
// is what makes frameworks that patch inputs (React and friends) observe the
// change, and it works from the isolated world.
function fillForm(username, password) {
  const pw = document.querySelector('input[type="password"]:not([disabled])');
  if (!pw) return;
  const form = pw.form || document;
  const user = form.querySelector(
    'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i]'
  );
  const set = (el, value) => {
    if (!el) return;
    const proto = Object.getPrototypeOf(el);
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    // Assign through the prototype setter so React and friends see the change.
    setter ? setter.call(el, value) : (el.value = value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  if (username) set(user, username);
  set(pw, password);
}
