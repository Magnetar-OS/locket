// Talks to passman-native-host. Nothing here caches secrets: a password is
// requested only when the user picks an entry, and is handed straight to the
// content script for that one fill.
const HOST = "io.github.idominikos.passman";

async function ask(message) {
  try {
    return await chrome.runtime.sendNativeMessage(HOST, message);
  } catch (e) {
    return { type: "error", message: String(e.message || e) };
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    switch (msg.type) {
      case "status":
        reply(await ask({ type: "status" }));
        break;
      case "search":
        reply(await ask({ type: "search", url: msg.url }));
        break;
      case "fill": {
        // Fetch the secret and inject it in one step, so it never sits in the
        // popup's memory or crosses more boundaries than necessary.
        const secret = await ask({ type: "get", id: msg.id });
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
