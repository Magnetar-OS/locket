const out = document.getElementById("out");
const saveBox = document.getElementById("save");
const send = (m) => new Promise((r) => chrome.runtime.sendMessage(m, r));

// A login submitted since the last visit, waiting for a decision. Rendered
// above the match list; saving goes through the background so the credential
// itself never has to pass through this page's DOM.
async function renderPending() {
  const res = await send({ type: "pending" });
  const pending = res?.pending;
  saveBox.textContent = "";
  if (!pending) return;

  const box = document.createElement("div");
  box.className = "save";
  const text = document.createElement("div");
  text.innerHTML = `<div class="label"></div><div class="user"></div>`;
  text.querySelector(".label").textContent = `Save login for ${pending.origin}?`;
  text.querySelector(".user").textContent = pending.username || "(no username)";
  const actions = document.createElement("div");
  actions.className = "actions";
  const save = document.createElement("button");
  save.textContent = "Save in locket";
  save.onclick = async () => {
    save.disabled = true;
    const r = await send({ type: "save-pending" });
    if (r.type === "saved") {
      text.querySelector(".label").textContent = r.updated
        ? "Updated the saved login."
        : "Saved.";
      actions.remove();
      setTimeout(() => saveBox.textContent = "", 1200);
    } else {
      text.querySelector(".user").textContent = r.message || "Could not save.";
      save.disabled = false;
    }
  };
  const dismiss = document.createElement("button");
  dismiss.textContent = "Not now";
  dismiss.onclick = async () => {
    await send({ type: "dismiss-pending" });
    saveBox.textContent = "";
  };
  actions.append(save, dismiss);
  box.append(text, actions);
  saveBox.append(box);
}

(async () => {
  await renderPending();
  const status = await send({ type: "status" });
  if (status.type === "error" || !status.daemon) {
    out.textContent = "locket is not running.";
    return;
  }
  if (!status.unlocked) {
    // The popup never asks for the passphrase; that belongs in locket itself.
    out.textContent = "Your vault is locked. Unlock it in locket, then reopen this.";
    return;
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const res = await send({ type: "search", url: tab.url });
  if (res.type !== "matches" || res.items.length === 0) {
    out.textContent = "No saved credentials for this site.";
    return;
  }

  out.textContent = "";
  for (const item of res.items) {
    const row = document.createElement("div");
    row.className = "row";
    const text = document.createElement("div");
    text.innerHTML = `<div class="label"></div><div class="user"></div>`;
    text.querySelector(".label").textContent = item.label;
    text.querySelector(".user").textContent = item.username || item.url;
    const fill = document.createElement("button");
    fill.textContent = "Fill";
    fill.onclick = async () => {
      // Send the URL the search was done for, so the background script can
      // notice if the tab has navigated since.
      const r = await send({
        type: "fill",
        id: item.id,
        username: item.username,
        tabId: tab.id,
        url: tab.url,
      });
      if (r.type === "ok") window.close();
      else out.textContent = r.message || "Could not fill.";
    };
    row.append(text, fill);
    out.append(row);
  }
})();
