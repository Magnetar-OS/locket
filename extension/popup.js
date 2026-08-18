const out = document.getElementById("out");
const send = (m) => new Promise((r) => chrome.runtime.sendMessage(m, r));

(async () => {
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
