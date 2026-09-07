// Notices a login being submitted, so the background can offer to save it.
//
// Runs in the isolated world on every page. It captures the values at the
// moment of submission — after navigation the inputs are gone — and hands
// them to the background script, which parks them in session storage until
// the user opens the popup and decides. Nothing is saved, and nothing leaves
// the browser, without that explicit decision.
//
// Deliberately capture-phase on `submit`: pages that preventDefault and
// submit via fetch still fire the event through the capture phase, which is
// most modern login forms.

(() => {
  const credentialsOf = (form) => {
    const pw = form.querySelector('input[type="password"]');
    if (!pw || !pw.value) return null;
    const user = form.querySelector(
      'input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i]'
    );
    return { username: user?.value || "", password: pw.value };
  };

  document.addEventListener(
    "submit",
    (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      const credentials = credentialsOf(form);
      if (!credentials) return;
      // Fire and forget: the page is probably about to navigate, and the
      // background script owns everything from here.
      chrome.runtime.sendMessage({
        type: "submitted",
        url: location.href,
        username: credentials.username,
        password: credentials.password,
      });
    },
    true
  );
})();
