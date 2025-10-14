// Change if your API lives elsewhere:
const API_BASE = "http://127.0.0.1:8000";

chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.id) return;

  // Ask the content script to collect the DOM HTML
  chrome.tabs.sendMessage(tab.id, { type: "GUARD_COLLECT_HTML" }, async (resp) => {
    if (chrome.runtime.lastError) {
      console.warn(chrome.runtime.lastError.message);
      return;
    }
    const { html, url } = resp || {};
    if (!html) return;

    try {
      const r = await fetch(`${API_BASE}/analyze_dom`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, html })
      });
      const data = await r.json();
      chrome.tabs.sendMessage(tab.id, { type: "GUARD_SHOW_RESULT", data });
    } catch (e) {
      chrome.tabs.sendMessage(tab.id, { type: "GUARD_SHOW_ERROR", message: String(e) });
    }
  });
});
