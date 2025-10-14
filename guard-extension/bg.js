// Change this if your Guard server is on a different host/port.
const GUARD_BASE = "http://127.0.0.1:8000";

async function captureAndSend(tabId) {
  // Run in-page to get full DOM and URL (uses the user’s session & cookies).
  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => ({
      html: document.documentElement.outerHTML,
      url: location.href
    })
  });
  if (!res || !res.result) return;

  try {
    await fetch(`${GUARD_BASE}/analyze_pasted_html`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Your FastAPI endpoint already trims server-side if huge
      body: JSON.stringify({
        html_text: res.result.html,
        source_url: res.result.url
      })
    });
    // Open (or focus) Guard UI so the user can see the analysis
    chrome.tabs.create({ url: `${GUARD_BASE}/` });
  } catch (e) {
    console.error("Guard post failed:", e);
    chrome.notifications?.create({
      type: "basic",
      iconUrl: "icon128.png",
      title: "Guard",
      message: "Failed to send page to Guard. Is the server running?"
    });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "guard-analyze",
    title: "Analyze with Guard",
    contexts: ["page"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "guard-analyze" && tab?.id) captureAndSend(tab.id);
});

chrome.action.onClicked.addListener((tab) => {
  if (tab?.id) captureAndSend(tab.id);
});
