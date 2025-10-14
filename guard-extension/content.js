// Listen for clicks from the background worker
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "GUARD_COLLECT_HTML") {
      const html = document.documentElement.outerHTML;
      sendResponse({ html, url: location.href });
    } else if (msg.type === "GUARD_SHOW_RESULT") {
      renderPanel(msg.data);
    } else if (msg.type === "GUARD_SHOW_ERROR") {
      renderPanel({ error: msg.message || "Request failed" });
    }
    return true;
  });
  
  function renderPanel(data) {
    const id = "guard-panel";
    const old = document.getElementById(id);
    if (old) old.remove();
  
    const el = document.createElement("div");
    el.id = id;
    el.style.cssText = `
      position:fixed; right:12px; bottom:12px; z-index:2147483647;
      width:380px; max-height:70vh; overflow:auto;
      background:#0b1020; color:#e7e9ee; border:1px solid #334;
      border-radius:12px; box-shadow:0 6px 30px rgba(0,0,0,.4); 
      font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    `;
    el.innerHTML = panelHTML(data);
    document.body.appendChild(el);
  }
  
  function panelHTML(data) {
    if (!data || data.error) {
      return `
        <div style="padding:12px 12px 8px; border-bottom:1px solid #223;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <b>Guard</b>
            <button onclick="this.closest('#guard-panel').remove()" style="background:none;border:0;color:#9aa;cursor:pointer">✕</button>
          </div>
        </div>
        <div style="padding:12px;">⚠️ ${escapeHtml(data?.error || "Error")}</div>
      `;
    }
  
    const label = data.label || "Result";
    const score = typeof data.risk_score === "number" ? Math.round(data.risk_score * 100) : "?";
    const reasons = (data.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join("");
    const c = data.content || {};
    const about = c.about ? `<div style="margin-bottom:6px"><b>What this link is:</b> ${escapeHtml(c.about)}</div>` : "";
    const summary = c.summary ? `<div style="margin-bottom:8px">${escapeHtml(c.summary)}</div>` : "";
    const badge = badgeHTML(label);
  
    return `
      <div style="padding:12px 12px 8px; border-bottom:1px solid #223;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <b>Guard</b>
          <button onclick="this.closest('#guard-panel').remove()" style="background:none;border:0;color:#9aa;cursor:pointer">✕</button>
        </div>
      </div>
      <div style="padding:12px;">
        <div style="margin-bottom:8px">${badge}
          <span style="margin-left:8px;opacity:.85">Risk score: <b>${score}</b>/100</span>
        </div>
        ${about}
        ${summary}
        ${reasons ? `<div style="opacity:.85">Why:</div><ul>${reasons}</ul>` : ""}
      </div>
    `;
  }
  
  function badgeHTML(label) {
    const bg = /High Risk/i.test(label) ? "#d63c3c" : /Needs Review|Suspicious/i.test(label) ? "#f59e0b" : "#10b981";
    return `<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:${bg};color:#fff;font-size:12px">${escapeHtml(label)}</span>`;
  }
  function escapeHtml(s) {
    return (s ?? "").toString().replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));
  }
  