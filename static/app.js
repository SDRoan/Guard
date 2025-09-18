const form = document.getElementById("check-form");
const input = document.getElementById("url-input");
const result = document.getElementById("result");
const btn = document.getElementById("check-btn");

function badge(label) {
  const cls =
    label === "High Risk" ? "bad" :
    label === "Suspicious" ? "warn" : "ok";
  return `<span class="badge ${cls}">${label}</span>`;
}

// Simple HTML escaper so we can safely show page text
function escapeHtml(s) {
  if (!s) return "";
  return s.replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const value = (input.value || "").trim();
  if (!value) return;

  btn.disabled = true; btn.textContent = "Checking…";
  result.classList.add("hidden");

  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ artifact_type: "url", value })
    });
    const data = await res.json();

    if (data.error) {
      result.innerHTML = `<div class="kv">Error: ${escapeHtml(String(data.error))}</div>`;
      result.classList.remove("hidden");
      return;
    }

    const label = data.label;
    const score = (data.risk_score * 100).toFixed(0);
    const reasons = (data.reasons || []).map(r => `<li>${escapeHtml(String(r))}</li>`).join("");
    const actions = (data.recommended_actions || []).map(a => `<li>${escapeHtml(String(a))}</li>`).join("");

    // New: two-part content from backend
    const c = data.content || {};
    const inside = c.inside || {};
    const insideHtml = `
      <ul>
        ${Array.isArray(inside.headings) && inside.headings.length ? `<li><b>Top headings:</b> ${inside.headings.map(h => escapeHtml(h)).join(" · ")}</li>` : ""}
        ${inside.forms ? `<li><b>Forms:</b> ${inside.forms.count || 0}${inside.forms.has_password ? " (password fields present)" : ""}${(inside.forms.actions||[]).length ? ` — actions: ${inside.forms.actions.map(a => escapeHtml(a)).join(", ")}` : ""}</li>` : ""}
        ${Array.isArray(inside.links_sample) && inside.links_sample.length ? `<li><b>Referenced domains:</b> ${inside.links_sample.map(l => escapeHtml(l)).join(" · ")}</li>` : ""}
        ${typeof inside.images === "number" ? `<li><b>Images:</b> ${inside.images}</li>` : ""}
      </ul>
    `;

    const aboutHtml = `
      <div class="kv" style="margin-top:10px">
        <div style="font-weight:600;margin-bottom:6px">What this link is</div>
        <ul>
          ${c.about ? `<li>${escapeHtml(String(c.about))}</li>` : "<li>Unknown page type</li>"}
          ${c.title ? `<li><b>Title:</b> ${escapeHtml(String(c.title))}</li>` : ""}
          ${c.final_url ? `<li><b>Final URL:</b> ${escapeHtml(String(c.final_url))}</li>` : ""}
          ${c.http_status ? `<li><b>HTTP Status:</b> ${escapeHtml(String(c.http_status))}</li>` : ""}
          ${c.content_type ? `<li><b>Content-Type:</b> ${escapeHtml(String(c.content_type))}</li>` : ""}
          ${typeof c.bytes_fetched === "number" ? `<li><b>Bytes fetched:</b> ${c.bytes_fetched}</li>` : ""}
          ${c.note ? `<li><b>Note:</b> ${escapeHtml(String(c.note))}</li>` : ""}
        </ul>
      </div>
    `;

    const contentsHtml = `
      <div class="kv" style="margin-top:10px">
        <div style="font-weight:600;margin-bottom:6px">What’s inside right now</div>
        ${insideHtml}
        ${c.summary ? `<div style="margin-top:6px"><b>Summary:</b> ${escapeHtml(String(c.summary))}</div>` : ""}
      </div>
    `;

    result.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>${badge(label)}</div>
        <div class="kv">Risk score: <b>${score}</b>/100</div>
      </div>
      <div style="height:10px;"></div>
      <div class="kv">Why:</div>
      <ul>${reasons}</ul>
      <div class="kv" style="margin-top:10px;">What to do:</div>
      <ul>${actions}</ul>
      ${aboutHtml}
      ${contentsHtml}
    `;
    result.classList.remove("hidden");
  } catch (err) {
    result.innerHTML = `<div class="kv">Request failed: ${escapeHtml(String(err))}</div>`;
    result.classList.remove("hidden");
  } finally {
    btn.disabled = false; btn.textContent = "Check Link";
  }
});
