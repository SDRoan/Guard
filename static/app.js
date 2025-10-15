// Guard — Link & QR Risk Check

// ===== Link checker DOM =====
const form   = document.getElementById("check-form");
const input  = document.getElementById("url-input");
const result = document.getElementById("result");
const btn    = document.getElementById("check-btn");

// ===== Anti-bot fallback DOM =====
const domDetails = document.getElementById("dom-fallback");
const domUrl     = document.getElementById("html-url");
const domText    = document.getElementById("html-snapshot");
const domBtn     = document.getElementById("html-analyze");
const domResult  = document.getElementById("dom-result");

// ===== QR DOM =====
const qrStartBtn = document.getElementById("qr-start");
const qrStopBtn  = document.getElementById("qr-stop");
const qrFile     = document.getElementById("qr-file");
const qrVideo    = document.getElementById("qr-video");
const qrCanvas   = document.getElementById("qr-canvas");
const qrResult   = document.getElementById("qr-result");

let qrStream = null;
let qrLoopId = null;

// ===== Helpers =====
function hide(el){ el && el.classList.add("hidden"); }
function show(el){ el && el.classList.remove("hidden"); }
function setLoading(el, isLoading, labelWhenLoading, labelWhenDone) {
  if (!el) return;
  el.disabled = !!isLoading;
  if (labelWhenLoading && isLoading) el.innerHTML = labelWhenLoading;
  if (labelWhenDone && !isLoading) el.innerHTML = labelWhenDone;
  el.classList.toggle("loading", !!isLoading);
}
function badge(label) {
  const cls =
    label === "High Risk"   ? "bad"  :
    label === "Suspicious"  ? "warn" :
    label === "Likely Safe" ? "ok"   : "";
  return `<span class="badge ${cls}">${escapeHtml(label)}</span>`;
}
function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (m) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"
  }[m]));
}
function fmtScore(p) {
  const n = Number(p);
  return Number.isFinite(n) ? (n * 100).toFixed(0) : "?";
}
function openDomFallback(prefillUrl) {
  if (!domDetails) return;
  domDetails.open = true;
  if (prefillUrl && domUrl && !domUrl.value) domUrl.value = prefillUrl;
  setTimeout(()=> domText && domText.focus(), 50);
}

// ===============================
// LINK CHECK
// ===============================
if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const value = (input.value || "").trim();
    if (!value) return;

    setLoading(btn, true, '<span>⏳</span> Checking…', '<span>🔍</span> Check Link');
    hide(result);

    try {
      const res = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifact_type: "url", value })
      });
      const data = await res.json();

      if (!res.ok || data.error) {
        result.innerHTML = `<div class="kv">Error: ${escapeHtml(data.error || res.statusText)}</div>`;
        show(result);
        return;
      }
      renderLinkAnalysis(data, result);

      // If site blocked automated fetch (anti-bot) or TLS issue -> nudge user to paste HTML
      const c = data.content || {};
      const note = (c.note || "").toLowerCase();
      if ((note.includes("fetch blocked") && note.includes("anti-bot"))
          || note.includes("tls verification failed")
          || (c.fetched === false && c.final_url)) {
        openDomFallback(c.final_url || value);
      }

    } catch (err) {
      result.innerHTML = `<div class="kv">Request failed: ${escapeHtml(String(err))}</div>`;
      show(result);
    } finally {
      setLoading(btn, false, null, '<span>🔍</span> Check Link');
    }
  });
}

function renderLinkAnalysis(data, container) {
  const label   = data.label;
  const score   = fmtScore(data.risk_score);
  const reasons = (data.reasons || []).map(r => `<li>${escapeHtml(String(r))}</li>`).join("");
  const actions = (data.recommended_actions || []).map(a => `<li>${escapeHtml(String(a))}</li>`).join("");

  const c = data.content || {};
  const inside = c.inside || {};

  // Redirect chain UI (if present)
  const chain = Array.isArray(c.redirect_chain) ? c.redirect_chain : [];
  const chainHtml = chain.length ? `
    <details class="kv" style="margin-top:10px">
      <summary style="cursor:pointer"><b>Redirect chain</b> (${chain.length} hop${chain.length>1?'s':''})</summary>
      <div style="overflow:auto; margin-top:8px;">
        <table style="width:100%; border-collapse:collapse; font-size:14px;">
          <thead>
            <tr>
              <th style="text-align:left; padding:6px; border-bottom:1px solid var(--border-light)">#</th>
              <th style="text-align:left; padding:6px; border-bottom:1px solid var(--border-light)">Domain</th>
              <th style="text-align:left; padding:6px; border-bottom:1px solid var(--border-light)">Status</th>
              <th style="text-align:left; padding:6px; border-bottom:1px solid var(--border-light)">HTTPS</th>
              <th style="text-align:left; padding:6px; border-bottom:1px solid var(--border-light)">Flags</th>
            </tr>
          </thead>
          <tbody>
            ${chain.map((h,i)=>`
              <tr>
                <td style="padding:6px;">${i+1}</td>
                <td style="padding:6px;"><code>${escapeHtml(h.domain || "")}</code></td>
                <td style="padding:6px;">${escapeHtml(String(h.status || ""))}</td>
                <td style="padding:6px;">${h.https ? "✅" : "❌"}</td>
                <td style="padding:6px;">
                  ${(h.flags || []).map(f=>`<span class="badge warn" style="margin-right:4px;">${escapeHtml(f)}</span>`).join(" ")}
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
        <div style="margin-top:8px; font-size:13px; opacity:.85;">
          Final URL: <code>${escapeHtml(c.final_url || "")}</code>
        </div>
      </div>
    </details>
  ` : "";

  // Probe summary (if present)
  const probes = (inside && inside.probes) || null;
  const probesHtml = probes ? `
    <div class="kv" style="margin-top:8px">
      <b>Probe results:</b> ${escapeHtml(probes.brief || "")}
    </div>
  ` : "";

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
        ${c.final_url ? `<li><b>Final URL:</b> <code>${escapeHtml(String(c.final_url))}</code></li>` : ""}
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
      ${probesHtml}
      ${c.summary ? `<div style="margin-top:6px"><b>Summary:</b> ${escapeHtml(String(c.summary))}</div>` : ""}
    </div>
  `;

  container.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div>${badge(label)}</div>
      <div class="kv">Risk score: <b>${escapeHtml(score)}</b>/100</div>
    </div>

    <div style="height:10px;"></div>

    ${chainHtml}

    <div class="kv" style="margin-top:10px;">Why:</div>
    <ul>${reasons}</ul>

    <div class="kv" style="margin-top:10px;">What to do:</div>
    <ul>${actions}</ul>

    ${aboutHtml}
    ${contentsHtml}
  `;
  show(container);
}


// ===============================
// Anti-bot DOM fallback wiring
// ===============================
if (domBtn && domText) {
  domBtn.addEventListener("click", analyzePastedDom);
  domText.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyzePastedDom();
    }
  });
}

async function analyzePastedDom() {
  const html = (domText.value || "").trim();
  const url  = (domUrl && domUrl.value ? domUrl.value.trim() : (input && input.value ? input.value.trim() : ""));
  hide(domResult);

  if (!html) {
    domResult.innerHTML = `<div class="kv">Paste the page HTML first.</div>`;
    show(domResult);
    return;
  }

  setLoading(domBtn, true, '<span>⏳</span> Analyzing…', '<span>⚙️</span>Analyze pasted HTML');

  try {
    const res = await fetch("/analyze_dom", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, html })
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      domResult.innerHTML = `<div class="kv">Error: ${escapeHtml(data.error || res.statusText)}</div>`;
      show(domResult);
      return;
    }
    renderLinkAnalysis(data, domResult);
  } catch (e) {
    domResult.innerHTML = `<div class="kv">Request failed: ${escapeHtml(e.message || e)}</div>`;
    show(domResult);
  } finally {
    setLoading(domBtn, false, null, '<span>⚙️</span>Analyze pasted HTML');
  }
}


// ===============================
// QR: camera + file decode
// ===============================
if (qrStartBtn) qrStartBtn.addEventListener("click", startQrCamera);
if (qrStopBtn)  qrStopBtn.addEventListener("click", stopQrCamera);
if (qrFile) {
  qrFile.addEventListener("change", async () => {
    const f = qrFile.files && qrFile.files[0];
    if (!f) return;
    const img = new Image();
    img.onload = async () => {
      const { width, height } = img;
      const w = Math.min(640, width);
      const h = Math.round((w / width) * height);
      qrCanvas.width = w; qrCanvas.height = h;
      const ctx = qrCanvas.getContext("2d");
      ctx.drawImage(img, 0, 0, w, h);
      tryDecodeFromCanvas();
    };
    img.src = URL.createObjectURL(f);
  });
}

async function startQrCamera() {
  try {
    stopQrCamera();
    qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
    qrVideo.srcObject = qrStream;
    await qrVideo.play();

    const w = qrVideo.videoWidth || 640;
    const h = qrVideo.videoHeight || 480;
    qrCanvas.width = w;
    qrCanvas.height = h;

    scanLoop();
  } catch (e) {
    qrResult.innerHTML = `<div class="kv">Camera error: ${escapeHtml(e.message || e)}</div>`;
    show(qrResult);
  }
}
function stopQrCamera() {
  if (qrLoopId) { cancelAnimationFrame(qrLoopId); qrLoopId = null; }
  if (qrStream) { qrStream.getTracks().forEach(t => t.stop()); qrStream = null; }
}
function scanLoop() {
  const ctx = qrCanvas.getContext("2d");
  ctx.drawImage(qrVideo, 0, 0, qrCanvas.width, qrCanvas.height);
  tryDecodeFromCanvas().then(found => {
    if (found) return;
    qrLoopId = requestAnimationFrame(scanLoop);
  });
}
async function tryDecodeFromCanvas() {
  try {
    const ctx = qrCanvas.getContext("2d");
    const imageData = ctx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });
    if (code && code.data) {
      stopQrCamera();
      await analyzeQrPayload(code.data);
      return true;
    }
  } catch (e) {
    qrResult.innerHTML = `<div class="kv">Decode error: ${escapeHtml(e.message || e)}</div>`;
    show(qrResult);
  }
  return false;
}
async function analyzeQrPayload(raw) {
  hide(qrResult);
  qrResult.innerHTML = `<div class="kv">Decoding…</div>`;
  try {
    const res = await fetch("/analyze_qr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload: String(raw || "") })
    });
    const data = await res.json();
    if (!res.ok || data.error) {
      qrResult.innerHTML = `<div class="kv">Error: ${escapeHtml(data.error || res.statusText)}</div>`;
      show(qrResult);
      return;
    }
    if (data.content || data.features) {
      renderLinkAnalysis(data, qrResult);
      return;
    }
    const qr = data.qr || {};
    const fields = qr.fields || {};
    const fieldList = Object.keys(fields).map(k => `<li><b>${escapeHtml(k)}:</b> ${escapeHtml(fields[k])}</li>`).join("");
    const actions = (data.recommended_actions || []).map(a => `<li>${escapeHtml(a)}</li>`).join("");
    qrResult.innerHTML = `
      <div class="kv">QR payload</div>
      <ul>
        <li><b>Type:</b> ${escapeHtml(qr.type || "Unknown")}</li>
        <li><b>Raw:</b> <code>${escapeHtml(qr.raw || "")}</code></li>
        ${fieldList}
      </ul>
      ${Array.isArray(data.reasons) && data.reasons.length ? `<div class="kv" style="margin-top:10px">Why:</div><ul>${data.reasons.map(r=>`<li>${escapeHtml(r)}</li>`).join("")}</ul>` : ""}
      ${actions ? `<div class="kv" style="margin-top:10px">What to do:</div><ul>${actions}</ul>` : ""}
    `;
    show(qrResult);
  } catch (e) {
    qrResult.innerHTML = `<div class="kv">Request failed: ${escapeHtml(e.message || e)}</div>`;
    show(qrResult);
  }
}


// ===============================
// Email Text Scanner (no OAuth) — only runs if the section exists
// ===============================
(() => {
  const section = document.getElementById("email-text-scanner");
  if (!section) return;

  const textarea = document.getElementById("raw-email");
  const scoreBtn = document.getElementById("score-raw");
  const statusEl = document.getElementById("raw-status");
  const outEl    = document.getElementById("raw-result");

  function setStatus(msg, loading=false) {
    statusEl.textContent = msg || "";
    statusEl.classList.toggle("loading", !!loading);
  }

  scoreBtn.addEventListener("click", async () => {
    const raw = (textarea.value || "").trim();
    if (!raw) {
      setStatus("Paste an email first."); return;
    }
    setStatus("Scoring…", true);
    hide(outEl);

    // Naive header/body split
    const lines = raw.split(/\r?\n/);
    let headers = {}, subject = "", from = "";
    let i = 0;
    for (; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) { i++; break; }
      const m = line.match(/^([^:]+):(.*)$/);
      if (m) {
        const k = m[1].trim();
        const v = m[2].trim();
        headers[k] = v;
        if (/^subject$/i.test(k)) subject = v;
        if (/^from$/i.test(k)) from = v;
      }
    }
    const body = lines.slice(i).join("\n");

    try {
      const r = await fetch("/api/score_raw", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          headers,
          from_addr: from,
          subject,
          text: body
        })
      });
      if (!r.ok) throw new Error("Request failed");
      const data = await r.json();

      const reasons = (data.reasons || []).map(x => `<li>${escapeHtml(x)}</li>`).join("");
      const links   = (data.links || []).map(x => `<li><a href="${escapeHtml(x)}" target="_blank" rel="noopener">${escapeHtml(x)}</a></li>`).join("");

      outEl.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div><b>Risk:</b> ${escapeHtml(data.risk)} — <b>Score:</b> ${escapeHtml(String(data.score))}</div>
          <div><b>From:</b> ${escapeHtml(data.from || "")}</div>
        </div>
        <div class="kv" style="margin-top:10px">Why:</div>
        <ul>${reasons || "<li>(no findings)</li>"}</ul>
        ${links ? `<div class="kv" style="margin-top:10px">Links noticed:</div><ul>${links}</ul>` : ""}
      `;
      show(outEl);
      setStatus("Done.");
    } catch (e) {
      setStatus("Failed to score email.");
    } finally {
      statusEl.classList.remove("loading");
    }
  });
})();


// ===============================
// Per-code Email Scan (privacy-safe)
// ===============================
(() => {
  const genBtn   = document.getElementById("gen-forward");
  const addrEl   = document.getElementById("forward-address");
  const statusEl = document.getElementById("scan-status");
  const cardEl   = document.getElementById("scan-card");

  if (!genBtn || !addrEl || !statusEl || !cardEl) return; // panel not present

  const GUARD_IMAP_USER = "guard25ai@gmail.com"; // change if your guard inbox user changes
  let scanCode = null;
  let pollId   = null;

  function makeCode() {
    // 8–10 char base36 code; plenty for short-lived lookups
    return Math.random().toString(36).slice(2, 10);
  }

  function showAddr() {
    const [local, domain] = GUARD_IMAP_USER.split("@");
    addrEl.textContent = `${local}+${scanCode}@${domain}`;
    addrEl.classList.add("copy");
    addrEl.title = "Click to copy";
  }

  async function fetchScan() {
    try {
      const r = await fetch(`/api/scan/${scanCode}`);
      if (r.status === 404) {
        statusEl.textContent = "Waiting for your forwarded email…";
        return;
      }
      if (!r.ok) {
        statusEl.textContent = "Error fetching result.";
        return;
      }
      const data = await r.json();
      statusEl.textContent = "Scan ready.";
      renderScanCard(data);
      clearInterval(pollId);
      pollId = null;
    } catch {
      statusEl.textContent = "Network error.";
    }
  }

  // ---- Deep scan of links (tidy cards UI) ----
  async function deepScanLinks(urls, resEl, stEl) {
    if (!Array.isArray(urls) || !resEl) return;
    const unique = Array.from(new Set(urls.filter(u => /^https?:/i.test(u))));
    const MAX = Math.min(unique.length, 8);
    stEl.textContent = MAX ? `Analyzing ${MAX} link(s)…` : "No links to analyze.";
    resEl.innerHTML = "";

    for (const u of unique.slice(0, MAX)) {
      // skeleton card
      const card = document.createElement("div");
      card.className = "link-card";
      card.innerHTML = `
        <div class="row" style="justify-content:space-between;align-items:flex-start;">
          <div class="url">${escapeHtml(u)}</div>
          <span class="badge">Checking…</span>
        </div>
        <div class="kv">Fetching…</div>
        <div class="summary"></div>
      `;
      resEl.appendChild(card);

      try {
        const res = await fetch("/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ artifact_type: "url", value: u })
        });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || res.statusText);

        const lbl   = data.label || "Needs Review";
        const c     = data.content || {};
        const final = c.final_url || u;
        const about = c.about || c.title || "General web page";
        const summary = c.summary || "No preview available.";

        const b = card.querySelector(".badge");
        b.className = `badge ${lbl === "High Risk" ? "bad" : lbl === "Likely Safe" ? "ok" : "warn"}`;
        b.textContent = lbl;

        card.querySelector(".url").innerHTML = `<a href="${escapeHtml(final)}" target="_blank" rel="noopener">${escapeHtml(final)}</a>`;
        card.querySelector(".kv").textContent = about;
        card.querySelector(".summary").textContent = summary;
      } catch {
        const b = card.querySelector(".badge");
        b.className = "badge warn";
        b.textContent = "Error";
        card.querySelector(".summary").textContent = "Failed to analyze this link.";
      }
    }
    if (MAX) stEl.textContent = "Done.";
  }

  function renderScanCard(payload) {
    const lvl   = payload?.scored?.risk ?? "Unknown";
    const score = payload?.scored?.score ?? "";
    const why   = Array.isArray(payload?.scored?.reasons) ? payload.scored.reasons : [];
    const links = Array.isArray(payload?.scored?.links) ? payload.scored.links : [];

    // PDFs: may exist at top-level (payload.pdfs) or nested (payload.scored.pdfs)
    const pdfs  = Array.isArray(payload?.pdfs)
      ? payload.pdfs
      : (Array.isArray(payload?.scored?.pdfs) ? payload.scored.pdfs : []);

    const safeLinks = links.filter(u => /^https?:/i.test(u));

    // PDFs block
    const pdfsHtml = pdfs.length ? `
      <div class="kv" style="margin-top:.5rem;"><strong>PDFs</strong> (${pdfs.length})</div>
      <div>
        ${pdfs.map(p => `
          <div class="card nested" style="padding:12px; margin-top:8px;">
            <div class="row" style="justify-content:space-between;">
              <div style="font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${escapeHtml(p.name || "attachment.pdf")}
              </div>
              ${typeof p.pages === "number" ? `<span class="hint">${p.pages} page${p.pages===1?"":"s"}</span>` : ""}
            </div>
            ${p.snippet ? `<div class="hint" style="margin-top:6px">${escapeHtml(p.snippet)}</div>` : ""}
          </div>
        `).join("")}
      </div>
    ` : "";

    // Scrollable link list with “Analyze links”
    const listHtml = safeLinks.length ? `
      <div class="scan-links" style="margin-top:.5rem;">
        <div class="row" style="margin:.25rem 0 .5rem">
          <div class="kv"><strong>Links</strong> (${safeLinks.length})</div>
          <button id="scan-links" class="btn"><span>🧪</span> Analyze links</button>
        </div>
        <ul class="link-list">
          ${safeLinks.map(u => `
            <li class="link-item">
              <a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(u)}</a>
            </li>`).join("")}
        </ul>
        <div id="link-scan-results" class="link-results"></div>
        <div id="scan-links-status" class="status"></div>
      </div>
    ` : `<p class="status">No links found.</p>`;

    cardEl.innerHTML = `
      <div class="card">
        <div class="row" style="justify-content:space-between; align-items:flex-start;">
          <h4 style="margin:0">${escapeHtml(payload.subject || "Scanned email")}</h4>
          ${badge(lvl)} ${score !== "" ? `<span class="hint" style="margin-left:6px">${escapeHtml(String(score))}</span>` : ""}
        </div>
        <p style="margin:.5rem 0 0;"><strong>From:</strong> ${escapeHtml(payload.from || "")}</p>
        ${why.length ? `<ul style="margin:.5rem 0 0;">${why.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>` : "<p style='margin:.5rem 0 0;'>No suspicious signals found.</p>"}
        ${pdfsHtml}
        ${listHtml}
      </div>
    `;

    // Wire up the "Analyze links" button
    const scanBtn = document.getElementById("scan-links");
    if (scanBtn) {
      const resEl = document.getElementById("link-scan-results");
      const stEl  = document.getElementById("scan-links-status");
      scanBtn.addEventListener("click", () => deepScanLinks(safeLinks, resEl, stEl));
    }
  }

  genBtn.addEventListener("click", () => {
    scanCode = makeCode();
    showAddr();
    statusEl.textContent = "Forward your suspicious email to the address above, then keep this tab open.";
    cardEl.innerHTML = "";
    if (pollId) clearInterval(pollId);
    pollId = setInterval(fetchScan, 4000);
  });

  // click-to-copy for convenience
  addrEl.addEventListener("click", async () => {
    const txt = addrEl.textContent.trim();
    if (!txt || txt === "—") return;
    try {
      await navigator.clipboard.writeText(txt);
      addrEl.style.opacity = "0.6";
      setTimeout(() => (addrEl.style.opacity = ""), 400);
    } catch {}
  });
})();
