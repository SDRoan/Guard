// Guard — Link & QR Risk Check

// ===== Link checker DOM =====
const form   = document.getElementById("check-form");
const input  = document.getElementById("url-input");
const result = document.getElementById("result");
const btn    = document.getElementById("check-btn");

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
function badge(label) {
  const cls = label === "High Risk" ? "bad" : label === "Suspicious" ? "warn" : "ok";
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

// ===============================
// LINK CHECK
// ===============================
if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const value = (input.value || "").trim();
    if (!value) return;

    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Checking…';
    btn.classList.add('loading');
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
    } catch (err) {
      result.innerHTML = `<div class="kv">Request failed: ${escapeHtml(String(err))}</div>`;
      show(result);
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>🔍</span> Check Link';
      btn.classList.remove('loading');
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

  // NEW: Redirect chain UI
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
// QR: camera + file decode
// ===============================
if (qrStartBtn) qrStartBtn.addEventListener("click", startQrCamera);
if (qrStopBtn) qrStopBtn.addEventListener("click", stopQrCamera);
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
// Email Text Scanner (no OAuth)
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
