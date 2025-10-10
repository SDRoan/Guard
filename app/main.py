# app/main.py
import os
import re
import html
import pathlib
import sqlite3
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, List, Dict, Tuple
from app.server_scan_router import router as server_scan_router
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# MIME parsing
from email import policy
from email.parser import BytesParser

from app.analyzer import (
    analyze_url,
    analyze_html_snapshot,    # manual "view source" paste
    analyze_rendered_html,    # browser/extension-rendered DOM
)

# ---- include the per-code scan router ----
from app.server_scan_router import router as scan_router

# ---------------- App setup ----------------
app = FastAPI(title="Guard", version="0.5.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        # If you host the UI elsewhere, add its origin here.
    ],
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(scan_router)  # <-- wire in /api/scan/{code}

# ---------------- Data store (SQLite) ----------------
DATA_DIR = pathlib.Path("data")
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "emails.db"

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    with _db() as cx:
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS emails (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              received_ts INTEGER NOT NULL,
              from_addr TEXT,
              subject TEXT,
              snippet TEXT,
              risk TEXT,
              score INTEGER,
              reasons TEXT,         -- JSON-encoded list
              links TEXT,           -- JSON-encoded list
              headers TEXT,         -- JSON-encoded dict
              storage_hint TEXT     -- provider-specific ref if you want later
            )
            """
        )
        cx.commit()

@app.on_event("startup")
def _startup():
    _init_db()

# --------------- Models ----------------
class AnalyzeBody(BaseModel):
    artifact_type: str  # expected "url"
    value: str

class AnalyzeDOMBody(BaseModel):
    url: str
    html: str  # user-pasted HTML snapshot when a site blocks automated fetch

class AnalyzeRenderedBody(BaseModel):
    url: str
    html: str  # rendered HTML captured by a browser/extension after scripts run

class QRBody(BaseModel):
    payload: str

# ---------------- Helpers for email scoring ----------------
URL_RE = re.compile(r'\bhttps?://[^\s)"\'>]+', re.I)
URGENCY = [
    "urgent","act now","verify your account","account will be closed",
    "password expires","invoice overdue","unusual activity","suspend","reset now"
]
BAD_TLDS = (".zip",".mov",".top",".click",".gq",".tk",".ml",".cf",".xyz")
EXEC_ATTACH = (".exe",".scr",".bat",".cmd",".js",".vbs",".apk",".msi",".jar",".ps1")
CYRILLIC_RE = re.compile(r'[\u0400-\u04FF]')
ZEROWIDTH_RE = re.compile(r'[\u200B-\u200D\uFEFF]')
LOOKALIKE = re.compile(r'(paypa[l1]|app1e|appleid|apple\-secure|faceb00k|micr0soft|amaz0n)', re.I)
BRANDS = ["paypal","apple","google","microsoft","amazon","netflix","bank","chase","boa","instagram","facebook"]

def _strip_html(html_text: str) -> str:
    txt = re.sub(r"<style[\s\S]*?</style>", " ", html_text, flags=re.I)
    txt = re.sub(r"<script[\s\S]*?</script>", " ", txt, flags=re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = html.unescape(txt)
    return re.sub(r"\s+", " ", txt).strip()

def _headers_map_from_user(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        canon = "-".join(p.capitalize() for p in k.split("-"))
        out[canon] = v
    return out

def _domain_of(addr: str) -> Optional[str]:
    if not addr:
        return None
    m = re.search(r"@([a-z0-9.-]+)", addr.lower())
    return m.group(1) if m else None

def _guess_brand(display: str) -> Optional[str]:
    d = (display or "").lower().strip().strip('"')
    for b in BRANDS:
        if b in d:
            return b
    return None

def _score_email(headers: dict, body: str, attachments: List[str] | None):
    findings, score = [], 0
    from_hdr = headers.get("From","")
    reply_to = headers.get("Reply-To","")
    auth_res = (headers.get("Authentication-Results","") + " " + headers.get("Received-Spf","")).lower()
    subject = headers.get("Subject","")

    m = re.match(r'^(.*?)\s*<([^>]+)>$', from_hdr)
    if m:
        display = m.group(1).strip().strip('"')
        addr = (m.group(2) or "").lower()
        brand = _guess_brand(display)
        if brand and brand not in addr:
            score += 25
            findings.append(f'Display name “{display}” doesn’t match sender domain ({addr})')

    d_from = _domain_of(from_hdr); d_reply = _domain_of(reply_to)
    if d_from and d_reply and d_from != d_reply:
        score += 20
        findings.append(f"Reply-To domain ({d_reply}) differs from From domain ({d_from})")

    if re.search(r"(spf|dkim|dmarc)=fail", auth_res):
        score += 30; findings.append("Sender authentication failed (SPF/DKIM/DMARC)")
    elif re.search(r"(spf|dkim|dmarc)=(none|neutral|softfail)", auth_res):
        score += 10; findings.append("Sender authentication missing/weak (SPF/DKIM/DMARC)")

    text = (subject + " " + (body or ""))[:40000]
    links, seen = [], set()
    for u in URL_RE.findall(text):
        u = html.unescape(u)
        if u not in seen:
            seen.add(u); links.append(u)
    for u in links:
        try:
            host_l = (urlparse(u).hostname or "").lower()
            if LOOKALIKE.search(host_l):
                score += 25; findings.append(f"Suspicious lookalike domain: {host_l}")
            if host_l.endswith(BAD_TLDS):
                score += 10; findings.append(f"Suspicious TLD: {host_l}")
        except Exception:
            pass

    low = text.lower()
    if any(w in low for w in URGENCY):
        score += 10; findings.append("Urgency/scare language detected")

    if ZEROWIDTH_RE.search(text) or (CYRILLIC_RE.search(text) and re.search(r"[A-Za-z]", text)):
        score += 10; findings.append("Possible homoglyph or zero-width tricking")

    if any((fn or "").lower().endswith(EXEC_ATTACH) for fn in (attachments or [])):
        score += 30; findings.append("Potentially dangerous attachment type")

    risk = "High" if score >= 50 else "Suspicious" if score >= 20 else "Low"
    return risk, score, findings, links[:20]

# --------- MIME parsing (works for Mailgun, SendGrid, Postmark, SES) ----------
def _parse_raw_mime(raw: str | bytes) -> Tuple[Dict[str, str], str, str, List[str]]:
    """Return (headers_dict, text_body, html_body, attachment_names)."""
    if raw is None:
        return {}, "", "", []
    if isinstance(raw, str):
        raw_b = raw.encode("utf-8", errors="ignore")
    else:
        raw_b = raw
    msg = BytesParser(policy=policy.default).parsebytes(raw_b)

    headers = {k: v for (k, v) in msg.items()}
    text, html_part = "", ""
    attachments: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            disp = part.get_content_disposition()  # 'inline' | 'attachment' | None
            ctype = part.get_content_type()
            if disp == "attachment":
                fn = part.get_filename()
                if fn:
                    attachments.append(fn)
                continue
            try:
                payload = part.get_content()
            except Exception:
                payload = ""
            if ctype == "text/plain":
                if isinstance(payload, str):
                    text += payload
            elif ctype == "text/html":
                if isinstance(payload, str):
                    html_part += payload
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            payload = ""
        if ctype == "text/plain" and isinstance(payload, str):
            text = payload
        elif ctype == "text/html" and isinstance(payload, str):
            html_part = payload

    return headers, text.strip(), html_part.strip(), attachments

def _store_email_result(from_addr: str, subject: str, snippet: str,
                        risk: str, score: int, reasons: List[str], links: List[str],
                        headers: Dict[str, str], storage_hint: str | None = None) -> int:
    import json
    with _db() as cx:
        cur = cx.execute(
            """
            INSERT INTO emails (received_ts, from_addr, subject, snippet, risk, score, reasons, links, headers, storage_hint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(time.time()),
                from_addr, subject, snippet, risk, int(score),
                json.dumps(reasons or []),
                json.dumps(links or []),
                json.dumps(headers or {}),
                storage_hint or ""
            )
        )
        cx.commit()
        return int(cur.lastrowid)

def _list_email_results(limit: int = 50) -> List[Dict]:
    import json
    with _db() as cx:
        rows = cx.execute(
            "SELECT id, received_ts, from_addr, subject, snippet, risk, score FROM emails ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "received_at": datetime.fromtimestamp(r["received_ts"], tz=timezone.utc).isoformat(),
            "from": r["from_addr"] or "",
            "subject": r["subject"] or "",
            "snippet": r["snippet"] or "",
            "risk": r["risk"] or "",
            "score": r["score"] or 0,
        })
    return out

def _get_email_result(eid: int) -> Optional[Dict]:
    import json
    with _db() as cx:
        r = cx.execute("SELECT * FROM emails WHERE id=?", (eid,)).fetchone()
    if not r:
        return None
    return {
        "id": r["id"],
        "received_at": datetime.fromtimestamp(r["received_ts"], tz=timezone.utc).isoformat(),
        "from": r["from_addr"] or "",
        "subject": r["subject"] or "",
        "snippet": r["snippet"] or "",
        "risk": r["risk"] or "",
        "score": r["score"] or 0,
        "reasons": __import__("json").loads(r["reasons"] or "[]"),
        "links": __import__("json").loads(r["links"] or "[]"),
        "headers": __import__("json").loads(r["headers"] or "{}"),
    }

# --------------- Basic routes ----------------
@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse("static/index.html")

@app.get("/health")
def health():
    return {"ok": True, "version": "0.5.1"}

# --------------- URL analysis ----------------
@app.post("/analyze")
async def analyze(body: AnalyzeBody):
    if body.artifact_type != "url":
        return JSONResponse(status_code=400, content={"error": "Only artifact_type='url' supported."})
    try:
        return analyze_url(body.value)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

# --------------- Anti-bot fallbacks ----------------
@app.post("/analyze_dom")
async def analyze_dom(body: AnalyzeDOMBody):
    url = (body.url or "").strip()
    html_blob = body.html or ""
    if not url or not html_blob:
        return JSONResponse(status_code=400, content={"error": "Both 'url' and 'html' are required."})
    MAX_BYTES = 2_000_000
    if len(html_blob.encode("utf-8")) > MAX_BYTES:
        html_blob = html_blob.encode("utf-8")[:MAX_BYTES].decode("utf-8", errors="ignore")
    try:
        return analyze_html_snapshot(url, html_blob)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/analyze_rendered")
async def analyze_rendered(body: AnalyzeRenderedBody):
    url = (body.url or "").strip()
    html_blob = body.html or ""
    if not url or not html_blob:
        return JSONResponse(status_code=400, content={"error": "Both 'url' and 'html' are required."})
    MAX_BYTES = 2_000_000
    if len(html_blob.encode("utf-8")) > MAX_BYTES:
        html_blob = html_blob.encode("utf-8")[:MAX_BYTES].decode("utf-8", errors="ignore")
    try:
        return analyze_rendered_html(url, html_blob)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

# -----------------------------
# Raw email scoring (used by IMAP poller)
# -----------------------------
class RawEmail(BaseModel):
    headers: Optional[Dict[str, str]] = None
    from_addr: Optional[str] = None
    subject: Optional[str] = None
    text: Optional[str] = None
    html: Optional[str] = None
    attachments: Optional[List[str]] = None  # filenames only

@app.post("/api/score_raw")
def score_raw(body: RawEmail):
    headers = _headers_map_from_user(body.headers or {})
    if body.from_addr:
        headers.setdefault("From", body.from_addr)
    if body.subject:
        headers.setdefault("Subject", body.subject)
    text = body.text or (_strip_html(body.html) if body.html else "")

    risk, score, reasons, links = _score_email(headers, text, body.attachments or [])
    return {
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "links": links,
        "from": headers.get("From", ""),
        "subject": headers.get("Subject", "")
    }

# ---------------- Inbound email webhook + inbox (DB) ----------------
@app.post("/ingest/inbound")
async def ingest_inbound(request: Request):
    """
    Accepts inbound webhooks from:
      - Mailgun Routes:    form field 'body-mime'
      - SendGrid Inbound:  form field 'email'
      - Postmark Inbound:  JSON with 'RawEmail'
      - SES/Other:         JSON with 'raw' or 'mime'
    Returns the stored record with its new id.
    """
    raw = None
    storage_hint = ""

    ctype = request.headers.get("content-type", "")
    try:
        if "application/json" in ctype:
            js = await request.json()
            raw = js.get("RawEmail") or js.get("email") or js.get("raw") or js.get("mime")
            storage_hint = js.get("MessageID", "") or js.get("message_id", "") or ""
        else:
            form = await request.form()
            # Mailgun/SendGrid
            raw = form.get("body-mime") or form.get("email") or form.get("mime")
            storage_hint = form.get("Message-Id") or form.get("message-id") or ""
    except Exception:
        raw = None

    if not raw:
        return JSONResponse(status_code=400, content={"error": "No raw MIME provided"})

    headers, text_body, html_body, attachments = _parse_raw_mime(raw)
    # Normalize headers for scoring
    score_headers = _headers_map_from_user(headers)
    # Prefer text; if only HTML exists, strip it
    body_for_scoring = text_body or _strip_html(html_body)
    risk, score, reasons, links = _score_email(score_headers, body_for_scoring, attachments)

    # Small human snippet
    snippet = (text_body or _strip_html(html_body) or "")[:280]

    eid = _store_email_result(
        from_addr=score_headers.get("From", ""),
        subject=score_headers.get("Subject", ""),
        snippet=snippet,
        risk=risk,
        score=score,
        reasons=reasons,
        links=links,
        headers=score_headers,
        storage_hint=storage_hint
    )

    return {
        "id": eid,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "links": links,
        "from": score_headers.get("From", ""),
        "subject": score_headers.get("Subject", ""),
        "snippet": snippet
    }

@app.get("/emails")
def list_emails(limit: int = 50):
    """Return the latest scored emails (metadata only) from the DB."""
    return {"items": _list_email_results(limit=limit)}

@app.get("/emails/{email_id}")
def get_email(email_id: int):
    rec = _get_email_result(email_id)
    if not rec:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return rec

# ---------------- QR analysis (kept as-is) ----------------
@app.post("/analyze_qr")
async def analyze_qr(body: QRBody):
    payload = (body.payload or "").strip()
    if not payload:
        return JSONResponse(status_code=400, content={"error": "Empty QR payload"})

    if re.match(r"^https?://", payload, re.I):
        try:
            out = analyze_url(payload)
            out.setdefault("features", {})
            out["features"]["from_qr"] = True
            return out
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

    qr = {"raw": payload, "type": "unknown", "fields": {}}

    def resp(reasons: List[str], actions: List[str]):
        return {
            "qr": qr,
            "label": "Info Only",
            "confidence": "High",
            "risk_score": 0.0,
            "reasons": reasons,
            "recommended_actions": actions,
        }

    if payload.lower().startswith("mailto:"):
        pr = urlparse(payload)
        qr["type"] = "email compose"
        to = unquote(pr.path or "")
        qs = parse_qs(pr.query or "")
        qr["fields"] = {"to": to, "subject": (qs.get("subject", [None])[0] or ""), "body": (qs.get("body", [None])[0] or "")}
        return resp(["Opens an email draft to the specified address."], ["Don’t send sensitive info; verify the address matches the real contact."])

    if payload.lower().startswith("tel:"):
        qr["type"] = "phone call"; qr["fields"] = {"number": payload[4:]}
        return resp(["Initiates a phone call when opened on a phone."], ["If unexpected, search the number first or call via the official app."])

    if re.match(r"^(sms|smsto|mmsto):", payload, re.I):
        pr = urlparse(payload.replace("smsto:", "sms:", 1).replace("mmsto:", "sms:", 1))
        qr["type"] = "SMS draft"
        number = unquote(pr.path or "")
        qs = parse_qs(pr.query or "")
        qr["fields"] = {"number": number, "body": (qs.get("body", [None])[0] or "")}
        return resp(["Creates an SMS draft to the given number."], ["Be wary of instructions to reply with codes or personal data."])

    if payload.upper().startswith("WIFI:"):
        f = {}
        for part in payload[5:].split(";"):
            if not part or ":" not in part: continue
            k, v = part.split(":", 1); f[k.strip().upper()] = v.strip()
        qr["type"] = "Wi-Fi configuration"
        qr["fields"] = {"security": f.get("T",""), "ssid": f.get("S",""), "password": f.get("P",""), "hidden": f.get("H","")}
        return resp(["Adds/joins a Wi-Fi network."], ["Avoid unknown networks; they can intercept traffic."])

    if payload.lower().startswith("geo:"):
        body = payload[4:]; latlon = body.split("?")[0]
        qr["type"] = "location"; qr["fields"] = {"coords": latlon}
        return resp(["Opens a location in maps."], ["Cross-check the place; don’t follow to remote pickup spots alone."])

    def _find_line(blob: str, prefix: str) -> Optional[str]:
        for line in blob.splitlines():
            if line.upper().startsWith(prefix.upper()):
                return line[len(prefix):].strip()
        return None

    if payload.strip().upper().startswith("BEGIN:VCARD"):
        name = _find_line(payload, "FN:") or _find_line(payload, "N:")
        email_addr = _find_line(payload, "EMAIL:"); tel = _find_line(payload, "TEL:"); org = _find_line(payload, "ORG:")
        qr["type"] = "contact (vCard)"; qr["fields"] = {"name": name or "", "email": email_addr or "", "tel": tel or "", "org": org or ""}
        return resp(["Adds a contact to your address book."], ["Don’t add unknown contacts; scammers abuse address books."])

    if payload.upper().startswith("MECARD:"):
        fields = {}
        for chunk in payload[7:].split(";"):
            if ":" not in chunk: continue
            k, v = chunk.split(":", 1); fields[k.upper()] = v
        qr["type"] = "contact (MECARD)"; qr["fields"] = {"name": fields.get("N",""), "email": fields.get("EMAIL",""), "tel": fields.get("TEL","")}
        return resp(["Adds a contact to your address book."], ["Verify the identity before saving the contact."])

    if re.match(r"^(upi|bitcoin|ethereum|litecoin|monero|payto|intent|market|whatsapp|tg):", payload, re.I):
        scheme = payload.split(":", 1)[0].lower() if ":" in payload else "unknown"
        qr["type"] = f"{scheme} intent"; qr["fields"] = {"uri": payload}
        return resp(["Launches an app/payment intent."], ["Never authorize payments from a QR you don’t fully trust."])

    qr["type"] = "text"; qr["fields"] = {"text": payload[:500] + (" …" if len(payload) > 500 else "")}
    return resp(["Plain text payload."], [])

# ---------------- Optional: admin-only inbox for debugging ----------------
ADMIN_TOKEN = os.getenv("GUARD_ADMIN_TOKEN", "")

def _require_admin(req: Request):
    if not ADMIN_TOKEN or req.headers.get("X-Admin-Token") != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="forbidden")

INBOX_JSON = DATA_DIR / "scored_inbox.json"  # legacy feed if you still write it

@app.get("/admin/inbox")
def admin_inbox(request: Request, limit: int = 200):
    _require_admin(request)
    if not INBOX_JSON.exists():
        return {"items": [], "count": 0, "updated": int(time.time())}
    items = __import__("json").loads(INBOX_JSON.read_text())
    items = sorted(items, key=lambda x: x.get("ts", 0), reverse=True)[:max(1, min(limit, 200))]
    return {"items": items, "count": len(items), "updated": int(time.time())}

@app.get("/admin/inbox/{uid}")
def admin_inbox_item(request: Request, uid: int):
    _require_admin(request)
    if not INBOX_JSON.exists():
        return JSONResponse(status_code=404, content={"error": "Not found"})
    items = __import__("json").loads(INBOX_JSON.read_text())
    for it in items:
        if int(it.get("uid", -1)) == uid:
            return it
    return JSONResponse(status_code=404, content={"error": "Not found"})
