# app/main.py
import re
import html
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, List, Dict

from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.analyzer import analyze_url

# ---------------- App setup ----------------
app = FastAPI(title="Guard", version="0.2.0")

# CORS (kept so a local tool/extension can call /api/score_raw)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static assets and landing page
app.mount("/static", StaticFiles(directory="static"), name="static")

# --------------- Models ----------------
class AnalyzeBody(BaseModel):
    artifact_type: str  # expected "url"
    value: str

class QRBody(BaseModel):
    payload: str

# --------------- Basic routes ----------------
@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse("static/index.html")

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/analyze")
async def analyze(body: AnalyzeBody):
    if body.artifact_type != "url":
        return JSONResponse(
            status_code=400,
            content={"error": "Only artifact_type='url' supported."},
        )
    try:
        return analyze_url(body.value)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

# -----------------------------
# QR analysis (URL or semantics)
# -----------------------------
@app.post("/analyze_qr")
async def analyze_qr(body: QRBody):
    payload = (body.payload or "").strip()
    if not payload:
        return JSONResponse(status_code=400, content={"error": "Empty QR payload"})

    # If it's http/https, reuse the link analyzer
    if re.match(r"^https?://", payload, re.I):
        try:
            out = analyze_url(payload)
            out.setdefault("features", {})
            out["features"]["from_qr"] = True
            return out
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

    # Otherwise: classify and extract fields so users know what it will do
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

    # mailto:
    if payload.lower().startswith("mailto:"):
        pr = urlparse(payload)
        qr["type"] = "email compose"
        to = unquote(pr.path or "")
        qs = parse_qs(pr.query or "")
        qr["fields"] = {
            "to": to,
            "subject": (qs.get("subject", [None])[0] or ""),
            "body": (qs.get("body", [None])[0] or ""),
        }
        return resp(
            ["Opens an email draft to the specified address."],
            ["Don’t send sensitive info; verify the address matches the real contact."],
        )

    # tel:
    if payload.lower().startswith("tel:"):
        qr["type"] = "phone call"
        qr["fields"] = {"number": payload[4:]}
        return resp(
            ["Initiates a phone call when opened on a phone."],
            ["If unexpected, search the number first or call via the official app."],
        )

    # sms:/smsto:/mmsto:
    if re.match(r"^(sms|smsto|mmsto):", payload, re.I):
        pr = urlparse(payload.replace("smsto:", "sms:", 1).replace("mmsto:", "sms:", 1))
        qr["type"] = "SMS draft"
        number = unquote(pr.path or "")
        qs = parse_qs(pr.query or "")
        qr["fields"] = {"number": number, "body": (qs.get("body", [None])[0] or "")}
        return resp(
            ["Creates an SMS draft to the given number."],
            ["Be wary of instructions to reply with codes or personal data."],
        )

    # WIFI:
    if payload.upper().startswith("WIFI:"):
        # WIFI:T:WPA;S:MySSID;P:mypassword;H:true;;
        qr["type"] = "Wi-Fi configuration"
        f = {}
        for part in payload[5:].split(";"):
            if not part or ":" not in part:
                continue
            k, v = part.split(":", 1)
            f[k.strip().upper()] = v.strip()
        qr["fields"] = {
            "security": f.get("T", ""),
            "ssid": f.get("S", ""),
            "password": f.get("P", ""),
            "hidden": f.get("H", ""),
        }
        return resp(
            ["Adds/joins a Wi-Fi network."],
            ["Avoid unknown networks; they can intercept traffic."],
        )

    # geo:
    if payload.lower().startswith("geo:"):
        qr["type"] = "location"
        body = payload[4:]
        latlon = body.split("?")[0]
        qr["fields"] = {"coords": latlon}
        return resp(
            ["Opens a location in maps."],
            ["Cross-check the place; don’t follow to remote pickup spots alone."],
        )

    # vCard / MECARD
    def _find_line(blob: str, prefix: str) -> Optional[str]:
        for line in blob.splitlines():
            if line.upper().startswith(prefix.upper()):
                return line[len(prefix):].strip()
        return None

    if payload.strip().upper().startswith("BEGIN:VCARD"):
        qr["type"] = "contact (vCard)"
        name = _find_line(payload, "FN:") or _find_line(payload, "N:")
        email = _find_line(payload, "EMAIL:")
        tel = _find_line(payload, "TEL:")
        org = _find_line(payload, "ORG:")
        qr["fields"] = {
            "name": name or "",
            "email": email or "",
            "tel": tel or "",
            "org": org or "",
        }
        return resp(
            ["Adds a contact to your address book."],
            ["Don’t add unknown contacts; scammers abuse address books."],
        )

    if payload.upper().startswith("MECARD:"):
        qr["type"] = "contact (MECARD)"
        fields = {}
        for chunk in payload[7:].split(";"):
            if ":" not in chunk:
                continue
            k, v = chunk.split(":", 1)
            fields[k.upper()] = v
        qr["fields"] = {
            "name": fields.get("N", ""),
            "email": fields.get("EMAIL", ""),
            "tel": fields.get("TEL", ""),
        }
        return resp(
            ["Adds a contact to your address book."],
            ["Verify the identity before saving the contact."],
        )

    # Payments / app intents (inform, don’t execute)
    if re.match(r"^(upi|bitcoin|ethereum|litecoin|monero|payto|intent|market|whatsapp|tg):", payload, re.I):
        scheme = payload.split(":", 1)[0].lower() if ":" in payload else "unknown"
        qr["type"] = f"{scheme} intent"
        qr["fields"] = {"uri": payload}
        return resp(
            ["Launches an app/payment intent."],
            ["Never authorize payments from a QR you don’t fully trust."],
        )

    # Plain text fallback
    qr["type"] = "text"
    qr["fields"] = {"text": payload[:500] + (" …" if len(payload) > 500 else "")}
    return resp(["Plain text payload."], [])

# ---------------- Email scoring (no OAuth; for local tool/extension) ----------------
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
    # Normalize casing a bit
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
