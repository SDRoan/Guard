# app/analyzer.py
from __future__ import annotations
import re, pathlib, urllib.parse as _up, ipaddress, random
from typing import Dict, List, Tuple, Optional, Iterable

from joblib import load
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import httpx
import certifi
from bs4 import BeautifulSoup
import trafilatura

# -------------------------------------------------------------------
# Model location + in-process cache
# -------------------------------------------------------------------
MODEL_PATH = pathlib.Path("models/url_model.joblib")
_model: Pipeline | None = None

# Cap absurd URL lengths so vectorizer stays sane
MAX_URL_LEN = 4096


# -------------------------------------------------------------------
# URL normalization (scheme, lowercase host, drop fragment)
# -------------------------------------------------------------------
def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return "http://"
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    try:
        parts = _up.urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:
            creds, _, hostport = netloc.rpartition("@")
            netloc = creds + "@" + hostport.lower()
        else:
            netloc = netloc.lower()
        url = _up.urlunsplit(
            (parts.scheme.lower(), netloc, parts.path or "", parts.query or "", "")
        )
    except Exception:
        pass
    return url[:MAX_URL_LEN]


# -------------------------------------------------------------------
# Model I/O
# -------------------------------------------------------------------
def load_model() -> Pipeline:
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise RuntimeError("Model not found. Train it with: python scripts/train_model.py")
        _model = load(MODEL_PATH)
    return _model


def predict_proba(url: str) -> float:
    mdl = load_model()
    return float(mdl.predict_proba([url])[0, 1])


def top_explanations(url: str, k: int = 5) -> List[str]:
    """
    For LogisticRegression + TF-IDF char n-grams, show the top positive n-grams
    contributing toward the 'malicious' class for this specific URL.
    """
    mdl = load_model()
    if not isinstance(mdl.named_steps.get("clf"), LogisticRegression):
        return []

    vec: TfidfVectorizer = mdl.named_steps["tfidf"]
    clf: LogisticRegression = mdl.named_steps["clf"]

    X = vec.transform([url])
    coef = clf.coef_[0]
    contrib = X.multiply(coef).toarray()[0]
    feats = vec.get_feature_names_out()

    idx = contrib.argsort()[::-1]  # largest to smallest
    out: List[str] = []
    for i in idx:
        if len(out) >= k:
            break
        if contrib[i] <= 0:
            break
        tok = feats[i]
        if tok in url:
            out.append(f"Pattern '{tok}' appears in URL")
    return out


# -------------------------------------------------------------------
# Thresholding to human-friendly labels/confidence
# -------------------------------------------------------------------
def label_for(p: float) -> str:
    if p >= 0.85:
        return "High Risk"
    if p <= 0.15:
        return "Likely Safe"
    return "Needs Review"


def confidence_for(label: str, p: float) -> str:
    if label == "High Risk":
        return "High" if p >= 0.92 else "Medium"
    if label == "Likely Safe":
        return "High" if p <= 0.08 else "Medium"
    return "Low"


# -------------------------------------------------------------------
# Safe content fetching & summarization (HTTP + HTTPS)
# -------------------------------------------------------------------
PRIVATE_HOST_NAMES = {"localhost"}
PRIVATE_SUFFIXES = (".local",)

def _is_public_web_url(u: str) -> tuple[bool, str]:
    try:
        p = _up.urlsplit(u)
        if p.scheme not in {"http", "https"}:
            return False, "Only http/https URLs are supported"
        host = (p.hostname or "").lower()
        if not host:
            return False, "Missing host"
        if host in PRIVATE_HOST_NAMES or any(host.endswith(suf) for suf in PRIVATE_SUFFIXES):
            return False, "Local hostname blocked"
        # If host is an IP, ensure it is public
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False, "Private/reserved IP blocked"
        except ValueError:
            pass
        return True, ""
    except Exception as e:
        return False, f"Parse error: {e}"


# Use a realistic UA; some big sites block unknown agents (e.g., 999/403/429)
_UA_POOL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
]
_ANTIBOT_STATUS = {403, 429, 999}

_CERT_ERR_SNIPPETS = (
    "CERTIFICATE_VERIFY_FAILED",
    "SSLCertVerificationError",
    "certificate verify failed",
    "hostname mismatch",
)

def _looks_like_cert_error(err: Exception) -> bool:
    s = f"{type(err).__name__}: {err}"
    return any(t in s for t in _CERT_ERR_SNIPPETS)

def _build_chain(resp: httpx.Response) -> List[Dict]:
    items = []
    chain = list(resp.history or []) + [resp]
    for r in chain:
        url = str(r.url)
        pr = _up.urlsplit(url)
        flags: List[str] = []
        if pr.scheme != "https":
            flags.append("NO HTTPS")
        items.append({
            "url": url,
            "domain": pr.hostname or "",
            "status": r.status_code,
            "https": (pr.scheme == "https"),
            "flags": flags,
        })
    return items

def _fetch_page(
    u: str,
    max_bytes: int = 2_000_000,
    timeout_s: float = 8.0,
) -> tuple[str | None, str, str | None, Dict]:
    """
    Return (html_text, final_url, err, info_dict).
    info_dict includes: status, content_type, bytes, blocked(bool),
                        tls_ok(bool|None), insecure_fallback(bool), redirect_chain(list)
    """
    headers = {
        "User-Agent": random.choice(_UA_POOL),
        "Accept": "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.4,*/*;q=0.1",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": "https://www.google.com/",
    }
    info = {
        "status": None,
        "content_type": None,
        "bytes": None,
        "blocked": False,
        "tls_ok": None,
        "insecure_fallback": False,
        "redirect_chain": [],
    }

    def _decode_body(r: httpx.Response) -> str:
        body = r.content[:max_bytes]
        if info["bytes"] is None:
            info["bytes"] = len(body)
        try:
            return body.decode(r.encoding or "utf-8", errors="replace")
        except Exception:
            return body.decode("utf-8", errors="replace")

    # --- 1) Secure attempt (normal TLS verification with certifi) ---
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout_s,
            headers=headers,
            http2=True,
            verify=certifi.where(),
        ) as client:
            r = client.get(u)
            final_url = str(r.url)
            info["status"] = r.status_code
            info["content_type"] = r.headers.get("content-type", "")
            cl = r.headers.get("content-length")
            if cl and cl.isdigit():
                info["bytes"] = int(cl)
            info["redirect_chain"] = _build_chain(r)

            if r.status_code in _ANTIBOT_STATUS:
                info["blocked"] = True
                info["tls_ok"] = True
                return None, final_url, f"Fetch blocked by site (HTTP {r.status_code})", info

            if r.status_code >= 400:
                info["tls_ok"] = True
                return None, final_url, f"HTTP {r.status_code}", info

            ctype = (info["content_type"] or "").lower()
            if not (ctype.startswith("text/html") or "xhtml" in ctype or ctype.startswith("text/plain")):
                info["tls_ok"] = True
                return None, final_url, f"Unsupported content-type: {ctype or 'unknown'}", info

            info["tls_ok"] = True
            return _decode_body(r), final_url, None, info

    except httpx.TransportError as e:
        if _looks_like_cert_error(e):
            pass  # handled below
        else:
            return None, u, f"Network/TLS error: {e}", info
    except Exception as e:
        return None, u, str(e), info

    # --- 2) Insecure TLS fallback (best-effort content preview) ---
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout_s,
            headers=headers,
            http2=True,
            verify=False,               # <— fallback: accept bad/unknown certs
        ) as client:
            r = client.get(u)
            final_url = str(r.url)
            info["status"] = r.status_code
            info["content_type"] = r.headers.get("content-type", "")
            cl = r.headers.get("content-length")
            if cl and cl.isdigit():
                info["bytes"] = int(cl)
            info["redirect_chain"] = _build_chain(r)

            if r.status_code in _ANTIBOT_STATUS:
                info["blocked"] = True
                info["tls_ok"] = False
                info["insecure_fallback"] = True
                return None, final_url, f"Fetch blocked by site (HTTP {r.status_code})", info

            if r.status_code >= 400:
                info["tls_ok"] = False
                info["insecure_fallback"] = True
                return None, final_url, f"HTTP {r.status_code}", info

            ctype = (info["content_type"] or "").lower()
            if not (ctype.startswith("text/html") or "xhtml" in ctype or ctype.startswith("text/plain")):
                info["tls_ok"] = False
                info["insecure_fallback"] = True
                return None, final_url, f"Unsupported content-type: {ctype or 'unknown'}", info

            info["tls_ok"] = False
            info["insecure_fallback"] = True
            return _decode_body(r), final_url, None, info

    except Exception as e:
        return None, u, f"Insecure fallback failed: {e}", info


# ---------------------------
# Anti-bot universal probes
# ---------------------------
_PROBE_HEADERS_SUBSET = (
    "server", "via", "x-powered-by",
    "content-type", "content-length", "content-security-policy",
    "x-frame-options", "strict-transport-security", "x-content-type-options",
    "set-cookie", "cf-ray", "cf-cache-status"
)

def _subset_headers(h: httpx.Headers) -> Dict[str, str]:
    out = {}
    for k in _PROBE_HEADERS_SUBSET:
        if k in h:
            out[k] = h.get(k)
    return out

def _origin(url: str) -> str:
    p = _up.urlsplit(url)
    netloc = p.hostname or ""
    if p.port:
        netloc = f"{netloc}:{p.port}"
    return _up.urlunsplit((p.scheme, netloc, "", "", ""))

def _probe_site(base_url: str, timeout_s: float = 7.0, max_bytes: int = 100_000) -> Dict:
    """
    When full fetch is blocked, run tiny, low-risk probes most sites allow.
    """
    out = {
        "head": None,
        "robots": None,
        "favicon": None,
        "root": None,
        "brief": None,
    }
    headers = {
        "User-Agent": random.choice(_UA_POOL),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        "Accept-Language": "en-US,en;q=0.9",
        "Range": f"bytes=0-{max_bytes}",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    origin = _origin(base_url)
    targets = {
        "head": (base_url, "HEAD"),
        "robots": (_up.urljoin(origin + "/", "robots.txt"), "GET"),
        "favicon": (_up.urljoin(origin + "/", "favicon.ico"), "GET"),
        "root": (origin + "/", "GET"),
    }

    def do_once(verify_flag: bool) -> None:
        nonlocal out
        try:
            with httpx.Client(follow_redirects=True, timeout=timeout_s, headers=headers,
                              http2=True, verify=(certifi.where() if verify_flag else False)) as c:
                # HEAD
                try:
                    url, _ = targets["head"]
                    r = c.request("HEAD", url)
                    out["head"] = {
                        "status": r.status_code,
                        "headers": _subset_headers(r.headers),
                    }
                except Exception:
                    pass
                # robots.txt
                try:
                    url, _ = targets["robots"]
                    r = c.get(url)
                    text = ""
                    if r.status_code < 400 and "text" in (r.headers.get("content-type","").lower()):
                        body = r.content[: min(max_bytes, 5000)]
                        try:
                            text = body.decode(r.encoding or "utf-8", errors="replace")
                        except Exception:
                            text = body.decode("utf-8", errors="replace")
                    out["robots"] = {
                        "status": r.status_code,
                        "bytes": int(r.headers.get("content-length") or len(r.content) or 0),
                        "present": r.status_code < 400,
                        "snippet": (re.sub(r"\s+", " ", text).strip()[:200] if text else ""),
                    }
                except Exception:
                    pass
                # favicon
                try:
                    url, _ = targets["favicon"]
                    r = c.get(url)
                    out["favicon"] = {
                        "status": r.status_code,
                        "bytes": int(r.headers.get("content-length") or len(r.content) or 0),
                        "present": r.status_code < 400,
                        "content_type": r.headers.get("content-type", ""),
                    }
                except Exception:
                    pass
                # root (range GET)
                try:
                    url, _ = targets["root"]
                    r = c.get(url)
                    title = meta_desc = ""
                    if r.status_code < 400 and "html" in (r.headers.get("content-type","").lower()):
                        chunk = r.content[:max_bytes]
                        try:
                            html_piece = chunk.decode(r.encoding or "utf-8", errors="replace")
                        except Exception:
                            html_piece = chunk.decode("utf-8", errors="replace")
                        soup = BeautifulSoup(html_piece, "html.parser")
                        title = (soup.title.string.strip() if soup.title and soup.title.string else "")
                        m1 = soup.find("meta", {"name":"description"})
                        m2 = soup.find("meta", {"property":"og:description"})
                        meta_desc = (m1 and m1.get("content")) or (m2 and m2.get("content")) or ""
                        if meta_desc:
                            meta_desc = meta_desc.strip()
                    out["root"] = {
                        "status": r.status_code,
                        "bytes": int(r.headers.get("content-length") or len(r.content) or 0),
                        "title": title,
                        "meta_description": meta_desc,
                    }
                except Exception:
                    pass
        except Exception:
            pass

    # First with normal TLS verify, then (only if nothing useful) with insecure verify
    do_once(True)
    if not any([out["head"], out["robots"], out["favicon"], out["root"]]):
        do_once(False)

    bits: List[str] = []
    if out["head"] and out["head"].get("status") is not None:
        st = out["head"]["status"]
        server = (out["head"]["headers"] or {}).get("server")
        bits.append(f"HEAD {st}" + (f" (server: {server})" if server else ""))
    if out["root"] and (out["root"].get("title") or out["root"].get("meta_description")):
        t = out["root"].get("title") or ""
        d = out["root"].get("meta_description") or ""
        if t:
            bits.append(f"title: “{t[:120]}”")
        if d:
            bits.append(f"desc: {d[:140]}")
    if out["robots"]:
        bits.append("robots.txt present" if out["robots"].get("present") else "robots.txt missing")
    if out["favicon"] and out["favicon"].get("status") is not None:
        bits.append("favicon ok" if out["favicon"]["status"] < 400 else "favicon missing")
    out["brief"] = "; ".join(bits) if bits else "Site responded to probes, but no previewable HTML was available."
    return out


def _get_meta(soup: BeautifulSoup) -> Dict[str, Optional[str]]:
    title = (soup.title.string.strip() if soup.title and soup.title.string else None)

    def pick_desc() -> Optional[str]:
        candidates = []
        for sel in [
            ("property", "og:description"),
            ("name", "twitter:description"),
            ("name", "description"),
        ]:
            tag = soup.find("meta", {sel[0]: sel[1]})
            if tag and tag.get("content"):
                candidates.append(tag.get("content").strip())
        if not candidates:
            p = soup.find("p")
            if p:
                txt = p.get_text(" ", strip=True)
                if txt:
                    candidates.append(txt)
        return candidates[0] if candidates else None

    def pick_keywords() -> Optional[str]:
        tag = soup.find("meta", {"name": "keywords"})
        return tag.get("content").strip() if tag and tag.get("content") else None

    return {"title": title, "description": pick_desc(), "keywords": pick_keywords()}


def _extract_readable_text(html: str, source_url: str | None = None) -> tuple[str, BeautifulSoup]:
    soup = BeautifulSoup(html, "html.parser")
    text = ""
    try:
        extracted = trafilatura.extract(html, url=source_url, include_comments=False, favor_recall=True)
        if extracted:
            text = extracted.strip()
    except Exception:
        pass
    if not text:
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if len(text) > 30_000:
        text = text[:30_000] + " …"
    return text, soup


def _summarize_text(text: str, max_sentences: int = 10, max_chars: int = 1200) -> str:
    if not text:
        return ""
    parts = re.split(r"(?<=[.!?])\s+", text)
    summary = " ".join(parts[:max_sentences]).strip()
    if len(summary) > max_chars:
        summary = summary[:max_chars].rstrip() + " …"
    return summary


# -------------------------------------------------------------------
# WHAT THE LINK IS + WHAT'S INSIDE NOW
# -------------------------------------------------------------------
_PURPOSE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Sign-in page", re.compile(r"\b(sign[ -]?in|log[ -]?in|authenticate|verify)\b", re.I)),
    ("Account recovery / password reset", re.compile(r"\b(reset password|forgot password|account recovery|2fa|otp)\b", re.I)),
    ("Checkout / payment", re.compile(r"\b(checkout|payment|billing|cart)\b", re.I)),
    ("News article", re.compile(r"\b(news|breaking|headline|byline)\b", re.I)),
    ("Product page", re.compile(r"\b(add to cart|buy now|specifications|model)\b", re.I)),
    ("Documentation / guide", re.compile(r"\b(doc(s|umentation)?|guide|tutorial|api reference|readme)\b", re.I)),
    ("Video / media page", re.compile(r"\b(video|watch|stream|player)\b", re.I)),
    ("Support / help", re.compile(r"\b(help|support|contact support|knowledge base|faq)\b", re.I)),
    ("File download", re.compile(r"\b(download|\.zip|\.pdf|release)\b", re.I)),
    ("Test / demo page", re.compile(r"\b(test|demo|example|placeholder|badssl)\b", re.I)),
    ("Homepage / portal", re.compile(r"\b(home|welcome)\b", re.I)),
]

def _classify_purpose(url: str, title: Optional[str], text: str, metas: Dict[str, Optional[str]], soup: BeautifulSoup | None) -> str:
    hay = " ".join([url, title or "", metas.get("description") or "", metas.get("keywords") or "", text[:2000]]).lower()

    if soup:
        meta_bits = []
        for m in soup.find_all("meta"):
            for key in ("name", "property"):
                if m.get(key) and m.get("content"):
                    meta_bits.append(f"{m.get(key)} {m.get('content')}")
        if meta_bits:
            hay += " " + " ".join(meta_bits[:20]).lower()

    for label, pat in _PURPOSE_PATTERNS:
        if pat.search(hay):
            return label

    path = _up.urlsplit(url).path.lower()
    if any(seg in path for seg in ("/login", "/signin", "/auth", "/account")):
        return "Sign-in page"
    if any(seg in path for seg in ("/checkout", "/cart", "/payment")):
        return "Checkout / payment"
    if any(path.endswith(ext) for ext in (".pdf", ".zip", ".dmg", ".exe")):
        return "File download"

    return "General web page"


def _infer_about_from_url(url: str) -> str:
    p = _up.urlsplit(url)
    host = (p.hostname or "").lower()
    path = (p.path or "").lower()

    def has(seg: str) -> bool:
        return seg in path

    if host.endswith("linkedin.com"):
        if has("/in/"):
            return "LinkedIn profile"
        if has("/company/"):
            return "LinkedIn company page"
        if has("/jobs/"):
            return "LinkedIn job posting"
        return "LinkedIn page"

    if host in {"x.com", "twitter.com", "mobile.twitter.com"}:
        if has("/status/"):
            return "X (Twitter) post"
        return "X (Twitter) profile/page"

    if host.endswith("instagram.com"):
        if has("/p/") or has("/reel/"):
            return "Instagram post/reel"
        return "Instagram profile/page"

    if host.endswith("youtube.com") or host == "youtu.be":
        if has("/watch") or host == "youtu.be":
            return "YouTube video"
        return "YouTube page"

    if host.endswith("docs.google.com"):
        if has("/forms/"):
            return "Google Form"
        if has("/document/"):
            return "Google Doc"
        if has("/spreadsheets/"):
            return "Google Sheet"
        if has("/presentation/"):
            return "Google Slides"
        return "Google Docs page"

    if host.endswith("github.com"):
        if len([seg for seg in path.split("/") if seg]) >= 2:
            return "GitHub repository"
        return "GitHub page"

    if any(path.endswith(ext) for ext in (".pdf", ".docx", ".pptx")):
        return "Document link"

    return "Unknown page type"


# ---------- NEW: deeper HTML feature extraction ----------
_SUSPICIOUS_PHRASES: List[re.Pattern] = [
    re.compile(r"\burgent\b", re.I),
    re.compile(r"verify (your )?account", re.I),
    re.compile(r"account (locked|suspended|on hold)", re.I),
    re.compile(r"\blog[- ]?in to continue\b", re.I),
    re.compile(r"confirm (payment|identity|details)", re.I),
    re.compile(r"\bgift card\b", re.I),
    re.compile(r"\bwire transfer\b", re.I),
    re.compile(r"\b(invoice|payment due)\b", re.I),
    re.compile(r"\bseed phrase\b", re.I),
    re.compile(r"\bwallet\b", re.I),
    re.compile(r"\bcrypto(currency)?\b", re.I),
]

_DOWNLOAD_EXTS = (".exe", ".msi", ".zip", ".dmg", ".apk", ".scr", ".bat", ".cmd", ".js", ".vbs", ".lnk", ".7z", ".rar", ".pdf")

def _top_counts(items: Iterable[str], n: int = 4) -> List[str]:
    from collections import Counter
    c = Counter([x for x in items if x])
    return [f"{k} ({v})" for k, v in c.most_common(n)]

def _detect_sensitive_fields(form: BeautifulSoup) -> List[str]:
    sens = set()
    for inp in form.find_all(["input", "textarea", "select"]):
        t = (inp.get("type") or "").lower()
        nm = (inp.get("name") or "").lower()
        ac = (inp.get("autocomplete") or "").lower()
        ph = (inp.get("placeholder") or "").lower()
        blob = " ".join([t, nm, ac, ph])
        if t == "password" or "password" in blob:
            sens.add("password")
        if t in {"email"} or "email" in blob:
            sens.add("email")
        if t in {"tel"} or "phone" in blob or "mobile" in blob:
            sens.add("phone")
        if "card" in blob or "cc" in blob or "cvv" in blob or "cvc" in blob:
            sens.add("credit card")
        if "ssn" in blob or "social security" in blob:
            sens.add("SSN")
        if "otp" in blob or "one-time" in blob:
            sens.add("OTP code")
    return sorted(sens)

def _extract_contents(html: str, base_url: str | None = None) -> Dict:
    out: Dict = {
        "headings": [],
        "forms": {"count": 0, "has_password": False, "actions": [], "sensitive": []},
        "links_sample": [],
        "images": 0,
        "links_total": 0,
        "downloads": [],               # like ['.pdf (3)', '.zip (1)']
        "iframes": 0,
        "scripts_total": 0,
        "script_domains": [],
        "suspicious_phrases": [],      # matched phrases from text
        "word_count": 0,
    }
    soup = BeautifulSoup(html, "html.parser")
    base_host = None
    if base_url:
        try:
            base_host = (_up.urlsplit(base_url).hostname or "").lower()
        except Exception:
            base_host = None

    # Headings
    heads: list[Tuple[int, str]] = []
    for level in ("h1", "h2", "h3"):
        for h in soup.find_all(level):
            txt = " ".join((h.get_text(" ", strip=True) or "").split())
            if txt:
                heads.append((int(level[1]), txt))
    heads = sorted(heads, key=lambda x: (x[0], -len(x[1])))[:6]
    out["headings"] = [t for _, t in heads]

    # Forms + sensitive fields
    forms = soup.find_all("form")
    out["forms"]["count"] = len(forms)
    actions = []
    sensitive_accum: List[str] = []
    has_pw = False
    for f in forms[:6]:
        act = f.get("action") or ""
        actions.append(act[:160] + ("…" if len(act) > 160 else ""))
        sens = _detect_sensitive_fields(f)
        if "password" in sens:
            has_pw = True
        sensitive_accum.extend(sens)
    out["forms"]["has_password"] = has_pw
    out["forms"]["actions"] = actions
    out["forms"]["sensitive"] = sorted(set(sensitive_accum))

    # Links + referenced domains + possible downloads
    from collections import Counter
    domains = []
    downloads_exts: List[str] = []
    anchors = soup.find_all("a", href=True)
    out["links_total"] = len(anchors)
    for a in anchors:
        try:
            href = a["href"]
            absu = _up.urljoin(base_url or "https://example.test/", href)
            p = _up.urlsplit(absu)
            host = (p.hostname or "").lower()
            if host and (not base_host or host != base_host):
                domains.append(host)
            # download ext
            path = (p.path or "").lower()
            for ext in _DOWNLOAD_EXTS:
                if path.endswith(ext):
                    downloads_exts.append(ext)
                    break
        except Exception:
            pass
    out["links_sample"] = _top_counts(domains, 5)
    if downloads_exts:
        out["downloads"] = _top_counts(downloads_exts, 5)

    # Images / iframes
    out["images"] = len(soup.find_all("img"))
    out["iframes"] = len(soup.find_all("iframe"))

    # Scripts
    out["scripts_total"] = len(soup.find_all("script"))
    sdomains: List[str] = []
    for s in soup.find_all("script", src=True):
        try:
            src = s.get("src") or ""
            absu = _up.urljoin(base_url or "https://example.test/", src)
            host = (_up.urlsplit(absu).hostname or "").lower()
            if host and (not base_host or host != base_host):
                sdomains.append(host)
        except Exception:
            pass
    out["script_domains"] = _top_counts(sdomains, 5)

    # Text & suspicious phrases
    try:
        for t in soup(["script", "style", "noscript"]):
            t.decompose()
    except Exception:
        pass
    text = re.sub(r"\s+", " ", (soup.get_text(" ", strip=True) or "")).strip()
    out["word_count"] = len(text.split())
    found = []
    for pat in _SUSPICIOUS_PHRASES:
        m = pat.search(text)
        if m:
            found.append(pat.pattern.strip("\\b").strip("()"))
    out["suspicious_phrases"] = sorted(set(found))[:6]

    return out


def _compose_summary(about: str, metas: Dict[str, Optional[str]], text: str, inside: Dict, site_label: str) -> str:
    parts: List[str] = []
    parts.append(f"This looks like a **{about.lower()}** on {site_label}.")

    # Extended, concrete “inside” details
    fc = (inside.get("forms") or {}).get("count", 0)
    sens = (inside.get("forms") or {}).get("sensitive", []) or []
    pw = (inside.get("forms") or {}).get("has_password", False)
    links_total = inside.get("links_total") or 0
    refs = inside.get("links_sample") or []
    downloads = inside.get("downloads") or []
    iframes = inside.get("iframes") or 0
    scripts_total = inside.get("scripts_total") or 0
    sdoms = inside.get("script_domains") or []
    sus = inside.get("suspicious_phrases") or []
    heads = inside.get("headings") or []
    imgs = inside.get("images", 0)

    # Forms / collection
    if fc:
        line = f"Forms detected: {fc}"
        if sens:
            line += f" — collects: {', '.join(sens[:4])}"
        elif pw:
            line += " — includes a password field"
        parts.append(line + ".")

    # Links / referenced domains / downloads
    if links_total:
        parts.append(f"Links on page: {links_total}.")
    if refs:
        parts.append("Referenced domains: " + ", ".join(refs[:4]) + ".")
    if downloads:
        parts.append("Possible downloads: " + ", ".join(downloads[:4]) + ".")

    # Embeds / scripts
    if iframes:
        parts.append(f"Iframes: {iframes}.")
    if scripts_total:
        if sdoms:
            parts.append(f"Scripts: {scripts_total} (external: {', '.join(sdoms[:3])}).")
        else:
            parts.append(f"Scripts: {scripts_total}.")

    # Suspicious phrases from visible text
    if sus:
        parts.append("Text hints: " + ", ".join(sus[:5]) + ".")

    # Headings / images
    if heads:
        parts.append("Top headings: " + "; ".join(heads[:3]) + ".")
    if imgs:
        parts.append(f"Images: {imgs}.")

    # If we still lack narrative, fall back to text summary / meta
    meta_desc = (metas.get("description") or "").strip()
    narrative = " ".join(parts)
    if len(narrative) < 200:
        if meta_desc and len(meta_desc) >= 40:
            parts.append(meta_desc)
        else:
            s = _summarize_text(text)
            if s:
                parts.append(s)

    return " ".join(p.strip() for p in parts if p).strip()


# -------------------------------------------------------------------
# Public entrypoint
# -------------------------------------------------------------------
def analyze_url(url: str) -> Dict:
    url_norm = normalize_url(url)
    p_mal = predict_proba(url_norm)
    label = label_for(p_mal)
    reasons = top_explanations(url_norm)
    if not reasons:
        reasons = (["AI model found phishing-like patterns"] if label == "High Risk"
                   else ["Probability is in the gray zone; needs human review"] if label == "Needs Review"
                   else ["AI model did not find strong phishing patterns"])

    try:
        parts = _up.urlsplit(url_norm)
        host = parts.hostname or ""
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
    except Exception:
        host, tld = "", ""

    content: Dict = {
        "fetched": False,
        "final_url": None,
        "title": None,
        "http_status": None,
        "content_type": None,
        "bytes_fetched": None,
        "about": None,
        "summary": None,
        "inside": None,
        "note": None,
        "redirect_chain": [],
    }

    ok, why_not = _is_public_web_url(url_norm)
    if ok:
        html, final_url, err, info = _fetch_page(url_norm)
        content["final_url"] = final_url
        content["http_status"] = info.get("status")
        content["content_type"] = info.get("content_type")
        content["bytes_fetched"] = info.get("bytes")
        content["redirect_chain"] = info.get("redirect_chain") or []

        inferred_about = _infer_about_from_url(final_url or url_norm)
        content["about"] = inferred_about

        # If TLS verification failed but we used insecure fallback, surface it
        if info.get("insecure_fallback"):
            reasons.insert(0, "HTTPS certificate verification failed on this site")
            content["note"] = (
                "TLS verification failed; content was shown via an insecure fallback. "
                "Treat this site as untrusted and do not enter credentials."
            )

        if err:
            # Still do probes to give users useful signals
            if info.get("blocked"):
                content["note"] = "Fetch blocked by site (anti-bot)."
            elif not content["note"]:
                content["note"] = f"Fetch skipped: {err}"

            probes = _probe_site(final_url or url_norm)
            content["inside"] = {"probes": probes}
            final_host = _up.urlsplit(final_url or url_norm).hostname or host
            probe_hint = f" Probe results: {probes.get('brief','')}" if probes else ""
            content["summary"] = (
                f"This appears to be a {inferred_about.lower()} at {final_host}. "
                f"The site did not allow automated fetching, so contents can’t be fully previewed here.{probe_hint}"
            )
        elif html:
            txt, soup = _extract_readable_text(html, final_url)
            metas = _get_meta(soup)
            title = metas.get("title")
            site_label = title or (host or final_url)

            inside = _extract_contents(html, final_url)
            about = _classify_purpose(final_url, title, txt, metas, soup) or inferred_about
            summary = _compose_summary(about, metas, txt, inside, site_label)

            content["fetched"] = True
            content["title"] = title
            content["about"] = about
            content["inside"] = inside
            content["summary"] = summary
        else:
            if not content["note"]:
                content["note"] = "Empty response"
            probes = _probe_site(final_url or url_norm)
            content.setdefault("inside", {})["probes"] = probes
            if not content.get("summary"):
                content["summary"] = f"Limited signals only. {probes.get('brief','')}"
    else:
        content["note"] = f"Fetch blocked: {why_not}"
        content["about"] = _infer_about_from_url(url_norm)
        content["summary"] = f"This appears to be a {content['about'].lower()} at {host}."

    actions = ([
        "Do not enter any credentials.",
        "If this claims to be your bank/service, open the official app or type the official domain.",
        "Report the message/sender in your mail or SMS app."
    ] if label == "High Risk" else
    [
        "Open the site via your known bookmarks or official app.",
        "Avoid entering credentials until verified by a trusted source."
    ] if label == "Needs Review" else
    [
        "Still be cautious. Only enter credentials on trusted sites.",
        "When in doubt, navigate to the official website directly."
    ])

    return {
        "label": label,
        "confidence": confidence_for(label, p_mal),
        "risk_score": round(p_mal, 2),
        "reasons": reasons[:5],
        "features": {"url": url_norm, "host": host, "tld": tld},
        "content": content,
        "recommended_actions": actions,
    }


# -------------------------------------------------------------------
# Anti-bot fallback: analyze a user-pasted HTML snapshot
# -------------------------------------------------------------------
def analyze_html_snapshot(url: str, html: str) -> Dict:
    """
    Analyze a user-provided HTML snapshot of a page that blocked automated fetch.
    Response shape matches analyze_url() so the UI can render it the same way.
    """
    url_norm = normalize_url(url)
    p_mal = predict_proba(url_norm)
    label = label_for(p_mal)
    reasons = top_explanations(url_norm)
    if not reasons:
        reasons = (["AI model found phishing-like patterns"] if label == "High Risk"
                   else ["Probability is in the gray zone; needs human review"] if label == "Needs Review"
                   else ["AI model did not find strong phishing patterns"])

    txt, soup = _extract_readable_text(html, url_norm)
    metas = _get_meta(soup)
    title = metas.get("title")
    site_label = title or (_up.urlsplit(url_norm).hostname or url_norm)

    inside = _extract_contents(html, url_norm)
    about = _classify_purpose(url_norm, title, txt, metas, soup) or _infer_about_from_url(url_norm)
    summary = _compose_summary(about, metas, txt, inside, site_label)

    try:
        host = _up.urlsplit(url_norm).hostname or ""
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
    except Exception:
        host, tld = "", ""

    actions = ([
        "Do not enter any credentials.",
        "If this claims to be your bank/service, open the official app or type the official domain.",
        "Report the message/sender in your mail or SMS app."
    ] if label == "High Risk" else
    [
        "Open the site via your known bookmarks or official app.",
        "Avoid entering credentials until verified by a trusted source."
    ] if label == "Needs Review" else
    [
        "Still be cautious. Only enter credentials on trusted sites.",
        "When in doubt, navigate to the official website directly."
    ])

    content = {
        "fetched": True,
        "final_url": url_norm,
        "title": title,
        "http_status": None,
        "content_type": "text/html (snapshot)",
        "bytes_fetched": len(html.encode("utf-8")),
        "about": about,
        "summary": summary,
        "inside": inside,
        "note": "Preview generated from user-pasted HTML (anti-bot fallback).",
        "redirect_chain": [],
    }

    return {
        "label": label,
        "confidence": confidence_for(label, p_mal),
        "risk_score": round(p_mal, 2),
        "reasons": reasons[:5],
        "features": {"url": url_norm, "host": host, "tld": tld},
        "content": content,
        "recommended_actions": actions,
    }


# ---- Rendered-HTML analyzer (for browser/extension snapshots) ----
def analyze_rendered_html(url: str, html: str) -> Dict:
    """
    Accepts fully rendered HTML captured by the browser/extension and
    reuses the snapshot pipeline. We just tweak the content metadata.
    """
    res = analyze_html_snapshot(url, html)
    c = res.get("content", {}) or {}
    c["content_type"] = "text/html (rendered DOM)"
    note = (c.get("note") or "").strip()
    if "rendered" not in note.lower():
        c["note"] = "Preview generated from browser-rendered HTML (extension)."
    res["content"] = c
    return res
