# app/analyzer.py
from __future__ import annotations
import re, pathlib, urllib.parse as _up, ipaddress
from typing import Dict, List, Tuple, Optional

from joblib import load
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import httpx
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
        url = _up.urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query or "", ""))
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
        # Only surface n-grams that actually appear in the URL string
        if tok in url:
            out.append(f"Pattern '{tok}' appears in URL")
    return out


# -------------------------------------------------------------------
# Thresholding to human-friendly labels/confidence
# -------------------------------------------------------------------
def label_for(p: float) -> str:
    # Tune these as your dataset grows
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
    """
    Allow http/https and block obvious SSRF targets (localhost, private IPs).
    """
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
            # Not an IP literal—fine
            pass
        return True, ""
    except Exception as e:
        return False, f"Parse error: {e}"

def _fetch_page(u: str, max_bytes: int = 2_000_000, timeout_s: float = 8.0) -> tuple[str | None, str, str | None, Dict]:
    """
    Return (html_text, final_url, err, info_dict). Limits size/content-type; follows redirects.
    info_dict includes status, content_type, bytes_fetched.
    """
    headers = {
        "User-Agent": "Guard/1.0 (+no-tracking; content-safety)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    }
    info = {"status": None, "content_type": None, "bytes": None}
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout_s, headers=headers, http2=True) as client:
            r = client.get(u)
            final_url = str(r.url)
            info["status"] = r.status_code
            info["content_type"] = r.headers.get("content-type", "")
            cl = r.headers.get("content-length")
            if cl and cl.isdigit():
                info["bytes"] = int(cl)

            if r.status_code >= 400:
                return None, final_url, f"HTTP {r.status_code}", info
            ctype = (info["content_type"] or "").lower()
            if not (ctype.startswith("text/html") or "xhtml" in ctype):
                return None, final_url, f"Unsupported content-type: {ctype or 'unknown'}", info

            body = r.content[:max_bytes]
            if info["bytes"] is None:
                info["bytes"] = len(body)
            try:
                html = body.decode(r.encoding or "utf-8", errors="replace")
            except Exception:
                html = body.decode("utf-8", errors="replace")
            return html, final_url, None, info
    except httpx.TransportError as e:
        # Certificate/TLS/network issues show up here
        return None, u, f"Network/TLS error: {e}", info
    except Exception as e:
        return None, u, str(e), info

def _get_meta(soup: BeautifulSoup) -> Dict[str, Optional[str]]:
    """
    Extract useful meta signals: title, description (og/twitter/html), and keywords.
    """
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
    """
    Use trafilatura when possible; fallback to BeautifulSoup get_text.
    Returns (plain_text, soup).
    """
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

def _summarize_text(text: str, max_sentences: int = 6, max_chars: int = 800) -> str:
    """Lightweight extractive summary (first few sentences)."""
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
    """
    Combine URL, title, meta description/keywords and early body text into a best-effort label.
    """
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

def _extract_contents(html: str) -> Dict:
    """
    Snapshot of 'what's inside right now':
    - prominent headings
    - forms (and whether any password fields exist)
    - a few prominent outbound links (domains)
    - image count
    """
    out = {
        "headings": [],
        "forms": {"count": 0, "has_password": False, "actions": []},
        "links_sample": [],
        "images": 0,
    }
    soup = BeautifulSoup(html, "html.parser")

    heads: list[Tuple[int, str]] = []
    for level in ("h1", "h2", "h3"):
        for h in soup.find_all(level):
            txt = " ".join((h.get_text(" ", strip=True) or "").split())
            if txt:
                heads.append((int(level[1]), txt))
    heads = sorted(heads, key=lambda x: (x[0], -len(x[1])))[:6]
    out["headings"] = [t for _, t in heads]

    forms = soup.find_all("form")
    out["forms"]["count"] = len(forms)
    actions = []
    has_pw = False
    for f in forms[:4]:
        act = f.get("action") or ""
        actions.append(act[:160] + ("…" if len(act) > 160 else ""))
        for inp in f.find_all(["input", "textarea", "select"]):
            if (inp.get("type") or "").lower() == "password":
                has_pw = True
    out["forms"]["has_password"] = has_pw
    out["forms"]["actions"] = actions

    from collections import Counter
    domains = []
    for a in soup.find_all("a", href=True):
        try:
            href = a["href"]
            absu = _up.urljoin("https://example.test/", href)  # harmless base to parse domain
            p = _up.urlsplit(absu)
            host = (p.hostname or "").lower()
            if host and host != "example.test":
                domains.append(host)
        except Exception:
            pass
    counts = Counter(domains)
    out["links_sample"] = [f"{d} ({n})" for d, n in counts.most_common(5)]

    out["images"] = len(soup.find_all("img"))
    return out

def _compose_summary(about: str, metas: Dict[str, Optional[str]], text: str, inside: Dict, site_label: str) -> str:
    """
    Human-friendly summary that always says what the page is for + what's inside.
    """
    parts: List[str] = []
    parts.append(f"This looks like a **{about.lower()}** on {site_label}.")
    meta_desc = (metas.get("description") or "").strip()
    if meta_desc and len(meta_desc) >= 40:
        parts.append(meta_desc)
    else:
        s = _summarize_text(text)
        if s:
            parts.append(s)

    heads = inside.get("headings") or []
    forms = inside.get("forms") or {}
    links = inside.get("links_sample") or []
    imgs = inside.get("images", 0)

    if heads:
        parts.append("Top headings: " + "; ".join(heads[:3]) + ".")
    if forms:
        fc = forms.get("count", 0)
        pw = forms.get("has_password", False)
        if fc:
            parts.append(f"Forms detected: {fc}{' (includes a password field)' if pw else ''}.")
        elif pw:
            parts.append("A password field is present.")
    if links:
        parts.append("Referenced domains: " + ", ".join(links[:4]) + ".")
    if imgs:
        parts.append(f"Images: {imgs}.")
    if len(" ".join(parts)) < 80 and meta_desc:
        parts.append(meta_desc)

    return " ".join(p.strip() for p in parts if p).strip()


# -------------------------------------------------------------------
# Public entrypoint (keeps the same response shape your UI expects)
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

    # Minimal “features” block for UI/telemetry (no heuristics)
    try:
        parts = _up.urlsplit(url_norm)
        host = parts.hostname or ""
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
    except Exception:
        host, tld = "", ""

    # --- Content analysis (About + Inside) ---
    content: Dict = {
        "fetched": False,
        "final_url": None,
        "title": None,
        "http_status": None,
        "content_type": None,
        "bytes_fetched": None,
        "about": None,        # WHAT THIS LINK IS
        "summary": None,      # rich, human sentence(s)
        "inside": None,       # snapshot dict for UI
        "note": None,
    }
    ok, why_not = _is_public_web_url(url_norm)
    if ok:
        html, final_url, err, info = _fetch_page(url_norm)
        content["final_url"] = final_url
        content["http_status"] = info.get("status")
        content["content_type"] = info.get("content_type")
        content["bytes_fetched"] = info.get("bytes")
        if err:
            content["note"] = f"Fetch skipped: {err}"
        elif html:
            txt, soup = _extract_readable_text(html, final_url)
            metas = _get_meta(soup)
            title = metas.get("title")
            site_label = title or (host or final_url)

            inside = _extract_contents(html)
            about = _classify_purpose(final_url, title, txt, metas, soup)
            summary = _compose_summary(about, metas, txt, inside, site_label)

            content["fetched"] = True
            content["title"] = title
            content["about"] = about
            content["inside"] = inside
            content["summary"] = summary
        else:
            content["note"] = "Empty response"
    else:
        content["note"] = f"Fetch blocked: {why_not}"

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
        "risk_score": round(p_mal, 2),  # 0..1 probability from the model
        "reasons": reasons[:5],
        "features": {
            "url": url_norm,
            "host": host,
            "tld": tld,
        },
        "content": content,          # two-part (about + summary) lives here
        "recommended_actions": actions,
    }
