# app/analyzer.py
from __future__ import annotations
import re, pathlib, urllib.parse as _up, ipaddress, random
from typing import Dict, List, Tuple, Optional

from joblib import load
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import httpx
from bs4 import BeautifulSoup
import trafilatura

# Optional (better domain labelling for redirect hops)
try:
    import tldextract  # noqa: F401
except Exception:  # keep running if it's not installed
    tldextract = None  # type: ignore

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


# Use a realistic UA; some big sites block unknown agents (e.g., 999/403/429)
_UA_POOL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
]
_ANTIBOT_STATUS = {403, 429, 999}

# --- Redirect-chain heuristics ---
_SUS_TLDS = (".zip", ".mov", ".top", ".click", ".gq", ".tk", ".ml", ".cf", ".xyz")

def _registered_domain(host: str) -> str:
    if not host:
        return ""
    if tldextract:
        ex = tldextract.extract(host)  # type: ignore[attr-defined]
        return f"{ex.domain}.{ex.suffix}" if ex.suffix else host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _fetch_page(u: str, max_bytes: int = 2_000_000, timeout_s: float = 8.0) -> tuple[str | None, str, str | None, Dict]:
    """
    Return (html_text, final_url, err, info_dict). Limits size/content-type; follows redirects.
    info_dict includes: status, content_type, bytes, blocked(bool), redirect_chain(list), redirect_score(int)
    """
    headers = {
        "User-Agent": random.choice(_UA_POOL),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": "https://www.google.com/",
    }
    info: Dict = {
        "status": None,
        "content_type": None,
        "bytes": None,
        "blocked": False,
        "redirect_chain": [],
        "redirect_score": 0,
        "redirect_reasons": [],
    }
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout_s, headers=headers, http2=True) as client:
            r = client.get(u)
            final_url = str(r.url)

            # Build redirect chain (history + final response)
            hops = list(r.history) + [r]
            chain: List[Dict] = []
            score = 0
            for hop in hops:
                url_s = str(hop.url)
                p = _up.urlsplit(url_s)
                host = (p.hostname or "").lower()
                dom = _registered_domain(host)
                ct = hop.headers.get("content-type", "")
                flags: List[str] = []
                if p.scheme != "https":
                    flags.append("No HTTPS")
                    score += 5
                if _host_is_ip(host):
                    flags.append("IP host")
                    score += 10
                if any(dom.endswith(t) for t in _SUS_TLDS):
                    flags.append("Suspicious TLD")
                    score += 10
                chain.append({
                    "url": url_s,
                    "status": hop.status_code,
                    "domain": dom or host,
                    "https": (p.scheme == "https"),
                    "content_type": (ct.split(";")[0].strip() if ct else ""),
                    "flags": flags,
                })

            info["redirect_chain"] = chain
            info["redirect_score"] = score
            if score >= 20:
                info["redirect_reasons"].append(
                    "Redirect chain points to a risky destination (non-HTTPS / IP host / suspicious TLD)."
                )

            # Fill normal fetch info
            info["status"] = r.status_code
            info["content_type"] = r.headers.get("content-type", "")
            cl = r.headers.get("content-length")
            if cl and cl.isdigit():
                info["bytes"] = int(cl)

            # Anti-bot detection
            if r.status_code in _ANTIBOT_STATUS:
                info["blocked"] = True
                return None, final_url, f"Fetch blocked by site (HTTP {r.status_code})", info

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


def _infer_about_from_url(url: str) -> str:
    """
    Fallback 'about' using only domain & path (works when fetch is blocked by anti-bot).
    """
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
        "redirect_chain": [], # NEW: list of hops with flags
    }
    ok, why_not = _is_public_web_url(url_norm)
    redirect_score = 0
    redirect_reasons: List[str] = []
    if ok:
        html, final_url, err, info = _fetch_page(url_norm)
        content["final_url"] = final_url
        content["http_status"] = info.get("status")
        content["content_type"] = info.get("content_type")
        content["bytes_fetched"] = info.get("bytes")
        content["redirect_chain"] = info.get("redirect_chain", [])
        redirect_score = int(info.get("redirect_score", 0))
        redirect_reasons = list(info.get("redirect_reasons", []) or [])

        # Always provide at least an inferred "about"
        inferred_about = _infer_about_from_url(final_url or url_norm)
        content["about"] = inferred_about

        if err:
            # Anti-bot or other failure -> still give a helpful summary
            if info.get("blocked"):
                content["note"] = f"Fetch blocked by site (anti-bot)."
            else:
                content["note"] = f"Fetch skipped: {err}"
            final_host = _up.urlsplit(final_url or url_norm).hostname or host
            content["summary"] = (
                f"This appears to be a {inferred_about.lower()} at {final_host}. "
                f"The site did not allow automated fetching, so contents can’t be previewed here."
            )
        elif html:
            txt, soup = _extract_readable_text(html, final_url)
            metas = _get_meta(soup)
            title = metas.get("title")
            site_label = title or (host or final_url)

            inside = _extract_contents(html)
            about = _classify_purpose(final_url, title, txt, metas, soup) or inferred_about
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
        content["about"] = _infer_about_from_url(url_norm)
        content["summary"] = f"This appears to be a {content['about'].lower()} at {host}."

    # Surface redirect chain reasons (if any)
    if redirect_reasons:
        reasons.extend(redirect_reasons)

    # Final actions (same as before)
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

    # Combine ML risk with redirect heuristic (soft bump; max 0.25)
    risk_score = min(1.0, round(p_mal + (redirect_score / 100.0), 4))

    return {
        "label": label,  # label still reflects the ML model; UI shows reasons for redirects
        "confidence": confidence_for(label, p_mal),
        "risk_score": round(risk_score, 2),  # 0..1 combined
        "reasons": reasons[:5],
        "features": {
            "url": url_norm,
            "host": host,
            "tld": tld,
        },
        "content": content,          # includes final_url + redirect_chain now
        "recommended_actions": actions,
    }
