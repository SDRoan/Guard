#!/usr/bin/env python3
"""
Guard IMAP poller (scoped-by-code)

Purpose:
- Never expose a shared inbox to the frontend.
- Only process emails that carry a per-user scan code and write a single
  result file for that code.

How a code can appear:
  1) Plus-address (preferred):  GUARD_IMAP_USER is e.g. guard25ai@gmail.com
     User forwards to guard25ai+<code>@gmail.com
  2) Subject fallback:          Subject contains [GUARD:<code>]

What it does:
- Logs into Gmail via IMAP (SSL) with an App Password
- Polls INBOX (and Spam, optionally)
- For NEW messages (by UID), if a code is present:
    * Extracts headers/text/html/attachment names
    * POSTs to Guard API /api/score_raw
    * Writes result to data/scan_results/<code>.json
- Maintains per-folder last UID in data/inbox_state.json
- Deletes stale scan files older than TTL

Required env:
  GUARD_IMAP_USER          -> Gmail address (e.g., guard25ai@gmail.com)
  GUARD_IMAP_PASS          -> 16-char Google App Password
  GUARD_API_BASE           -> e.g. http://127.0.0.1:8000

Optional env:
  GUARD_IMAP_POLL          -> seconds between polls (default 15)
  GUARD_IMAP_BATCH         -> max messages per folder per poll (default 50)
  GUARD_IMAP_INCLUDE_SPAM  -> "1" (default) to also scan Spam; "0" to skip
  GUARD_SCAN_TTL_HOURS     -> hours to keep per-code files (default 24)
"""

import os
import re
import ssl
import json
import time
import imaplib
import pathlib
import traceback
from typing import Dict, List, Optional, Tuple

import httpx
import email
from email import policy
from email.header import decode_header, make_header

# ---------------- Paths & config ----------------
DATA_DIR = pathlib.Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

STATE_PATH = DATA_DIR / "inbox_state.json"        # {"INBOX": 123, "[Gmail]/Spam": 456, ...}
SCAN_DIR   = DATA_DIR / "scan_results"
SCAN_DIR.mkdir(parents=True, exist_ok=True)

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

POLL_SECONDS  = int(os.environ.get("GUARD_IMAP_POLL", "15"))
BATCH_LIMIT   = int(os.environ.get("GUARD_IMAP_BATCH", "50"))  # max msgs per cycle per folder
MAX_HTML_BYTES = 200_000
INCLUDE_SPAM  = os.environ.get("GUARD_IMAP_INCLUDE_SPAM", "1") != "0"
SCAN_TTL_HOURS = int(os.environ.get("GUARD_SCAN_TTL_HOURS", "24"))

# ---------------- Env helpers ----------------
def env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v

# ---------------- State I/O ----------------
def load_state() -> Dict[str, int]:
    if STATE_PATH.exists():
        try:
            j = json.loads(STATE_PATH.read_text())
            if isinstance(j, dict):
                return {str(k): int(v) for k, v in j.items() if isinstance(k, str)}
        except Exception:
            pass
    return {}

def save_state(state: Dict[str, int]) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2))

# ---------------- Message helpers ----------------
def _decode_header(val: Optional[str]) -> str:
    if not val:
        return ""
    try:
        return str(make_header(decode_header(val)))
    except Exception:
        return val

def extract_parts(msg: email.message.Message) -> Tuple[str, str, List[str]]:
    """
    Returns (plain_text, html_text, attachment_names[])
    """
    plain, html = "", ""
    atts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            cdisp = (part.get("Content-Disposition") or "").lower()
            ctype = (part.get_content_type() or "").lower()
            fname = part.get_filename()
            if fname:
                atts.append(_decode_header(fname))

            if "attachment" in cdisp:
                continue

            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""

            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")

            if ctype == "text/plain" and not plain:
                plain = text
            elif ctype == "text/html" and not html:
                html = text
    else:
        try:
            payload = msg.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        charset = msg.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except Exception:
            text = payload.decode("utf-8", errors="replace")

        ctype = (msg.get_content_type() or "").lower()
        if ctype == "text/html":
            html = text
        else:
            plain = text

    if len(html.encode("utf-8")) > MAX_HTML_BYTES:
        html = html.encode("utf-8")[:MAX_HTML_BYTES].decode("utf-8", errors="ignore")

    return plain, html, atts

def score_message(api_base: str, payload: Dict) -> Dict:
    url = f"{api_base.rstrip('/')}/api/score_raw"
    with httpx.Client(timeout=20.0) as client:
        r = client.post(url, json=payload)
        r.raise_for_status()
        return r.json()

# ---------------- IMAP helpers ----------------
def fetch_uids_newer_than(imap: imaplib.IMAP4_SSL, last_uid: int) -> List[int]:
    # Gmail UIDs are monotonic within a mailbox
    typ, data = imap.uid("search", None, "ALL")
    if typ != "OK":
        return []
    raw = data[0].decode() if data and data[0] else ""
    uids = [int(x) for x in raw.split() if x.isdigit()]
    uids.sort()
    newer = [u for u in uids if u > last_uid]
    return newer[-BATCH_LIMIT:] if newer else []

def fetch_msg_by_uid(imap: imaplib.IMAP4_SSL, uid: int) -> Optional[email.message.Message]:
    typ, data = imap.uid("fetch", str(uid), "(RFC822)")
    if typ != "OK" or not data or not data[0]:
        return None
    raw = data[0][1]
    return email.message_from_bytes(raw, policy=policy.default)

def _list_mailboxes(imap: imaplib.IMAP4_SSL) -> List[str]:
    """Return decoded mailbox names (e.g., 'INBOX', '[Gmail]/Spam')."""
    typ, boxes = imap.list()
    names: List[str] = []
    if typ == "OK" and boxes:
        for raw in boxes:
            s = raw.decode("utf-8", errors="ignore")
            m = re.search(r' "/" (.+)$', s)  # format: (*flags*) "delim" "name"
            name = (m.group(1) if m else s).strip()
            if name.startswith('"') and name.endswith('"'):
                name = name[1:-1]
            names.append(name)
    return names

def _detect_spam_box(imap: imaplib.IMAP4_SSL) -> Optional[str]:
    """Attempt to find Gmail's Spam mailbox (varies by locale)."""
    for name in _list_mailboxes(imap):
        lower = name.lower()
        if lower == "spam" or lower.endswith("/spam") or lower.endswith("] spam"):
            return name
    return None

def _select_box(imap: imaplib.IMAP4_SSL, box: str) -> bool:
    """Select mailbox, trying quoted name if needed."""
    typ, _ = imap.select(box, readonly=True)
    if typ == "OK":
        return True
    typ, _ = imap.select(f'"{box}"', readonly=True)
    return typ == "OK"

# ---------------- Code extraction ----------------
def _compile_plus_code_regex(imap_user: str) -> re.Pattern:
    """
    Build a regex that matches: localpart+<code>@domain
    Returns a compiled pattern that extracts <code> in group 1.
    """
    try:
        local, domain = imap_user.split("@", 1)
    except ValueError:
        local, domain = imap_user, "gmail.com"
    pat = rf"{re.escape(local)}\+([A-Za-z0-9_-]{{6,64}})@{re.escape(domain)}"
    return re.compile(pat, re.IGNORECASE)

SUBJECT_CODE_RE = re.compile(r"\[GUARD:([A-Za-z0-9_-]{6,64})\]")

def _extract_code_from_headers(msg: email.message.Message, plus_re: re.Pattern) -> Optional[str]:
    # Look in To, Cc, Delivered-To, X-Original-To, etc.
    fields = []
    for k in ("To", "Cc", "Delivered-To", "X-Original-To", "X-Forwarded-To"):
        vals = msg.get_all(k, [])
        if vals:
            fields.extend(vals)
    blob = " ".join(fields)
    m = plus_re.search(blob)
    if m:
        return m.group(1)

    # Fallback: subject tag
    subj = msg.get("Subject") or ""
    m2 = SUBJECT_CODE_RE.search(subj)
    if m2:
        return m2.group(1)

    return None

# ---------------- Cleanup ----------------
def _cleanup_old_scans():
    cutoff = time.time() - SCAN_TTL_HOURS * 3600
    for p in SCAN_DIR.glob("*.json"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)
        except Exception:
            pass

# ---------------- Main loop ----------------
def run_loop():
    api_base = env("GUARD_API_BASE")
    user = env("GUARD_IMAP_USER")
    app_pass = env("GUARD_IMAP_PASS")

    plus_code_re = _compile_plus_code_regex(user)

    print(f"IMAP connecting as {user} …")
    context = ssl.create_default_context()
    with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context) as imap:
        imap.login(user, app_pass)

        folders = ["INBOX"]
        spam_box = _detect_spam_box(imap) if INCLUDE_SPAM else None
        if spam_box and spam_box not in folders:
            folders.append(spam_box)
        print(f"Watching folders: {', '.join(folders)}")
        print("IMAP connected. Polling… (Ctrl+C to stop)")

        state = load_state()  # {folder: last_uid}

        while True:
            try:
                for box in folders:
                    if not _select_box(imap, box):
                        print(f"Could not select folder: {box}")
                        continue

                    last_uid = int(state.get(box, 0))
                    new_uids = fetch_uids_newer_than(imap, last_uid)
                    if not new_uids:
                        continue

                    for uid in new_uids:
                        try:
                            msg = fetch_msg_by_uid(imap, uid)
                            if not msg:
                                state[box] = uid
                                continue

                            # Extract code
                            code = _extract_code_from_headers(msg, plus_code_re)
                            # Regardless of presence of code, advance the cursor to avoid reprocessing
                            state[box] = uid
                            save_state(state)

                            if not code:
                                # No code => ignore silently. We never create a shared feed.
                                continue

                            # Basic headers for scoring
                            h = {
                                "From": msg.get("From") or "",
                                "Subject": msg.get("Subject") or "",
                                "Reply-To": msg.get("Reply-To") or "",
                                "To": ", ".join(msg.get_all("To", [])) if msg.get_all("To", []) else "",
                                "Cc": ", ".join(msg.get_all("Cc", [])) if msg.get_all("Cc", []) else "",
                                "Authentication-Results": msg.get("Authentication-Results") or "",
                                "Received-Spf": msg.get("Received-SPF") or msg.get("Received-Spf") or "",
                            }
                            from_addr = _decode_header(h["From"])
                            subject   = _decode_header(h["Subject"])

                            plain, html, atts = extract_parts(msg)

                            payload = {
                                "headers": h,
                                "from_addr": from_addr,
                                "subject": subject,
                                "text": plain if plain else None,
                                "html": html if html else None,
                                "attachments": atts or [],
                            }

                            scored = {}
                            try:
                                scored = score_message(api_base, payload)
                            except Exception as e:
                                print(f"[{box}] [UID {uid}] scoring failed: {e}")
                                continue

                            doc = {
                                "code": code,
                                "uid": uid,
                                "folder": box,
                                "date": msg.get("Date") or "",
                                "from": scored.get("from") or from_addr,
                                "subject": scored.get("subject") or subject,
                                "scored": {
                                    "risk": scored.get("risk", "Unknown"),
                                    "score": scored.get("score"),
                                    "reasons": scored.get("reasons", []),
                                    "links": scored.get("links", []),
                                },
                                "ts": int(time.time()),
                            }

                            (SCAN_DIR / f"{code}.json").write_text(json.dumps(doc, indent=2))
                            print(f"[{box}] [UID {uid}] -> code={code}  {doc['scored']['risk']} ({doc['scored']['score']}) — {doc['subject']}")

                        except Exception as inner_e:
                            print(f"[{box}] [UID {uid}] error: {inner_e}")
                            traceback.print_exc()

                _cleanup_old_scans()
                time.sleep(POLL_SECONDS)

            except KeyboardInterrupt:
                print("\nStopping.")
                break
            except imaplib.IMAP4.abort:
                print("IMAP aborted; reconnecting in 5s…")
                time.sleep(5)
                try:
                    imap.logout()
                except Exception:
                    pass
                # reconnect
                try:
                    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context)
                    imap.login(user, app_pass)
                    print("Reconnected.")
                except Exception as e:
                    print("Reconnect failed:", e)
                    time.sleep(5)
            except Exception as e:
                print("Error:", e)
                traceback.print_exc()
                time.sleep(5)

if __name__ == "__main__":
    run_loop()
