# app/server_scan_router.py
import re, json, pathlib, time
from fastapi import APIRouter, HTTPException

router = APIRouter()
SCAN_DIR = pathlib.Path("data/scan_results")
SCAN_DIR.mkdir(parents=True, exist_ok=True)

CODE_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
TTL_SECONDS = 24 * 3600  # keep in sync with GUARD_SCAN_TTL_HOURS

@router.get("/api/scan/{code}")
def get_scan(code: str):
    if not CODE_RE.match(code):
        raise HTTPException(status_code=400, detail="invalid code")

    p = SCAN_DIR / f"{code}.json"
    if not p.exists():
        # poller hasn’t produced it yet
        raise HTTPException(status_code=404, detail="pending")

    # optional expiry
    try:
        if time.time() - p.stat().st_mtime > TTL_SECONDS:
            p.unlink(missing_ok=True)
            raise HTTPException(status_code=404, detail="expired")
    except Exception:
        pass

    try:
        return json.loads(p.read_text())
    except Exception:
        raise HTTPException(status_code=500, detail="corrupt result")
