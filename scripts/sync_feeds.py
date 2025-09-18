import csv, io, pathlib, sys, requests

OUT = pathlib.Path("data/ioc_urls.txt")

# Public feeds (no auth):
URLHAUS_HOSTFILE = "https://urlhaus.abuse.ch/downloads/hostfile/"      # domains (e.g., 0.0.0.0 bad.com)
URLHAUS_CSV_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"  # recent URLs (CSV)

def fetch_hostfile():
    print("[*] Fetching URLhaus hostfile (domains)…")
    r = requests.get(URLHAUS_HOSTFILE, timeout=30)
    r.raise_for_status()
    items = set()
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Lines look like: "0.0.0.0 bad.example"
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].strip().lower()
            if domain and domain != "localhost":
                items.add(domain)
    print(f"    + {len(items)} domains")
    return items

def fetch_csv_recent():
    print("[*] Fetching URLhaus recent URLs (CSV)…")
    r = requests.get(URLHAUS_CSV_RECENT, timeout=30)
    r.raise_for_status()
    data = r.text
    # CSV has comment header lines starting with '#'
    data = "\n".join(l for l in data.splitlines() if not l.startswith("#"))
    f = io.StringIO(data)
    reader = csv.DictReader(f)
    items = set()
    for row in reader:
        url = (row.get("url") or "").strip().lower()
        host = (row.get("host") or "").strip().lower()
        if host: items.add(host)
        if url: items.add(url)
    print(f"    + {len(items)} url/host indicators")
    return items

def write_blocklist(items):
    OUT.parent.mkdir(parents=True, exist_ok=True)
    prev = set()
    if OUT.exists():
        prev.update(
            line.strip().lower()
            for line in OUT.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )
    merged = prev | items
    header = "# IOC blocklist (domains and full URLs)\n# Sources: URLhaus hostfile + csv_recent\n"
    OUT.write_text(header + "\n".join(sorted(merged)), encoding="utf-8")
    print(f"[*] Wrote {len(merged)} total indicators to {OUT}")

def main():
    try:
        items = set()
        items |= fetch_hostfile()
        items |= fetch_csv_recent()
        if not items:
            print("[x] No items fetched; aborting."); sys.exit(1)
        write_blocklist(items)
        print("[✓] Done.")
    except Exception as e:
        print("[x] Sync failed:", e); sys.exit(2)

if __name__ == "__main__":
    main()
