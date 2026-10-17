#!/usr/bin/env python3
"""recon.py — BadRecon-style passive recon pipeline (stdlib only, no keys required).

Usage:
  python recon.py run --target example.com [--scope scope.txt] [--resolve] [--out DIR]
  python recon.py run --target example.com --engines crtsh,wayback,urlscan
  VT_API_KEY env var enables the VirusTotal provider (optional).

Artifacts (BadRecon-compatible): subdomains.csv, urls.csv, ips.csv,
providers.json, recon_notes.md, FINDINGS.md, raw/<engine>.json
"""
import argparse, csv, datetime, json, os, re, socket, sys, time
import urllib.request, urllib.parse, urllib.error

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

# keys: auto-load keys.env next to the skill, env vars override/extend
KEYS = {}
_kf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "keys.env")
if os.path.exists(_kf):
    for line in open(_kf, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); KEYS[k.strip()] = v.strip()
VT_KEYS = [k for k in ([x.strip() for x in KEYS.get("VT_API_KEYS", "").split(",")] + ([os.environ["VT_API_KEY"]] if os.environ.get("VT_API_KEY") else [])) if k]
SHODAN_KEY = KEYS.get("SHODAN_API_KEY") or os.environ.get("SHODAN_API_KEY")

def fetch_retry(url, timeout=90, tries=3, backoff=12):
    """Fetch with retry for rate-limit responses (Wayback 503/429)."""
    st, body = 0, b""
    for _ in range(tries):
        st, body = fetch(url, timeout)
        if st in (503, 429): time.sleep(backoff); continue
        break
    return st, body
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Private Key Block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\."),
    ("Stripe Key", r"(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}"),
    ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{30,}"),
]
INTERESTING_URL = re.compile(r"(?i)(/admin|/backup|\.bak($|\?)|\.env($|\?)|\.sql($|\?)|\.git/|/config|/debug|/internal|/private|token|secret|/api/|/upload)")

def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try: body = e.read()
        except Exception: body = b""
        return e.code, body
    except Exception as e:
        return 0, str(e).encode()

# ---------------- providers ----------------

def p_crtsh(dom):
    st, body = fetch("https://crt.sh/?q=" + urllib.parse.quote("%." + dom) + "&output=json", timeout=60)
    if st != 200: return _err("crtsh", st, body)
    names = set()
    for row in json.loads(body.decode("utf-8", "replace")):
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lstrip("*.").lower()
            if n.endswith(dom) and n: names.add(n)
    return {"subs": names}

def p_shodan_ctl(dom):
    st, body = fetch(f"https://ctl.shodan.io/api/v1/domain/{dom}/hostnames")
    if st != 200: return _err("shodan_ctl", st, body)
    return {"subs": {h.lower() for h in json.loads(body.decode("utf-8", "replace")) if isinstance(h, str)}}

def p_hackertarget(dom):
    st, body = fetch("https://api.hackertarget.com/hostsearch/?q=" + dom)
    if st != 200 or b"API count exceeded" in body or b"error check" in body.lower():
        return _err("hackertarget", st, body)
    subs, ips = set(), {}
    for line in body.decode("utf-8", "replace").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 2 and parts[1]:
            subs.add(parts[0].lower()); ips[parts[0].lower()] = parts[1]
    return {"subs": subs, "ips": ips}

def p_certspotter(dom):
    st, body = fetch(f"https://api.certspotter.com/v1/issuances?domain={dom}&include_subdomains=true&expand=dns_names")
    if st == 403 or st == 401:  # unauthenticated quota
        return _status("certspotter", "rate_limited", st)
    if st != 200: return _err("certspotter", st, body)
    names = set()
    for iss in json.loads(body.decode("utf-8", "replace")):
        for n in iss.get("dns_names", []):
            n = n.lstrip("*.").lower()
            if n.endswith(dom): names.add(n)
    return {"subs": names}

def p_urlscan(dom):
    st, body = fetch(f"https://urlscan.io/api/v1/search/?q=domain:{dom}&size=1000")
    if st != 200: return _err("urlscan", st, body)
    subs, urls, ips = set(), [], {}
    for r in json.loads(body.decode("utf-8", "replace")).get("results", []):
        page = r.get("page", {})
        d = str(page.get("domain", "")).lower()
        if d.endswith(dom): subs.add(d)
        u = r.get("url") or page.get("url")
        if u: urls.append({"url": u, "ts": page.get("url", "") and r.get("@timestamp", "")})
        if page.get("ip"): ips[d] = page["ip"]
    return {"subs": subs, "urls": [x["url"] for x in urls], "ips": ips}

WB_JUICY = r".*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$"

def p_wayback(dom):
    # all URLs (any subdomain, any path): *.domain/* — NOT ".domain/" which is root-only
    q = urllib.parse.urlencode({"url": f"*.{dom}/*", "collapse": "urlkey", "output": "text", "fl": "original", "limit": "50000"})
    st, body = fetch_retry(f"https://web.archive.org/cdx/search/cdx?{q}")
    if st != 200: return _err("wayback", st, body)
    urls = [l.strip() for l in body.decode("utf-8", "replace").splitlines() if l.strip().startswith("http")]
    # filtered URLs: juicy file extensions (configs, backups, archives, secrets, keys)
    qf = urllib.parse.urlencode({"url": f"*.{dom}/*", "collapse": "urlkey", "output": "text", "fl": "original", "filter": f"original:{WB_JUICY}", "limit": "20000"})
    st2, body2 = fetch_retry(f"https://web.archive.org/cdx/search/cdx?{qf}")
    filt = [l.strip() for l in body2.decode("utf-8", "replace").splitlines() if l.strip().startswith("http")] if st2 == 200 else []
    return {"urls": urls, "filtered_urls": filt, "filter_http": st2}

def p_shodan(dom):
    if not SHODAN_KEY: return _status("shodan", "skipped_no_key", None)
    st, body = fetch(f"https://api.shodan.io/dns/domain/{dom}?key={SHODAN_KEY}")
    if st in (401, 403): return _status("shodan", "auth_failed", st)
    if st != 200: return _err("shodan", st, body)
    d = json.loads(body.decode("utf-8", "replace"))
    subs = set()
    for s in d.get("subdomains", []):
        s = s.strip().lstrip("*.").lower()
        if not s: continue
        subs.add(s if s.endswith(dom) else f"{s}.{dom}")
    return {"subs": subs}

def p_vt(dom):
    if not VT_KEYS: return _status("virustotal", "skipped_no_key", None)
    for i, key in enumerate(VT_KEYS):
        st, body = fetch(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={key}&domain={dom}")
        if st in (204, 403, 429):  # quota — rotate to next key
            time.sleep(2); continue
        if st != 200: return _err("virustotal", st, body)
        d = json.loads(body.decode("utf-8", "replace"))
        subs = {s.lower() for s in d.get("subdomains", []) if s}
        ips = {}
        for r in d.get("resolutions", [])[:50]:
            if r.get("last_resolved_address"): ips[r.get("hostname", dom)] = r["last_resolved_address"]
        return {"subs": subs, "ips": ips, "provider_detail": f"key#{i+1}"}
    return _status("virustotal", "all_keys_exhausted", None)

def p_rdap(dom):
    st, body = fetch(f"https://rdap.org/domain/{dom}")
    if st != 200: return _status("rdap", "no_data", st)
    d = json.loads(body.decode("utf-8", "replace"))
    return {"meta": {"handle": d.get("handle"), "registrar": next((e.get("vcardArray") for e in d.get("entities", []) if "registrar" in e.get("roles", [])), None), "nameservers": [ns.get("ldhName") for ns in d.get("nameservers", [])]}}

def _err(name, st, body):
    return _status(name, f"http_{st}", st, detail=body[:200].decode("utf-8", "replace") if isinstance(body, bytes) else str(body)[:200])

def _status(name, state, st, detail=""):
    return {"provider_status": {"engine": name, "state": state, "http": st, "detail": detail}}

PROVIDERS = {"crtsh": p_crtsh, "shodan_ctl": p_shodan_ctl, "hackertarget": p_hackertarget,
             "certspotter": p_certspotter, "urlscan": p_urlscan, "wayback": p_wayback,
             "shodan": p_shodan, "virustotal": p_vt, "rdap": p_rdap}

# ---------------- pipeline ----------------

def resolve_dns(subs, cap=200):
    out = {}
    for s in list(subs)[:cap]:
        try: out[s] = socket.gethostbyname(s)
        except Exception: pass
        time.sleep(0.1)
    return out

def run(args):
    dom = args.target.lower().strip()
    outdir = args.out or os.path.join("recon-out", f"{dom}-{datetime.date.today().isoformat()}")
    os.makedirs(os.path.join(outdir, "raw"), exist_ok=True)
    engines = [e.strip() for e in args.engines.split(",")] if args.engines else list(PROVIDERS)
    sub_src, url_src, ip_src, filt_src = {}, {}, {}, {}
    provider_log, meta = [], {}
    for eng in engines:
        fn = PROVIDERS.get(eng)
        if not fn: provider_log.append({"engine": eng, "state": "unknown_engine"}); continue
        print(f"[*] {eng} ...", flush=True)
        try: res = fn(dom) or {}
        except Exception as e: res = {"provider_status": {"engine": eng, "state": f"exception:{type(e).__name__}", "http": None}}
        time.sleep(1.5)
        if "provider_status" in res:
            provider_log.append(res["provider_status"]); continue
        provider_log.append({"engine": eng, "state": "ok", "http": 200, "subdomains": len(res.get("subs", [])), "urls": len(res.get("urls", []))})
        with open(os.path.join(outdir, "raw", f"{eng}.json"), "w", encoding="utf-8") as f:
            json.dump({k: (sorted(v) if isinstance(v, set) else v) for k, v in res.items()}, f, indent=1)
        for s in res.get("subs", set()): sub_src.setdefault(s, set()).add(eng)
        for u in res.get("urls", []): url_src.setdefault(u, set()).add(eng)
        for u in res.get("filtered_urls", []): filt_src.setdefault(u, set()).add(eng)
        for h, ip in (res.get("ips") or {}).items(): ip_src.setdefault(ip, set()).add(h)
        if res.get("meta"): meta[eng] = res["meta"]

    # DNS resolution (touches only target DNS; polite, capped)
    resolved = resolve_dns(sub_src.keys()) if args.resolve else {}
    for s, ip in resolved.items(): ip_src.setdefault(ip, set()).add(s)

    # scope matching
    scope = [l.strip().lower() for l in (open(args.scope, encoding="utf-8").read().splitlines() if args.scope else [dom]) if l and not l.startswith("#")]
    def in_scope(s):
        for sc in scope:
            if s == sc or s.endswith("." + sc) or (sc.startswith("*.") and s.endswith(sc[2:])): return True
        return False

    # exports
    def wcsv(name, rows, header):
        with open(os.path.join(outdir, name), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(header); [w.writerow(r) for r in rows]
    wcsv("subdomains.csv", [[s, ";".join(sorted(v)), resolved.get(s, ""), "yes" if in_scope(s) else "no"] for s, v in sorted(sub_src.items())], ["subdomain", "sources", "resolved_ip", "in_scope"])
    wcsv("urls.csv", [[u, ";".join(sorted(v)), "yes" if in_scope(urllib.parse.urlsplit(u).netloc.lower()) else "no"] for u, v in sorted(url_src.items())], ["url", "sources", "in_scope"])
    wcsv("ips.csv", [[ip, ";".join(sorted(hs))] for ip, hs in sorted(ip_src.items())], ["ip", "hostnames"])
    wcsv("filtered_urls.csv", [[u, ";".join(sorted(v))] for u, v in sorted(filt_src.items())], ["url", "sources"])

    # interesting URLs + secret detection (redacted ALWAYS)
    flagged = [u for u in url_src if INTERESTING_URL.search(u)]
    secrets = []
    raw_blob = ""
    for f in os.listdir(os.path.join(outdir, "raw")):
        raw_blob += open(os.path.join(outdir, "raw", f), encoding="utf-8", errors="replace").read()
    for label, pat in SECRET_PATTERNS:
        for m in re.findall(pat, raw_blob):
            secrets.append(f"{label}: {str(m)[:6]}***REDACTED")
    with open(os.path.join(outdir, "providers.json"), "w", encoding="utf-8") as f:
        json.dump({"target": dom, "started": datetime.datetime.now().isoformat(), "providers": provider_log, "meta": meta}, f, indent=1)
    with open(os.path.join(outdir, "recon_notes.md"), "w", encoding="utf-8") as f:
        f.write(f"# Recon notes — {dom}\n\n| Engine | State | Detail |\n|---|---|---|\n")
        for p in provider_log: f.write(f"| {p['engine']} | {p['state']} | http={p.get('http')} {p.get('detail','')} |\n")
        f.write(f"\nTotals: {len(sub_src)} subdomains, {len(url_src)} URLs, {len(ip_src)} IPs. Empty provider ≠ absent asset — check states above.\n")
    with open(os.path.join(outdir, "FINDINGS.md"), "w", encoding="utf-8") as f:
        f.write(f"# FINDINGS (leads) — {dom}\n\n## Juicy-extension URLs from Wayback ({len(filt_src)})\n")
        for u in sorted(filt_src)[:200]: f.write(f"- {u}\n")
        f.write(f"\n## Interesting URLs ({len(flagged)})\n")
        for u in flagged[:100]: f.write(f"- {u}\n")
        f.write(f"\n## Secret-shaped values ({len(secrets)}) — REDACTED, never reuse\n")
        for s in sorted(set(secrets)): f.write(f"- {s}\n")
    print(f"[+] done → {outdir} ({len(sub_src)} subs, {len(url_src)} urls, {len(filt_src)} juicy, {len(ip_src)} ips, {len(flagged)} flagged, {len(set(secrets))} secret-shapes)")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--target", required=True)
    ap.add_argument("--scope")
    ap.add_argument("--resolve", action="store_true")
    ap.add_argument("--engines")
    ap.add_argument("--out")
    run(ap.parse_args())
