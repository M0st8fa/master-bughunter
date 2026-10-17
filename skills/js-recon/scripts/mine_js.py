#!/usr/bin/env python3
"""Mine JS bundles for endpoints, GraphQL ops, secrets, internal hosts.
Usage: python mine_js.py <file_or_dir> [more...] [--out findings.json]
Handles local files and http(s) URLs (downloads with curl_cffi if available, else urllib)."""
import re, sys, json, os, pathlib

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
OUT = "js_findings.json"
if "--out" in sys.argv:
    OUT = sys.argv[sys.argv.index("--out") + 1]

SECRETS = [
    (r"AKIA[0-9A-Z]{16}", "aws-access-key"),
    (r"AIza[0-9A-Za-z_\-]{35}", "google-api-key"),
    (r"sk_live_[A-Za-z0-9]+", "stripe-secret"),
    (r"rk_[a-f0-9]{32,}", "generic-secret-key"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "slack-token"),
    (r"ghp_[A-Za-z0-9]{36}", "github-token"),
    (r"-----BEGIN [A-Z ]+PRIVATE KEY-----", "private-key-block"),
    (r"eyJhbGciOi[A-Za-z0-9._\-]{30,}", "jwt"),
]
PATH_Q = r'["`]/((?:api|backend|bff|iam|graphql|internal|admin|debug|actuator)[a-zA-Z0-9/_.${}-]{2,90})["`]'
GRAPHQL = r"(query|mutation)\s+([A-Za-z0-9_]+)"
INTERNAL = r"(?:https?://)?[a-z0-9-]+\.svc\.cluster\.local[^\s`\"',)]*"
INTERNAL2 = r"internal(?:Url|Host)\s*:\s*[`\"']([^`\"']+)[`\"']"
DYN_BASE = r"([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z0-9_$]+)*\s*=\s*[`\"']/(?:backend|api)/[a-zA-Z0-9/_.-]{2,60}[`\"'])"

def fetch(u):
    try:
        from curl_cffi import requests as cr
        return cr.get(u, impersonate="chrome", timeout=30).text
    except Exception:
        import urllib.request
        req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
        return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")

texts = {}
for a in ARGS:
    if re.match(r"https?://", a):
        try:
            texts[os.path.basename(a)] = fetch(a)
        except Exception as e:
            print(f"FETCH FAIL {a}: {e}", file=sys.stderr)
    else:
        p = pathlib.Path(a)
        if p.is_dir():
            for f in p.rglob("*.js"): texts[f.name] = f.read_text(errors="ignore")
            for f in p.rglob("*.mjs"): texts[f.name] = f.read_text(errors="ignore")
        elif p.exists():
            texts[p.name] = p.read_text(errors="ignore")

res = {"paths": {}, "graphql": set(), "secrets": {}, "internal": set(), "dynamic_bases": set()}
for name, src in texts.items():
    norm = lambda s: re.sub(r"\$\{[^}]*\}", "{ID}", s)
    for m in re.findall(PATH_Q, src):
        res["paths"].setdefault("/" + norm(m), []).append(name)
    for kind, op in re.findall(GRAPHQL, src):
        if op not in ("or", "and", "has", "will", "with", "to", "from", "operations", "where"):
            res["graphql"].add(f"{kind} {op}")
    for pat, label in SECRETS:
        for v in re.findall(pat, src):
            res["secrets"].setdefault(label, set()).add(v[:20] + "…")
    res["internal"].update(re.findall(INTERNAL, src))
    res["internal"].update(re.findall(INTERNAL2, src))
    res["dynamic_bases"].update(m.strip() for m in re.findall(DYN_BASE, src))

res["graphql"] = sorted(res["graphql"])
res["secrets"] = {k: sorted(v) for k, v in res["secrets"].items()}
res["internal"] = sorted(res["internal"])
res["dynamic_bases"] = sorted(res["dynamic_bases"])[:60]
res["paths"] = {k: v[:4] for k, v in sorted(res["paths"].items(), key=lambda kv: -len(kv[1]))}

json.dump(res, open(OUT, "w"), indent=1)
print(f"== {len(res['paths'])} API paths | {len(res['graphql'])} graphql ops | {len(res['secrets'])} secret classes | {len(res['internal'])} internal hosts")
for p in list(res["paths"])[:40]: print("  ", p)
for g in res["graphql"][:30]: print("  G", g)
for s, vals in res["secrets"].items(): print("  !SECRET", s, vals[:3])
for i in res["internal"][:15]: print("  H", i)
print(f"full: {OUT}")
