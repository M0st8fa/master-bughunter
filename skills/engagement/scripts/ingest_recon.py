#!/usr/bin/env python3
"""ingest_recon.py — first-class ingestion of an existing recon directory.

Stdlib only. Run isolated:  python3 -I ingest_recon.py <recon_dir> [--workspace recon]

Turns a supplied recon output directory (recon.sh layout, BadRecon-style, or an ad-hoc
mix) into a deduplicated master URL inventory ready for hunting — WITHOUT re-running
recon. Adapts to the actual files present rather than assuming one layout.

What it does
  A. Inventory the directory recursively; read run config + logs FIRST to record which
     tools ran / failed / were skipped (a failed tool is missing evidence, never coverage).
  B. Extract URLs from the known formats: .txt/.lst, .csv, .json, .jsonl (httpx output),
     keeping method, params, path, status, tech and source provenance.
  C. Deduplicate preserving meaningful variants (method, param-set, endpoint) — never
     collapse a POST onto a GET or a parameterized URL onto its bare path.
  D. Scope-classify every URL against the engagement manifest. In-scope rows go to
     inventory.jsonl with a per-URL test_status + a suggested specialist route; out-of-
     scope rows go to a SEPARATE excluded_inventory.jsonl and are never scheduled.
  E. Resume-safe: merging into an existing inventory preserves prior test_status,
     checks_done, evidence and findings; completed URLs are not reset.

Outputs (under --workspace): inventory.jsonl, excluded_inventory.jsonl, ingest_report.json
Prints a JSON summary. Exit 0 on success.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from urllib.parse import urlsplit, parse_qsl

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import engagement as eng  # noqa: E402  (scope matching + manifest io)

URL_RE = re.compile(r"https?://[^\s'\"<>\\|)\]}]+", re.IGNORECASE)
# files that are logs/config, parsed for tool status rather than as URL lists
LOG_HINTS = ("log", "run_config", "summary", "recon_notes", "providers", "config")
MAX_FILE_BYTES = 64 * 1024 * 1024


# ---- url normalization + dedup key ---------------------------------------------
def normalize(url: str):
    """Return a record dict or None if not a usable http(s) URL."""
    url = url.strip().strip('",;')
    if not URL_RE.match(url):
        return None
    sp = urlsplit(url)
    if not sp.netloc:
        return None
    host = sp.netloc.rsplit("@", 1)[-1].split(":", 1)[0].lower().rstrip(".")
    path = sp.path or "/"
    params = sorted(k for k, _ in parse_qsl(sp.query, keep_blank_values=True))
    return {"host": host, "path": path, "params": params, "query": sp.query,
            "scheme": sp.scheme.lower()}


def dedup_key(rec, method="GET"):
    # Distinct on method + host + path + the SET of param names. Preserves variants:
    # GET vs POST, ?id= vs ?id=&debug=, /a vs /a/ are all kept separate.
    return (method.upper(), rec["scheme"], rec["host"], rec["path"], tuple(rec["params"]))


# ---- intelligent routing by endpoint semantics ---------------------------------
def route(rec, method="GET", tech=""):
    path = rec["path"].lower()
    params = set(rec["params"])
    q = rec["query"].lower()
    routes = []

    def add(s):
        if s not in routes:
            routes.append(s)

    if path.endswith(".js") or "/static/" in path and ".js" in path:
        add("js-recon"); add("js-audit")
    if any(seg in path for seg in ("/graphql", "/gql")) or "graphql" in q:
        add("bb-graphql")
    if any(seg in path for seg in ("/oauth", "/authorize", "/callback", "/sso", "/login",
                                   "/signin", "/token", "/connect/")):
        add("bb-oauth")
    if any(seg in path for seg in ("/signup", "/register", "/account", "/password",
                                   "/reset", "/verify", "/mfa", "/2fa")):
        add("bb-authz"); add("signup-agent")
    if any(seg in path for seg in ("/upload", "/file", "/attachment", "/import", "/avatar")):
        add("bb-upload")
    # object-specific API endpoints -> authorization / IDOR
    if "/api/" in path or re.search(r"/v\d+/", path) or re.search(r"/\d+(?:/|$)", path) \
            or params & {"id", "uid", "user_id", "account_id", "order_id", "object_id"}:
        add("api-security"); add("bb-authz"); add("idor-runner")
    # parameterized search/filter -> injection
    if params & {"q", "query", "search", "s", "filter", "sort", "order", "name", "email"}:
        add("bb-sqli"); add("bb-xss")
    # redirect / fetch params -> ssrf / open redirect
    if params & {"url", "next", "redirect", "redirect_uri", "return", "returnurl",
                 "dest", "destination", "continue", "callback", "u", "link", "target"}:
        add("bb-ssrf")
    # state-changing non-GET -> csrf consideration
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        add("bb-csrf")
    if not routes:
        add("target-intelligence")  # inspect before deciding
    return routes


# ---- tool status from logs/config ----------------------------------------------
def scan_tool_status(recon_dir):
    status = {}
    for dp, _dn, fn in os.walk(recon_dir):
        for name in fn:
            low = name.lower()
            if not any(h in low for h in LOG_HINTS):
                continue
            p = os.path.join(dp, name)
            try:
                if os.path.getsize(p) > MAX_FILE_BYTES:
                    continue
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    txt = f.read()
            except OSError:
                continue
            # providers.json (passive) carries explicit per-engine state
            if low.endswith(".json") and "provider" in low:
                try:
                    data = json.loads(txt)
                    for eng_name, meta in (data.get("engines", data) or {}).items():
                        st = meta.get("state") if isinstance(meta, dict) else None
                        if st:
                            status[eng_name] = _norm_state(st)
                except (ValueError, AttributeError):
                    pass
            # generic log lines: "<tool>: not found / failed / skipped / error"
            for m in re.finditer(r"(?im)^\s*(?:\[[^\]]+\]\s*)?([a-z0-9_\-]{2,20})\s*[:=\-]\s*"
                                 r"(not found|missing|failed|error|skipped|timeout|ok|done|complete)\b", txt):
                status.setdefault(m.group(1).lower(), _norm_state(m.group(2)))
    return status


def _norm_state(s):
    s = s.lower()
    if any(k in s for k in ("not found", "missing", "no_key", "skip")):
        return "skipped" if "skip" in s else ("missing" if "found" in s or "missing" in s else "skipped")
    if any(k in s for k in ("fail", "error", "exception", "timeout", "rate_limited", "403")):
        return "failed"
    if any(k in s for k in ("ok", "done", "complete", "success")):
        return "ok"
    return s


# ---- extraction ----------------------------------------------------------------
def _iter_urls_from_file(path):
    """Yield (url, method, status, tech) tuples from a single file by format."""
    low = path.lower()
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return
    except OSError:
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # JSONL (httpx) — one object per line
            if low.endswith((".jsonl", ".ndjson")):
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    yield from _from_json_obj(line)
                return
            data = f.read()
    except OSError:
        return

    if low.endswith(".json"):
        try:
            obj = json.loads(data)
        except ValueError:
            # concatenated json objects (httpx sometimes) -> line mode
            for line in data.splitlines():
                yield from _from_json_obj(line)
            return
        if isinstance(obj, list):
            for it in obj:
                yield from _from_json_obj(it)
        else:
            yield from _from_json_obj(obj)
        return

    if low.endswith(".csv") or low.endswith(".tsv"):
        delim = "\t" if low.endswith(".tsv") else ","
        try:
            reader = csv.DictReader(data.splitlines(), delimiter=delim)
            if reader.fieldnames and any(h and h.lower() in ("url", "endpoint", "uri", "location")
                                         for h in reader.fieldnames):
                for row in reader:
                    u = (row.get("url") or row.get("URL") or row.get("endpoint")
                         or row.get("uri") or row.get("location") or "")
                    if u:
                        yield (u, (row.get("method") or "GET"),
                               row.get("status_code") or row.get("status") or "",
                               row.get("tech") or row.get("technologies") or "")
                return
        except (csv.Error, ValueError):
            pass
        # fall through: regex any URLs in the CSV text
    # plain text / lst / unknown -> regex every URL-looking token
    for m in URL_RE.finditer(data):
        yield (m.group(0), "GET", "", "")


def _from_json_obj(obj):
    if isinstance(obj, str):
        s = obj.strip()
        if not s:
            return
        try:
            obj = json.loads(s)
        except ValueError:
            for m in URL_RE.finditer(s):
                yield (m.group(0), "GET", "", "")
            return
    if not isinstance(obj, dict):
        return
    url = obj.get("url") or obj.get("input") or obj.get("endpoint") or obj.get("uri")
    if not url:
        return
    method = obj.get("method") or "GET"
    status = obj.get("status_code") or obj.get("status-code") or obj.get("status") or ""
    tech = obj.get("tech") or obj.get("technologies") or obj.get("webserver") or ""
    if isinstance(tech, list):
        tech = ",".join(str(t) for t in tech)
    yield (str(url), str(method), str(status), str(tech))


# ---- inventory build -----------------------------------------------------------
def load_jsonl(path):
    rows = {}
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            rows[r["key"]] = r
    return rows


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows.values():
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def ingest(recon_dir, workspace):
    manifest = eng.load(workspace)
    if manifest is None:
        roots, excl = [], []
        manifest_note = "no engagement manifest found; all URLs marked needs_clarification"
    else:
        roots = manifest["scope"]["in_scope_roots"]
        excl = manifest["scope"]["exclusions"]
        manifest_note = f"scope from engagement {manifest['engagement_id']}"

    inv_path = os.path.join(workspace, "inventory.jsonl")
    exc_path = os.path.join(workspace, "excluded_inventory.jsonl")
    os.makedirs(workspace, exist_ok=True)

    inventory = load_jsonl(inv_path)        # resume: preserve prior status/evidence
    excluded = load_jsonl(exc_path)

    files_seen, raw_urls, added, updated = 0, 0, 0, 0
    counts = {"in_scope": 0, "out_of_scope": 0, "needs_clarification": 0}

    for dp, _dn, fn in os.walk(recon_dir):
        for name in fn:
            path = os.path.join(dp, name)
            low = name.lower()
            if any(h in low for h in LOG_HINTS) and not low.endswith((".txt", ".lst")):
                continue  # logs/config handled by scan_tool_status
            files_seen += 1
            src = os.path.relpath(path, recon_dir)
            for url, method, status, tech in _iter_urls_from_file(path):
                rec = normalize(url)
                if rec is None:
                    continue
                raw_urls += 1
                cls = eng.classify_target(rec["host"], roots, excl) if (roots or excl) \
                    else "needs_clarification"
                mk, scheme, khost, kpath, kparams = dedup_key(rec, method)
                key = "|".join((mk, scheme, khost, kpath, ",".join(kparams)))
                target = inventory if cls != "out_of_scope" else excluded
                if key in target:
                    r = target[key]
                    if src not in r["sources"]:
                        r["sources"].append(src)
                    if status and not r.get("status_code"):
                        r["status_code"] = status
                    if tech and not r.get("tech"):
                        r["tech"] = tech
                    updated += 1
                else:
                    r = {
                        "key": key,
                        "url": url.split("#", 1)[0],
                        "method": method.upper(),
                        "host": rec["host"],
                        "path": rec["path"],
                        "params": rec["params"],
                        "scope": cls,
                        "status_code": status,
                        "tech": tech,
                        "sources": [src],
                        "route": route(rec, method, tech) if cls == "in_scope" else [],
                        "test_status": "pending" if cls == "in_scope" else "excluded",
                        "checks_done": [],
                        "evidence": [],
                        "findings": [],
                    }
                    target[key] = r
                    added += 1
                counts[cls] = counts.get(cls, 0) + 1

    tool_status = scan_tool_status(recon_dir)

    write_jsonl(inv_path, inventory)
    write_jsonl(exc_path, excluded)

    in_scope_total = sum(1 for r in inventory.values() if r["scope"] == "in_scope")
    pending = sum(1 for r in inventory.values()
                  if r["scope"] == "in_scope" and r["test_status"] == "pending")
    report = {
        "recon_dir": recon_dir,
        "workspace": workspace,
        "note": manifest_note,
        "files_scanned": files_seen,
        "raw_urls_seen": raw_urls,
        "distinct_added": added,
        "distinct_updated": updated,
        "inventory": inv_path,
        "excluded_inventory": exc_path,
        "in_scope_distinct": in_scope_total,
        "out_of_scope_distinct": len(excluded),
        "pending": pending,
        "classification_counts": counts,
        "tool_status": tool_status,
        "coverage_warning": ("some recon tools failed/were skipped — their absence is "
                             "missing evidence, not coverage"
                             if any(v in ("failed", "skipped", "missing")
                                    for v in tool_status.values()) else None),
    }
    with open(os.path.join(workspace, "ingest_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # persist recon state into the manifest (imported)
    if manifest is not None:
        manifest["recon"]["status"] = "imported"
        manifest["recon"]["engine"] = "imported"
        manifest["recon"]["recon_dir"] = recon_dir
        manifest["recon"]["inventory"] = inv_path
        manifest["recon"]["excluded_inventory"] = exc_path
        manifest["recon"]["tool_status"] = tool_status
        if manifest["phase"] in ("setup", "scope", "recon", "import"):
            manifest["phase"] = "inventory"
        manifest.setdefault("completed_work", []).append(
            f"{eng._now()} import: ingested {recon_dir} ({in_scope_total} in-scope URLs)")
        eng.save(workspace, manifest)

    return report


def next_batch(workspace, limit=50, route_filter=None):
    """Scheduler: return the next pending in-scope URLs (all of them, batched), so no
    distinct in-scope URL is silently dropped. Resume-safe: completed stay completed."""
    inv = load_jsonl(os.path.join(workspace, "inventory.jsonl"))
    pend = [r for r in inv.values()
            if r["scope"] == "in_scope" and r["test_status"] == "pending"
            and (not route_filter or route_filter in r.get("route", []))]
    pend.sort(key=lambda r: (0 if r.get("route") else 1, r["host"], r["path"]))
    return pend[:limit], len(pend)


def main(argv):
    p = argparse.ArgumentParser(description="Ingest an existing recon directory into a hunt inventory.")
    p.add_argument("recon_dir", help="path to the supplied recon output directory")
    p.add_argument("--workspace", default="recon", help="engagement workspace (default: recon)")
    p.add_argument("--next-batch", type=int, metavar="N",
                   help="instead of ingesting, print the next N pending in-scope URLs")
    p.add_argument("--route", help="with --next-batch: only URLs routed to this specialist")
    a = p.parse_args(argv[1:])

    if a.next_batch is not None:
        batch, total = next_batch(a.workspace, a.next_batch, a.route)
        print(json.dumps({"pending_total": total, "batch": batch}, indent=2))
        return 0

    if not os.path.isdir(a.recon_dir):
        print(f"not a directory: {a.recon_dir}", file=sys.stderr)
        return 1
    report = ingest(a.recon_dir, a.workspace)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
