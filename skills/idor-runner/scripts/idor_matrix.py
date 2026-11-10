#!/usr/bin/env python3
"""Cross-account IDOR/BOLA matrix runner for OWN test accounts on an authorized target.
Usage:
  python idor_matrix.py --base https://target --jars acc1_cookies.txt acc2_cookies.txt \
      --ua "exact UA from the cURL blocks" --tests tests.json [--inventory inv.json] [--out idor_results]
Jar files: one line of "k=v; k=v" cookies each.
tests.json: [{"method":"GET","path":"/api/x/{OBJ:acc1.address.id}","body":{...}}, ...]
  {OBJ:<jarname-without-.txt>.<dotted.path>} is replaced with values from --inventory.
Inventory JSON: {"acc1": {"address": {"id": 123}}, ...}  (the Step-2 object table).
  A test whose placeholders cannot be resolved from the inventory is SKIPPED with a
  warning — never fired against a literal {OBJ:...} path. Each jar gets its OWN HTTP
  session (one shared session let account A's Set-Cookie responses bleed into account
  B's requests and skew differentials). Results are saved incrementally after every
  test, so a crash mid-run keeps everything completed so far.
Requires: pip install curl_cffi
"""
import argparse, json, os, re, time, sys

OBJ_RE = re.compile(r"\{OBJ:([^}]+)\.([^}]+)\}")

def load_jar(path):
    c = {}
    for part in open(path, encoding="utf-8").read().strip().split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            c[k.strip()] = v.strip()
    return c

def interp(path, inv):
    """Resolve {OBJ:jar.dotted.path} from the inventory. Returns (path, unresolved list)."""
    unresolved = []
    def rep(m):
        jar, dotted = m.group(1), m.group(2).split(".")
        node = inv.get(jar)
        for k in dotted:
            node = (node or {}).get(k)
        if node is None:
            unresolved.append(m.group(0))
            return m.group(0)
        return str(node)
    return OBJ_RE.sub(rep, path), unresolved

def save(out, results):
    tmp = out + ".json.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    os.replace(tmp, out + ".json")  # atomic: incremental state is never truncated

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--jars", nargs="+", required=True)
    ap.add_argument("--ua", required=True)
    ap.add_argument("--tests", required=True)
    ap.add_argument("--inventory", help="JSON of discovered object IDs per jar (Step-2 table)")
    ap.add_argument("--out", default="idor_results")
    ap.add_argument("--delay", type=float, default=1.3)
    a = ap.parse_args()

    try:
        from curl_cffi import requests as cr
    except ImportError:
        sys.exit("pip install curl_cffi")

    inv = {}
    if a.inventory:
        with open(a.inventory, encoding="utf-8") as f:
            inv = json.load(f)
    with open(a.tests, encoding="utf-8") as f:
        tests = json.load(f)
    jars = {re.sub(r"\.txt$", "", j): load_jar(j) for j in a.jars}
    # ONE SESSION PER JAR — never share a cookie jar across accounts (response
    # Set-Cookies from jar A would otherwise persist and co-send with jar B).
    sessions = {name: cr.Session(impersonate="chrome") for name in jars}
    H = {"User-Agent": a.ua, "Accept": "application/json, text/plain, */*",
         "Accept-Language": "en-US,en;q=0.9", "Referer": a.base + "/"}

    log = open(a.out + ".log", "w", encoding="utf-8")

    def emit(line):
        print(line); log.write(line + "\n"); log.flush()

    results = []

    # Phase 0: identify each session
    emit("=== SESSION IDENTIFICATION (fill identity_path in tests.json as __IDENTITY__ to customize) ===")
    ident = next((t for t in tests if t.get("role") == "identity"), None)
    if ident:
        for name, s in sessions.items():
            try:
                r = s.get(a.base + ident["path"], headers=H, cookies=jars[name], timeout=25)
                alive = r.status_code == 200 and "false" not in r.text[:60]
                emit(f"[{name}] {r.status_code} {r.text[:120]} -> {'ALIVE' if alive else 'DEAD (ask user for fresh jar)'}")
            except Exception as e:
                emit(f"[{name}] ERR {type(e).__name__}")
            time.sleep(a.delay)

    for i, t in enumerate(tests):
        if t.get("role") in ("identity",): continue
        method = t["method"].upper()
        path, unresolved = interp(t["path"], inv)
        if unresolved:
            emit(f"\n--- TEST {i+1}: SKIPPED — unresolved placeholder(s) {unresolved} "
                 f"(add the object IDs to the --inventory JSON from the Step-2 listing)")
            results.append({"method": method, "path": t["path"], "verdict": "skipped-unresolved-placeholder",
                            "unresolved": unresolved, "attempts": []})
            save(a.out, results)
            continue
        body = t.get("body")
        row = {"method": method, "path": path, "attempts": []}
        emit(f"\n--- TEST {i+1}: {method} {path}")
        for name, s in sessions.items():
            try:
                r = s.request(method, a.base + path, headers={**H, "Content-Type": "application/json"},
                              cookies=jars[name], json=body, timeout=25)
                emit(f"[{name}] {r.status_code} {r.text[:180]}")
                row["attempts"].append({"jar": name, "status": r.status_code, "body": r.text[:500]})
            except Exception as e:
                emit(f"[{name}] ERR {type(e).__name__}")
            time.sleep(a.delay)
        # verdict heuristics — an all-errored test is INCONCLUSIVE, not uniform
        st = {x["jar"]: x["status"] for x in row["attempts"]}
        if not st:
            row["verdict"] = "INCONCLUSIVE — every request errored (no attempt succeeded; fix connectivity/tokens and re-run)"
        elif len(set(st.values())) > 1:
            ok_owner = any(v in (200, 201, 204) for v in st.values())
            row["verdict"] = ("DIFFERENTIAL — check who got what; foreign 2xx = suspected IDOR" if ok_owner
                              else "DIFFERENTIAL statuses (verify positive control first)")
        else:
            row["verdict"] = f"uniform {list(st.values())[0]}"
        emit(f"VERDICT: {row['verdict']}")
        results.append(row)
        save(a.out, results)   # incremental: a crash never loses completed tests

    save(a.out, results)
    log.close()
    print(f"\nsaved {a.out}.json / .log")

if __name__ == "__main__":
    main()
