#!/usr/bin/env python3
"""Cross-account IDOR/BOLA matrix runner for OWN test accounts on an authorized target.
Usage:
  python idor_matrix.py --base https://target --jars acc1_cookies.txt acc2_cookies.txt \
      --ua "exact UA from the cURL blocks" --tests tests.json [--inventory inv.json] [--out idor_results]
Jar files: one line of "k=v; k=v" cookies each.
tests.json: [{"method":"GET","path":"/api/x/{OBJ:acc1.address.id}","body":{...}}, ...]
  {OBJ:<jarname-without-.txt>.<dotted.path>} is replaced with values from inventory JSON.
Inventory JSON: {"acc1": {"address": {"id": 123}}, ...}  (from Step-2 listing dumps)
Requires: pip install curl_cffi
"""
import argparse, json, re, time, sys

def load_jar(path):
    c = {}
    for part in open(path).read().strip().split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            c[k.strip()] = v.strip()
    return c

def interp(path, inv):
    def rep(m):
        jar, dotted = m.group(1), m.group(2).split(".")
        node = inv.get(jar)
        for k in dotted:
            node = (node or {}).get(k)
        return str(node) if node is not None else m.group(0)
    return re.sub(r"\{OBJ:([^}]+)\.([^}]+)\}", rep, path)

def deep_find(obj, key_re, hits):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if re.search(key_re, str(k), re.I) and not isinstance(v, (dict, list)):
                hits.append(v)
            deep_find(v, key_re, hits)
    elif isinstance(obj, list):
        for it in obj: deep_find(it, key_re, hits)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--jars", nargs="+", required=True)
    ap.add_argument("--ua", required=True)
    ap.add_argument("--tests", required=True)
    ap.add_argument("--inventory", help="JSON of discovered object IDs per jar")
    ap.add_argument("--out", default="idor_results")
    ap.add_argument("--delay", type=float, default=1.3)
    a = ap.parse_args()

    try:
        from curl_cffi import requests as cr
    except ImportError:
        sys.exit("pip install curl_cffi")
    s = cr.Session(impersonate="chrome")
    H = {"User-Agent": a.ua, "Accept": "application/json, text/plain, */*",
         "Accept-Language": "en-US,en;q=0.9", "Referer": a.base + "/"}

    inv = json.load(open(a.inventory)) if a.inventory else {}
    tests = json.load(open(a.tests))
    jars = {re.sub(r"\.txt$", "", j): load_jar(j) for j in a.jars}
    results, log = [], open(a.out + ".log", "w", encoding="utf-8")

    def emit(line):
        print(line); log.write(line + "\n"); log.flush()

    # Phase 0: identify each session
    emit("=== SESSION IDENTIFICATION (fill identity_path in tests.json as __IDENTITY__ to customize) ===")
    ident = next((t for t in tests if t.get("role") == "identity"), None)
    if ident:
        for name, ck in jars.items():
            r = s.get(a.base + interp(ident["path"], {}), headers=H, cookies=ck, timeout=25)
            alive = r.status_code == 200 and "false" not in r.text[:60]
            emit(f"[{name}] {r.status_code} {r.text[:120]} -> {'ALIVE' if alive else 'DEAD (ask user for fresh jar)'}")
            time.sleep(a.delay)

    for i, t in enumerate(tests):
        if t.get("role") in ("identity",): continue
        method, path = t["method"].upper(), interp(t["path"], inv)
        body = t.get("body")
        row = {"method": method, "path": path, "attempts": []}
        emit(f"\n--- TEST {i+1}: {method} {path}")
        for name, ck in jars.items():
            try:
                r = s.request(method, a.base + path, headers={**H, "Content-Type": "application/json"},
                              cookies=ck, json=body, timeout=25)
                emit(f"[{name}] {r.status_code} {r.text[:180]}")
                row["attempts"].append({"jar": name, "status": r.status_code, "body": r.text[:500]})
            except Exception as e:
                emit(f"[{name}] ERR {type(e).__name__}")
            time.sleep(a.delay)
        # verdict heuristics
        st = {x["jar"]: x["status"] for x in row["attempts"]}
        if len(set(st.values())) > 1:
            ok_owner = any(v in (200, 201, 204) for v in st.values())
            row["verdict"] = ("DIFFERENTIAL — check who got what; foreign 2xx = suspected IDOR" if ok_owner
                              else "DIFFERENTIAL statuses (verify positive control first)")
        else:
            row["verdict"] = f"uniform {list(st.values())[0]}"
        emit(f"VERDICT: {row['verdict']}")
        results.append(row)

    json.dump(results, open(a.out + ".json", "w"), indent=1)
    print(f"\nsaved {a.out}.json / .log")

if __name__ == "__main__":
    main()
