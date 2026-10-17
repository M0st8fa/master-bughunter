#!/usr/bin/env python3
"""Query the reddelexc/hackerone-reports corpus (14.8k disclosed H1 reports).

Usage:
  query.py --program gitlab [--vuln idor] [--min-bounty 1000] [--q keyword] [--sort bounty|upvotes] [--limit 20]
  query.py --vuln "business logic" --min-bounty 5000
  query.py --stats              # top programs & vuln types by count/payout
  query.py --refresh            # re-download data.csv from GitHub
"""
import argparse, csv, os, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "data.csv")
SRC = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"

def load():
    if not os.path.exists(DATA): refresh()
    rows = []
    with open(DATA, encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows

def refresh():
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    req = urllib.request.Request(SRC, headers={"User-Agent": "h1-reports-skill/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r, open(DATA, "wb") as f:
        f.write(r.read())
    print(f"[+] corpus refreshed: {sum(1 for _ in open(DATA, encoding='utf-8', errors='replace'))} lines")

def show(rows, limit):
    if not rows: print("0 matches"); return
    print(f"{len(rows)} matching reports\n")
    for r in rows[:limit]:
        b = r.get("bounty", "0") or "0"
        try: b = f"${float(b):,.0f}"
        except Exception: b = "$?"
        link = r.get("link", "")
        link = link[len("https://"):] if link.startswith("https://") else link
        print(f"  {b:>9} [{(r.get('vuln_type') or '?')[:34]:34}] {r.get('program','?')[:18]:18} | {(r.get('title') or '')[:80]}")
        print(f"           https://{link}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program"); ap.add_argument("--vuln"); ap.add_argument("--q")
    ap.add_argument("--min-bounty", type=float, default=0)
    ap.add_argument("--sort", choices=["bounty", "upvotes", "recent"], default="bounty")
    ap.add_argument("--limit", type=int, default=15)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    a = ap.parse_args()
    if a.refresh: refresh(); return
    rows = load()
    if a.stats:
        from collections import Counter, defaultdict
        pc, pb = Counter(), defaultdict(float)
        vc, vb = Counter(), defaultdict(float)
        for r in rows:
            try: b = float(r.get("bounty") or 0)
            except Exception: b = 0
            pc[r["program"]] += 1; pb[r["program"]] += b
            v = r.get("vuln_type") or "Unknown"; vc[v] += 1; vb[v] += b
        print("== top programs by payout ==")
        for p, t in sorted(pb.items(), key=lambda x: -x[1])[:15]:
            print(f"  ${t:>12,.0f}  {pc[p]:>5} reports  {p}")
        print("\n== top vuln types by payout ==")
        for v, t in sorted(vb.items(), key=lambda x: -x[1])[:15]:
            print(f"  ${t:>12,.0f}  {vc[v]:>5} reports  {v}")
        return
    def match(r):
        if a.program and a.program.lower() not in r.get("program", "").lower(): return False
        if a.vuln and a.vuln.lower() not in (r.get("vuln_type") or "").lower(): return False
        if a.q and a.q.lower() not in (r.get("title") or "").lower(): return False
        try: b = float(r.get("bounty") or 0)
        except Exception: b = 0
        return b >= a.min_bounty
    rows = [r for r in rows if match(r)]
    key = (lambda r: float(r.get("bounty") or 0)) if a.sort == "bounty" else (lambda r: float(r.get("upvotes") or 0))
    rows.sort(key=key, reverse=True)
    show(rows, a.limit)

if __name__ == "__main__":
    main()
