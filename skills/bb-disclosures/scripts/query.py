#!/usr/bin/env python3
"""Query the local real-bug disclosure corpus (11,338 records, HackerOne/Bugcrowd/Immunefi/Intigriti).

Usage:
  python query.py --class "Access control" --min-bounty 5000 -n 10
  python query.py --q "password reset" --severity Critical
  python query.py --q race --class "Business logic"
  python query.py --stats
  python query.py --q "kubernetes" --json            # machine-readable output

Filters: --q (keyword in title+weakness), --class, --severity, --platform, --kind,
         --min-bounty, --year, --sort (bounty|date), --n, --json, --stats
"""
import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "disclosures.jsonl")


def load():
    rows = []
    with open(DATA, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--q")
    ap.add_argument("--class", dest="vclass")
    ap.add_argument("--severity")
    ap.add_argument("--platform")
    ap.add_argument("--kind")
    ap.add_argument("--min-bounty", type=float, default=0)
    ap.add_argument("--year")
    ap.add_argument("--sort", default="bounty", choices=["bounty", "date"])
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args()

    rows = load()

    if a.stats:
        import collections
        print(f"total: {len(rows)}")
        for field in ("vulnerabilityClass", "severity", "platform", "kind"):
            c = collections.Counter((r.get(field) or "Unknown") for r in rows)
            print(f"\n== {field} ==")
            for k, v in c.most_common(20):
                print(f"{v:6d}  {k}")
        return

    def hit(r):
        if a.q:
            hay = (r.get("title") or "").lower() + " " + (r.get("weakness") or "").lower()
            if a.q.lower() not in hay:
                return False
        if a.vclass and (r.get("vulnerabilityClass") or "").lower() != a.vclass.lower():
            return False
        if a.severity and (r.get("severity") or "").lower() != a.severity.lower():
            return False
        if a.platform and (r.get("platform") or "").lower() != a.platform.lower():
            return False
        if a.kind and (r.get("kind") or "").lower() != a.kind.lower():
            return False
        if a.min_bounty and (r.get("bounty") or 0) < a.min_bounty:
            return False
        if a.year and not (r.get("disclosedAt") or "").startswith(a.year):
            return False
        return True

    out = [r for r in rows if hit(r)]
    if a.sort == "bounty":
        out.sort(key=lambda r: -(r.get("bounty") or 0))
    else:
        out.sort(key=lambda r: (r.get("disclosedAt") or ""), reverse=True)
    out = out[: a.n]

    if a.json:
        print(json.dumps(out, indent=1, ensure_ascii=False))
        return

    print(f"{len(out)} shown (of {len(rows)} records)")
    for r in out:
        b = r.get("bounty")
        bs = f"${b:,.0f}" if isinstance(b, (int, float)) and b else "-"
        w = (r.get("weakness") or "")[:90]
        print(f"\n{bs:>9} [{r.get('severity')}] {r.get('vulnerabilityClass')} — {r.get('title')}")
        if w:
            print(f"          weakness: {w}")
        print(f"          {r.get('platform')} | {r.get('disclosedAt')} | {r.get('url')}")


if __name__ == "__main__":
    main()
