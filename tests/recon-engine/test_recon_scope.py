#!/usr/bin/env python3
"""Offline tests for recon.py's dot-boundary scope matching (IQ-009 fix).

A bare suffix check matched lookalike domains ('evilacme.com' vs '*.acme.com') into
in_scope results. These checks pin the corrected behavior. Stdlib only, no network. Run:
    python3 -I tests/recon-engine/test_recon_scope.py
"""
from __future__ import annotations

import importlib.util
import os
import sys
sys.dont_write_bytecode = True  # keep __pycache__ out of the repo tree

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "skills", "recon-engine", "scripts", "recon.py")

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail and not cond else ""))


def load_module():
    spec = importlib.util.spec_from_file_location("recon", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load_module()
    # _same_or_sub helper (provider-level matching)
    check("same-or-sub-exact", m._same_or_sub("acme.com", "acme.com"))
    check("same-or-sub-real-sub", m._same_or_sub("app.acme.com", "acme.com"))
    check("same-or-sub-deep-sub", m._same_or_sub("dev.app.acme.com", "app.acme.com"))
    check("same-or-sub-rejects-lookalike", not m._same_or_sub("evilacme.com", "acme.com"))
    check("same-or-sub-rejects-prefix", not m._same_or_sub("notacme.com", "acme.com"))

    # _host_in_scope — the REAL run()-level matcher (imported, not mirrored)
    f = lambda s: m._host_in_scope(s, ["*.acme.com"])
    check("wildcard-matches-apex-and-subs",
          f("acme.com") and f("x.acme.com") and f("a.b.acme.com"))
    check("wildcard-rejects-lookalikes",
          not f("evilacme.com") and not f("notacme.com") and not f("acme.com.evil.net"))
    g = lambda s: m._host_in_scope(s, ["api.acme.io"])
    check("bare-apex-matches-only-itself", g("api.acme.io") and not g("x.api.acme.io"))
    h = lambda s: m._host_in_scope(s, ["*.acme.com", "api.acme.io"])
    check("mixed-patterns", h("x.acme.com") and h("api.acme.io") and not h("x.api.acme.io"))

    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
