#!/usr/bin/env python3
"""Runnable offline tests for scope_gate.py (operator-declaration authorization gate).

Stdlib only, no network. Run:
    python3 -I tests/engagement/test_scope_gate.py
Exit 0 if all pass, 1 otherwise.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
sys.dont_write_bytecode = True  # keep __pycache__ out of the repo tree
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "skills", "engagement", "scripts")
sys.path.insert(0, SCRIPTS)
import scope_gate as sg  # noqa: E402
import engagement as eng  # noqa: E402

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail and not cond else ""))


def run(argv):
    from io import StringIO
    buf, old = StringIO(), sys.stdout
    err, old_err = StringIO(), sys.stderr
    sys.stdout, sys.stderr = buf, err
    try:
        rc = sg.main(["scope_gate.py", *argv])
    finally:
        sys.stdout, sys.stderr = old, old_err
    out = buf.getvalue().strip() or err.getvalue().strip()
    try:
        return rc, json.loads(out)
    except ValueError:
        return rc, out


def t_yaml_parsing():
    tmp = tempfile.mkdtemp()
    try:
        p = os.path.join(tmp, "scope.yaml")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write("# comment\n"
                    "in_scope:\n"
                    '  - "*.acme.com"\n'
                    "out_of_scope:\n"
                    "  - blog.acme.com\n"
                    "rate_limit_rps: 3\n"
                    "posture: lab\n"
                    "program: bugcrowd:acme\n"
                    "restrictions:\n"
                    '  - "no automated scanning"\n'
                    "unknown_key: x\n")
        cfg, seen = sg.load_scope_yaml(p)
        check("yaml-lists", cfg.get("in_scope") == ["*.acme.com"]
              and cfg.get("out_of_scope") == ["blog.acme.com"]
              and cfg.get("restrictions") == ["no automated scanning"], str(cfg))
        check("yaml-scalars", cfg.get("rate_limit_rps") == "3" and cfg.get("posture") == "lab"
              and cfg.get("program") == "bugcrowd:acme", str(cfg))
        check("yaml-unknown-reported", "unknown_key" in cfg.get("_unknown_keys", []), str(cfg))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_declaration_establishes_manifest():
    ws = tempfile.mkdtemp()
    try:
        rc, out = run(["--workspace", ws, "--operator-declared", "acme.com, api.acme.io",
                       "--quote", "hunt acme.com and api.acme.io", "--target", "app.acme.com"])
        check("gate-established", rc == 0 and out.get("status") == "established", str(out))
        check("gate-roots-are-wildcards", out.get("effective_roots") == ["*.acme.com", "*.api.acme.io"],
              str(out.get("effective_roots")))
        check("gate-classifies-dot-boundary",
              out.get("classification", {}).get("app.acme.com") == "in_scope", str(out))
        m = eng.load(ws)
        check("gate-writes-manifest", m is not None
              and m["authorization"]["basis"] == "operator-declared"
              and m["authorization"]["established"] is True, str(bool(m)))
        check("gate-run-record-exists", os.path.exists(out.get("run_record", "")))
        check("gate-audit-log-exists", os.path.exists(os.path.join(ws, "audit.log")))
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def t_lookalike_host_needs_clarification():
    ws = tempfile.mkdtemp()
    try:
        rc, out = run(["--workspace", ws, "--operator-declared", "acme.com",
                       "--quote", "q", "--target", "evilacme.com"])
        check("gate-lookalike-not-in-scope",
              rc == 0 and out.get("classification", {}).get("evilacme.com") == "needs_clarification",
              str(out))
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def t_reuse_and_conflict():
    ws = tempfile.mkdtemp()
    try:
        run(["--workspace", ws, "--operator-declared", "acme.com", "--quote", "q"])
        rc, out = run(["--workspace", ws, "--operator-declared", "acme.com", "--quote", "q2"])
        check("gate-reuse-idempotent", rc == 0 and out.get("status") == "reused", str(out))
        rc, out = run(["--workspace", ws, "--operator-declared", "other.com", "--quote", "q3"])
        check("gate-conflict-cross-program", rc == 1 and out.get("status") == "conflict", str(out))
        m = eng.load(ws)
        check("gate-conflict-preserves-manifest", m["program"]["id"].startswith("operator:acme"))
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def t_halt_when_nothing_declared():
    ws = tempfile.mkdtemp()
    try:
        rc, out = run(["--workspace", ws])
        check("gate-halts-empty", rc == 1 and out.get("status") == "halted", str(out))
        check("gate-halt-writes-blocked-record",
              any(n.startswith("blocked-") for n in os.listdir(os.path.join(ws, "runs"))),
              str(os.listdir(os.path.join(ws, "runs"))))
        check("gate-halt-writes-no-manifest", eng.load(ws) is None)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def t_secret_quote_refused():
    ws = tempfile.mkdtemp()
    try:
        rc, out = run(["--workspace", ws, "--operator-declared", "acme.com",
                       "--quote", "Authorization: Bearer eyJabcDEF123456789012345"])
        check("gate-refuses-secret-quote", rc == 2 and out.get("status") == "refused", str(out))
        check("gate-refusal-writes-no-manifest", eng.load(ws) is None)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def t_scope_yaml_contributes_and_exclusions_win():
    ws = tempfile.mkdtemp()
    try:
        with open(os.path.join(ws, "scope.yaml"), "w", encoding="utf-8", newline="\n") as f:
            f.write("out_of_scope:\n  - internal.acme.com\nrate_limit_rps: 3\n"
                    "restrictions:\n  - \"no automated scanning\"\n")
        rc, out = run(["--workspace", ws, "--operator-declared", "acme.com",
                       "--quote", "test acme", "--exclude", "staging.acme.com",
                       "--target", "internal.acme.com"])
        check("gate-yaml-exclusions-merged",
              out.get("exclusions") == ["staging.acme.com", "internal.acme.com"], str(out))
        check("gate-yaml-excluded-host-out-of-scope",
              out.get("classification", {}).get("internal.acme.com") == "out_of_scope", str(out))
        m = eng.load(ws)
        check("gate-yaml-rate-limit-persisted", m["scope"]["rate_limit_rps"] == 3.0, str(m["scope"]))
        check("gate-yaml-restrictions-persisted",
              "no automated scanning" in m["scope"]["testing_restrictions"], str(m["scope"]))
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def main():
    for fn in [t_yaml_parsing, t_declaration_establishes_manifest,
               t_lookalike_host_needs_clarification, t_reuse_and_conflict,
               t_halt_when_nothing_declared, t_secret_quote_refused,
               t_scope_yaml_contributes_and_exclusions_win]:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check(fn.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
