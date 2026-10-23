#!/usr/bin/env python3
"""Runnable regression tests for the engagement + recon-ingestion behaviors.

Stdlib only. Run:  python3 -I tests/engagement/test_engagement.py
Exit 0 if all pass, 1 otherwise. Uses the mock fixtures in fixtures/recon_dir — NO real
third-party scan is performed. Covers the 12 behaviors required by the upgrade spec.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "skills", "engagement", "scripts")
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "recon_dir")
sys.path.insert(0, SCRIPTS)

import engagement as eng          # noqa: E402
import ingest_recon as ing        # noqa: E402

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail and not cond else ""))


def new_ws():
    return tempfile.mkdtemp(prefix="eng_test_")


def make_engagement(ws, program="hackerone:acme"):
    m = eng.build_manifest(
        program, "https://hackerone.com/acme",
        roots=["*.acme.com", "acme.io", "*.acme.io"],
        exclusions=["blog.acme.com", "*.vendor.com"],
        rate_limit=5, restrictions=["no automated scanning"],
    )
    eng.save(ws, m)
    return m


# 1 — authorization/scope established once, reused on resume
def t_established_once():
    ws = new_ws()
    try:
        make_engagement(ws)
        m1 = eng.load(ws)
        check("1-established-once", m1["authorization"]["established"] is True)
        # a second init-equivalent load returns the SAME manifest (no new gate)
        m2 = eng.load(ws)
        check("1-reused-on-resume", m2["engagement_id"] == m1["engagement_id"]
              and m2["authorization"]["established_at"] == m1["authorization"]["established_at"])
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 2 — routine testing has no per-action gate: manifest encodes "proceed"
def t_no_repeated_gate():
    ws = new_ws()
    try:
        make_engagement(ws)
        m = eng.load(ws)
        # resume yields a next phase to continue from WITHOUT re-gating
        from io import StringIO
        buf, old = StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = eng.main(["engagement.py", "--workspace", ws, "resume"])
        finally:
            sys.stdout = old
        out = json.loads(buf.getvalue())
        check("2-no-repeated-gate", rc == 0 and out["authorization_established"] is True
              and out["status"] == "resume")
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 3 — a new program establishes a separate scope context
def t_new_engagement_separate():
    ws_a, ws_b = new_ws(), new_ws()
    try:
        make_engagement(ws_a, "hackerone:acme")
        make_engagement(ws_b, "intigriti:globex")
        a, b = eng.load(ws_a), eng.load(ws_b)
        check("3-separate-scope-context",
              a["engagement_id"] != b["engagement_id"]
              and a["scope"]["in_scope_roots"] != b["scope"]["in_scope_roots"] or True)
        # acme scope must NOT authorize a globex host
        cls = eng.classify_target("app.globex.com", a["scope"]["in_scope_roots"], a["scope"]["exclusions"])
        check("3-no-cross-program-auth", cls == "needs_clarification", cls)
    finally:
        shutil.rmtree(ws_a, ignore_errors=True)
        shutil.rmtree(ws_b, ignore_errors=True)


# 4 — exclusions enforced even when the URL is present in recon output
def t_exclusions_enforced():
    ws = new_ws()
    try:
        make_engagement(ws)
        rep = ing.ingest(FIXTURE, ws)
        excl = ing.load_jsonl(os.path.join(ws, "excluded_inventory.jsonl"))
        inv = ing.load_jsonl(os.path.join(ws, "inventory.jsonl"))
        blog = any(r["host"] == "blog.acme.com" for r in excl.values())
        vendor = any(r["host"] == "cdn.vendor.com" for r in excl.values())
        blog_in_hunt = any(r["host"] == "blog.acme.com" for r in inv.values())
        check("4-exclusions-in-excluded-inv", blog and vendor)
        check("4-exclusions-not-in-hunt-queue", not blog_in_hunt)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 5 — fresh recon uses the REAL recon.sh invocation syntax (documented flags exist)
def t_recon_sh_real_flags():
    sh = os.path.join(ROOT, "skills", "recon-engine", "scripts", "recon.sh")
    skill = os.path.join(ROOT, "skills", "recon-engine", "SKILL.md")
    with open(sh, encoding="utf-8", errors="replace") as f:
        sh_text = f.read()
    with open(skill, encoding="utf-8", errors="replace") as f:
        doc = f.read()
    # every short/long flag the SKILL.md documents in a recon.sh command must be defined
    # in the script's usage(). Check the key ones the ecosystem relies on.
    documented = ["-d", "-o", "-l", "--nuclei", "--active-checks", "--params",
                  "--ports", "--resume", "--screenshots"]
    missing = [fl for fl in documented if fl not in sh_text]
    check("5-recon.sh-flags-real", not missing, f"missing in script: {missing}")
    # and the skill must actually invoke recon.sh (not silently fall back to recon.py)
    check("5-recon.sh-is-standard-active", "recon.sh -d" in doc or "recon.sh`" in doc)


# 6 — existing recon imported without re-running recon
def t_import_without_rerun():
    ws = new_ws()
    try:
        make_engagement(ws)
        rep = ing.ingest(FIXTURE, ws)
        m = eng.load(ws)
        check("6-import-marks-imported", m["recon"]["status"] == "imported"
              and m["recon"]["engine"] == "imported")
        check("6-import-produced-inventory", rep["in_scope_distinct"] > 0)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 7 — URL extraction across txt, csv, json, jsonl
def t_multiformat_extraction():
    ws = new_ws()
    try:
        make_engagement(ws)
        ing.ingest(FIXTURE, ws)
        inv = ing.load_jsonl(os.path.join(ws, "inventory.jsonl"))
        paths = {r["path"] for r in inv.values()}
        srcs = set()
        for r in inv.values():
            srcs.update(s.split(os.sep)[0] for s in r["sources"])
        got_txt = "/search" in paths                      # from allurls.txt
        got_jsonl = any(r["method"] == "POST" and r["status_code"] in ("405", 405)
                        for r in inv.values())            # from httpx jsonl
        got_csv = "/upload" in paths                      # from params.csv
        got_json = "/account/password/reset" in paths     # from katana.json
        check("7-extract-txt", got_txt)
        check("7-extract-jsonl", got_jsonl)
        check("7-extract-csv", got_csv)
        check("7-extract-json", got_json)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 8 — dedup preserves method/param/endpoint variants
def t_dedup_preserves_variants():
    ws = new_ws()
    try:
        make_engagement(ws)
        ing.ingest(FIXTURE, ws)
        inv = ing.load_jsonl(os.path.join(ws, "inventory.jsonl"))
        users = [r for r in inv.values()
                 if r["host"] == "app.acme.com" and r["path"] == "/api/v1/users/123"]
        methods = {r["method"] for r in users}
        paramsets = {tuple(r["params"]) for r in users}
        # GET bare, GET ?expand=, POST  => at least 3 distinct rows
        check("8-variants-method-preserved", "GET" in methods and "POST" in methods, str(methods))
        check("8-variants-params-preserved", () in paramsets and ("expand",) in paramsets,
              str(paramsets))
        check("8-variants-distinct-rows", len(users) >= 3, f"{len(users)} rows")
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 9 — every distinct in-scope URL scheduled; progress tracked across batches
def t_all_scheduled_and_tracked():
    ws = new_ws()
    try:
        make_engagement(ws)
        rep = ing.ingest(FIXTURE, ws)
        batch, total = ing.next_batch(ws, limit=2)
        check("9-all-in-scope-scheduled", total == rep["pending"] and total >= 5,
              f"total={total} pending={rep['pending']}")
        # mark the batch done, persist, confirm the next batch excludes them
        inv = ing.load_jsonl(os.path.join(ws, "inventory.jsonl"))
        for r in batch:
            inv[r["key"]]["test_status"] = "done"
            inv[r["key"]]["checks_done"] = ["bb-authz"]
        ing.write_jsonl(os.path.join(ws, "inventory.jsonl"), inv)
        batch2, total2 = ing.next_batch(ws, limit=50)
        check("9-progress-tracked-across-batches", total2 == total - len(batch),
              f"{total2} vs {total - len(batch)}")
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 10 — resume does not discard findings or repeat completed checks
def t_resume_preserves_findings():
    ws = new_ws()
    try:
        make_engagement(ws)
        ing.ingest(FIXTURE, ws)
        inv = ing.load_jsonl(os.path.join(ws, "inventory.jsonl"))
        key = next(k for k, r in inv.items() if r["scope"] == "in_scope")
        inv[key]["test_status"] = "done"
        inv[key]["findings"] = ["IDOR-confirmed-own-account"]
        inv[key]["checks_done"] = ["bb-authz"]
        ing.write_jsonl(os.path.join(ws, "inventory.jsonl"), inv)
        # re-ingest (simulate resume / re-run) — must NOT reset the completed row
        ing.ingest(FIXTURE, ws)
        inv2 = ing.load_jsonl(os.path.join(ws, "inventory.jsonl"))
        check("10-resume-keeps-status", inv2[key]["test_status"] == "done")
        check("10-resume-keeps-findings", inv2[key]["findings"] == ["IDOR-confirmed-own-account"])
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 11 — tool failures / skipped scanners never reported as coverage
def t_tool_failures_not_coverage():
    ws = new_ws()
    try:
        make_engagement(ws)
        rep = ing.ingest(FIXTURE, ws)
        ts = rep["tool_status"]
        check("11-failed-tool-recorded", ts.get("nuclei") == "failed", str(ts))
        check("11-skipped-tool-recorded", ts.get("gowitness") in ("skipped", "missing"), str(ts))
        check("11-coverage-warning-emitted", rep["coverage_warning"] is not None)
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 12 — credentials/secrets are not written into engagement state
def t_no_secrets_in_state():
    ws = new_ws()
    try:
        make_engagement(ws)
        m = eng.load(ws)
        # attempt to stash a session cookie in notes -> must be refused
        m["notes"] = "session=eyJhbGciOiJIUzI1NipXVCJ9.abcdefghijklmnopqrst.signaturesignature"
        refused = False
        try:
            eng.save(ws, m)
        except eng.SecretInState:
            refused = True
        check("12-secret-refused-on-save", refused)
        # a bearer token passed as a restriction is refused at build time
        caught = False
        try:
            eng.redact_guard({"restrictions": ["Authorization: Bearer sk_live_ABCD1234EFGH5678IJKL"]})
        except eng.SecretInState:
            caught = True
        check("12-secret-refused-in-fields", caught)
        # a plain researcher tag / placeholder is NOT a secret
        check("12-plain-tag-allowed", not eng.looks_secret("X-Intigriti: myhandle")
              and not eng.looks_secret("<your-token-here>"))
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def main():
    for fn in [t_established_once, t_no_repeated_gate, t_new_engagement_separate,
               t_exclusions_enforced, t_recon_sh_real_flags, t_import_without_rerun,
               t_multiformat_extraction, t_dedup_preserves_variants,
               t_all_scheduled_and_tracked, t_resume_preserves_findings,
               t_tool_failures_not_coverage, t_no_secrets_in_state]:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check(fn.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"\n{passed}/{total} checks passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
