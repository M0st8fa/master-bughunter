#!/usr/bin/env python3
"""Runnable offline tests for recon_sync.py (canonical recon.sh freshness check).

Stdlib only, no network/git needed. Run:
    python3 -I tests/recon-engine/test_recon_sync.py
Exit 0 if all pass, 1 otherwise.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(ROOT, "skills", "recon-engine", "scripts")
sys.path.insert(0, SCRIPTS)
import recon_sync as rs  # noqa: E402

RESULTS = []
BUNDLED = os.path.join(SCRIPTS, "recon.sh")


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail and not cond else ""))


def run(*args):
    from io import StringIO
    buf, old = StringIO(), sys.stdout
    sys.stdout = buf
    try:
        rc = rs.main(["recon_sync.py", *args])
    finally:
        sys.stdout = old
    try:
        return rc, json.loads(buf.getvalue())
    except ValueError:
        return rc, buf.getvalue()


def t_lock_points_at_canonical_repo():
    rc, out = run("lock")
    check("lock-repo-is-recon-script", rc == 0
          and "M0st8fa/Recon-Script".lower() in out.get("repo", "").lower(), str(out))
    check("lock-records-synced-commit", bool(out.get("synced_commit")))
    check("lock-records-recon-sha", bool(out.get("recon_sh_sha256")))


def t_status_up_to_date_vs_identical_reference():
    # the bundled recon.sh compared against an identical copy = up_to_date
    tmp = tempfile.mkdtemp()
    try:
        ref = os.path.join(tmp, "recon.sh")
        shutil.copy(BUNDLED, ref)
        rc, out = run("status", "--local", BUNDLED, "--reference", ref)
        check("status-up-to-date", rc == 0 and out.get("state") == "up_to_date", str(out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_status_stale_vs_different_reference():
    tmp = tempfile.mkdtemp()
    try:
        ref = os.path.join(tmp, "recon.sh")
        with open(ref, "w") as f:
            f.write("#!/usr/bin/env bash\n# a different, newer recon.sh\n")
        rc, out = run("status", "--local", BUNDLED, "--reference", ref)
        check("status-stale", rc == 0 and out.get("state") == "stale", str(out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_status_missing_local():
    rc, out = run("status", "--local", "/nonexistent/recon.sh")
    check("status-missing", rc == 0 and out.get("state") == "missing", str(out))


def t_status_drift_from_lock_bundled_only():
    # Drift-from-lock applies to the BUNDLED copy only: a hand-edited bundle is flagged,
    # while a separate --local/clone that differs is NOT (it is checked vs the repo).
    backup = BUNDLED + ".bak"
    shutil.copy(BUNDLED, backup)
    try:
        with open(BUNDLED, "a") as f:
            f.write("\n# locally appended, drifts from the vendored lock\n")
        rc, out = run("status")   # no --local/--dir -> checks the bundled copy
        check("status-drifted-bundled", rc == 0 and out.get("state") == "drifted-from-lock"
              and out.get("checking") == "bundled", str(out))
    finally:
        shutil.move(backup, BUNDLED)
    # an explicit non-bundled script that differs is not mislabeled as drift
    tmp = tempfile.mkdtemp()
    try:
        local = os.path.join(tmp, "recon.sh")
        with open(local, "w") as f:
            f.write("#!/usr/bin/env bash\n# a different standalone script\n")
        rc, out = run("status", "--local", local)
        check("status-explicit-not-drift", rc == 0 and out.get("state") != "drifted-from-lock",
              str(out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_local_recon_prefers_clone_dir():
    # with --dir, the freshness check targets the clone's recon.sh, not the bundled copy
    tmp = tempfile.mkdtemp()
    try:
        clone = os.path.join(tmp, "recon.sh")
        with open(clone, "w") as f:
            f.write("#!/usr/bin/env bash\n# clone copy\n")
        rc, out = run("status", "--dir", tmp)   # tmp has no .git -> falls to lock-marker path
        check("local-recon-prefers-clone",
              out.get("checking") == "clone" and out.get("local_recon_sh") == clone, str(out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_norm_repo_equivalence():
    same = rs._norm_repo("https://github.com/M0st8fa/Recon-Script.git") == \
        rs._norm_repo("git@github.com:m0st8fa/recon-script") == \
        rs._norm_repo("https://github.com/M0st8fa/Recon-Script/")
    diff = rs._norm_repo("https://github.com/evil/Recon-Script") != \
        rs._norm_repo("https://github.com/M0st8fa/Recon-Script")
    check("norm-repo-equiv", same and diff)


def t_bundled_matches_lock():
    # the committed recon.sh must match the sha recorded in recon-script.lock
    lock = rs.read_lock()
    check("bundled-recon.sh-matches-lock",
          os.path.exists(BUNDLED) and rs.sha256_file(BUNDLED) == lock.get("recon_sh_sha256"),
          "vendored recon.sh drifted from recon-script.lock")


def main():
    for fn in [t_lock_points_at_canonical_repo, t_status_up_to_date_vs_identical_reference,
               t_status_stale_vs_different_reference, t_status_missing_local,
               t_status_drift_from_lock_bundled_only, t_local_recon_prefers_clone_dir,
               t_norm_repo_equivalence, t_bundled_matches_lock]:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check(fn.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
