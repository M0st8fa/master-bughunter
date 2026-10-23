#!/usr/bin/env python3
"""recon_sync.py — keep the recon engine in sync with its canonical repo.

Stdlib only. Run isolated:  python3 -I recon_sync.py <cmd> ...

The canonical source of `recon.sh` + `setup.sh` is the repo named in
`recon-script.lock` (M0st8fa/Recon-Script). The copies bundled next to this script are a
vendored mirror. Before hunting, the workflow runs `status` to check the bundled/local
`recon.sh` against the canonical repo and runs `ensure` to update it when stale.

This script NEVER executes `recon.sh` or `setup.sh` — it only fetches/compares text and
reports what to run. Running the installer or the recon engine is a separate, explicit
step gated by the recon-engine decision table (trusted user-owned host only).

Commands
  lock                 print the parsed recon-script.lock (repo, synced_commit, hashes).
  status [--dir D] [--local FILE] [--reference FILE]
                       report whether recon.sh is up to date vs the canonical repo.
                       --reference compares against a known-good file offline (no network).
                       Otherwise, with git + network, fetch the repo and compare.
  ensure --dir D       clone the canonical repo into D if absent, else `git pull --ff-only`;
                       print the recon.sh/setup.sh paths + commit. (Clones text only.)

Exit 0 on success; status exits 0 and reports state in JSON (never fails the hunt itself).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = os.path.join(HERE, "recon-script.lock")
DEFAULT_REPO = "https://github.com/M0st8fa/Recon-Script"


def read_lock():
    data = {"repo": DEFAULT_REPO, "branch": "HEAD"}
    if os.path.exists(LOCK):
        with open(LOCK, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                data[k.strip()] = v.strip()
    return data


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args, cwd=None, timeout=300):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=timeout)


def _have_git():
    try:
        return _git("--version").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def cmd_lock(a):
    print(json.dumps(read_lock(), indent=2))
    return 0


def _local_recon(a, lock):
    if a.local:
        return a.local
    cand = os.path.join(HERE, "recon.sh")
    return cand if os.path.exists(cand) else None


def cmd_status(a):
    lock = read_lock()
    local = _local_recon(a, lock)
    out = {"canonical_repo": lock.get("repo"), "local_recon_sh": local}
    if not local or not os.path.exists(local):
        out.update(state="missing",
                   action=f"clone it: python3 -I recon_sync.py ensure --dir <dir>  "
                          f"(canonical: {lock.get('repo')})")
        print(json.dumps(out, indent=2))
        return 0
    local_sha = sha256_file(local)
    out["local_sha256"] = local_sha

    # Offline path: compare against a known-good reference file (used in tests/CI).
    if a.reference:
        ref_sha = sha256_file(a.reference)
        out["reference_sha256"] = ref_sha
        out["state"] = "up_to_date" if ref_sha == local_sha else "stale"
        out["action"] = ("none" if ref_sha == local_sha else
                         "update: python3 -I recon_sync.py ensure --dir <dir>")
        print(json.dumps(out, indent=2))
        return 0

    # The lock records the sha synced from the canonical repo; a local edit that drifts
    # from it is flagged even before any network check.
    locked_sha = lock.get("recon_sh_sha256")
    if locked_sha and locked_sha != local_sha:
        out.update(state="drifted-from-lock", locked_sha256=locked_sha,
                   action="local recon.sh differs from the vendored lock; re-sync with "
                          "`ensure` or restore the vendored copy")
        print(json.dumps(out, indent=2))
        return 0

    # Online path: ask the canonical repo for its current recon.sh and compare.
    if a.dir and os.path.isdir(os.path.join(a.dir, ".git")) and _have_git():
        fetch = _git("fetch", "--depth", "1", "origin", lock.get("branch", "HEAD"),
                     cwd=a.dir)
        if fetch.returncode == 0:
            show = _git("show", "FETCH_HEAD:recon.sh", cwd=a.dir)
            if show.returncode == 0:
                remote_sha = hashlib.sha256(show.stdout.encode()).hexdigest()
                out["remote_sha256"] = remote_sha
                out["state"] = "up_to_date" if remote_sha == local_sha else "stale"
                out["action"] = ("none" if remote_sha == local_sha else
                                 f"update: python3 -I recon_sync.py ensure --dir {a.dir}")
                print(json.dumps(out, indent=2))
                return 0
        out.update(state="unknown-network",
                   action="could not reach the canonical repo; proceed with the vendored "
                          "copy and note the freshness check was skipped")
        print(json.dumps(out, indent=2))
        return 0

    # No clone / no git / no reference: fall back to the lock marker.
    out.update(state="up_to_date-by-lock" if locked_sha == local_sha else "unknown",
               note="no canonical clone available; compared against recon-script.lock only",
               action="run `ensure --dir <dir>` once to enable live freshness checks")
    print(json.dumps(out, indent=2))
    return 0


def cmd_ensure(a):
    lock = read_lock()
    repo = lock.get("repo", DEFAULT_REPO)
    if not _have_git():
        print(json.dumps({"state": "no-git",
                          "action": f"git unavailable; clone {repo} manually"}), file=sys.stderr)
        return 1
    d = a.dir
    if os.path.isdir(os.path.join(d, ".git")):
        pull = _git("pull", "--ff-only", cwd=d)
        ok = pull.returncode == 0
        action = "pulled" if ok else f"pull failed: {pull.stderr.strip()[:160]}"
    else:
        os.makedirs(os.path.dirname(os.path.abspath(d)) or ".", exist_ok=True)
        env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1")
        clone = subprocess.run(["git", "clone", "--depth", "1", repo, d],
                               capture_output=True, text=True, timeout=600, env=env)
        ok = clone.returncode == 0
        action = "cloned" if ok else f"clone failed: {clone.stderr.strip()[:160]}"
    recon = os.path.join(d, "recon.sh")
    setup = os.path.join(d, "setup.sh")
    commit = _git("rev-parse", "HEAD", cwd=d).stdout.strip() if ok else None
    print(json.dumps({"state": "ok" if ok else "failed", "action": action,
                      "recon_sh": recon if os.path.exists(recon) else None,
                      "setup_sh": setup if os.path.exists(setup) else None,
                      "commit": commit,
                      "note": "text cloned only; recon.sh/setup.sh are NOT executed by this "
                              "script — run them per the decision table on a trusted host"},
                     indent=2))
    return 0 if ok else 1


def main(argv):
    p = argparse.ArgumentParser(description="Keep recon.sh in sync with its canonical repo.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lock").set_defaults(func=cmd_lock)
    s = sub.add_parser("status")
    s.add_argument("--dir", help="a local clone of the canonical repo (for live checks)")
    s.add_argument("--local", help="path to the recon.sh to check (default: bundled copy)")
    s.add_argument("--reference", help="compare against this known-good file offline")
    s.set_defaults(func=cmd_status)
    e = sub.add_parser("ensure")
    e.add_argument("--dir", required=True, help="where to clone/update the canonical repo")
    e.set_defaults(func=cmd_ensure)
    a = p.parse_args(argv[1:])
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
