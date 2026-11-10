#!/usr/bin/env python3
"""scope_gate.py — quick-start authorization gate via OPERATOR DECLARATION.

Stdlib only. Run isolated:  python3 -I scope_gate.py <args>

The MERGED gate model (one durable state store):
  Path A — operator declaration (this script). The operator's prompt names one or more
  domains and declares them in scope ("hunt example.com", "test example.com and
  api.example.com"). The declaration IS the authorization basis for that engagement.
  This script records the verbatim quote + timestamp (runs/run-<ts>.md + audit.log),
  resolves the effective scope, and writes the SAME engagement manifest
  (engagement.py, authorization.basis = operator-declared) that every specialist reads.
  Path B — program materials / scope.yaml (engagement.py init; scope.yaml is also
  consumed here when present).

Effective scope = the declared domains AND their subdomains, minus exclusions the
operator states, minus `out_of_scope` entries in scope.yaml. Only the operator widens or
narrows scope. A host matching no root stays needs_clarification and is never tested.

scope.yaml (optional, minimal subset — comments and blank lines allowed):
  in_scope:            # list, one pattern per "- " line (contributes roots)
    - "*.acme.com"
  out_of_scope:        # list — ALWAYS becomes exclusions, whatever path established the gate
    - blog.acme.com
  rate_limit_rps: 5    # scalar
  posture: production  # production | lab
  program: bugcrowd:acme
  restrictions:        # list of testing restrictions
    - "no automated scanning"

Halt-and-log: with NEITHER a declared target NOR any scope source, nothing is authorized
— a blocked record is written (runs/blocked-<ts>.md) and exit 1. The human-judgment
gates in docs/SAFETY.md still apply AFTER this gate (destructive testing, payment flows,
mass account creation, report submission) — establishing authorization never automates
those away.

Exit 0 established/reused · 1 conflict/halt · 2 refused (secret-shaped quote).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import engagement as eng  # noqa: E402  (same directory; stdlib only)

_YAML_LIST_KEYS = ("in_scope", "out_of_scope", "restrictions")
_YAML_SCALAR_KEYS = ("rate_limit_rps", "posture", "program", "platform")


def load_scope_yaml(path):
    """Parse the minimal scope.yaml subset (lists of strings + scalars). Returns
    (dict, consumed_keys). Unknown keys are reported, never silently ignored."""
    cfg, seen = {}, []
    if not path or not os.path.exists(path):
        return cfg, seen
    cur_list = None
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip()
            if not line.strip() or line.strip().startswith("#"):
                continue
            stripped = line.strip()
            if stripped.startswith("- ") and cur_list:
                cfg.setdefault(cur_list, []).append(stripped[2:].strip().strip("'\""))
                continue
            if ":" in stripped and not stripped.startswith("- "):
                k, _, v = stripped.partition(":")
                k, v = k.strip(), v.strip().strip("'\"")
                if k in _YAML_LIST_KEYS:
                    cur_list = k
                    if v:
                        cfg.setdefault(k, []).append(v)
                    else:
                        cfg.setdefault(k, [])
                elif k in _YAML_SCALAR_KEYS:
                    cur_list = None
                    cfg[k] = v
                else:
                    cur_list = None
                    cfg.setdefault("_unknown_keys", []).append(k)
                seen.append(k)
    return cfg, seen


def _now_slug() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_run_record(workspace, kind, *, quote, declared, roots, exclusions,
                      yaml_keys, yaml_path, extra=""):
    runs = os.path.join(workspace, "runs")
    os.makedirs(runs, exist_ok=True)
    name = f"{kind}-{_now_slug()}.md"
    lines = [
        f"# {kind} — {_now_slug()}",
        "",
        f"- authorization_basis: operator-declared" if kind == "run" else "- status: blocked",
        f"- verbatim declaration: {quote or '(none supplied)'}",
        f"- declared domains: {', '.join(declared) if declared else '(none)'}",
        f"- effective in-scope roots: {', '.join(roots) if roots else '(none)'}",
        f"- effective exclusions: {', '.join(exclusions) if exclusions else '(none)'}",
        f"- scope.yaml: {yaml_path or '(not used)'}"
        + (f" (contributed: {', '.join(yaml_keys)})" if yaml_keys else ""),
    ]
    if extra:
        lines += ["", extra]
    p = os.path.join(runs, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return p


def _audit(workspace, line):
    os.makedirs(workspace, exist_ok=True)
    with open(os.path.join(workspace, "audit.log"), "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {line}\n")


def main(argv):
    ap = argparse.ArgumentParser(description="Operator-declaration authorization gate (writes the engagement manifest).")
    ap.add_argument("--workspace", default="recon")
    ap.add_argument("--target", help="one host to classify and echo (defaults to the first declared domain)")
    ap.add_argument("--operator-declared", dest="operator_declared", default="",
                    help="comma/newline list of domains the operator declared in scope")
    ap.add_argument("--quote", default="", help="verbatim operator words that declared the scope")
    ap.add_argument("--exclude", default="", help="extra out-of-scope patterns stated by the operator")
    ap.add_argument("--scope-yaml", dest="scope_yaml", default=None,
                    help="scope.yaml path (default: <workspace>/scope.yaml when present)")
    ap.add_argument("--program", default=None, help="program id (default: operator:<first-domain> or scope.yaml program)")
    ap.add_argument("--platform", default=None)
    ap.add_argument("--restrictions", default="")
    ap.add_argument("--rate-limit", dest="rate_limit", type=float, default=None)
    ap.add_argument("--header", action="append", default=[], help="'Name:value' (non-secret), repeatable")
    ap.add_argument("--posture", default=None, choices=["production", "lab"])
    ap.add_argument("--scope-source", dest="scope_source", default="", help="provenance string for the manifest")
    a = ap.parse_args(argv[1:])

    os.makedirs(a.workspace, exist_ok=True)
    yaml_path = a.scope_yaml or os.path.join(a.workspace, "scope.yaml")
    yaml_used = os.path.exists(yaml_path)
    cfg, yaml_keys = load_scope_yaml(yaml_path if yaml_used else None)

    declared = [d for d in eng._split(a.operator_declared)]
    roots = [f"*.{d}" for d in declared]                      # apex + subdomains
    for r in cfg.get("in_scope", []):                         # Path B contribution
        if r not in roots:
            roots.append(r)
    exclusions = [e for e in eng._split(a.exclude)] + list(cfg.get("out_of_scope", []))
    restrictions = [r for r in eng._split(a.restrictions)] + list(cfg.get("restrictions", []))
    rate_limit = a.rate_limit if a.rate_limit is not None else \
        (float(cfg["rate_limit_rps"]) if cfg.get("rate_limit_rps") else None)
    posture = a.posture or cfg.get("posture") or "production"
    program = a.program or cfg.get("program") or \
        (f"operator:{eng._slug(declared[0])}" if declared else None)
    platform = a.platform or cfg.get("platform") or ""

    if not roots:
        # Halt-and-log: nothing was declared and no file contributed scope.
        rec = _write_run_record(a.workspace, "blocked", quote=a.quote, declared=[],
                                roots=[], exclusions=exclusions, yaml_keys=yaml_keys,
                                yaml_path=yaml_path if yaml_used else None,
                                extra="No declared target and no scope source — nothing is "
                                      "authorized to test. Ask ONE consolidated question for "
                                      "the missing essentials; passive-only study meanwhile.")
        _audit(a.workspace, f"[GATE] blocked — no declared target and no scope source ({rec})")
        print(json.dumps({"status": "halted", "reason": "no declared target and no scope source",
                          "blocked_record": rec}), file=sys.stderr)
        return 1

    if a.quote and eng.looks_secret(a.quote):
        print(json.dumps({"status": "refused",
                          "reason": "the declaration quote looks secret-shaped; re-state it "
                                    "redacted (the quote is persisted as the audit record)"}),
              file=sys.stderr)
        return 2

    existing = eng.load(a.workspace)
    if existing is not None:
        same = existing.get("program", {}).get("id") == program
        if not same:
            print(json.dumps({"status": "conflict",
                              "existing_program": existing.get("program", {}).get("id"),
                              "requested_program": program,
                              "message": "A different engagement occupies this workspace; "
                                         "authorization never crosses programs. Use a new workspace."},
                             indent=2), file=sys.stderr)
            return 1
        rec = _write_run_record(a.workspace, "run", quote=a.quote, declared=declared,
                                roots=existing["scope"]["in_scope_roots"],
                                exclusions=existing["scope"]["exclusions"],
                                yaml_keys=yaml_keys, yaml_path=yaml_path if yaml_used else None,
                                extra="Manifest already established for this program — REUSED "
                                      "(no second gate), run record appended for the audit trail.")
        _audit(a.workspace, f"[GATE] operator-declared {', '.join(declared) or '(file scope)'} -> reused "
                            f"engagement {existing['engagement_id']} ({rec})")
        print(json.dumps({"status": "reused", "engagement_id": existing["engagement_id"],
                          "phase": existing["phase"], "run_record": rec,
                          "target_classification": eng.classify_target(
                              a.target or declared[0] if declared else a.target or "",
                              existing["scope"]["in_scope_roots"],
                              existing["scope"]["exclusions"])}, indent=2))
        return 0

    source = a.scope_source or (f"operator declaration ({_now_slug()}; quote in runs/)"
                                + (f" + {os.path.basename(yaml_path)}" if yaml_used else ""))
    m = eng.build_manifest(
        program, source, roots, exclusions,
        platform=platform, basis="operator-declared", posture=posture,
        rate_limit=rate_limit, restrictions=restrictions,
        required_headers=eng._kv(a.header),
    )
    if yaml_keys:
        m.setdefault("notes", "")
        m["notes"] = (m["notes"] + "\n" if m["notes"] else "") + \
            f"scope.yaml contributed: {', '.join(yaml_keys)}"
    try:
        eng.save(a.workspace, m)
    except eng.SecretInState as e:
        print(json.dumps({"status": "refused", "reason": str(e)}), file=sys.stderr)
        return 2

    rec = _write_run_record(a.workspace, "run", quote=a.quote, declared=declared,
                            roots=roots, exclusions=exclusions, yaml_keys=yaml_keys,
                            yaml_path=yaml_path if yaml_used else None)
    _audit(a.workspace, f"[GATE] operator-declared {', '.join(declared) or '(file scope)'} -> "
                        f"established engagement {m['engagement_id']} ({rec})")
    targets = ([a.target] if a.target else []) + declared
    print(json.dumps({"status": "established", "engagement_id": m["engagement_id"],
                      "program": program, "basis": "operator-declared",
                      "effective_roots": roots, "exclusions": exclusions,
                      "scope_yaml_used": yaml_used,
                      "run_record": rec,
                      "classification": {t: eng.classify_target(t, roots, exclusions)
                                         for t in targets if t}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
