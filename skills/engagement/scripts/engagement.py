#!/usr/bin/env python3
"""engagement.py — persistent authorization + scope + progress state.

Stdlib only. Run isolated:  python3 -I engagement.py <cmd> ...

One engagement manifest (engagement.json) per engagement workspace. The authorization
and scope gate runs ONCE when the manifest is created; afterward every skill/command/
specialist reads the manifest and proceeds with routine authorized research WITHOUT
re-asking. A new or materially changed scope gets a fresh engagement (its own id);
authorization is never carried from one program to unrelated targets.

NEVER stores raw credentials, cookies, API secrets, or tokens. All string values written
into the manifest pass through redact_guard(); secret-shaped values are rejected so they
cannot leak into persistent state (spec behavior #12).

Commands
  init     create (or reuse) the manifest. Idempotent: if one exists for the same
           program it is REUSED and reported as "reused" (no re-gate on resume).
  show     print the manifest JSON.
  classify classify hosts/URLs as in_scope | out_of_scope | needs_clarification.
  set      update phase / recon status / recon dir / add a completed-work entry.
  resume   print the next incomplete phase to continue from.

Exit code 0 on success, 1 on error. 2 if init refused for a secret-shaped value.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from urllib.parse import urlsplit

SCHEMA_VERSION = "1.0"
MANIFEST_NAME = "engagement.json"

PHASE_ORDER = [
    "setup", "scope", "recon", "import", "inventory", "intel",
    "routing", "validation", "evidence", "report", "coverage", "complete",
]

# ---- secret guard --------------------------------------------------------------
# Reject values that look like real credentials/cookies/tokens before they can be
# written into persistent engagement state. Placeholders and plain tags pass.
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|apikey|secret|token|passwd|password|cookie|authorization|session|bearer)\b\s*[:=]\s*\S{6,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9._\-]{20,}"),                    # JWT
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),                # AWS key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),               # GitHub token
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),             # Slack token
    re.compile(r"\b\d{6,}:[A-Za-z0-9_\-]{30,}\b"),               # telegram bot token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(r"(?i)\b[a-z0-9]+=[A-Za-z0-9+/]{24,}={0,2}(?:;|\s|$)"),  # cookie=base64blob
]
# A value is exempt only when the WHOLE value is a placeholder (a `<...>` marker or an
# env: reference), never because a placeholder word appears somewhere inside a real
# secret (e.g. "Bearer eyJ... (see example.com)" must NOT be exempt).
_PLACEHOLDER = re.compile(r"(?i)\s*(<[^>]+>|env:\S*|xxx+|changeme|placeholder|dummy|redacted|your[\w\-]*|\.\.\.)\s*")
# Keys under which ANY non-placeholder string is treated as a credential, even when the
# value itself has no obvious secret shape (e.g. a short opaque Authorization/Cookie value).
_SENSITIVE_KEY = re.compile(r"(?i)(authorization|cookie|set-cookie|api[_-]?key|x[_-]?api[_-]?key|token|secret|passwd|password)")


class SecretInState(ValueError):
    pass


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.fullmatch(value.strip())) if isinstance(value, str) else False


def looks_secret(value: str) -> bool:
    if not isinstance(value, str) or _is_placeholder(value):
        return False
    return any(p.search(value) for p in _SECRET_PATTERNS)


def redact_guard(obj, path="manifest"):
    """Raise SecretInState if any string in obj looks like a real secret, or if any
    non-placeholder string is stored under a sensitive key (checks dict KEYS too)."""
    if isinstance(obj, str):
        if looks_secret(obj):
            raise SecretInState(f"secret-shaped value refused at {path}: {obj[:24]}...")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v.strip() and _SENSITIVE_KEY.search(str(k)) \
                    and not _is_placeholder(v):
                raise SecretInState(f"value under sensitive key refused at {path}.{k}")
            redact_guard(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            redact_guard(v, f"{path}[{i}]")
    return obj


# ---- scope matching ------------------------------------------------------------
def _host_of(target: str) -> str:
    t = target.strip().lower()
    if not t:
        return ""
    if "://" in t:
        t = urlsplit(t).netloc or t
    # strip userinfo + port
    t = t.rsplit("@", 1)[-1].split(":", 1)[0]
    return t.rstrip(".")


def _pattern_matches(host: str, pattern: str) -> bool:
    """True if host matches a scope pattern.

    Supports:
      exact        acme.com            -> acme.com only
      wildcard     *.acme.com          -> any label under acme.com AND acme.com itself
      deep wild    *.cloud.acme.com    -> any host ending in .cloud.acme.com (+ the apex)
      url pattern  https://acme.com/x  -> matched on host only
    A bare apex like 'acme.com' matches only that host, NOT its subdomains, so an
    out-of-scope apex does not silently exclude in-scope siblings.
    """
    host = _host_of(host)
    pat = _host_of(pattern) if "*" not in pattern else pattern.strip().lower()
    if "://" in pat:
        pat = urlsplit(pat).netloc or pat
    pat = pat.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    if not host or not pat:
        return False
    if pat.startswith("*."):
        base = pat[2:]
        return host == base or host.endswith("." + base)
    return host == pat


def classify_target(target: str, roots, exclusions):
    """Return in_scope | out_of_scope | needs_clarification.

    Exclusions win over inclusions (an explicitly excluded host is never tested even
    when it appears inside an in-scope app's crawl output). A host matching no in-scope
    root is needs_clarification (never silently tested)."""
    host = _host_of(target)
    if not host:
        return "needs_clarification"
    if any(_pattern_matches(host, e) for e in (exclusions or [])):
        return "out_of_scope"
    if any(_pattern_matches(host, r) for r in (roots or [])):
        return "in_scope"
    return "needs_clarification"


# ---- manifest io ---------------------------------------------------------------
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest_path(workspace: str) -> str:
    return os.path.join(workspace, MANIFEST_NAME)


def load(workspace: str):
    p = manifest_path(workspace)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def save(workspace: str, manifest: dict) -> str:
    redact_guard(manifest)
    os.makedirs(workspace, exist_ok=True)
    p = manifest_path(workspace)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, p)  # atomic: a crash mid-write never truncates the manifest
    return p


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.strip().lower()).strip("-") or "engagement"


def build_manifest(program_id, scope_source, roots, exclusions, *, platform="",
                   researcher_tag="", basis="bug-bounty-program", posture="production",
                   rate_limit=None, restrictions=None, recon_dir=None,
                   required_headers=None) -> dict:
    m = {
        "schema_version": SCHEMA_VERSION,
        "engagement_id": _slug(program_id),
        "program": {
            "id": program_id,
            "platform": platform,
            "scope_source": scope_source,
        },
        "authorization": {
            "established": True,
            "basis": basis,
            "posture": posture,
            "established_at": _now(),
        },
        "scope": {
            "in_scope_roots": list(roots or []),
            "exclusions": list(exclusions or []),
            "rate_limit_rps": rate_limit,
            "required_headers": dict(required_headers or {}),
            "testing_restrictions": list(restrictions or []),
        },
        "recon": {
            "status": "none",
            "engine": "none",
            "recon_dir": recon_dir,
            "inventory": None,
            "excluded_inventory": None,
            "tool_status": {},
        },
        "phase": "scope",
        "completed_work": [f"{_now()} setup: engagement established"],
        "notes": "",
    }
    if researcher_tag:
        m["program"]["researcher_tag"] = researcher_tag
    return m


# ---- commands ------------------------------------------------------------------
def cmd_init(a) -> int:
    existing = load(a.workspace)
    if existing is not None:
        same = existing.get("program", {}).get("id") == a.program
        if same or not a.program:
            # Resume: reuse the established manifest. No second authorization gate.
            print(json.dumps({"status": "reused", "engagement_id": existing["engagement_id"],
                              "phase": existing["phase"],
                              "authorization_established": existing["authorization"]["established"],
                              "path": manifest_path(a.workspace)}, indent=2))
            return 0
        print(json.dumps({"status": "conflict",
                          "message": "A different engagement already occupies this workspace. "
                                     "A new program needs its own workspace/engagement; authorization "
                                     "is never carried across programs.",
                          "existing_program": existing.get("program", {}).get("id"),
                          "requested_program": a.program}, indent=2), file=sys.stderr)
        return 1
    try:
        m = build_manifest(
            a.program, a.scope_source,
            _split(a.roots), _split(a.exclude),
            platform=a.platform or "", researcher_tag=a.researcher_tag or "",
            basis=a.basis, posture=a.posture,
            rate_limit=a.rate_limit, restrictions=_split(a.restrictions),
            recon_dir=a.recon_dir,
            required_headers=_kv(a.header),
        )
        path = save(a.workspace, m)
    except SecretInState as e:
        print(json.dumps({"status": "refused", "reason": str(e)}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "created", "engagement_id": m["engagement_id"],
                      "phase": m["phase"], "path": path}, indent=2))
    return 0


def cmd_show(a) -> int:
    m = load(a.workspace)
    if m is None:
        print("no engagement manifest in workspace", file=sys.stderr)
        return 1
    print(json.dumps(m, indent=2, ensure_ascii=False))
    return 0


def cmd_classify(a) -> int:
    m = load(a.workspace)
    if m is None:
        print("no engagement manifest in workspace", file=sys.stderr)
        return 1
    roots = m["scope"]["in_scope_roots"]
    excl = m["scope"]["exclusions"]
    out = {t: classify_target(t, roots, excl) for t in a.targets}
    print(json.dumps(out, indent=2))
    return 0


def cmd_set(a) -> int:
    m = load(a.workspace)
    if m is None:
        print("no engagement manifest in workspace", file=sys.stderr)
        return 1
    try:
        if a.phase:
            if a.phase not in PHASE_ORDER:
                print(f"unknown phase: {a.phase}", file=sys.stderr)
                return 1
            m["phase"] = a.phase
        if a.recon_status:
            m["recon"]["status"] = a.recon_status
        if a.recon_engine:
            m["recon"]["engine"] = a.recon_engine
        if a.recon_dir:
            m["recon"]["recon_dir"] = a.recon_dir
        if a.inventory:
            m["recon"]["inventory"] = a.inventory
        if a.excluded_inventory:
            m["recon"]["excluded_inventory"] = a.excluded_inventory
        if a.add_completed:
            m.setdefault("completed_work", []).append(f"{_now()} {a.add_completed}")
        if a.note:
            m["notes"] = (m.get("notes", "") + ("\n" if m.get("notes") else "") + a.note).strip()
        save(a.workspace, m)
    except SecretInState as e:
        print(json.dumps({"status": "refused", "reason": str(e)}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "updated", "phase": m["phase"],
                      "recon_status": m["recon"]["status"]}, indent=2))
    return 0


def cmd_resume(a) -> int:
    m = load(a.workspace)
    if m is None:
        print(json.dumps({"status": "no_engagement",
                          "next": "run `engagement.py init` to establish the engagement once"}))
        return 0
    cur = m.get("phase", "setup")
    idx = PHASE_ORDER.index(cur) if cur in PHASE_ORDER else 0
    nxt = PHASE_ORDER[min(idx, len(PHASE_ORDER) - 1)]
    print(json.dumps({"status": "resume", "engagement_id": m["engagement_id"],
                      "authorization_established": m["authorization"]["established"],
                      "current_phase": cur, "continue_from": nxt,
                      "recon_status": m["recon"]["status"],
                      "completed_work": m.get("completed_work", [])}, indent=2))
    return 0


def _split(s):
    if not s:
        return []
    return [x.strip() for x in re.split(r"[,\n]", s) if x.strip()]


def _kv(pairs):
    out = {}
    for p in pairs or []:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def build_parser():
    p = argparse.ArgumentParser(description="Persistent engagement authorization + scope + progress state.")
    p.add_argument("--workspace", default="recon", help="engagement workspace dir (default: recon)")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="create or reuse the engagement manifest (one-time gate)")
    i.add_argument("--program", required=True, help="program identifier, e.g. hackerone:acme")
    i.add_argument("--scope-source", dest="scope_source", default="", help="URL/path/statement the scope came from")
    i.add_argument("--roots", default="", help="comma/newline list of in-scope roots (supports *.wildcards)")
    i.add_argument("--exclude", default="", help="comma/newline list of out-of-scope patterns")
    i.add_argument("--platform", default="")
    i.add_argument("--researcher-tag", dest="researcher_tag", default="", help="non-secret header identifier")
    i.add_argument("--basis", default="bug-bounty-program")
    i.add_argument("--posture", default="production", choices=["production", "lab"])
    i.add_argument("--rate-limit", dest="rate_limit", type=float, default=None)
    i.add_argument("--restrictions", default="", help="comma/newline list of testing restrictions")
    i.add_argument("--recon-dir", dest="recon_dir", default=None)
    i.add_argument("--header", action="append", default=[], help="required header 'Name:value' (non-secret), repeatable")
    i.set_defaults(func=cmd_init)

    s = sub.add_parser("show")
    s.set_defaults(func=cmd_show)

    c = sub.add_parser("classify")
    c.add_argument("targets", nargs="+")
    c.set_defaults(func=cmd_classify)

    st = sub.add_parser("set")
    st.add_argument("--phase", choices=PHASE_ORDER)
    st.add_argument("--recon-status", dest="recon_status",
                    choices=["none", "running", "complete", "imported", "stale", "failed"])
    st.add_argument("--recon-engine", dest="recon_engine",
                    choices=["recon.sh", "recon.py", "imported", "none"])
    st.add_argument("--recon-dir", dest="recon_dir")
    st.add_argument("--inventory")
    st.add_argument("--excluded-inventory", dest="excluded_inventory")
    st.add_argument("--add-completed", dest="add_completed")
    st.add_argument("--note")
    st.set_defaults(func=cmd_set)

    r = sub.add_parser("resume")
    r.set_defaults(func=cmd_resume)
    return p


def main(argv):
    args = build_parser().parse_args(argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
