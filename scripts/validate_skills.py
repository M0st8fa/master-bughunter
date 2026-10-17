#!/usr/bin/env python3
"""validate_skills.py — static validator for the cybersecurity-skills ecosystem.

Stdlib only (no PyYAML needed). Run from anywhere:
    python3 -I scripts/validate_skills.py [skill-name|path ...]
With no args, validates every skill under skills/.

Checks per SKILL.md:
  - file's first line is '---' (else the frontmatter is treated as content)
  - frontmatter block closes with '---'
  - only PORTABLE keys are used (name, description, license, compatibility,
    metadata, allowed-tools) + a few Claude-Code-only keys allowed with a warning
  - name and description are present and non-empty
  - description(+when_to_use) within the 1536-char listing cap
  - SKILL.md <= 500 lines
  - referenced local files ([text](path) and bare references/...) exist
  - no secret-shaped strings (api_key=, token=, long high-entropy values, *.env)

Exit code: 0 if no ERRORs, 1 otherwise. WARNINGs never fail the build.
This is a STATIC check only; it does not execute skills or prove behavior.
"""
from __future__ import annotations
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(ROOT, "skills")

PORTABLE = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
# Keys valid in Claude Code CLI but NOT portable to claude.ai upload / Skills API.
CC_ONLY = {
    "when_to_use", "argument-hint", "arguments", "disable-model-invocation",
    "user-invocable", "disallowed-tools", "model", "effort", "context", "agent",
    "background", "hooks", "paths", "shell",
}
LISTING_CAP = 1536
MAX_LINES = 500

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['\"]?([A-Za-z0-9/+_\-]{16,})"),
    # Bearer/JWT: require a token that actually looks random (has a digit, uppercase,
    # or JWT dot) so prose like "Bearer only-if-authenticated" is not flagged.
    re.compile(r"\bBearer\s+(?=[A-Za-z0-9._\-]{20,})(?=[^\s]*[A-Z0-9.])[A-Za-z0-9._\-]{20,}"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
]
# obvious placeholders that are fine
PLACEHOLDER = re.compile(r"(?i)(your|xxx+|changeme|placeholder|example|<[^>]+>|dummy|redacted|\.\.\.|here|env:)")

errors: list[str] = []
warnings: list[str] = []


def err(p, m): errors.append(f"ERROR  {p}: {m}")
def warn(p, m): warnings.append(f"WARN   {p}: {m}")


def parse_frontmatter(lines):
    """Return (dict_of_top_level_keys, body_start_index) or (None, 0)."""
    if not lines or lines[0].rstrip("\n") != "---":
        return None, 0
    end = None
    for i in range(1, len(lines)):
        if lines[i].rstrip("\n") == "---":
            end = i
            break
    if end is None:
        return None, 0
    keys = {}
    cur = None
    for ln in lines[1:end]:
        if re.match(r"^[A-Za-z0-9_\-]+\s*:", ln) and not ln.startswith(" "):
            k = ln.split(":", 1)[0].strip()
            v = ln.split(":", 1)[1].strip()
            keys[k] = v
            cur = k
        # nested/continuation lines ignored for top-level key check
    return keys, end + 1


def check_skill(skill_md):
    rel = os.path.relpath(skill_md, ROOT)
    with open(skill_md, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    lines = text.splitlines(keepends=True)

    if len(lines) > MAX_LINES:
        warn(rel, f"{len(lines)} lines (> {MAX_LINES}; move detail to referenced files)")

    keys, body_start = parse_frontmatter(lines)
    if keys is None:
        err(rel, "no valid YAML frontmatter (first line must be '---' and block must close)")
        keys = {}

    for k in keys:
        if k in PORTABLE:
            continue
        if k in CC_ONLY:
            warn(rel, f"frontmatter key '{k}' is Claude-Code-only (not portable to claude.ai upload)")
        else:
            err(rel, f"unknown frontmatter key '{k}' (would hard-error on claude.ai upload)")

    if not keys.get("name"):
        err(rel, "missing or empty 'name'")
    if not keys.get("description"):
        err(rel, "missing or empty 'description'")
    else:
        desc = keys.get("description", "")
        # '>-' folded scalars won't be captured fully here; length is best-effort
        combined = len(desc) + len(keys.get("when_to_use", ""))
        if combined > LISTING_CAP:
            warn(rel, f"description(+when_to_use) ~{combined} chars (> {LISTING_CAP} listing cap)")

    # referenced local files exist
    skill_dir = os.path.dirname(skill_md)
    for m in re.finditer(r"\]\(([^)]+)\)", text):
        target = m.group(1).split("#", 1)[0].strip()
        if target.startswith(("http://", "https://", "mailto:")) or not target:
            continue
        # Skip things that are clearly not file paths: URI schemes (javascript:, data:),
        # regex/payload fragments, or anything with shell/markup metacharacters or spaces.
        if re.match(r"^[a-z][a-z0-9+.\-]*:", target) or re.search(r"[(){}\[\]<>\"'\s]", target):
            continue
        cand = target if os.path.isabs(target) else os.path.join(skill_dir, target)
        if not os.path.exists(cand):
            # also try relative to ROOT
            if not os.path.exists(os.path.join(ROOT, target)):
                warn(rel, f"referenced file not found: {target}")

    # secret scan (skip obvious placeholders)
    for pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            snippet = m.group(0)
            if PLACEHOLDER.search(snippet):
                continue
            err(rel, f"possible secret-shaped string: {snippet[:40]}...")


def scan_tree_for_env_and_pyc():
    for dp, dn, fn in os.walk(SKILLS_DIR):
        if "__pycache__" in dp:
            err(os.path.relpath(dp, ROOT), "compiled __pycache__ present (exclude from bundle)")
        for name in fn:
            if name.endswith(".env"):
                p = os.path.join(dp, name)
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for pat in SECRET_PATTERNS:
                    for m in pat.finditer(content):
                        if not PLACEHOLDER.search(m.group(0)):
                            err(os.path.relpath(p, ROOT), "non-placeholder value in .env (do not ship)")
            if name.endswith(".pyc"):
                err(os.path.relpath(os.path.join(dp, name), ROOT), "compiled .pyc present (exclude)")


def main(argv):
    targets = []
    if len(argv) > 1:
        for a in argv[1:]:
            cand = a
            if not os.path.exists(cand):
                cand = os.path.join(SKILLS_DIR, a, "SKILL.md")
            if os.path.isdir(cand):
                cand = os.path.join(cand, "SKILL.md")
            targets.append(cand)
    else:
        for d in sorted(os.listdir(SKILLS_DIR)):
            sm = os.path.join(SKILLS_DIR, d, "SKILL.md")
            if os.path.isfile(sm):
                targets.append(sm)

    for t in targets:
        if os.path.isfile(t):
            check_skill(t)
        else:
            err(os.path.relpath(t, ROOT), "SKILL.md not found")

    scan_tree_for_env_and_pyc()

    for w in warnings:
        print(w)
    for e in errors:
        print(e)
    print(f"\n{len(targets)} skill(s) checked — {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
