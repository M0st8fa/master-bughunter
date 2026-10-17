---
description: Audit the whole library for quality, consistency, and safety — duplicates, missing capabilities, unsupported/outdated instructions, broken links, missing deps, invalid metadata, unsafe assumptions, weak validation. Produces a severity-ranked report. Usage: /skills-audit
allowed-tools: Read, Grep, Glob, Bash(python3 *), Bash(find *), Bash(grep *), Bash(md5sum *)
---

# /skills-audit

Produce an actionable audit report. Every finding carries **severity, evidence
(file:line), affected files, and a remediation step**.

## Checks
1. **Metadata/structure** — run `scripts/validate_skills.py`: valid YAML, portable keys
   only, non-empty `name`+`description`, description within the listing cap, SKILL.md
   first line is `---`, < 500 lines.
2. **Secrets** — grep for secret-shaped strings (`*.env`, api_key=, token=, long
   high-entropy values). Any non-placeholder hit is **P0**.
3. **Duplicates/overlap** — md5 identical assets; skills with overlapping
   responsibilities (compare descriptions + bug-class map).
4. **Broken references** — every `[...](file)` and `references/...` path resolves.
5. **Dependencies** — tools named without an install/version/availability note.
6. **Consistency** — terminology, output formats, finding schema conformance,
   conflicting instructions between skills.
7. **Safety** — each active-testing skill has an authorization/scope gate and
   non-destructive-proof guidance; no unscoped mass-scan defaults.
8. **Coverage** — reconcile `COVERAGE.md` against the actual `skills/` set.
9. **Validation debt** — skills marked `validated`/`production-ready` without matching
   `TEST_RESULTS.md` evidence (a correctness defect in the classification).

## Report format
Group by severity (P0→P3). For each: `severity | finding | evidence (file:line) |
affected files | remediation`. End with a summary table and the top 5 fixes. File each
actionable item into `IMPROVEMENT_QUEUE.md`. Do not fix here — audit only.
