---
description: Report the state of the whole cybersecurity-skills ecosystem — counts, statuses, coverage, defects, pending proposals, last audit/test. Usage: /skills-status
allowed-tools: Read, Bash(ls *), Bash(find *), Bash(grep *), Bash(wc *)
---

# /skills-status

Produce an honest state-of-the-ecosystem report. Read, don't assume.

## Gather
1. **Skills:** count directories under `skills/` with a `SKILL.md`; group by layer
   (orchestration / specialist) and by `metadata.status` where present.
2. **Commands:** list `commands/*.md`.
3. **Coverage:** summarize `COVERAGE.md` (✅ / 🟡 / ❌ counts; name the gaps).
4. **Quality:** from `SKILL_INDEX.md`, the status distribution (experimental →
   production-ready) and any skill failing a gate category.
5. **Research incorporated:** count `RESEARCH_LOG.md` entries; note how many are
   `Verified: yes`.
6. **Known defects / pending proposals:** open items in `IMPROVEMENT_QUEUE.md` by
   priority and status.
7. **Validation:** last static + behavioral runs from `TEST_RESULTS.md` (say "not yet
   run" where true).
8. **Dependencies/compatibility:** note any skill requiring external tools not assumed
   present.

## Report format
A short dashboard:
```
Skills: N total (X specialists, 1 orchestrator) — status: a validated / b under-review / c experimental
Commands: M
Coverage: P strong, Q partial, R gaps  (gaps: …)
Research: S entries (T verified)
Open proposals: P0=.. P1=.. P2=..
Last static check: <date|never>   Last behavioral: <date|never>
Top risks / defects: …
```
End with the 3 highest-value next actions. State uncertainty plainly; never report a
test as passed that was not run.
