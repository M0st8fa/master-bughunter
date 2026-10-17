# MAINTENANCE.md

How to research, test, review, and safely update the ecosystem over time.

## The loop (who writes what)
```
Observe → Collect → Verify → Compare → Propose → Test → Approve → Update → Measure
```
| Step | Command | Writes to |
|---|---|---|
| Collect/verify research | `/skills-research`, `/skills-learn` | `RESEARCH_LOG.md`, `references/research/` |
| Distill task lessons | `/skills-learn-from-task` | `LEARNING_LOG.md` |
| Propose changes | any of the above + `/skills-improve`, `/skills-audit` | `IMPROVEMENT_QUEUE.md` |
| Approve | **human** edits the queue row → `approved` | `IMPROVEMENT_QUEUE.md` |
| Apply | `/skills-update <IQ-id>` | the skill + `CHANGELOG.md` + `SKILL_INDEX.md` |
| Measure | `/skills-test`, `scripts/validate_skills.py` | `TEST_RESULTS.md` |

## Approval policy
Nothing auto-applies. A proposal must be `approved` (by you) before `/skills-update`
touches a skill. `/skills-update` previews by default. This is the guardrail against
infinite self-revision and unbounded growth.

## Evidence discipline
- Every lesson carries an **evidence class**: `verified` / `hypothesis` / `failed`.
- A `hypothesis` becomes `verified` only after a real check (reproduction, primary
  source, or a passing regression test in `TEST_RESULTS.md`).
- One success is not universal proof — record the environment caveat.

## Status promotion (see QUALITY_RUBRIC.md)
`experimental → under-review → validated → production-ready`, with `deprecated` for
retired skills. A skill reaches `validated`/`production-ready` only when its named checks
actually pass. Never relabel on belief.

## Adding a new skill
1. `skills/<name>/SKILL.md` with portable frontmatter (`name`, `description`, …).
2. Keep SKILL.md < 500 lines; put detail in `references/` and reference it.
3. Add an authorization/scope gate + non-destructive-proof guidance if it tests targets.
4. Add scenarios in `tests/<name>/`; run `/skills-test`.
5. `python3 -I scripts/validate_skills.py <name>` → 0 errors.
6. Register it in `SKILL_INDEX.md` and `COVERAGE.md`; log in `CHANGELOG.md`.

## Deprecating a skill
Mark `metadata.status: deprecated`, add a pointer to its replacement, and keep it for
history. Don't delete knowledge — move it to `references/` if still useful.

## Before packaging / committing
- `python3 -I scripts/validate_skills.py` → 0 errors (also fails on `.env` with real
  values, `.pyc`, and secret-shaped strings).
- Confirm no secrets: `grep -rnI -E '(api[_-]?key|secret|token|password)\s*[:=]' skills/`
  returns only placeholders.
- Update `CHANGELOG.md` and `TEST_RESULTS.md`.
