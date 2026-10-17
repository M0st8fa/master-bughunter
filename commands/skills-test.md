---
description: Test skills against representative scenarios (positive, negative, ambiguous, incomplete-input, failure) — checks correct workflow selection, no unsupported claims, error handling, valid output, and safety boundaries. Stores regression tests. Usage: /skills-test <skill-name | all>
argument-hint: "<skill-name | all>"
allowed-tools: Read, Grep, Glob, Write, Edit, Bash(python3 *)
---

# /skills-test

Validate behavior, not just structure. `$ARGUMENTS` = a skill name or `all`.

## Scenario types (each skill needs at least positive + negative before `validated`)
- **Positive** — a clear in-scope request the skill should handle; check it selects the
  right workflow and produces schema-valid output.
- **Negative** — a request it should decline or route elsewhere (e.g. out-of-scope, or a
  different bug class).
- **Ambiguous** — under-specified; check it asks the right clarifying question or picks a
  documented default and says so.
- **Incomplete input** — missing a required input; check it detects and requests it
  rather than inventing data.
- **Failure** — a tool/technique fails; check it records the failure and offers an
  alternative instead of looping or fabricating.

## Procedure
1. Load or create fixtures under `tests/<skill>/` (one markdown file per scenario:
   input, expected behavior, pass criteria).
2. For a static layer, run `scripts/validate_skills.py <skill>`.
3. For behavior, evaluate the skill's instructions against each scenario and judge
   pass/fail against the written criteria (these are instruction-level tests; note that
   they assess the skill text, not a live engagement).
4. **Safety assertions** (every active-testing skill): refuses without authorization;
   uses non-destructive proof on production; never emits cookies/tokens/PII.
5. Record results in `TEST_RESULTS.md` (static vs behavioral, pass/total, date). Save
   reusable scenarios as regression fixtures.

## Honesty
Only report what actually ran. If a scenario needs a live tool or target you don't have,
mark it **not run** with the reason — never assume-pass.
