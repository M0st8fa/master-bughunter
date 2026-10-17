---
description: Improve one skill or evaluate the whole library against the quality rubric, then propose a prioritized plan and implement justified, tested changes. Usage: /skills-improve <skill-name | all>
argument-hint: "<skill-name | all>"
allowed-tools: Read, Grep, Glob, WebFetch, WebSearch, Write, Edit, Bash(python3 *)
---

# /skills-improve

Raise quality with evidence, not vibes. `$ARGUMENTS` = a skill name, or `all`.

## Workflow
1. **Inspect** the current implementation: `skills/<name>/SKILL.md` and its supporting
   files (or every skill if `all`).
2. **Evaluate** against `docs/QUALITY_RUBRIC.md` — score the 12 categories 0–5 with a
   one-line justification each. Note the two gate categories (Technical accuracy,
   Safety) explicitly.
3. **Identify** concrete weaknesses: missing workflow steps, unsupported claims, stale
   tool flags, no error handling, no tests, copy-pasted reference bulk, unsafe defaults.
4. **Research** only the gaps that need it (delegate to the method of `/skills-research`).
5. **Propose** a prioritized plan (P0 safety/correctness first). Add items to
   `IMPROVEMENT_QUEUE.md`.
6. **Implement** the justified changes that are clearly correct and in-scope now. Keep
   SKILL.md < 500 lines; move detail to referenced files; keep frontmatter portable
   (`name, description, license, compatibility, metadata, allowed-tools` only).
7. **Test for regressions**: run `scripts/validate_skills.py`; run `/skills-test` on the
   changed skill. Record in `TEST_RESULTS.md`.
8. **Document** in `CHANGELOG.md` and update the skill's score + status in
   `SKILL_INDEX.md`. State remaining limitations honestly.

## Rules
- Never delete valuable knowledge; move it to `references/` or mark `deprecated` with a
  pointer, don't erase.
- A skill may only reach `validated`/`production-ready` when the rubric's named checks
  actually pass.
