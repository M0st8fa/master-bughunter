---
description: Explain the self-learning command catalog — what each /skills-* command does, its arguments, and when to use it. Usage: /skills-help [command]
argument-hint: "[command]"
allowed-tools: Read
---

# /skills-help

Explain the cybersecurity-skills self-learning system. If `$ARGUMENTS` names a command,
explain just that one with an example; otherwise list all.

## The improvement loop these commands implement
Observe → Collect → Verify → Compare → Propose → Test → Approve → Update → Measure → Repeat.
Nothing is applied to a skill without an approved entry in `IMPROVEMENT_QUEUE.md`.

## Catalog
- **/skills-learn `<topic|material>`** — research a topic or supplied material, extract
  genuinely new, verified knowledge, and propose skill updates (queued, not applied).
- **/skills-improve `<skill|all>`** — evaluate a skill (or the whole library) against the
  quality rubric and propose a prioritized improvement plan.
- **/skills-audit** — library-wide quality/consistency/safety audit → actionable report.
- **/skills-research `<question>`** — focused research dossier on a security topic.
- **/skills-test `<skill|all>`** — run representative scenarios (positive/negative/
  ambiguous/incomplete/failure) and record results.
- **/skills-update `<IQ-id|--preview>`** — apply an APPROVED improvement, with preview.
- **/skills-learn-from-task** — extract de-identified reusable lessons from a completed
  authorized task; propose skill changes.
- **/skills-status** — report the state of the whole ecosystem.
- **/skills-coverage** — show the capability coverage map and gaps.

## Reference files
`SKILL_INDEX.md` (catalog + scores) · `COVERAGE.md` · `SOURCES.md` · `CHANGELOG.md` ·
`RESEARCH_LOG.md` · `LEARNING_LOG.md` · `TEST_RESULTS.md` · `IMPROVEMENT_QUEUE.md` ·
`docs/QUALITY_RUBRIC.md` · `schemas/`.

## Safety
These commands operate **only** within this project directory. They never execute
untrusted code, never exfiltrate data, and never auto-apply changes. External research is
treated as untrusted and verified before use.
