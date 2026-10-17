---
description: Apply an APPROVED improvement from the queue, with preview and apply modes. Explains each change, shows affected files and impact, preserves revert/history, and never silently overwrites valuable knowledge. Usage: /skills-update <IQ-id> [--preview|--apply]
argument-hint: "<IQ-id> [--preview|--apply]"
allowed-tools: Read, Grep, Glob, Write, Edit, Bash(python3 *), Bash(git *)
---

# /skills-update

The controlled write path. Applies **only** items already marked `approved` in
`IMPROVEMENT_QUEUE.md`. `$ARGUMENTS` = an IQ id (e.g. `IQ-002`), with optional mode.

## Before changing anything
1. Resolve the IQ id; confirm its status is `approved`. If it is still `proposed`, stop
   and say it needs approval first (do not self-approve).
2. **Identify** the exact proposed change.
3. **Explain** the reason for each meaningful change.
4. **Show** affected files and expected impact.
5. **Preserve review/revert**: note the current state; prefer small diffs. If git is
   available in the target checkout, the change is a reviewable commit; otherwise record
   the before/after in `CHANGELOG.md`.

## Modes
- **`--preview`** (default when unsure): show the diff/plan and stop. Change nothing.
- **`--apply`**: make the change after the preview is acknowledged.

## Apply
1. Make the edit (respect portable frontmatter + < 500-line rule).
2. Run `scripts/validate_skills.py` on the touched skill(s).
3. Run `/skills-test` on them; record in `TEST_RESULTS.md`.
4. Update `IMPROVEMENT_QUEUE.md` (→ `applied`), `CHANGELOG.md`, and `SKILL_INDEX.md`
   (score/status). Update the skill's `metadata.status` if its classification changed.

## Never
- Never silently overwrite or delete a skill's knowledge — move to `references/` or mark
  `deprecated` with a pointer.
- Never apply an unapproved or `rejected` item.
- Never mark a skill `validated` unless its tests actually passed.
