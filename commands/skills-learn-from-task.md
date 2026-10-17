---
description: Extract reusable, de-identified lessons from a completed authorized task — what worked, what failed, false positives, misleading assumptions — and propose skill changes and regression tests. Usage: /skills-learn-from-task [task-notes-path]
argument-hint: "[path to task notes / evidence]"
allowed-tools: Read, Grep, Glob, Write, Edit
---

# /skills-learn-from-task

Convert one finished authorized task into durable, generalized knowledge. `$ARGUMENTS` =
a path to the task's notes/evidence (if empty, use the current session's task context).

## Workflow
1. **Review** the task's relevant inputs, actions, outputs, and evidence.
2. **Separate** what worked from what failed, and **generalizable** knowledge from
   **target-specific** detail.
3. **Identify** misleading assumptions and **false positives** encountered.
4. **Propose** reusable workflow improvements for the affected skills.
5. **Sanitize — mandatory:** strip secrets, credentials, tokens, cookies, personal data,
   and target-specific identifiers (hostnames, account ids, internal URLs). A lesson must
   be safe to share.
6. **Write lessons** to `LEARNING_LOG.md` conforming to `schemas/lesson.schema.json`,
   each with an **evidence class** (`verified` / `hypothesis` / `failed`) and, for a
   single success, an `environment_caveat` — one win is not universal proof.
7. **Create regression tests** where useful (fixtures under `tests/`).
8. **Queue** skill changes in `IMPROVEMENT_QUEUE.md` (status `proposed`). Apply only via
   `/skills-update` per the approval policy.

## Guardrails
- Never persist anything sensitive. If unsure whether a detail is identifying, drop it.
- A false positive is as valuable as a success — record it so the library stops
  repeating it (mirrors a false-positive ledger).
