# USAGE.md

## Start with the orchestrator
Describe your objective and the orchestrator handles routing:
```
Use security-hunt — I have an in-scope program (scope: *.example.com),
help me find and validate access-control bugs.
```
`security-hunt` confirms authorization/scope, then dispatches recon → intel → the right
`bb-*` hunter → validation → reporting. It keeps one evidence-first finding record
(`schemas/finding.schema.json`).

## Invoke a specialist directly
If you already know the class:
```
Use bb-authz on this endpoint (two of my own accounts attached) …
Use recon-engine on example.com (passive) …
Use bb-report to write up finding F-2026-001 from my evidence log …
```

## Calibrate before you submit
```
Use bb-disclosures — what do access-control bugs pay, and is my finding strong enough?
Use h1-reports — what does <program> historically pay for IDOR?
```

## Drive the self-learning loop
- `/skills-status` — current state of the library.
- `/skills-coverage` — what's covered and the gaps.
- `/skills-research <question>` — produce a dossier (→ `references/research/`).
- `/skills-learn <topic|url|path>` — extract verified knowledge → queue proposals.
- `/skills-improve <skill|all>` — score + improve against the rubric.
- `/skills-audit` — library-wide quality/safety report.
- `/skills-test <skill|all>` — run representative scenarios; record results.
- `/skills-learn-from-task` — distill de-identified lessons from a finished task.
- `/skills-update <IQ-id> [--preview|--apply]` — apply an **approved** change.
- `/skills-help [command]` — details and examples.

## Typical improvement cycle
```
/skills-audit                 → files issues into IMPROVEMENT_QUEUE.md
# review the queue, mark an item 'approved'
/skills-update IQ-00X --preview   → see the diff/plan
/skills-update IQ-00X --apply     → apply + validate + test + log
```

## Golden rules in use
- No active testing without authorization/scope — the skills will ask.
- Evidence over claims: a finding stays `hypothesis` until you have an artifact.
- Own-account PoCs only for cross-account bugs.
- Nothing sensitive (keys, cookies, PII) in reports, logs, or lessons.
