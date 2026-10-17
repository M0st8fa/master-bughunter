---
description: Show the capability coverage map and gaps across security domains, reconciled against the actual skills present. Usage: /skills-coverage [domain]
argument-hint: "[domain]"
allowed-tools: Read, Glob, Bash(ls *), Bash(find *)
---

# /skills-coverage

Report what the library covers and where the gaps are. `$ARGUMENTS` optionally narrows to
one domain.

## Procedure
1. Read `COVERAGE.md`.
2. **Reconcile** it against reality: list `skills/*/SKILL.md` and confirm each ✅ domain
   maps to a skill that exists; flag any drift (claimed-but-missing, or
   present-but-unlisted).
3. Summarize counts (✅ strong / 🟡 partial / ❌ gap) and name the gaps in priority order.
4. If `$ARGUMENTS` names a domain, show just that row plus the skills and references that
   touch it.

## Output
A compact table + the prioritized gap list + the single highest-value skill to add next
and why. If coverage drift is found, queue a fix in `IMPROVEMENT_QUEUE.md`.
