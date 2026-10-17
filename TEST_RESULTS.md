# TEST_RESULTS.md — Validation History

Distinguishes **static checks** (structure/metadata/links — can run without executing
skills) from **behavioral checks** (did the skill pick the right workflow, respect
safety, produce valid output on representative scenarios). Newest first.

Honesty rule: only checks that actually ran are listed. Anything not yet tested is
named as untested, not assumed-passing.

---

## Static checks

### 2026-10-17 — after recon-engine active-engine integration ✅ 32/32 pass
- `python3 -I scripts/validate_skills.py` → **0 errors, 0 warnings**, 32 skills checked.
- Confirms the rewritten `recon-engine/SKILL.md` keeps portable-only frontmatter, stays
  under the listing cap and the 500-line limit, carries no secret-shaped strings, and that
  its referenced files (`scripts/recon.sh`, `references/active-enumeration.md`) exist.
- Added `scripts/recon.sh` (user-supplied, inspected not executed): manual secret grep →
  only empty `SLACK_WEBHOOK`/`DISCORD_WEBHOOK` vars + classification patterns; no keys.
- **Static only** — recon.sh's live behavior (Go toolchain vs a real target) is NOT tested
  here; it requires those tools installed and an authorized target, out of this sandbox.

### 2026-10-10 — first run ✅ 29/29 pass
- `python3 -I scripts/validate_skills.py` → **0 errors, 0 warnings**, 29 skills checked.
- Checks exercised: valid YAML frontmatter (first line `---`, block closes),
  portable-keys-only, non-empty `name`+`description`, listing-cap length, referenced
  files exist, no secret-shaped strings, no `.env` with real values, no `.pyc`/caches.
- Fixes made during the run: tightened the Bearer-token heuristic and the link checker to
  remove false positives (documentation prose / payload strings).
- **This is a static check only** — it validates structure/metadata/links/secrets, not
  skill behavior against a target.

## Behavioral checks

### 2026-10-10 — Batch 2: instruction-level behavioral tests (4 skills)
These are **instruction-level** tests: each asserts the SKILL.md actually instructs the
required behavior (correct routing, refusal without authorization, evidence discipline,
safety). They test the skill text, not a live engagement against a target.

| Skill | Scenarios | Pass | Fixture |
|---|---|---|---|
| `security-hunt` | POS/NEG/AMB/INC/FAIL/SAFE | 6/6 | tests/security-hunt/scenarios.md |
| `bb-authz` | POS/NEG/SAFE/INC | 4/4 | tests/bb-authz/scenarios.md |
| `bb-chains` | POS/NEG/GATE/SAFE | 4/4 | tests/bb-chains/scenarios.md |
| `recon-engine` | POS/SAFE×2 | 3/3 | tests/recon-engine/scenarios.md (+ source-verified key guards) |

All four now meet the `validated` criteria (static pass + positive & negative behavioral
pass, both gate categories ≥3). Remaining 25 skills: fixtures pending (Batch 3), status
`under-review`.

### Not yet run
- Full scenario sets (ambiguous/incomplete/failure) for the remaining specialists.
- Live execution of skill scripts against lab targets (requires a lab + tools; out of
  this environment).

---

## Summary table (updated each run)
| Date | Scope | Static pass/total | Behavioral pass/total | Notes |
|------|-------|-------------------|-----------------------|-------|
| 2026-10-10 | all skills | 29/29 | not run | Batch 1 backbone; behavioral sets pending |
| 2026-10-10 | security-hunt, bb-authz, bb-chains, recon-engine | 4/4 | 17/17 | Batch 2 instruction-level; these 4 → validated |
| 2026-10-10 | all skills (incl. 3 new) | 32/32 | — | Batch 4: +api-security, cloud-security, detection-engineering |
| 2026-10-10 | api-security, cloud-security, detection-engineering | 3/3 | 12/12 | Batch 4 instruction-level; these 3 → validated |
| 2026-10-17 | all skills | 32/32 | — | recon-engine: +active engine recon.sh (static only; live run out of sandbox) |
