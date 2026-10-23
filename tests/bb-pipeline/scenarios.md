# Test scenarios — bb-pipeline

Instruction-level assertions on the pipeline's SKILL.md (checks the text, not a live run).

## ENG-1 — engagement established once, reused on resume (2026-10-23)
- **Input:** an in-scope program; later "continue the hunt".
- **Expected:** loads/creates the manifest once; on resume reuses it (no re-confirm scope),
  continues from the saved phase.
- **Pass if:** the intro + Phase 0 load/create the manifest via `engagement.py`, and
  Session continuity loads `engagement.py resume`.
- **Result (2026-10-23):** PASS.

## ENG-2 — no per-phase approval
- **Input:** routine progression through the pipeline phases.
- **Expected:** advances automatically; does not ask the user to approve/advance each phase.
- **Pass if:** intro states "do not ask the user to approve or advance each phase".
- **Result (2026-10-23):** PASS.

## IMPORT-1 — existing recon imported (Phase 1b)
- **Input:** a supplied recon directory.
- **Expected:** ingests via `ingest_recon.py` instead of re-running recon; schedules every
  distinct in-scope URL; keeps out-of-scope URLs excluded.
- **Pass if:** Phase 0 recon-branch + Phase 1b are present.
- **Result (2026-10-23):** PASS.

## ACTIVE-1 — recon.sh is the standard active engine
- **Input:** active depth needed on the in-scope set.
- **Expected:** hands off to recon-engine's `recon.sh`; does not downgrade a requested
  active run to passive-only.
- **Pass if:** Phase 1 notes recon.sh as the standard active engine + no silent downgrade.
- **Result (2026-10-23):** PASS.

## COVERAGE-1 — honest coverage
- **Input:** declaring a hunt complete with pending URLs or a tool failure.
- **Expected:** does not claim full coverage; reports gaps.
- **Pass if:** the Coverage review section reads `inventory.jsonl` + `recon.tool_status`.
- **Result (2026-10-23):** PASS.

## PORTABLE-1 — no hardcoded absolute paths
- **Input:** the bb-disclosures calibration command.
- **Expected:** uses a portable `<skills>/bb-disclosures/...` path, not a machine-specific
  `C:/Users/Admin/...` path.
- **Pass if:** the hardcoded Windows path is gone.
- **Result (2026-10-23):** PASS.

Summary: 6/6 pass (instruction-level).
