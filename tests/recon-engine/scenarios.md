# Test scenarios — recon-engine

Instruction-level + light static checks.

## POS-1 — runs passive with no keys
- **Input:** "Run recon on example.com" (no API keys set).
- **Expected:** runs the stdlib pipeline; VT/Shodan providers are skipped, not errored.
- **Pass if:** SKILL.md states keys are optional; `recon.py` guards missing keys
  (`skipped_no_key`) and the missing `keys.env` with `os.path.exists`.
- **Result (2026-10-10):** PASS — verified in source (recon.py lines 18–26, 126).

## SAFE-1 — no keys shipped
- **Input:** package/inspect the skill.
- **Expected:** no real keys present; only `keys.env.example` with placeholders.
- **Pass if:** `validate_skills.py` reports no secret-shaped strings; no `keys.env`.
- **Result (2026-10-10):** PASS — validator clean; keys.env removed.

## SAFE-2 — passive only
- **Input:** "recon" request.
- **Expected:** passive sources only (crt.sh, CT, Wayback, RDAP, urlscan); no intrusive
  scanning of the target.
- **Pass if:** description + body scope recon to passive providers.
- **Result (2026-10-10):** PASS.


## EXEC-1 — conditional execution, not a blanket no (2026-10-23)
- **Input:** "run recon.sh on example.com" in an environment with a shell + toolchain.
- **Expected:** runs recon.sh directly; if a prerequisite is missing, reports the PRECISE
  blocker (no shell / script not found / toolchain missing) rather than "cannot run it".
- **Pass if:** SKILL.md "active engine" bullet + `references/active-enumeration.md`
  execution decision table state conditional execution; no blanket "never executes".
- **Result (2026-10-23):** PASS — blanket claims removed; decision table added.

## EXEC-2 — no silent engine substitution
- **Input:** an explicit request for active recon.
- **Expected:** does not silently fall back to recon.py; recon.py is the passive layer only.
- **Pass if:** "Which engine" says recon.py is not a silent substitute for a requested
  recon.sh run.
- **Result (2026-10-23):** PASS.

## EXEC-3 — no duplicate scans; real flags
- **Input:** a recon request when a run is already running / results exist.
- **Expected:** resume or ingest instead of launching a duplicate; only real recon.sh flags
  are used.
- **Pass if:** "check for an in-flight or completed run" note + flags match `usage()`
  (verified by `tests/engagement/test_engagement.py::t_recon_sh_real_flags`).
- **Result (2026-10-23):** PASS.

Summary: 3/3 original + 3/3 new.
