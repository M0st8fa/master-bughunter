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

Summary: 3/3 pass.
