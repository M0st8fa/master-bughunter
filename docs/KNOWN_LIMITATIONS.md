# KNOWN_LIMITATIONS.md

Honest disclosure of what is incomplete, unsupported, or unverified. Updated 2026-10-10.

## Self-learning
- **No autonomous background learning.** The library has no scheduler/daemon of its own.
  "Self-learning" here is a **human-approved, file-based loop** driven by the `/skills-*`
  commands when you run them. Nothing updates on its own.
- Learning persists only in this directory's ledgers. If the directory isn't kept with
  the skills, the learning context is lost.

## Validation status (as of this build)
- Static validation: **all 29 skills pass** (`scripts/validate_skills.py`, 0 errors).
- Behavioral tests: **framework in place, full scenario sets not yet run** for the ported
  specialists. They are therefore `under-review`, not `validated`. Quality scores in
  `SKILL_INDEX.md` are not yet filled in per skill — that is Batch 2+ work via
  `/skills-improve` and `/skills-test`.
- The static validator checks structure/metadata/links/secrets — it does **not** execute
  skills or prove that a hunting technique works against a real target.

## Coverage
- The library is strong on **web/bug-bounty**. Gaps remain (planned, see `COVERAGE.md`):
  dedicated cloud/IAM, container/Kubernetes, network-service, API-security,
  source-review, SAST/DAST orchestration, detection-engineering, and threat-hunting
  skills. CRLF/CORS/request-smuggling are only partially covered.
- Mobile and web3 are intentionally out of core scope (noted, not built).

## Tooling
- Skills name external tools (subfinder, httpx, nuclei, wpscan, etc.) but **none are
  bundled and none are assumed installed**. Each skill should check availability; where a
  tool is missing, use the documented manual equivalent.
- Scripts are stdlib-oriented where possible; some skill scripts may need common
  libraries. The validator itself is stdlib-only.

## Data assets
- `bb-disclosures` (11,338 records) and `h1-reports` (14,878 rows) are **point-in-time
  snapshots** from public aggregations; they age and are not exhaustive.
- `bb-xss` and `bb-domxss` ship an identical 222 KB payload file (dedup queued as IQ-002,
  not yet applied — deferred to avoid editing two skill bodies before their Batch-2
  hardening).

## Provenance caveats
- The mcpmarket methodology page (S6) has **unverified provenance** (author mismatch,
  unlocated repo); only its methodology was adopted, not its unsafe unscoped-scan scripts.
- Source archive shipped **live API keys** (`recon-engine/keys.env`); excluded here and
  the user was advised to rotate them. They are not recoverable from this ecosystem.

## Not a guarantee
These skills structure and accelerate authorized testing. They do not guarantee findings,
and they never substitute for the tester's judgment on scope, authorization, and impact.
