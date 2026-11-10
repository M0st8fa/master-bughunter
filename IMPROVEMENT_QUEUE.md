# IMPROVEMENT_QUEUE

Proposed changes awaiting review. Nothing here is applied automatically.
`/skills-update` applies an APPROVED item; `/skills-improve`, `/skills-learn`,
`/skills-audit`, `/skills-learn-from-task` add items here.

Status: `proposed` → `approved` → `applied` (or `rejected`).
Priority: P0 (safety/correctness) · P1 (high value) · P2 · P3.

| ID | Pri | Status | Target | Change | Why / evidence | Added |
|----|-----|--------|--------|--------|----------------|-------|
| IQ-001 | P0 | **applied** | recon-engine | Removed `keys.env`; keys read from env / git-ignored local file; added `keys.env.example` + `.gitignore` | Live keys shipped in archive (SOURCES.md S0) | 2026-10-10 |
| IQ-002 | P1 | **rejected** | bb-xss, bb-domxss | ~~Dedupe identical payloads.txt → shared ref~~ | REJECTED: Claude Code skills are installed individually, so a root-level `references/` file is not co-located when a skill is copied into `.claude/skills/`. Per-skill `assets/payloads.txt` keeps each skill self-contained; the 222KB duplication is the correct tradeoff for portability. | 2026-10-10 |
| IQ-003 | P1 | **applied** | security-hunt | Added orchestration entry skill | No router existed in archive | 2026-10-10 |
| IQ-004 | P1 | **applied** | commands/ | Added `/skills-*` self-learning catalog (10 commands) | Core requirement, absent in archive | 2026-10-10 |
| IQ-005 | P2 | **partially applied** | (new) api/cloud/detection + (planned) container/network | Fill coverage gaps | COVERAGE.md gap analysis — api-security, cloud-security, detection-engineering built & validated; container-k8s, network-service, source-review, sast-dast still planned | 2026-10-10 |
| IQ-006 | P2 | proposed | all archive skills | Normalize to quality rubric sections | Uneven structure across 28 skills | 2026-10-10 |
| IQ-007 | P1 | **applied** | bb-report (+vuln-report, bb-chains, bb-pipeline, security-hunt, finding.schema) | Bugcrowd VRT integration: `bb-report/references/vrt-mapping.md` (official snapshot 2026-07-08) + VRT line in report formats + gate question 9 + P1/P2 reward-band hunting priorities + optional `vrt` finding field | User-approved 2026-11-08; mission requires VRT alongside CVSS | 2026-11-08 |
| IQ-008 | P0 | **applied** | (repo-wide) .gitattributes + recon_sync.py + tests | Force eol=lf for .sh/.py/.lock/.json/.jsonl/.csv/.md; renormalize CRLF-committed blobs; recon_sync hashes LF-normalized text and validates setup.sh pin; test no longer mutates the vendored recon.sh | CRLF working trees broke recon.sh execution (WSL/Git Bash) and falsely reported `drifted-from-lock` on Windows | 2026-11-08 |
| IQ-009 | P0 | **applied** | recon.sh, api_discover.sh, recon.py, ingest_recon.py, idor_matrix.py | Security/correctness fixes: recon.sh untrusted-data→`bash -c` injection replaced with env-passing workers; api_discover.sh unquoted `$AUTH` (header never sent + token leaked as a curl URL) → quoted array; recon.py dot-boundary scope matching (`evilacme.com` no longer in scope for `*.acme.com`) + early scope-file validation; ingest_recon.py KeyError guard + IPv6 netloc + distinct needs_clarification state; idor_matrix.py per-jar sessions (no cookie cross-contamination), incremental saves, unresolved-placeholder skip, SKILL.md aligned | User-approved 2026-11-08 (audit P-3…P-7) | 2026-11-08 |
| IQ-010 | P1 | **applied** | (new) engagement/scope_gate.py, security-hunt, engagement, bb-pipeline, ENGAGEMENT.md, (new) bb-cache, SAFETY.md, SKILL_INDEX, README | Merged authorization architecture (option c): operator-declaration quick-start (`scope_gate.py` + scope.yaml) writes the SAME engagement manifest; runs/run-<ts>.md + audit.log records; halt-and-log when nothing is declared; SAFETY.md human gates preserved. `bb-cache` skill ported from local; program-specific skills documented as local-only | User-approved 2026-11-08 (P-8 merge); dangling local refs (scope_gate.py/bb-writeups) resolved | 2026-11-08 |

## Notes
- IQ-001 and IQ-003/004 are being actioned in Batch 1 (will move to `applied` in
  CHANGELOG when done). Others are tracked for later batches.
