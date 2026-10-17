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

## Notes
- IQ-001 and IQ-003/004 are being actioned in Batch 1 (will move to `applied` in
  CHANGELOG when done). Others are tracked for later batches.
