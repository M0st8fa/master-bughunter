# COVERAGE.md — Capability Coverage & Gap Analysis

Legend: ✅ strong (dedicated skill) · 🟡 partial (covered inside another skill) ·
❌ gap (planned) · ⬜ out of core scope (noted only).
Base = attached archive's 28 skills. Updated 2026-10-10.

## Web application security
| Domain | Status | Skill(s) |
|---|---|---|
| Reconnaissance / attack-surface mapping | ✅ | recon-engine, badrecon, footprinting, target-intelligence |
| JS / bundle analysis | ✅ | js-recon, js-audit |
| XSS (reflected/stored/DOM) | ✅ | bb-xss, bb-domxss |
| SQL injection | ✅ | bb-sqli |
| SSRF | ✅ | bb-ssrf |
| CSRF | ✅ | bb-csrf |
| RCE / injection-to-RCE | ✅ | bb-rce |
| Broken access control / IDOR / BOLA | ✅ | bb-authz, idor-runner |
| Business logic | ✅ | bb-bizlogic |
| Race conditions / TOCTOU | ✅ | bb-race |
| File upload (serve-side) | ✅ | bb-upload |
| OAuth / SSO / ATO | ✅ | bb-oauth |
| GraphQL | ✅ | bb-graphql |
| PII / data exposure | ✅ | bb-pii |
| CRLF / HTTP response splitting / host-header | ❌ | *(gap — Agentic-Bug-Hunter has it)* |
| CORS misconfiguration | 🟡 | partially in js-audit/authz; no dedicated skill |
| Request smuggling / desync | 🟡 | mentioned in csrf/rce; no dedicated skill |
| Open redirect | 🟡 | within oauth/xss |

## Workflow / knowledge / reporting
| Domain | Status | Skill(s) |
|---|---|---|
| Hunting pipeline / orchestration | 🟡→✅ | bb-pipeline (+ new `security-hunt` router) |
| Escalation / chaining / validation gate | ✅ | bb-chains |
| Paid-disclosure calibration corpus | ✅ | bb-disclosures, h1-reports, h1-playbooks |
| Report writing | ✅ | bb-report, vuln-report |
| Account creation for testing | ✅ | signup-agent |

## Coverage GAPS to fill (prioritized — Batch 4)
| Domain | Status | Plan |
|---|---|---|
| API security (REST/GraphQL authz, versioning, methods) | ✅ | `api-security` (new, validated) |
| Cloud security & IAM (AWS/GCP/Azure, metadata, perms) | ✅ | `cloud-security` (new, validated) |
| Container / Kubernetes / infra | ❌ | new `container-k8s-security` skill (planned) |
| Network service assessment | ❌ | new `network-service-assessment` skill (planned) |
| DNS / TLS / HTTP / protocol analysis | 🟡 | partly recon; consider `protocol-analysis` |
| Source code / secure code review | 🟡 | js-audit only; new `source-review` skill (planned) |
| SAST / DAST orchestration + result normalization | ❌ | new `sast-dast-orchestration` skill (planned) |
| Detection engineering & log analysis | ✅ | `detection-engineering` (new, validated; incl. threat hunting) |
| Threat hunting / incident investigation | 🟡 | hunt mode inside `detection-engineering`; dedicated IR skill planned |
| Threat intel / attack-path analysis | ❌ | new `threat-intel-attackpath` skill |
| Vulnerability triage / impact / reproducibility | 🟡 | in bb-chains; consider dedicated `vuln-triage` |
| Mobile application security | ⬜ | out of core scope; add only if user wants |
| Web3 / smart contracts | ⬜ | present in sources; out of core scope |

## Cross-cutting (added in Batch 1)
| Capability | Status | Where |
|---|---|---|
| Orchestration / scope & authorization gate | ✅ | `security-hunt` |
| Self-learning command system | ✅ | `commands/skills-*` |
| Quality scoring & status classification | ✅ | `docs/QUALITY_RUBRIC.md` |
| Shared references (deduped) | 🟡 | `references/` (building) |
| Test / regression framework | 🟡 | `tests/`, TEST_RESULTS.md (building) |
