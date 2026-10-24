# SKILL_INDEX.md — Catalog & Routing

33 skills (1 orchestrator + 1 orchestration-support + 31 specialists) + 10 self-learning commands.
Status per `docs/QUALITY_RUBRIC.md`. 7 skills are `validated` (behavioral tests passed);
the rest pass static validation (0 errors) and are `under-review` pending their behavioral
sets. Scores filled in by `/skills-improve` and `/skills-test`. Last static run:
2026-10-23 (33/33 pass, 0 errors).

## Layer 1 — Orchestration
| Skill | Status | Purpose |
|---|---|---|
| `security-hunt` | validated | Entry router: authorization/scope gate → classify → dispatch specialists → track findings → deliverables. |
| `engagement` | under-review | Orchestration-support: persistent engagement manifest (one-time authorization+scope gate, `engagement.py`) + first-class recon-folder ingestion (`ingest_recon.py` — inventory, dedup preserving method/param/endpoint variants, scope split, specialist routing, resume). Schema `schemas/engagement.schema.json`; format `docs/ENGAGEMENT.md`. |

## Layer 2 — Specialists

### Recon & intelligence
| Skill | Status | Purpose |
|---|---|---|
| `recon-engine` | validated | Two engines: passive brain `recon.py` (keyless, sandbox-safe — crt.sh, CT, Wayback, RDAP; VT/Shodan optional via env) + active muscle `recon.sh` (Go toolchain: subfinder/dnsx/katana/gospider/httpx + opt-in nuclei/gitleaks/arjun/naabu — the standard engine for fresh active recon; execution conditional on a terminal + toolchain, see the decision table, never a silent passive-only fallback). Keys from env/`keys.env` (git-ignored); see `references/active-enumeration.md`. |
| `badrecon` | under-review | Operate/triage a self-hosted multi-engine recon system's exports. |
| `footprinting` | under-review | Tech-stack fingerprint → stack-specific known-bug attack plan. |
| `target-intelligence` | under-review | Build a passive Target Intelligence Document before hunting. |
| `js-recon` | under-review | Harvest endpoints/secrets/config from JS bundles (no requests beyond the JS). |
| `js-audit` | under-review | Deep JS bundle interpreter → 10-section attack-surface report. |
| `signup-agent` | under-review | Authorized account creation (disposable inbox + form automation) for testing. |

### Vulnerability hunters (bug class → skill)
| Skill | Status | Class |
|---|---|---|
| `bb-authz` | validated | Broken access control / IDOR / BOLA / privesc / 403 bypass |
| `idor-runner` | under-review | Safe cross-account IDOR/BOLA matrices with own-account sessions |
| `bb-xss` | under-review | XSS (reflected/stored/DOM, CSP) |
| `bb-domxss` | under-review | DOM XSS source→sink |
| `bb-sqli` | under-review | SQL injection (non-destructive proof) |
| `bb-ssrf` | under-review | Server-Side Request Forgery |
| `bb-csrf` | under-review | Modern CSRF |
| `bb-rce` | under-review | RCE / injection-to-RCE (harmless-marker proof only) |
| `bb-bizlogic` | under-review | Business logic / money flows |
| `bb-race` | under-review | Race conditions / TOCTOU |
| `bb-upload` | under-review | File-upload (serve-side) |
| `bb-oauth` | under-review | OAuth / SSO / ATO |
| `bb-graphql` | under-review | GraphQL-specific |
| `bb-pii` | under-review | PII exposure / data leaks |

### Extended-coverage specialists (new, Batch 4)
| Skill | Status | Purpose |
|---|---|---|
| `api-security` | validated | REST/GraphQL testing vs OWASP API Top 10 (2023) — BOLA/BFLA, inventory, mass assignment. |
| `cloud-security` | validated | AWS/GCP/Azure posture + IAM privesc review (external + authenticated modes). |
| `detection-engineering` | validated | Build/tune detections (Sigma→SPL/KQL/EQL), ATT&CK mapping, hypothesis-driven threat hunting. |

### Pipeline, calibration & reporting
| Skill | Status | Purpose |
|---|---|---|
| `bb-pipeline` | under-review | Full authorized-hunt pipeline orchestration. |
| `bb-chains` | validated | Escalation/chaining + 8-question validation gate. |
| `bb-disclosures` | under-review | 11,338-record paid-disclosure corpus + query engine. |
| `h1-reports` | under-review | 14,878 HackerOne reports; program-specific payout calibration. |
| `h1-playbooks` | under-review | Top-paid attack-pattern playbooks per class. |
| `bb-report` | under-review | HackerOne/Intigriti-style report writer (with tested-negative section). |
| `vuln-report` | under-review | Strict 5-section report template. |

## Self-learning commands (`commands/`)
`/skills-help` · `/skills-status` · `/skills-learn` · `/skills-improve` ·
`/skills-audit` · `/skills-research` · `/skills-test` · `/skills-update` ·
`/skills-learn-from-task` · `/skills-coverage`.

## Scorecard (rubric 0–5; gates = Technical accuracy, Safety)
Filled in as `/skills-improve` scores each skill. Four scored in Batch 2:

| Skill | Acc(gate) | Safety(gate) | Complete | Clarity | Useful | Evidence | Tools | Errors | Maint | Interop | Docs | Test | Overall | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `bb-authz` | 5 | 5 | 5 | 5 | 5 | 5 | 3 | 4 | 5 | 5 | 4 | 4 | **4.5** | validated |
| `bb-chains` | 5 | 5 | 5 | 5 | 5 | 5 | 4 | 4 | 5 | 5 | 4 | 4 | **4.7** | validated |
| `security-hunt` | 5 | 5 | 4 | 5 | 4 | 4 | 3 | 4 | 5 | 5 | 4 | 4 | **4.3** | validated |
| `recon-engine` | 4 | 5 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | **4.1** | validated |
| `api-security` | 5 | 5 | 5 | 5 | 5 | 4 | 4 | 4 | 5 | 5 | 4 | 4 | **4.5** | validated |
| `cloud-security` | 5 | 5 | 4 | 4 | 5 | 4 | 4 | 4 | 5 | 5 | 4 | 4 | **4.4** | validated |
| `detection-engineering` | 5 | 5 | 5 | 5 | 5 | 4 | 4 | 4 | 5 | 4 | 4 | 4 | **4.5** | validated |

Notes: scores are evidence-backed from the skill text + source review (see `tests/`).
Tool-integration sits at 3–4 across the set because the skills are methodology-first and
name tools without bundling them (by design — see `docs/KNOWN_LIMITATIONS.md`). Remaining
25 specialists pass static validation and are `under-review` pending their behavioral
sets and per-skill scores (Batch 3).

## Routing quick-reference
See `skills/security-hunt/SKILL.md` for the full objective→skill map. Phase order:
recon → intel → exploit → validate → report.
