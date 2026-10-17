# SOURCES.md — Source Inventory & Provenance

Status legend: ✅ fully examined · 🟡 partially examined · ❌ inaccessible
Last updated: 2026-10-10

This ecosystem is built for **authorized, defensive security work** (bug bounty on
in-scope programs, threat hunting, detection engineering, authorized pentest
methodology, responsible disclosure). All sources below were treated as **untrusted
data**: inspected, never executed. Downloaded code was read, not run.

---

## S0 — Attached archive `skills.tar.gz` ✅

- **Received:** 2026-10-10, attached to the project thread (1.43 MB gzip, 7.2 MB uncompressed).
- **Extracted to (isolated):** scratchpad `archive_extract/` — not executed.
- **Contents:** 28 Claude Code skills under `skills/`, 125 entries total. Correct
  Claude Code frontmatter (`name` + `description` only) on every SKILL.md.
- **This is the highest-quality, most coherent base** of all sources and the
  foundation of the new ecosystem.

### Skills in the archive (28)
Recon/intel: `badrecon`, `recon-engine`, `footprinting`, `target-intelligence`,
`js-recon`, `js-audit`, `signup-agent`.
Vuln hunters: `bb-authz`, `bb-bizlogic`, `bb-chains`, `bb-csrf`, `bb-domxss`,
`bb-graphql`, `bb-oauth`, `bb-pii`, `bb-race`, `bb-rce`, `bb-sqli`, `bb-ssrf`,
`bb-upload`, `bb-xss`.
Orchestration/data: `bb-pipeline`, `bb-disclosures` (11,338-record paid-disclosure
corpus, JSONL), `h1-reports` (14,878 HackerOne reports, CSV), `h1-playbooks`
(top-paid patterns per class), `idor-runner`, `bb-report`, `vuln-report`.

### Notable data assets
- `bb-disclosures/data/disclosures.jsonl` — 11,338 records (id, title, platform,
  program, researcher, url, vulnerabilityClass, weakness, severity, bounty, kind,
  disclosedAt). 4.6 MB. Source attributed to bug-bounty-disclosures.vercel.app.
- `h1-reports/data/data.csv` — 14,878 rows (program, title, link, upvotes, bounty,
  vuln_type). 2.0 MB. Source attributed to reddelexc/hackerone-reports.
- `bb-xss/assets/payloads.txt` and `bb-domxss/assets/payloads.txt` — **byte-identical**
  (md5 `1ee4b4…`, 222 KB each). Dedup opportunity → single shared reference.
- `bb-sqli/assets/sql-wordlist.txt` (33 KB).

### ⚠️ SECURITY FINDING — live credentials in the archive
- `skills/recon-engine/keys.env` contains **non-placeholder** values:
  `VT_API_KEYS` (~194 chars, i.e. one or more VirusTotal keys) and
  `SHODAN_API_KEY` (32 chars, matches Shodan key length).
- **Action taken:** values were NOT read beyond length/shape, NOT copied into the
  new ecosystem, and will NOT appear in any deliverable or the final ZIP.
- **Recommended to user:** treat these as compromised and **rotate them** (they have
  been sitting in a distributable archive). The new `recon-engine` reads keys from
  the environment / a git-ignored local file only.
- Compiled `__pycache__/*.pyc` files (js_audit, footprint) were found and will be
  **excluded** (untrusted build artifacts; source `.py` kept and reviewed).

---

## S1 — github.com/0xN0RMXL/BugBountySkills ✅ (cloned, read)

- **What it is:** A knowledge vault — "615 markdown files, ~76k lines." NOT skills
  format (0 SKILL.md). Dirs: `KNOWLEDGE_BASE`, `CHECKLISTS`, `REFERENCE`, `SAMPLES`,
  `MASTER_SYSTEM_PROMPTS`, `SKILL_FILES`, `scripts` (7 py).
- **Value:** Deep per-class reference content and checklists. Best used as **Layer-3
  shared reference material** (curated, deduped), not as drop-in skills.
- **License:** present (LICENSE) — attribution to be preserved for any imported content.

## S2 — github.com/elementalsouls/Claude-BugHunter ✅ (cloned, read)

- **What it is:** Mature Claude Code **plugin** (`.claude-plugin/`): 83 SKILL.md,
  15 slash commands (`commands/*.md`), Python `engine/`, `eval/` harness,
  `ENGAGEMENTS.md` scaffolding, Burp MCP integration, 681 disclosed-report patterns.
- **Command format confirmed:** `.md` file with `name` + `description` frontmatter and
  a `## Usage` body (e.g. `recon.md`, `hunt.md`, `triage.md`, `validate.md`,
  `report.md`, `remember.md`, `memory-gc.md`).
- **Value:** command catalog patterns, engagement-folder scaffolding, enterprise
  identity + infra attack matrices, eval harness design.
- **Overlap:** heavy with S0 on web vuln classes.

## S3 — github.com/awarexone/Agentic-Bug-Hunter (skills/) ✅ (cloned, read)

- **What it is:** Claude Code plugin + CLI: 20 SKILL.md, per-vuln `commands/`
  (arsenal, bypass-403, cors, crlf, cloud-recon, chain, dashboard, autopilot…),
  `hooks/`, 173 py, `web3/`, `rules/`, `install_tools.sh`.
- **Value:** command-per-technique pattern, hooks model, cloud-recon and CRLF/CORS/403
  coverage (gaps in S0), web3 angle (out of core scope, noted only).

## S4 — github.com/0xmannaf/Ai-Hunting ✅ (cloned, read)

- **What it is:** OpenCode-based agent (opencode.json, `.opencode`): 22 SKILL.md and a
  real **`learning_engine/`** — SQLite-backed, 5 documented hooks
  (`record_finding`, `record_triage`, `recall`, `distill`, `score`) plus session
  lifecycle hooks (before_recon/during_testing/after_finding/before_summary/after_triage),
  JSON schemas (`findings.json`, `triage.json`, `signals.json`), and `memory/` ledgers
  (`FALSE_POSITIVE_DB.md`, `patterns.md`, `report-lessons.md`, `CONTEXT_LEDGER.md`,
  per-class `targets/*.md`).
- **Value:** **the key reference for Objective 7 (real learning loop)** — a concrete,
  auditable design for distinguishing evidence vs hypothesis and persisting lessons /
  false positives. We adapt its *design* to Claude Code's file-based model + the
  self-learning slash commands.

## S5 — github.com/PentesterFlow/agent ✅ (cloned, read)

- **What it is:** TypeScript CLI (`src/`, bun/node), 11 SKILL.md, human-in-the-loop
  pentest lifecycle, `memory/` continuous-learning, Burp integration, explicit
  `SECURITY.md` model. Apache-2.0.
- **Value:** human-in-the-loop gating model and lifecycle framing (recon → enumeration
  → validation → evidence → reporting with analyst control). Reinforces our safety layer.

## S6 — mcpmarket.com/tools/skills/red-team-bug-bounty-methodology 🟡 (web-read)

- **What it is:** A single skill doc (frontmatter credits author "zebbern" v1.1; listing
  credits a different account) — a 10-section recon→analysis playbook built on OSS tools
  (Amass, Subfinder, httpx, FFUF, Nuclei, Dalfox…) with the **Jason Haddix heat-map
  methodology** (section 6) as its distinctive manual layer.
- **Value:** the Haddix application-analysis checklist and tool-chain structure.
- **⚠️ Provenance caution:** listing/metadata author mismatch, 0 stars, linked repo
  appears unrelated. Its own recon script runs Nuclei against all hosts with **no scope
  check or rate limit** — advisory safety only. We adopt the *methodology* (Haddix
  heat-map) but NOT its unsafe unscoped-scan scripts; any adopted idea is marked
  "unverified provenance" in RESEARCH_LOG.

---

## Authoritative runtime reference (not a "source" to merge)
- **Claude Code Agent Skills docs** (code.claude.com/docs/en/skills) ✅ — confirmed the
  real SKILL.md spec: frontmatter optional; portable keys outside Claude Code are
  limited to `name, description, license, compatibility, metadata, allowed-tools`
  (any other key is a hard error on claude.ai upload / Skills API). Skills double as
  `/` slash commands via `name`; `.claude/commands/*.md` also supported. Keep SKILL.md
  < 500 lines; move detail to referenced files; scripts are executed, not loaded.
- Slash-commands / subagents / hooks docs: to be cross-checked before finalizing the
  command layer (RESEARCH_LOG).

## Access summary
| Source | Access | Method |
|---|---|---|
| S0 archive | ✅ full | tar extract (isolated) |
| S1 BugBountySkills | ✅ full | git clone --depth 1 |
| S2 Claude-BugHunter | ✅ full | git clone --depth 1 |
| S3 Agentic-Bug-Hunter | ✅ full | git clone --depth 1 |
| S4 Ai-Hunting | ✅ full | git clone --depth 1 |
| S5 PentesterFlow/agent | ✅ full | git clone --depth 1 |
| S6 mcpmarket page | 🟡 web-read | WebFetch (single page) |

Nothing claimed here as "analyzed" was left unopened. The S6 page is the only
web-only (not cloned) source; its underlying repo was not located/verified.
