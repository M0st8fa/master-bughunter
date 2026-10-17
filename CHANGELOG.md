# CHANGELOG

All notable changes and major decisions for the Cybersecurity Hunting Skills ecosystem.
Format: reverse-chronological. Dates are absolute (YYYY-MM-DD).

## [Unreleased]

### 2026-10-17 — recon-engine: Telegram notifications in recon.sh (run summary + per-finding alerts)
- Added Telegram support to `scripts/recon.sh`, mirroring the existing Slack/Discord notify
  pattern. Config via `--telegram <bot_token>:<chat_id>` (split on the last colon, since bot
  tokens contain a `:`) OR `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` env vars (flag overrides
  env). Added to `parse_args`, `usage()`, and the NOTIFICATIONS section.
- New `telegram_notify()` helper (POSTs to `api.telegram.org/bot<token>/sendMessage` with
  `--data-urlencode`, `parse_mode=HTML`, `disable_web_page_preview=true`, bounded timeout,
  `|| true`); no-ops quietly when unconfigured. `send_notification()` now also sends the
  end-of-run summary to Telegram.
- New per-finding alerts (opt-in, high-signal only) via `telegram_finding()`, wired into:
  zone-transfer vulnerable, subdomain takeover (subzy, confirmed only), nuclei
  critical/high, confirmed open redirect, CORS misconfig, exposed `.git`, public cloud
  bucket, and secrets found. Secret **values** are never sent — only type/host/counts.
- **Secrets:** bot token/chat id come only from the flag or env at runtime; nothing
  hardcoded. Added empty `TELEGRAM_BOT_TOKEN=`/`TELEGRAM_CHAT_ID=` placeholders +
  docs to `keys.env.example`; `.gitignore` still blocks real `*.env`/`keys.env`.
- Docs: Telegram option added to `SKILL.md`, `references/active-enumeration.md`, and the
  README notifications area.

### 2026-10-17 — recon-engine: added toolchain installer (user's setup.sh) + README install steps
- Added `skills/recon-engine/scripts/setup.sh` (user-supplied, inspected not executed;
  secrets check clean — the subfinder provider-config it writes has empty `""`
  placeholders only, downloads only from standard upstreams). Ubuntu 20.04/22.04/24.04
  installer: Go 1.22 + the recon toolchain (subfinder, dnsx, httpx, katana, gospider,
  nuclei, gowitness, gitleaks, naabu, gf, …), Python recon tools, gf patterns, nuclei
  templates, ~1 GB SecLists, DNS resolvers, and shell/tmux env.
- Wired "install the toolchain first" into `SKILL.md` and
  `references/active-enumeration.md`: run `scripts/setup.sh` (Ubuntu, sudo) before the
  first `recon.sh` run; `recon.sh`'s `check_tools` reports anything still missing.
- Updated root `README.md` install section to the clone-and-copy steps
  (`git clone … && cp -r skills/* ~/.claude/skills/ && cp -r commands/* ~/.claude/commands/`)
  and added an "Optional: active recon toolchain" subsection documenting `setup.sh`.

### 2026-10-17 — recon-engine: added active-enumeration engine (user's recon.sh)
- Integrated the user-supplied `recon.sh` as the **active** engine behind `recon-engine`
  at `skills/recon-engine/scripts/recon.sh` (inspected, not executed; no secrets — Slack/
  Discord webhook vars are empty, no hardcoded keys). The skill is now two-engine:
  `recon.py` = passive brain (keyless, sandbox-safe), `recon.sh` = active muscle (Go
  bug-bounty toolchain: subfinder, dnsx, waybackurls/gau, katana, gospider, httpx +
  opt-in nuclei/gowitness/gitleaks/arjun/naabu/subzy).
- Rewrote `SKILL.md` to a brain+muscle model: which engine when, passive-first discipline,
  active output summary, unified interpretation rules (read "what ran" first — `logs/*.log`
  + `run_config.txt` are the active equivalent of `providers.json`), class→hunter handoff.
- Added `references/active-enumeration.md`: run modes/flags, required vs optional tools,
  full output-dir layout, the ~30 classification buckets, scope-filter mechanics, and a
  "where recon.sh beats recon.py / where recon.py still wins" comparison.
- **recon.py NOT superseded** — kept as the passive/API-source layer and the only engine
  that runs with no tools installed. Documented the honest caveat: `recon.sh` needs those
  tools installed and runs on the user's own machine, never in this sandbox.
- Static validator re-run (see TEST_RESULTS); ledgers RESEARCH_LOG/LEARNING_LOG/SKILL_INDEX
  updated. Not pushed, ZIP not re-packaged (awaiting user go-ahead).

### 2026-10-10 — Phase 1: inventory & architecture
- Created persistent workspace `/mnt/project-files/cybersecurity-skills/`.
- Examined attached archive (28 skills) and all 6 external sources; recorded full
  provenance in `SOURCES.md`.
- **Security:** flagged live VirusTotal/Shodan keys in archive `recon-engine/keys.env`;
  excluded from all deliverables; advised user to rotate.
- Confirmed Claude Code as target runtime and its real SKILL.md / command spec.
- Decided 6-layer architecture (orchestration, specialists, shared references, tool
  integration, QA, self-learning) — see `docs/ARCHITECTURE.md`.

### 2026-10-10 — Phase 2 (Batch 1): foundational backbone  [done]
- Initialized ledgers: CHANGELOG, RESEARCH_LOG, LEARNING_LOG, SKILL_INDEX, COVERAGE,
  TEST_RESULTS, IMPROVEMENT_QUEUE.
- Added quality rubric (`docs/QUALITY_RUBRIC.md`) and JSON schemas (`schemas/`).
- Added orchestration skill `security-hunt`.
- Added self-learning command catalog under `commands/` (10 `/skills-*`).
- Added stdlib static validator; ported 28 archive skills with live keys + `.pyc`
  stripped (IQ-001 applied); first static run 29/29 pass.
- Added README + 7 docs (ARCHITECTURE, SAFETY, QUALITY_RUBRIC, INSTALL, USAGE,
  MAINTENANCE, KNOWN_LIMITATIONS) + `.gitignore`.

### 2026-10-10 — Phase 2 (Batch 4): new extended-coverage skills  [done]
- Built 3 new validated specialists filling the top coverage gaps (IQ-005, partial):
  `api-security` (OWASP API Top 10 2023), `cloud-security` (AWS/GCP/Azure + IAM privesc),
  `detection-engineering` (Sigma/ATT&CK + threat hunting — the first defensive specialist).
- Each with authorization/scope gate, evidence-vs-hypothesis discipline, tool-availability
  caveats, failure handling, and acceptance criteria. Added test fixtures; instruction-
  level tests 12/12 pass. Library now 32 skills; static 32/32 pass.
- Updated COVERAGE (3 gaps closed), SKILL_INDEX (+scorecards). Still planned:
  container-k8s, network-service, source-review, sast-dast.

### 2026-10-10 — Phase 2 (Batch 2): harden & score foundational skills  [done]
- **Rejected IQ-002** (payload dedupe): would break per-skill self-containment since
  Claude Code skills install individually; duplication is the correct tradeoff.
- Seeded behavioral test fixtures (`tests/`) for security-hunt, bb-authz, bb-chains,
  recon-engine; ran instruction-level tests (17/17 pass).
- Scored those four against the 12-category rubric (overalls 4.1–4.7); promoted all four
  to `validated`. Remaining 25 specialists stay `under-review` pending their sets.

---

## Decision log (why, not just what)
- **Base on the attached archive, not a merge of all sources.** It is the most coherent
  and highest-quality set; external sources contribute specific ideas, not bulk files.
  (Goal: real capability, not file count.)
- **Portable frontmatter only** (`name`, `description`, …) so every SKILL.md loads on
  claude.ai upload and the Skills API, not just Claude Code CLI.
- **Self-learning = human-approved file-based loop**, not autonomous background learning
  (the runtime has no scheduler the library controls). Proposals land in
  `IMPROVEMENT_QUEUE.md`; nothing auto-applies. Honesty over hype (Objective 7).
