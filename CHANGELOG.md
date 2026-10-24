# CHANGELOG

All notable changes and major decisions for the Cybersecurity Hunting Skills ecosystem.
Format: reverse-chronological. Dates are absolute (YYYY-MM-DD).

## [Unreleased]

### 2026-10-23 — recon-engine: canonical Recon-Script source + pre-hunt freshness check
- **Canonical source.** `recon.sh` and `setup.sh` are now vendored from the canonical repo
  **`https://github.com/M0st8fa/Recon-Script`**, recorded in
  `skills/recon-engine/scripts/recon-script.lock` (repo URL, synced commit, sha256 of each
  script). The bundled copies were replaced with that repo's current versions (commit
  `4e10781`); they are a mirror, not hand-edited.
- **Pre-hunt freshness check.** New `scripts/recon_sync.py` (stdlib): `status` reports
  `up_to_date` / `stale` / `missing` / `drifted-from-lock` / `unknown-network` by comparing
  the local `recon.sh` against the canonical repo (git fetch, an offline `--reference`
  file, or the lock sha); `ensure` clones or `git pull --ff-only`s the repo; `lock` prints
  the lock. It treats the repo as **untrusted data** — clones/compares text only and
  **never executes** `recon.sh`/`setup.sh` (that stays the explicit, trusted-host step).
- **Wired into the workflow.** `recon-engine` SKILL.md + `references/active-enumeration.md`
  (new "Canonical source & freshness" section + a `stale` row in the execution decision
  table), the `engagement` skill (recon branch), and `bb-pipeline` Phase 1 now run the
  freshness check before a fresh active run and install the toolchain from the canonical
  `setup.sh` when tools are missing.
- **Notifications reconciled to the canonical script.** The canonical `recon.sh` has only
  Slack/Discord webhooks, so the Telegram/per-finding-alert docs (a prior local-only
  addition) were removed from `SKILL.md`, `active-enumeration.md`, `README.md`, and
  `keys.env.example` so the documented invocation matches the actual script. Telegram can
  be re-added upstream in Recon-Script and picked up on the next sync.
- **Tests:** `tests/recon-engine/test_recon_sync.py` (8 checks, offline, no network/git) +
  `scenarios.md` SYNC-1..3. Validator 33/33, 0 errors.

### 2026-10-23 — Persistent authorization, autonomous hunting & recon-first workflow
- **New `engagement` skill (orchestration-support)** — persistent engagement manifest
  (`engagement.json`, schema `schemas/engagement.schema.json`). `scripts/engagement.py`
  runs the authorization + scope gate **once per engagement**, persists program id, scope
  source, in-scope roots, exclusions, rate limits, required headers (non-secret), testing
  restrictions, posture, recon status, current phase, and completed work; `init` is
  idempotent (reuse on resume, no re-gate), a different program is a conflict (fresh
  workspace). Scope classifier (in/out/needs-clarification; exclusions beat inclusions;
  wildcard-aware). A secret-shape guard **refuses** credentials/cookies/tokens so they
  never enter persistent state. Commands: `init`, `show`, `classify`, `set`, `resume`.
- **First-class recon-folder ingestion** — `scripts/ingest_recon.py` inventories a
  supplied recon directory (recon.sh layout / BadRecon / ad-hoc), reads run config + logs
  first (records per-tool ran/failed/skipped — a failed tool is missing evidence, never
  coverage), extracts URLs from `.txt/.csv/.json/.jsonl`, builds a deduplicated
  `inventory.jsonl` preserving method/param/endpoint variants with provenance, scope-splits
  into a separate `excluded_inventory.jsonl` (never scheduled), routes each in-scope URL to
  specialists by endpoint semantics, and tracks per-URL `test_status` for resume. A
  `--next-batch` scheduler yields every distinct in-scope URL (no arbitrary cap).
- **Stopped repeated authorization prompts (ecosystem-wide, boundaries intact).**
  `security-hunt` Step 0 is now a one-time engagement gate (resume reuses it); added a
  "stop re-asking" rule, a unified continuous workflow (setup→scope→recon|import→inventory
  →intel→routing→validation→evidence→report→coverage), engagement-context pass-through to
  specialists, and a tightened human-judgment gate list (destructive prod tests, material
  scope ambiguity, program-prohibited actions, mass test-account creation, payment flows,
  report submission). `bb-pipeline` loads/creates the manifest once, no longer asks to
  advance each phase, added Phase 1b (import existing recon) and coverage review, and fixed
  a hardcoded `C:/Users/Admin/...` bb-disclosures path. `docs/SAFETY.md` reworded
  "specialists re-check it" → specialists **inherit** the established context (enforce
  scope, don't re-interview) and listed the remaining approval gates.
- **recon.sh is the standard active engine; execution is conditional, not forbidden.**
  Replaced the blanket "this skill never executes recon.sh" claims in
  `skills/recon-engine/SKILL.md` and `references/active-enumeration.md` with an execution
  decision table: run it directly when a terminal + the script + toolchain are available;
  otherwise report the **precise** blocker (no shell / script missing / toolchain missing)
  and install or prepare the exact command — never silently fall back to `recon.py` for a
  requested active run, never launch a duplicate over a running/existing job. Documented
  invocation verified against the script's real `usage()` flags (no invented flags).
- **Docs & index:** new `docs/ENGAGEMENT.md` (manifest format + resume + scope rules);
  `SKILL_INDEX.md`/`README.md`/`docs/ARCHITECTURE.md` updated (33 skills; engagement data
  contract). **Tests:** `tests/engagement/` — runnable `test_engagement.py` (28 checks
  across the 12 required behaviors, mock fixtures, no live scan) + instruction-level
  `scenarios.md`; new scenarios added to security-hunt/recon-engine/bb-pipeline.
- **Boundaries preserved:** no scope enforcement removed, `docs/SAFETY.md` intact and
  strengthened, validator/quality rules unchanged, no secrets in state/logs/reports.
- **Review hardening (CodeRabbit pass):** secret guard now inspects dict **keys** (a
  value under a sensitive key like `Authorization`/`Cookie` is refused even when shapeless)
  and only exempts a value that is wholly a placeholder (a placeholder word inside a real
  secret no longer disables it); engagement/inventory writes are **atomic** (`os.replace`)
  so resume state survives a crash mid-write; `ingest_recon.py` now **redacts credential
  query-params** (`token`, `access_token`, `sig`, …) before persisting a URL, matches
  run-log/config files by whole filename/extension (so `login_urls.json`,
  `blog_endpoints.jsonl`, `catalog.csv` are no longer silently dropped) and records
  `files_skipped`, merges tool status by **severity** (a later `failed` is never hidden by
  an earlier `ok`), and **reclassifies** stored inventory rows when scope/exclusions change
  on re-ingest (a newly-excluded host leaves the hunt queue). `engagement.py set` validates
  `--phase/--recon-status/--recon-engine` against the schema enums. Active-recon decision
  table restricts `setup.sh` (sudo) to a trusted user-owned host. Tests: 38 checks (adds
  real `init` reuse/conflict coverage, URL-redaction, log-filename, and reclassify cases).

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
