# master-bughunter — Cybersecurity Hunting Skills Ecosystem

A modular, evidence-driven, self-improving library of **Claude Code skills** for
**authorized** security work: bug bounty on in-scope programs, threat hunting, detection
engineering, authorized pentest methodology, and responsible disclosure.

> ## ⚠️ Authorized / defensive use only
> Every active-testing skill gates on **authorization and scope** and uses
> **non-destructive proof** only. Use these skills **only** against assets you are
> explicitly permitted to test: an in-scope bug bounty program, a signed engagement, a
> lab/CTF, or your own systems. Respect published scope, exclusions, rate limits, and
> destructive-testing rules; practice responsible disclosure. This library will **refuse**
> to help attack arbitrary targets, bypass authorization, run autonomous mass
> exploitation, or do anything destructive. Full rules: [`docs/SAFETY.md`](docs/SAFETY.md).

## What this is

A coherent **ecosystem** of skills for [Claude Code](https://claude.com/claude-code), not a
loose folder of prompts. One orchestrator routes work to focused specialists; a quality
system scores and validates every skill; and a human-approved, file-based improvement loop
lets the library get better over time without ever auto-applying changes to a target or to
itself.

- **32 skills** — 1 orchestrator (`security-hunt`) + 31 specialists (recon &
  intelligence, per-bug-class hunters, API/cloud/detection, pipeline & calibration,
  reporting). Full catalog: [`SKILL_INDEX.md`](SKILL_INDEX.md).
- **10 self-learning commands** (`/skills-*`) — a controlled, human-approved
  Observe → Verify → Propose → Test → Approve → Update loop.
- **Quality system** — a 12-category rubric ([`docs/QUALITY_RUBRIC.md`](docs/QUALITY_RUBRIC.md)),
  a stdlib-only static validator ([`scripts/validate_skills.py`](scripts/validate_skills.py),
  currently **32/32 pass, 0 errors**), and JSON schemas ([`schemas/`](schemas/)).
- **Persistent ledgers** — `SOURCES.md`, `CHANGELOG.md`, `RESEARCH_LOG.md`,
  `LEARNING_LOG.md`, `COVERAGE.md`, `TEST_RESULTS.md`, `IMPROVEMENT_QUEUE.md`.

## Skill index

Start with **`security-hunt`** — it confirms authorization and scope, then routes to the
right specialist. Status is `validated` (behavioral tests passed) or `under-review` (passes
static validation, behavioral set pending). Full table in [`SKILL_INDEX.md`](SKILL_INDEX.md).

**Orchestration**
- `security-hunt` — entry router: authorization/scope gate → classify → dispatch → track findings → deliverables.

**Recon & intelligence**
- `recon-engine` — passive brain (`recon.py`, keyless/sandbox-safe) + active muscle (`recon.sh`, Go toolchain, runs on your machine) · `badrecon` · `footprinting` · `target-intelligence` · `js-recon` · `js-audit` · `signup-agent` (authorized account creation for testing).

**Vulnerability hunters (bug class → skill)**
- `bb-authz` (access control / IDOR / BOLA / privesc) · `idor-runner` · `bb-xss` · `bb-domxss` · `bb-sqli` · `bb-ssrf` · `bb-csrf` · `bb-rce` · `bb-bizlogic` · `bb-race` · `bb-upload` · `bb-oauth` · `bb-graphql` · `bb-pii`.

**API, cloud & defensive**
- `api-security` (OWASP API Top 10 2023) · `cloud-security` (AWS/GCP/Azure posture + IAM) · `detection-engineering` (Sigma → SPL/KQL/EQL, ATT&CK, threat hunting).

**Pipeline, calibration & reporting**
- `bb-pipeline` · `bb-chains` (escalation/chaining) · `bb-disclosures` (paid-disclosure corpus + query engine) · `h1-reports` (payout calibration) · `h1-playbooks` · `bb-report` · `vuln-report`.

**Self-learning commands** — `/skills-help` · `/skills-status` · `/skills-coverage` ·
`/skills-research` · `/skills-learn` · `/skills-learn-from-task` · `/skills-improve` ·
`/skills-audit` · `/skills-test` · `/skills-update`.

## Install

Full steps in [`docs/INSTALL.md`](docs/INSTALL.md). Clone the repo and copy the skills and
commands into your Claude Code scope:

```sh
git clone https://github.com/M0st8fa/master-bughunter.git
cd master-bughunter
mkdir -p ~/.claude/skills ~/.claude/commands
cp -r skills/* ~/.claude/skills/
cp -r commands/* ~/.claude/commands/
```

Then in Claude Code, run `/skills` to confirm they loaded (or just ask Claude to use
`security-hunt`), and `/skills-help` to list the commands.

**Requirements:** Claude Code (CLI, desktop, web, or IDE). Python 3.8+ for the validator
and a few skill scripts (stdlib only for the validator). Individual skills may *name*
external tools (subfinder, httpx, nuclei, …) — none are bundled or assumed present; each
skill documents its own needs.

### Optional: active recon toolchain (for `recon-engine`'s `recon.sh`)

The `recon-engine` skill has two engines: a passive `recon.py` (stdlib, no tools, runs
anywhere) and an active `recon.sh` that drives the Go bug-bounty toolchain. To use the
**active** engine, install the toolchain **first** with the bundled setup script:

```sh
bash skills/recon-engine/scripts/setup.sh
```

> ⚠️ **Ubuntu 20.04 / 22.04 / 24.04 only**, and it needs **sudo**. It installs a large
> toolset (Go + subfinder, httpx, katana, gospider, nuclei, gowitness, gitleaks, naabu,
> gf and more), Python recon tools, nuclei templates, and **~1 GB of SecLists** wordlists,
> and writes Go/recon env to your shell profile. Run it on your **own** machine, never in a
> sandbox. After it finishes, `recon.sh`'s own `check_tools` reports anything still missing.
> Subfinder API keys are **optional** (empty placeholders are written to
> `~/.config/subfinder/provider-config.yaml`) — add them for broader subdomain coverage.

**Optional recon keys:** `recon-engine` can use VirusTotal/Shodan if keys are present via
environment variables or a **git-ignored** `skills/recon-engine/keys.env` (copy from
`keys.env.example`). **Never commit real keys.** Without keys, those providers are skipped.

Validate anytime:
```sh
python3 -I scripts/validate_skills.py   # expect: 0 error(s)
```

## Usage

Describe the objective and let the orchestrator route (details in [`docs/USAGE.md`](docs/USAGE.md)):

```
Use security-hunt — I have an in-scope program (scope: *.example.com),
help me find and validate access-control bugs.
```

Or invoke a specialist directly when you already know the class:

```
Use bb-authz on this endpoint (two of my own accounts attached) …
Use recon-engine on example.com (passive) …
Use bb-disclosures — what do access-control bugs pay, and is my finding strong enough?
```

Drive the improvement loop with the `/skills-*` commands:

```
/skills-audit                    → files issues into IMPROVEMENT_QUEUE.md
# review the queue, mark an item 'approved'
/skills-update IQ-00X --preview  → see the diff/plan
/skills-update IQ-00X --apply    → apply + validate + test + log
```

## Repository structure

```
master-bughunter/
├─ skills/        32 skills (each a dir: SKILL.md + optional references/scripts/assets)
├─ commands/      /skills-* self-learning command catalog (.md)
├─ references/    shared knowledge (deduped)
├─ scripts/       validate_skills.py and utilities
├─ schemas/       finding.schema.json, lesson.schema.json
├─ tests/         behavioral scenario fixtures
├─ docs/          ARCHITECTURE, SAFETY, QUALITY_RUBRIC, INSTALL, USAGE, MAINTENANCE, KNOWN_LIMITATIONS
└─ *.md           persistent ledgers (SOURCES, CHANGELOG, RESEARCH_LOG, LEARNING_LOG, COVERAGE, TEST_RESULTS, IMPROVEMENT_QUEUE)
```

## Honest about "self-learning"

This is a **human-approved, file-based** improvement loop
(Observe → Verify → Propose → Test → Approve → Update), **not** autonomous background
learning. Nothing is applied to a skill without an approved entry in
`IMPROVEMENT_QUEUE.md`. Known limitations are documented plainly in
[`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).

## Provenance

Built from an attached 28-skill base archive plus several public repositories and one
methodology page, engineered into one coherent system — not a copy-paste merge. Full
provenance, including a documented live-key finding in the *source* archive (its values
were never read beyond length/shape and are **excluded** here), is in
[`SOURCES.md`](SOURCES.md).
