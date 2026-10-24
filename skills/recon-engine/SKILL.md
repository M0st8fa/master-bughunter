---
name: recon-engine
description: Two-engine recon for authorized bug bounty / attack-surface mapping. PASSIVE brain (scripts/recon.py, stdlib, no keys, sandbox-safe) collects subdomains/URLs/IPs/providers from crt.sh, Shodan CTL, HackerTarget, CertSpotter, urlscan, Wayback, VirusTotal (with VT_API_KEY) and RDAP into BadRecon-style artifacts (subdomains.csv, urls.csv, ips.csv, providers.json, recon_notes.md, FINDINGS.md), scope-matched. ACTIVE muscle (scripts/recon.sh) chains the Go bug-bounty suite (subfinder, dnsx, waybackurls/gau, katana, gospider, httpx, + opt-in nuclei/gowitness/gitleaks/arjun/naabu/subzy) for DNS brute-force, live crawling, HTTP probing, ~30-bucket URL classification and opt-in active checks — the standard engine for fresh active recon, run wherever a terminal and the toolchain are available (install via setup.sh), not a sandbox-only passive fallback. Use whenever the user asks for recon, subdomain enumeration, attack-surface mapping, "find subdomains/URLs/assets for X", or "run recon on" any target.
---

# Recon Engine — passive brain + active muscle

Two engines, one skill. The skill is the **brain** (scope, decisioning, triage,
handoff); the scripts are the **muscle** (enumeration).

- **`scripts/recon.py` — passive engine.** Stdlib Python, no keys required, safe to run
  anywhere including this sandbox. Multi-source intelligence collection; the only traffic
  touching the target is optional DNS resolution.
- **`scripts/recon.sh` — active engine (the standard engine for fresh recon).** Bash
  pipeline chaining the standard Go bug-bounty toolchain. Breadth and depth on a scoped,
  authorized target. **Execution is conditional on the environment, not forbidden:** run
  it directly whenever you have a local terminal (Bash tool / shell) **and** the script is
  present **and** its toolchain is installed; only then does it do real work. If a
  prerequisite is missing — no shell, `recon.sh` not found, or `check_tools` reports the
  Go suite absent — report the **precise** blocker (which of those three) and either run
  `scripts/setup.sh` first or fall back to `recon.py` for passive breadth. Do **not** claim
  a blanket "cannot run recon.sh," and do **not** silently substitute `recon.py` for a
  requested active run. Full guide + the execution decision table:
  `references/active-enumeration.md`.

**Install the toolchain first (for `recon.sh`).** `recon.sh` needs the Go bug-bounty
suite installed. On a fresh Ubuntu (20.04/22.04/24.04) machine, have the user run
`scripts/setup.sh` **before** the first `recon.sh` run — it installs Go + the toolchain
(subfinder, dnsx, httpx, katana, gospider, nuclei, gowitness, gitleaks, naabu, gf, …),
Python recon tools, nuclei templates, ~1 GB of SecLists wordlists, and shell/tmux env.
It needs sudo and runs on the user's own machine, never the sandbox. After it finishes,
`recon.sh`'s own `check_tools` reports anything still missing. `recon.py` (passive) needs
none of this.

**Canonical source + freshness (do this before hunting).** `recon.sh` and `setup.sh` are
vendored from the canonical repo recorded in `scripts/recon-script.lock`
(**`https://github.com/M0st8fa/Recon-Script`**). Before a fresh active run, check the
bundled/local `recon.sh` is up to date against that repo and update it when stale — then,
if the toolchain is missing, run that repo's `setup.sh`:

```bash
# 1) freshness check (safe; fetches + compares text, never executes recon.sh/setup.sh)
python3 -I <skill_dir>/scripts/recon_sync.py status --dir <local_clone>
# 2) if missing/stale → clone or fast-forward the canonical repo
python3 -I <skill_dir>/scripts/recon_sync.py ensure --dir <local_clone>
# 3) if the Go toolchain is missing, install it from the canonical setup.sh (trusted host)
bash <local_clone>/setup.sh                                    # Ubuntu, sudo, user's own machine
```

```bash
# passive — always available
python <skill_dir>/scripts/recon.py run --target example.com [--scope scope.txt] [--resolve] [--out DIR]
# VT_API_KEY=<key> python recon.py run --target example.com   # adds VirusTotal provider

# active — on the user's own machine, after the freshness check + setup above
bash <local_clone>/recon.sh -d example.com -o recon_example
bash <local_clone>/recon.sh -d example.com --nuclei --active-checks --params --ports
# notify: --slack/--discord <webhook> send the end-of-run summary (opt-in)
```

**Notifications.** The canonical `recon.sh` pushes the end-of-run summary to **Slack or
Discord** (`--slack`/`--discord <webhook>`); opt-in, the webhook is passed at runtime and
never committed, and secret values are never sent. (Telegram/per-finding alerts are **not**
part of the canonical script; if you want them, add them upstream in the Recon-Script repo
and re-sync — the skill tracks whatever the canonical repo ships.) Full setup:
`references/active-enumeration.md`.

## Which engine

- **Fresh active recon on an authorized, scoped target → `recon.sh` (standard).** Run it
  wherever a terminal + the toolchain are available — including this environment when it
  has a shell and the tools are installed. It is the requested engine for active
  subdomain brute-force, live crawling, HTTP probing, classification and opt-in checks.
- **No shell / toolchain absent / first passive map / keyless API-source intel →
  `recon.py`.** The passive layer that runs anywhere, including a locked-down sandbox.
- **Best practice:** run `recon.py` for passive breadth, then `recon.sh` for depth on the
  resolved in-scope set. `recon.py` is **not** superseded, and it is **not** a silent
  substitute for a requested `recon.sh` run — it is the passive/API-source layer and the
  only one that runs with no tools. See the comparison, the execution decision table, and
  the full flag/output reference in `references/active-enumeration.md`.

**Before launching, check for an in-flight or completed run.** If the engagement manifest
(`engagement.py`) reports `recon.status: running` or a recon dir already exists, do **not**
start a duplicate scan — resume (`recon.sh --resume -o <dir>`) or ingest the existing
output instead (see `engagement` skill → `ingest_recon.py`). When a run finishes, hand its
output directory straight to the hunting workflow (`ingest_recon.py <dir>`).

**Passive-first always.** Prefer passive collection; active modules that send traffic to
the target (`recon.sh` crawlers and especially its opt-in `--nuclei`, `--screenshots`,
`--gitleaks`, `--params`, `--ports`, `--test-redirects`, `--active-checks`) run only
within a confirmed program scope on a target the user is authorized to test.

## Passive output contract (recon.py — BadRecon-compatible)

| Artifact | Contents | Agent use |
|---|---|---|
| `subdomains.csv` | subdomain, sources, resolved_ip, in_scope | scope-filtered attack surface |
| `urls.csv` | url, sources, in_scope | endpoint dictionary; feed js-audit/js-recon |
| `ips.csv` | ip, hostnames | infra clustering, cross-target correlation |
| `providers.json` | per-engine state + counts + timestamps | read BEFORE interpreting anything |
| `recon_notes.md` | provider status table + totals | the "what actually ran" record |
| `FINDINGS.md` | interesting-URL flags + redacted secret-shapes | triage leads (leads, NOT findings) |
| `raw/<engine>.json` | unnormalized provider output | re-parse without re-fetching |

## Active output (recon.sh — summary)

Writes a structured output dir: `subdomains/`, `urls/` (in-scope `allurls.txt` +
~30 classified buckets), `httpx/` (`httpx_all.json`, status-split, `tech_summary.txt`),
`dns/`, `vuln/`, `ports/`, `params/`, `screenshots/`, `leaks/`, `logs/`, `reports/summary.md`.
Scope is enforced by snapshotting the original roots (`root_domains.txt`) before
enumeration and filtering every crawled URL against them. Full layout, tool list
(required vs optional) and run modes: `references/active-enumeration.md`.

## Interpretation rules (inherited from BadRecon discipline — enforce all)

1. **Read the "what ran" record first.** Passive: `providers.json` — an engine in
   `rate_limited`/`http_403`/`skipped_no_key`/`exception:*` state proves nothing about the
   target. Active: `logs/*.log` + `run_config.txt` — a tool that errored or was missing
   proves nothing either. Empty from a healthy source is data; empty from a failing or
   not-run source is "missing evidence" — record, never conclude absence.
2. **Asset / source / scan separation.** Passive keeps it in the `sources` column on every
   row; correlation claims ("this IP ties two targets") must cite the observing sources.
3. **Scope-match before anything else.** `in_scope=no` rows / out-of-scope hosts are context
   only — never tested, never reported as target findings. Active scope is only as good as
   the roots you give `recon.sh`; confirm the program scope and pass exactly those roots.
4. **Interesting URLs, secret-shapes and every `vuln/` hit are LEADS.** Passive stores
   secret values redacted (`AKIA00***REDACTED`); active nuclei/CORS/`.git`/open-redirect
   hits must be reproduced by hand before they are findings. Validity checks and CVE
   claims need explicit authorization plus version/reproduction evidence.
5. **CT/DNS/intel sources give names, not liveness.** Historical subdomains may be dead —
   resolve (passive `--resolve` or active httpx) before treating as live; dead-but-in-CT
   names still matter (takeover checks, historical content).

## Triage handoff

Summarize totals (`recon_notes.md` / `reports/summary.md`) → list in-scope subdomains by
source count → group flagged URLs by pattern (admin/config/backup/api/env/params) → hand
the endpoint set and `httpx_all.json` to `js-recon`/`js-audit`, class buckets to the
matching hunters (`sqli_params`→`bb-sqli`, `redirect_ssrf`→`bb-ssrf`,
`idor_params`→`idor-runner`/`bb-authz`, `oauth_endpoints`→`bb-oauth`, …), takeover
candidates to takeover review, and any **hand-confirmed** issue to `vuln-report` (strict
5-section template). Recon observations go to the report's intel section, never its
findings section. Handoff map in detail: `references/active-enumeration.md`.

## Passive engine notes (recon.py)

- `crtsh` — Certificate Transparency; slowest, richest for historical names. `*.domain` wildcard query.
- `shodan_ctl` — free hostname enumeration via Shodan's CT feed, no key.
- `hackertarget` — hostsearch with IPs; unauthenticated quota can exhaust → handled as rate-limited.
- `certspotter` — unauthenticated tier rate-limits; `rate_limited` state is normal without a key.
- `urlscan` — public scan index: URLs + page IPs + domains.
- `wayback` — archived URLs (capped 30k, collapsed); best source for forgotten endpoints and old JS.
- `virustotal` — only with `VT_API_KEY` env; reputation/resolutions, never vulnerability proof.
- `rdap` — registrar/ASN context; never a testing authorization.

Custom subsets: `--engines crtsh,wayback,urlscan`. Re-run single engines alone and merge
CSVs by the `sources` column. Provider keys load from env / git-ignored `keys.env`
(`keys.env.example` is the placeholder template — never commit real keys).
