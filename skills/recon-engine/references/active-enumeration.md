# recon-engine — Active enumeration engine (`scripts/recon.sh`)

`recon.sh` is the heavy active-enumeration engine behind this skill. Where `recon.py`
is a passive, keyless, sandbox-safe intelligence collector, `recon.sh` chains the
standard Go bug-bounty tool suite for breadth and speed on a scoped target you are
authorized to test. The skill is the brain (scope, decisioning, triage, handoff); the
script is the muscle (enumeration).

> **Runtime caveat — read first.** `recon.sh` is a Bash pipeline that shells out to
> external tools (subfinder, dnsx, httpx, katana, …). It does real work only on a machine
> where those tools are installed, run against a target inside an authorized program's
> scope. **Whether Claude executes it is conditional on the environment, not a blanket
> no:** when a local terminal (the Bash/shell tool) is available **and** `recon.sh` is
> present **and** its toolchain is installed, run it directly and then interpret the
> output. When a prerequisite is missing, report the *precise* blocker and either install
> the toolchain (`scripts/setup.sh`) or prepare the exact command for the user to run on
> their own machine. Never silently substitute `recon.py` for a requested active run.

### Execution decision table (run it, or report the exact blocker)

| Condition | Action |
|---|---|
| Shell available + `recon.sh` present + toolchain installed | **Run `recon.sh` directly** on the in-scope roots; hand the output dir to `ingest_recon.py`. |
| Shell available + `recon.sh` present + toolchain missing, **on a trusted user-owned Ubuntu host** | Run `scripts/setup.sh` (Ubuntu, sudo) to install, then run `recon.sh`. |
| Shell available + toolchain missing, **but not a trusted user-owned host** (any locked-down/shared/sandbox environment) | Do **not** run `setup.sh` (it needs sudo and writes system-wide). Report "toolchain missing" + the exact `setup.sh`/`recon.sh` commands for the user to run on their own machine. |
| Shell available + `recon.sh` not found | Report "recon.sh not found at `<path>`"; locate it (`$PATH`, repo `scripts/`, `/root/recon.sh`) before constructing any command. |
| No shell / locked-down sandbox | Report "no local terminal"; use `recon.py` for passive breadth and prepare the `recon.sh` command for the user's machine. Never run `setup.sh` here. |
| A recon job is already running / output exists | Do **not** launch a duplicate; `--resume` or ingest the existing directory. |

Inspect the actual script's `usage()` before building a command — never invent flags.
`recon.sh` accepts `-d <domain>` / `-l <file>`, `-o <dir>`, `-v`, tuning (`-t -r -D -T -w
-R`), `--skip-*`, opt-in `--nuclei --screenshots --gitleaks --params --ports
--test-redirects --active-checks`, `--resume`, and `--slack/--discord/--telegram`.

## When to use which engine

| Situation | Engine |
|---|---|
| No tools installed / inside the sandbox / first-pass passive map | `recon.py` (passive) |
| Keyless CT + archive + RDAP intel, no traffic to target but DNS | `recon.py` (passive) |
| User has the Go toolchain and an authorized, scoped target | `recon.sh` (active) |
| Want brute-force DNS, live HTTP probing, crawling, classification | `recon.sh` (active) |
| Opt-in active checks (CORS, `.git`, open-redirect, ports, nuclei) | `recon.sh` (active) |
| Best practice | run `recon.py` for passive breadth, then `recon.sh` for depth on the resolved in-scope set |

`recon.py` is **not** superseded — it is the passive/API-source layer and the only one
that runs where no tools are installed. The two are complementary.

## Install the toolchain first (`scripts/setup.sh`)

`recon.sh` only works once the Go bug-bounty suite is installed. Before the first run,
have the user run the bundled installer **on their own machine**:

```bash
bash scripts/setup.sh
```

`setup.sh` targets **Ubuntu 20.04 / 22.04 / 24.04** and needs **sudo**. It installs Go
1.22, the required and optional tools below (via `go install` + apt), Python recon tools
(arjun, uro, paramspider, waymore, dnsgen), gf patterns, nuclei templates, **~1 GB of
SecLists** wordlists under `/opt/wordlists` (with a `/usr/share/seclists` compat symlink),
DNS resolver lists, and Go/recon env + a tmux config written to the shell profile. It
writes an **empty-placeholder** subfinder provider-config at
`~/.config/subfinder/provider-config.yaml` — adding API keys there is optional and only
widens subdomain coverage. Do **not** run it in the sandbox. When it finishes,
`recon.sh`'s own `check_tools` step re-verifies and names anything still missing.

## Required vs optional tools

- **Required** (script exits if missing): `subfinder`, `waybackurls`, `katana`,
  `gospider`, `httpx`, `anew`, `unfurl`, `dig`.
- **Optional** (feature silently disabled if absent, with a warning): `dnsx` (DNS
  brute-force + resolution + CNAME/wildcard mapping), `gau` (Common Crawl/OTX URLs),
  `nuclei`, `gowitness`/`aquatone` (screenshots), `gitleaks` (JS secret scan), `arjun`
  (param guessing), `naabu` (port scan), `subzy` (subdomain takeover), `qsreplace`
  (open-redirect payload injection), `jq` (httpx JSON parsing — without it the status
  split and tech summary are skipped), `amass`.
- A DNS wordlist enables brute-force; the script searches several SecLists locations
  (`WORDLIST_FALLBACKS`) or takes `-w <wordlist>`. No wordlist → brute-force skipped.

## How to run it

```bash
# single target
bash recon.sh -d example.com -o recon_example

# multiple roots from a file
bash recon.sh -l roots.txt -o recon_out -t 100

# passive-ish pass (skip crawlers), then a fuller active pass
bash recon.sh -d example.com --skip-gospider --skip-katana
bash recon.sh -d example.com --nuclei --screenshots --params --ports \
              --test-redirects --active-checks
```

Key flags: `-t` threads (50), `-r` httpx rate req/s (150), `-D` katana depth (3),
`-T` timeout (10s), `-w` wordlist, `-R` resolvers, `--resume` resume a prior output dir,
`--skip-*` to drop modules, `--slack`/`--discord <webhook>` or `--telegram` for
notifications (see below). The
opt-in modules (`--nuclei`, `--screenshots`, `--gitleaks`, `--params`, `--ports`,
`--test-redirects`, `--active-checks`) are **off by default** — they send active traffic
to the target, so only enable them inside program scope. Run `bash recon.sh -h` for the
full option list.

## Notifications (Slack / Discord / Telegram)

`recon.sh` can push the end-of-run summary (subdomains / URLs / live / nuclei counts +
output dir) to a channel, and — for **Telegram** — also fire a short alert the moment a
high-signal finding is confirmed.

- **Slack / Discord:** `--slack <webhook>` / `--discord <webhook>` (summary only).
- **Telegram:** `--telegram <bot_token>:<chat_id>` **or** export `TELEGRAM_BOT_TOKEN` and
  `TELEGRAM_CHAT_ID` (env keeps the token out of shell history; the flag overrides env
  when both are given). Because a bot token itself contains a `:`, the flag value is split
  on its **last** colon. The token is a credential — pass it at runtime only, never commit
  it. Telegram is **opt-in**: with nothing configured, all notify calls are silent no-ops.
- **Per-finding Telegram alerts** fire on confirmed/high-signal findings only — zone
  transfer, subdomain takeover (subzy), nuclei critical/high, confirmed open redirect,
  CORS misconfig, exposed `.git`, public cloud bucket, and secrets found. Secret **values**
  are never sent — only the finding type, affected host/URL, and counts/location.

```bash
# token out of shell history
export TELEGRAM_BOT_TOKEN='123456789:AA...'; export TELEGRAM_CHAT_ID='123456789'
bash recon.sh -d example.com --nuclei --active-checks
# or inline
bash recon.sh -d example.com --active-checks --telegram '123456789:AA...:123456789'
```

## Output layout (`$OUTPUT_DIR/`)

```
subdomains/   subfinder.txt, brute_force.txt, all_subdomains.txt, dnsx_resolved.txt,
              cname_map.txt, interesting_subs.txt, zone_transfer_subs.txt
urls/         waybackurls.txt, gau.txt, katana.txt, gospider.txt, allurls.txt (in-scope,
              static assets stripped) + ~30 classified buckets (see below)
httpx/        httpx_all.json (structured), httpx_all.txt, httpx<CODE>.txt split by exact
              status_code, httpx_other.txt, tech_summary.txt, potential_wp_sites.txt
dns/          nameservers.txt, zone_transfers.txt, txt_records.txt, dnssec_check.txt,
              mx_records.txt, cname_records.txt, ipv6.txt, cloud_storage_*.txt, s3_amazon.txt
vuln/         nuclei_results.txt, nuclei_critical.txt, nuclei_cves.txt, exposed_panels.txt,
              default_logins.txt, subdomain_takeover.txt, open_redirect_confirmed.txt,
              cors_misconfig.txt, git_exposure.txt
ports/        open_ports.txt + per-host files        params/   per-domain + all_params.txt
screenshots/  gowitness/aquatone output               leaks/    gitleaks_report.json, grep_secrets.txt
logs/         per-tool stderr + run_config.txt         reports/  summary.md
```

### URL classification buckets (the triage leads)
`classify_urls()` greps `allurls.txt` into ~30 buckets by extension and parameter name:
`php/asp/aspx/jsp/js/config_js`, `apis_all`, `api_docs_endpoints` (swagger/graphql),
`backups`, `archives_dbs`, `secrets` (`.env/.pem/.key/…`), `data_configs`, `logs`,
`documents`, `dev_scripts`, `lfi_params`, `redirect_ssrf`, `idor_params`, `admin_panels`,
`dev_envs`, `sensitive_keywords`, `ssrf_internal`, `xss_params`, `sqli_params`,
`upload_params`, `debug_endpoints`, `oauth_endpoints`, `aws_s3`, `jwt_endpoints`,
`others`.

## Scope discipline (how the script enforces it)

- `prepare_domains()` snapshots the **original roots** to `root_domains.txt` *before*
  subdomain enumeration appends discovered hosts into `alldomains.txt`.
- `filter_in_scope()` then drops every URL whose host is not one of those roots or a
  subdomain of one — so social-media, CDN and third-party links that crawlers pick up
  from `<a href>`/`<script src>` are removed from `allurls.txt`.
- **This is only as good as the roots you give it.** Confirm the program's declared
  scope first and pass exactly the in-scope roots. Out-of-scope hosts the script
  surfaces (e.g. in `subfinder.txt`) are intel/context, never test targets.

## Where recon.sh is stronger than recon.py

- **Active subdomain discovery:** subfinder (all sources, recursive) + dnsx DNS
  brute-force + zone-transfer (AXFR) attempts + subzy takeover checks. `recon.py` is
  passive CT/intel only.
- **URL discovery depth:** katana + gospider live crawling and gau, on top of Wayback —
  it finds endpoints that only exist by crawling the live app, not just archives.
- **Liveness + fingerprint:** real httpx probing (status, title, tech, length,
  redirects) parsed from JSON, with an exact-status-code split and a tech summary.
  `recon.py` gives names, not liveness.
- **Richer classification:** ~30 parameter/extension buckets vs the passive skill's
  juicy-URL flagging.
- **Opt-in active checks** the passive skill has no concept of: nuclei, screenshots,
  gitleaks on downloaded JS, arjun params, naabu ports, active CORS / `.git` /
  open-redirect verification.

Where `recon.py` still wins: it is keyless, passive, sandbox-safe, needs no tool
install, and gives the asset↔source↔scan separation (`sources` column) and the strict
`providers.json` provenance that active crawling does not produce.

## Feeding the output into the hunt skills

1. **Read what actually ran first.** `logs/run_config.txt` + each `logs/*.log` are the
   active-engine equivalent of `providers.json`: a tool that errored or was missing
   proves nothing about the target. A missing optional tool means that signal is
   absent-because-not-run, never absent-because-clean.
2. **Scope-filter is already applied** to `urls/allurls.txt`; still treat anything the
   run surfaces outside the confirmed program scope as context only.
3. **Hand off by class:**
   - `httpx/httpx_all.json`, `urls/js.txt`, `urls/config_js.txt` → `js-recon` / `js-audit`
   - `urls/sqli_params.txt` → `bb-sqli`; `redirect_ssrf.txt` → `bb-ssrf`;
     `idor_params.txt` → `idor-runner` / `bb-authz`; `xss_params.txt` → `bb-xss`;
     `upload_params.txt` → `bb-upload`; `oauth_endpoints.txt` → `bb-oauth`;
     `admin_panels.txt` → `bb-authz`
   - `subdomains/cname_map.txt` + `vuln/subdomain_takeover.txt` → takeover review
   - `vuln/*` (nuclei, CORS, `.git`, open-redirect) → **leads to re-verify manually**,
     then `vuln-report` (strict 5-section template)
4. **Every `vuln/` hit is a lead, not a finding.** nuclei output, reflected-CORS and
   `.git` hits must be reproduced by hand before they enter a report. Recon observations
   go to the report's intel section, never its findings section.
