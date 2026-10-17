---
name: badrecon
description: Operate and analyze results from BadRecon — the user's self-hosted multi-engine recon system (Docker Compose: app + worker + PostgreSQL + Redis). Use whenever the user mentions BadRecon, recon exports (urls.csv, subdomains.csv, findings.csv, ips.csv), scan jobs, CT/DNS/urlscan/wayback engines, or asks to run recon against a target, triage recon findings, or correlate scan results across targets.
---

# BadRecon — Multi-Engine Recon System Operator

BadRecon is a complete recon pipeline, not a single-command tool: it takes a target (domain/hostname), fans out to intelligence/discovery engines, normalizes observations into PostgreSQL, and exports per-scan artifacts the agent then reads for triage, correlation, and reporting.

## Architecture (Docker Compose on VPS)

| Component | Role |
|---|---|
| `badrecon_app` | UI + REST API: create targets/scans, view results |
| `badrecon_worker` | Executes long scan jobs in background (jobs queued via Redis) |
| `badrecon_postgres` | Stores targets, scans, subdomains, URLs, IPs, findings, technologies, CVEs |
| `badrecon_redis` | Job queue/cache between app and worker |
| `badrecon_setup` | DB migrations on startup |
| `/data/recon-results/` | Archive of exported (non-live) results, separate from the DB |

Consequence of the app/worker split: scans keep running on the VPS after the laptop disconnects, as long as Docker services and the VPS stay up. When checking results later, first check the scan/job status — a scan still queued or running must never be analyzed as if complete.

## Workflow

```
Target → create target + scan config → Redis queue → worker runs engines
→ observations normalized into PostgreSQL → counts/status
→ export CSV/Markdown/evidence → redact secrets → unified index
→ AI triage/correlation/prioritization → report (use vuln-report skill)
→ optional AUTHORIZED validation phase
```

Scan config shape (from prior confirmed setups): `inputType=domain`, `inputHostname`, `expandSubdomains=true`, `deepScan=true`, enabled engines list, deep-scan categories (e.g. `js`). Exact REST endpoints vary by deployment — confirm with the running instance or the user rather than guessing paths.

## Engines and how to interpret each

| Engine | Data | Interpretation rule |
|---|---|---|
| CRT_SH / CERTSPOTTER | Certificate Transparency names | Subdomain discovery incl. historical/child environments — names are LEADS, not live assets |
| CHAOS | Subdomain intelligence | Expand the list; treat as leads |
| SECURITYTRAILS | DNS/history (needs API key) | Hostname/DNS history linkage — NOT proof of current exposure |
| ALIENVAULT_OTX | Threat intel observations | Enrichment; filter false positives hard |
| VIRUSTOTAL | Domain/URL/IP intel (needs API key) | Reputation/observations only — never vulnerability proof |
| URLSCAN | Public scan URLs/pages/assets | Discover links/technologies; beware sensitive data in captures |
| WAYBACK_MACHINE | Archived URLs/paths | Old endpoints, docs, legacy JS — gold for forgotten paths |
| RDAP | Registration/ASN/IP ownership | Network/ownership context — never a testing authorization |
| WAPPALYZER | Technology fingerprints | Framework/server/library versions — fingerprint ≠ CVE proof |
| CVE_MATCH | tech/version → CVE mapping | LEAD only: needs version evidence + in-scope check + separate validation |

Two global interpretation rules:
1. **Empty result ≠ absent asset.** Some engines need API keys; some return zero results, rate-limits, or errors. Always read the stored provider status and collection time before concluding anything from an absence. Record provider failures as "missing evidence", not "asset doesn't exist".
2. **Three-way separation:** every observation distinguishes the *asset discovered*, the *source that proved it*, and the *scan that saw it*. Preserve this in all correlation — cross-target pivots (e.g. same IP across targets) depend on it.

## Deep scan / JS category

With `deepScan` + `js`, deeper results attach to URLs/JS files: paths, API hints, configuration clues. These are endpoint leads for later authorized testing — not findings.

**Hard rule:** any secret-looking value surfaced from JS or archived URLs passes through redaction FIRST. Never re-use an auto-discovered token or cookie against any target. Redacted values appear in reports as partial (e.g. `AKIA...***`); validity checks only within explicit authorization.

## Export artifacts (per completed scan)

| File | Contents | Agent use |
|---|---|---|
| `urls.csv` | URLs/paths + available HTTP fields | endpoint dictionary, param mining, wayback-pivot |
| `subdomains.csv` | subdomains + status/data | alive/dead triage, scope matching against program rules |
| `findings.csv` | raw findings/warnings | triage queue — dedupe, validate, severity-sort |
| `ips.csv` | IPs ↔ asset linkage | infra clustering, cross-target correlation |
| technology export | fingerprints per subdomain | attack-surface mapping, CVE_MATCH input |
| `recon_notes.md` | operational notes/context | read before interpreting CSVs |
| `FINDINGS.md` | human summaries/leads | cross-check against findings.csv |
| `evidence/` | scan-linked evidence | cite in reports |
| `tar.gz` | portable archive | long-term storage |

The batch exporter: fetches scan history → selects completed scans → fetches details → downloads the CSVs → collects technologies per observed subdomain → writes one directory + one `tar.gz` per scan. HTTP 404s on some technology endpoints during export are **non-fatal warnings** — log them as missing evidence; the scan itself did not fail.

## Operating BadRecon via REST (agent runbook)

BadRecon's app exposes a REST API. The exact endpoint shapes vary per deployment, so bootstrap once per instance:

**Step 0 — connection info (only the user can supply):** base URL of `badrecon_app` (e.g. `http://<vps>:<port>`), and an auth header if the instance requires one.

**Step 1 — map the API:** run `scripts/api_discover.sh <base_url> ["Authorization: Bearer <tok>"]`. It probes doc surfaces (`/docs`, `/openapi.json`, …), liveness (`/health`, `/api`), and resource shapes (`/api/targets`, `/api/scans`, exports). If an OpenAPI doc is found, read it and use it as the authoritative API map — skip guessing.

**Step 2 — create target + scan:** POST the target and scan config (`inputType=domain`, `inputHostname=<target>`, `expandSubdomains=true`, `deepScan=true`, engines list, deep-scan categories `js`). The app returns a job id; execution happens in the worker via Redis — the HTTP call returning does NOT mean the scan ran.

**Step 3 — poll status:** GET the scan/job until status is completed (respect provider runs: a completed scan can still contain per-engine failures — read `scan_provider_run` states). Never analyze a queued/running scan.

**Step 4 — export:** trigger or download the export bundle per scan: `urls.csv`, `subdomains.csv`, `findings.csv`, `ips.csv`, technology export, `recon_notes.md`, `FINDINGS.md`, `evidence/`, `tar.gz`. If export hits 404s on technology endpoints, log as missing evidence and continue.

**Step 5 — analyze** per the triage procedure below, with curl against the API or from the downloaded CSVs.

If the VPS is unreachable from the agent environment, ask the user to run the export on the VPS and share the `/data/recon-results/` directory (or one `tar.gz`) — the analysis phase works identically from files.

## Agent triage procedure (after export)

1. Read `recon_notes.md` and provider statuses first — know what actually ran.
2. Match every subdomain/URL against the program's declared scope before anything else; out-of-scope assets are noted, never tested.
3. Build the endpoint dictionary from `urls.csv` (+ wayback URLs); group by service prefix.
4. Correlate: IPs across targets (ips.csv), shared technologies, historical names from CT sources that still resolve.
5. Severity-sort findings.csv leads; for CVE_MATCH rows, verify version evidence and applicability before promoting to a finding.
6. Write outputs with the `vuln-report` skill (strict 5-section template). Recon-only observations go to the intel/context section, not the findings section.
7. Validation of any lead requires explicit authorization and separate confirmation — recon data alone never enters a report as a vulnerability.
