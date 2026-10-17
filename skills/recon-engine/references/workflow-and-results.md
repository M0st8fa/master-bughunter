# recon-engine — Workflow & Field Results

## Invocation

```
python recon.py run --target <domain> [--scope scope.txt] [--resolve] [--engines a,b,c] [--out DIR]
```
Talk format: *"run recon on target.com"* — minimum input is a domain; everything else defaults.

## Workflow (7 stages)

```
┌─ 1. TRIGGER ──────── user says "run recon on X" → skill auto-loads
├─ 2. SCOPE ────────── scope file written (if given); default = target itself
├─ 3. COLLECT ──────── 9 engines queried sequentially (1.5s spacing, per-engine timeouts)
│                       keys auto-loaded from keys.env (VT ×3 rotation, Shodan Pro)
├─ 4. STATUS ───────── every engine writes a provider state (ok / rate_limited /
│                       skipped_no_key / http_5xx / exception) → providers.json
├─ 5. NORMALIZE ────── subdomains/URLs/IPs unified; sources column keeps
│                       asset↔source↔scan separation; scope column added to every row
├─ 6. EXPORT ───────── subdomains.csv, urls.csv, filtered_urls.csv, ips.csv,
│                       providers.json, recon_notes.md, FINDINGS.md, raw/*.json
├─ 7. TRIAGE ───────── read provider states FIRST → scope-filter → group juicy URLs
│                       → redact secret-shapes → hand off: js-audit (bundles),
│                       vuln-report (findings, 5-section template)
└─ OPTIONAL ────────── --resolve: live DNS (200 hosts max, 10/s) — only traffic
                        that touches the target; everything else is passive
```

## Engines

| # | Engine | Key | dpd.ie yield |
|---|---|---|---|
| 1 | crt.sh | — | 70 subs |
| 2 | shodan_ctl (free CT feed) | — | 62 subs |
| 3 | shodan (/dns/domain) | Pro key | 65 subs |
| 4 | hackertarget | — | 51 subs + IPs |
| 5 | certspotter | — (RL-handled) | 28 subs |
| 6 | urlscan | — | 14 subs, 100 URLs, page IPs |
| 7 | wayback (all + juicy filter, 503-retry) | — | 37,493 URLs / 149 juicy |
| 8 | virustotal (3-key rotation) | 3 keys | 86 subs + resolutions |
| 9 | rdap | — | registrar/NS context |

## Field results

### Run 1 — ginandjuice.shop (functional test, --resolve)
- Providers: 4 ok, crt.sh http_0 (timeout), wayback 503 (pre-fix), VT skipped_no_key (pre-keys)
- 1 subdomain, 6 URLs, 2 IPs; DNS-resolved 34.246.169.176
- Validated: provider-failure ≠ absent-asset discipline, sources column, artifact set

### Run 2 — dpd.ie (production, scope = 11 program hosts)
- Providers: 8/9 ok, rdap no_data (.ie not in rdap.org — recorded, not concluded)
- **92 subdomains — all 11 in-scope hosts confirmed multi-source; 81 OOS catalogued**
- OOS intel gained: preprod cluster (pre-prod-papi, preprod-reporting, preprod-ukcollections,
  aws-testpapi, cp-testtemp, cp-clone-live, dpdstagingenv, peopleonline, returns3, shipping, reporting)
- 25 IPs; 37,493 archived URLs; 149 juicy-extension files (all in-scope hits = public T&Cs/brochures)
- Secret-shaped values in 37K corpus: **0**
- Bug found & fixed: CDX `url=.$domain/` matches root paths only → `*.$domain/*` (1 → 37,493 URLs)

### Run 3 — example.com (3-key VT smoke test)
- VT key pool loaded (3 keys), provider ok, 100 subs in one call — rotation pool verified

## Hard rules (enforced by SKILL.md)

1. Read providers.json before interpreting anything
2. Empty-from-failing-engine = missing evidence, never absence
3. in_scope=no → context only, never tested
4. Secrets redacted on discovery (AKIA00***), never reused
5. Recon leads never enter reports as findings — separate validation, separate template
