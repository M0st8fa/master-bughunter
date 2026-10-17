# <Program Name> Bug Bounty — Working Report
Target: <host(s)> | Program: <platform>/<name> | Session: <date> | Researcher: <handle>
Scope-respected: <in-scope patterns>. Audit log: recon/audit.log

---

## FINDING-1 (<Severity>): [Vuln type] <exact location>
- Title: <Vuln type + exact location — one line>
- Summary: <what, where, what an attacker can do — 2-3 sentences>
- PoC:
  ```
  <exact curl / click path — reproducible as written>
  ```
- Impact: <attacker outcome, chained impact>
- Remediation: <one actionable fix>
- CVSS: <vector> (<score>)
- Evidence: <recon/... file paths>

## TESTED-NEGATIVE (do not report)
- <lead> -> <server's own error string / status>. (<inconclusive if positive control failed>)

## OPEN SURFACES (need <X> to test)
- <surface> — blocked on <resource>

## ARTIFACTS
- recon/audit.log — timestamped action log
- recon/subdomains/{in_scope,out_of_scope,all_subs_raw}.txt
- recon/js/ + js_findings.json
- recon/ips/idor_results.{json,log}
