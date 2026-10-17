# Hunt-challenge playbooks (what actually produced $7k–$20k per campaign)

Distilled from three documented Voorivex campaigns: $20,300 / 200 hours / 2 hunters (Bugcrowd), $9,240 / 30 days / 1 hunter (HackerOne), $7,000 / 40 days / single app (HackerOne).

## Program selection is a decision, not a vibe ($9,240 lesson)

- The author earned $350 in 2 months of unfocused hopping across programs; the SAME skills produced $9,240 in 30 days after committing to ONE program chosen from data: bounty tables (min/max per severity) + triage response-time stats.
- Wide scope with mixed old/modern architectures + fast payouts + professional triage = best expected value ($20.3k campaign criteria).
- Set an HOURS-based goal (tracked in Toggl), not a money goal — it forces continued work through the dead months while reports sit in triage. Payouts lag months; plan for it.

## Narrow vs wide recon — switch depth, not targets ($7,000 lesson)

- When subdomain enumeration dries up, don't switch targets — switch depth: use the actual product features. The bugs were in the main app "in plain sight".
- **Parameter bruteforcing is an XSS factory**: GAP (Burp ext) to extract existing params, then `x8` to bruteforce more on EVERY page — most paid XSS came from non-obvious parameters found this way (`addon=`, `resource=`).
- Hunt legacy endpoints by fuzzing: previous-gen upload endpoints (Content-Type-only checks → webshell = $1,500) and forgotten login paths (`legacy-login` → password-reset chain).
- Sequential numeric IDs on "private" resources: fuzz the full range (1–10000); privacy flags are rarely enforced on download endpoints.
- Follow admin-panel bottoms: unaudited panels hide behind buttons at the bottom of admin pages ($500 IDOR).
- Detail obsession completes chains: two stray spaces around a POSTed email blocked an entire ATO chain until trimmed.

## Wide-scope asset discovery ($20,300 lesson)

- **Certificates by Organization field, not just CN**: `curl -s "https://crt.sh/?O=<Org%20Inc.>&output=json" | jq -r ".[].common_name" | tr A-Z a-z | unfurl format %r.%t | sort -u` — finds root domains CN search misses. Same for Shodan/Censys org searches.
- **ASN → IP → cert pivot**: `echo AS714 | tlsx -san -cn -silent -resp-only`.
- **Read the company's own blog/news posts manually** — 60 unknown domains extracted from ~5,000 posts; marketing-announced domains exist in NO technical recon source.
- Unauth Swagger on bruteforced hostnames (`test.` labels): test all ~100 APIs individually — boring beats clever; 10 open, 2 leaked PII.
- On 403'd endpoints: switch method (GET→PATCH) AND add `Accept: application/json` — either alone often fails, together unlocked 200 + data.
- Time-based SQLi first on legacy DB-populated fields (country/state dropdowns): `1'XOR(SELECT CASE WHEN(1234=1234) THEN SLEEP(7) ELSE 0 END)XOR'Z`.
- WPEngine sites: check `/_wpeprivate/config.json` (config leak with DB creds).

## Session-upgrade flows are a goldmine ($9,240 findings)

Anonymous → authenticated → JWT conversion → 2FA chains hide: session-swap 2FA bypasses (replace victim session ID with attacker's converted anonymous session at `/login/key/<random>`-style converters), tokens surviving revocation ("grant access"), pre-account-takeover (signup without email verification, wait for victim's OAuth signup), and email edge cases (`user@gmail.com.` trailing dot treated as new user → skipped 2FA).

## Mindset when stalled ($9,240 lesson)

Two months of stall → STOP touching targets, debug the PROCESS: consume methodology material (pentest→bug-buddy content), talk to experienced hunters, then restart with one program + fixed challenge window. And argue severity: a downgraded report was re-accepted after a written challenge.
