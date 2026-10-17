# Tech Matrix — fingerprint → known bugs → tools → manual checks

Read this after `footprint.py` prints the detected stack. The matrix expands each technology into the aggressive hunt the user wants ("if WordPress — go at WordPress"). Version first, then CVEs, then tool + manual ladder. Everything stays within program scope and rate rules.

## Universal pre-step: pin the version
Version beats product. `server`/`x-powered-by` headers, `/CHANGELOG.txt`, `/readme.html`, meta generators, `elmah`/`actuator` endpoints, static asset URLs with version strings, favicon hash comparison against known deployments. With a version: match CVEs (search `<tech> <version> CVE` + the bb-disclosures corpus `--q "<tech>"`), else run the family checks below.

## WordPress (still the #1 jackpot on corp sites)
1. `wpscan --url <t> --enumerate u,ap,at,cb,dbe --api-token <T>` (u=users, ap=active plugins, at=themes, cb=codebase outdated, dbe=db exports). No token? manual equivalents below.
2. User enumeration (report as info; chain into brute only within rules): `/wp-json/wp/v2/users`, `?rest_route=/v2/users`, `?author=1..8` (follow display-name in redirects).
3. Plugin/theme version → CVE matching: read `Readme.txt` / asset `ver=` params; each outdated plugin is a searchcoft moment.
4. `xmlrpc.php`: `system.listMethods`; if present: pingback SSRF (report with internal-probe proof), `system.multicall` = N-queries-per-request password oracle (mind rules).
5. File exposure ladder: `/wp-content/debug.log`, `/wp-config.php.bak|~|save|old`, `/wp-content/uploads/` listing, `/wp-content/backup*`, db exports (`*.sql`, `*.wpress` — the wpscan `dbe` enum).
6. `wp-cron.php` + `admin-ajax.php` nopriv actions.
7. Staging twins: `staging.`/`dev.`/`test.` + `/wp/` subfolder installs — wayback CDX finds forgotten ones.

## IIS / ASP.NET
1. **Shortname (8.3) disclosure — run shortscan**: `shortscan <t>` (or `java -jar iis_shortname_scanner.jar http://t/~a`). Leaks file/dir first-letters → reconstruct config/backup names → fetch them.
2. **WebDAV**: `PROPFIND /` (207 = enabled → try `PUT`/`MOVE` upload); `OPTIONS` for allowed methods.
3. `trace.axd` (request tracing), `elmah.axd` (error logs with tokens), `WebResource.axd` behaviors.
4. **ViewState**: grab `__VIEWSTATE` + `__VIEWSTATEGENERATOR`; check `enableViewStateMac` (missing MAC → ysoserial.net deserialization → RCE); `aspnet:MaxHttpCollectionKeys` DoS-era checks skip.
5. Old IIS auth bypass patterns: `:80/../`, unicode normalization, trailing-dot paths.

## Java stack (Tomcat/JBoss/WebLogic/Spring)
- Spring: `/actuator/{env,heapdump,heapdump?format=heap,trace,mappings}` — env = secrets, heapdump = in-memory creds. `env` POST property-override → RCE on some setups.
- Tomcat: `/manager/html` (default creds? `/manager/status` role?), `PUT` JSP (CVE-2017-12617), examples + docs apps.
- JBoss/WebLogic: deployment consoles (`/jmx-console`, `/console`), IIOP/T3 deserialization families — historical but live on corp nets.
- Deserialization probes need explicit permission — marker payloads only.

## Atlassian (Jira/Confluence/Bitbucket)
- Jira: `/secure/Signup!default.jspa` (open signup?), `/rest/api/2/user/picker?query=` (user enum), serverInfo version → CVE match (OGNL family CVE-2022-26134 Confluence, template injection CVE-2023-22527).
- Public projects/repos: `/browse`, `/explore`, Bitbucket `/repos` — internal code + tokens in config files.

## CMS others
- Drupal: `CHANGELOG.txt` version → Drupalgeddon2/3 checks (PHP filters, REST RCE) — needs permission for RCE proof.
- Joomla: `joomscan`; `com_*` component CVEs by version.
- Bitrix: `/bitrix/admin/`, RCE family by version.
- Laravel: `/.env` (APP_KEY + SMTP + DB creds), `/_ignition/executeSolution` (CVE-2021-3129 when debug), `APP_KEY` leak → cookie deserialization RCE (report key leak; PoC only with permission).
- ThinkPHP: `index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo` family on 5.x.

## Infra/ops tools exposed
- Jenkins: `/script` console (authed?), CVE-2024-23897 CLI file read (POST to `/cli?Remoting=false` with `help` + `@/etc/passwd`).
- Grafana/Kibana: unauth dashboards, datasource configs; Kibana TiUI RCE chain on old versions.
- Elasticsearch: `GET /` (we found an anon 2.4.1 exactly this way), `_cat/indices`.
- k8s/Argo CD: API 401 vs anonymous-enabled; CSRF on control-plane sessions pays ($4.6k precedent).

## Framework tells
- PHP: `PHPSESSID` + expose_php header; `?=PHPB8B5F2A0-...` exposes phpinfo-era signatures; uploads + `cgi.fix_pathinfo`.
- Django: `csrfmiddlewaretoken` + `/admin/`; DEBUG pages leak settings — reproduce with a 500 (once).
- Next.js: `__NEXT_DATA__` props (authed data leaks), `_next/data/` routes, chunk maps (js-audit).
- Vue/React: bundle mining (js-audit); `v-html`/`dangerouslySetInnerHTML` sinks (bb-xss).

## Git/SVN/env exposure (any tech)
```
/.git/HEAD            200 = repo; if yes: git-dumper / manual object walk
/.git/config          tokens/origins
/.svn/entries         wc
/.env / .env.local    secrets (framework-agnostic)
/backup.* /*.zip /*.sql /.bak tilde variants  (IIS shortname scan finds the names)
/composer.json /package.json  dependency versions → CVE match
```

## Cloudflare in front
- Scripted clients get challenged → curl_cffi impersonation or the CDP browser-pass (bb-pipeline 2.5).
- Origin discovery (if scope permits): historical DNS/certs for origin IPs, then probe origin directly with Host header — bypasses WAF rules tied to the edge.

## Rules of engagement
- All of this is ACTIVE testing: scope-check first, ≤5 req/s, required program headers.
- RCE/deserialization proofs on production need explicit permission — marker payloads only (sleep/id/DNS), never shells.
- Match against the program's known-issues list before reporting anything found here (version disclosures are usually pre-declared dupes unless chained).
