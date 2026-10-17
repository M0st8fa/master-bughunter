#!/usr/bin/env python3
"""footprint.py — fingerprint a web target, match known tech, and emit the
bug-hunt plan per technology (CVE families, tools, manual checks).

Usage:
  python footprint.py https://target.com [--probe] [--out plan.md]
  --probe: also send paced tech-confirmation requests (default OFF = passive-ish:
           homepage + robots.txt + one 404 probe).
"""
import argparse, hashlib, json, re, sys, time

RULES = [
    {"tech": "WordPress", "match": {"header_or_body": ["wp-content", "wp-json", "wp-includes", "X-Pingback"]},
     "confirm": [["GET", "/wp-login.php"], ["GET", "/wp-json/wp/v2/users"], ["GET", "/readme.html"], ["GET", "/wp-content/debug.log"]],
     "bugs": ["user enumeration via REST (?rest_route=/v1/users or /wp-json/wp/v2/users)", "xmlrpc.php brute/SSRF (system.multicall)", "wpcron DoS-ish (report only)", "plugin/theme vulns — enumerate versions then match CVEs", "debug.log exposure", "backup wp-config leaks (.bak, ~)"],
     "tools": ["wpscan --url {0} --enumerate u,ap,at,cb,dbe --api-token <WPSCAN_TOKEN>", "nuclei -tags wordpress,cms -u {0}", "droopescan scan wp --url {0}"]},
    {"tech": "Drupal", "match": {"header_or_body": ["Drupal", "drupal.org", "sites/default/files", "X-Drupal-"]},
     "confirm": [["GET", "/user/login"], ["GET", "/CHANGELOG.txt"], ["GET", "/core/CHANGELOG.txt"]],
     "bugs": ["Drupalgeddon family (REST/PHP filter RCE) on unpatched 7/8/9", "CHANGELOG version disclosure", "/user/register open?", "PHP filter module RCE (CVE-2024-454x if enabled)"],
     "tools": ["droopescan scan drupal -u {0}", "nuclei -tags drupal -u {0}"]},
    {"tech": "Joomla", "match": {"header_or_body": ["Joomla", "/media/jui/", "com_content"]},
     "confirm": [["GET", "/administrator/"], ["GET", "/language/en-GB/en-GB.xml"]],
     "bugs": ["com_fields SQLi/RCE history", "directory listing checks", "configuration.php backup leak"],
     "tools": ["joomscan -u {0}", "nuclei -tags joomla -u {0}"]},
    {"tech": "IIS", "match": {"headers": ["Microsoft-IIS", "X-Powered-By: ASP.NET", "X-AspNet", "X-AspNetMvc"]},
     "confirm": [["PROPFIND", "/"], ["GET", "/aspnet_client/"], ["GET", "/~a"]],  # ~a = shortname probe
     "bugs": ["shortname 8.3 disclosure (~ leaks files/dirs — use IIS-ShortName-Scanner/shortscan)", "WebDAV PROPFIND/PUT", "trace.axd / elmah.axd exposure", "ViewState deserialization (MAC validation?)", "IIS shortname + auth bypass combos", "tilde enum → find backup config files"],
     "tools": ["shortscan {0}", "nuclei -tags iis -u {0}", "nikto -h {0}", "aspx ViewState: ysoserial.net if MAC missing"]},
    {"tech": "Apache", "match": {"headers": ["Apache"]},
     "confirm": [["GET", "/server-status"], ["GET", "/server-info"]],
     "bugs": ["server-status exposure", "mod_cgi shellshock-era", "path traversal CVE-2021-41773 (2.4.49/50)", ".ht* file reads"],
     "tools": ["nuclei -tags apache -u {0}", "nikto -h {0}"]},
    {"tech": "nginx", "match": {"headers": ["nginx"]},
     "confirm": [["GET", "/status"], ["GET", "/nginx_status"]],
     "bugs": ["alias traversal (location /x { alias /y/; } → /x../)", "off-by-slash path confusion", "merge_slashes misrouting"],
     "tools": ["nuclei -tags nginx -u {0}"]},
    {"tech": "Tomcat", "match": {"headers": ["Tomcat", "Coyote"]},
     "confirm": [["GET", "/manager/html"], ["GET", "/host-manager/html"]],
     "bugs": ["manager creds/guessable", "CVE-2017-12617 PUT JSP upload (if PUT allowed)", "examples/* exposure", "client-cert desync family (CVE-2023-45648)"],
     "tools": ["nuclei -tags tomcat,apache-tomcat -u {0}"]},
    {"tech": "Spring Boot", "match": {"header_or_body": ["Whitelabel Error Page", "spring", "X-Application-Context"]},
     "confirm": [["GET", "/actuator"], ["GET", "/actuator/env"], ["GET", "/actuator/heapdump"], ["GET", "/actuator/health"]],
     "bugs": ["actuator env → secrets", "heapdump → in-memory creds", "/trace (old) → session/token leak", "Eureka/H2 console chaining"],
     "tools": ["nuclei -tags spring,springboot -u {0}"]},
    {"tech": "Django", "match": {"header_or_body": ["csrfmiddlewaretoken", "__admin__", "DJANGO", "X-Frame-Options: DENY + csrftoken cookie"]},
     "confirm": [["GET", "/admin/"], ["GET", "/nonexistent404page"]],
     "bugs": ["DEBUG=True error pages (stack + settings)", "admin login exposed", "ALLOWED_HOSTS header injection era"],
     "tools": ["nuclei -tags django -u {0}"]},
    {"tech": "PHP", "match": {"headers": ["X-Powered-By: PHP"], "cookies": ["PHPSESSID"]},
     "confirm": [["GET", "/index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"]],  # phpinfo expose probe
     "bugs": ["version via expose_php", "cgi-fix_pathinfo → PHP exec in uploads", "session fixation/hijack chains", ".php.bak/.old source leaks"],
     "tools": ["nuclei -tags php -u {0}"]},
    {"tech": "ASP.NET", "match": {"headers": ["X-AspNet", "X-Powered-By: ASP.NET"], "cookies": ["ASPXAUTH", "ASP.NET_SessionId"]},
     "confirm": [["GET", "/trace.axd"], ["GET", "/elmah.axd"], ["GET", "/WebResource.axd"]],
     "bugs": ["ViewState (MAC? validators? → ysoserial.net)", "trace.axd request disclosure", "elmah.axd error logs", "padding oracle (legacy)"],
     "tools": ["nuclei -tags aspnet -u {0}"]},
    {"tech": "SharePoint", "match": {"header_or_body": ["SharePoint", "_layouts", "MicrosoftSharePointTeamServices"]},
     "confirm": [["GET", "/_layouts/15/viewlsts.aspx"], ["GET", "/_vti_bin/webs.asmx"]],
     "bugs": ["anonymous _layouts pages", "/_layouts/15/diagnostics.aspx", "spsearch CVE family", "UNC upload → SMB relay"],
     "tools": ["nuclei -tags sharepoint -u {0}"]},
    {"tech": "Elasticsearch", "match": {"body": ["\"cluster_name\"", "You Know, for Search", "lucene_version"]},
     "confirm": [["GET", "/_cat/indices"], ["GET", "/"], ["GET", "/_cluster/health"]],
     "bugs": ["open cluster data read", "old CVE families on 1.x/2.x", "script sandbox escapes on ancient versions"],
     "tools": ["nuclei -tags elasticsearch -u {0}"]},
    {"tech": "Kibana", "match": {"body": ["kbn-", "kibana"], "cookies": ["kbn-version"]},
     "confirm": [["GET", "/app/kibana"], ["GET", "/api/status"]],
     "bugs": ["5.x/6.x unauth dashboards + CVE-2019 TiUI RCE chain", "saved-objects import RCE (older)"],
     "tools": ["nuclei -tags kibana -u {0}"]},
    {"tech": "Jenkins", "match": {"header_or_body": ["Jenkins", "X-Jenkins"]},
     "confirm": [["GET", "/login"], ["GET", "/jnlpJars/jenkins-cli.jar"], ["GET", "/asynchPeople/"]],
     "bugs": ["anonymous /script console", "CVE-2024-23897 (CLI arbitrary file read)", "job config → creds decode", "update-center MITM era"],
     "tools": ["nuclei -tags jenkins -u {0}"]},
    {"tech": "GitLab", "match": {"header_or_body": ["GitLab", "gitlab-logo"]},
     "confirm": [["GET", "/users/sign_in"], ["GET", "/api/v4/version"], ["GET", "/explore"]],
     "bugs": ["CVE-2021-22205 unauth ExifTool RCE", "token leak in /api/v4 if authed", "public projects/repos in /explore", "GraphQL introspection"],
     "tools": ["nuclei -tags gitlab -u {0}"]},
    {"tech": "Jira/Confluence", "match": {"header_or_body": ["Jira", "confluence", "Atlassian", "ajs-"]},
     "confirm": [["GET", "/secure/Signup!default.jspa"], ["GET", "/rest/api/2/serverInfo"], ["GET", "/serverInfo.action"]],
     "bugs": ["user enumeration via user picker", "CVE-2023-22527 Confluence template RCE", "CVE-2022-26134 OGNL injection", "AVATAR SSRF family", "signup enabled?"],
     "tools": ["nuclei -tags jira,confluence,atlassian -u {0}"]},
    {"tech": "Bitrix", "match": {"header_or_body": ["Bitrix", "bitrix"]},
     "confirm": [["GET", "/bitrix/admin/"], ["GET", "/bitrix/tools/"]],
     "bugs": ["Bitrix RCE/SQLi history (1c-dns CVE family)", "admin brute surface"],
     "tools": ["nuclei -tags bitrix -u {0}"]},
    {"tech": "Laravel", "match": {"header_or_body": ["laravel_session", "XSRF-TOKEN + laravel"], "cookies": ["laravel_session"]},
     "confirm": [["GET", "/.env"], ["GET", "/storage/"], ["POST", "/_ignition/executeSolution"]],
     "bugs": ["Ignition RCE (CVE-2021-3129) if debug", ".env exposure", "APP_KEY leak → deserialization (RCE)"],
     "tools": ["nuclei -tags laravel -u {0}"]},
    {"tech": "ThinkPHP", "match": {"header_or_body": ["think\\", "ThinkPHP", "X-Powered-By: ThinkPHP"]},
     "confirm": [["GET", "/index.php?s=/index/\\think\\app/invokefunction"]],
     "bugs": ["5.x/6.x invokefunction RCE family", "log file exposure"],
     "tools": ["nuclei -tags thinkphp -u {0}"]},
    {"tech": "React/Next.js SPA", "match": {"body": ["__NEXT_DATA__", "_next/static", "react"]},
     "confirm": [["GET", "/_next/"], ["GET", "/api/"]],
     "bugs": ["NEXT_DATA JSON leaks (server-rendered props incl. authed data)", "stale chunk enumeration", "source maps in chunks"],
     "tools": ["js-audit skill on _next chunks"]},
    {"tech": "Vue SPA", "match": {"body": ["data-v-", "vue", "id=\"app\""]},
     "confirm": [["GET", "/static/js/"]],
     "bugs": ["bundle secrets", "v-html sinks"],
     "tools": ["js-audit skill on chunks"]},
    {"tech": "Cloudflare", "match": {"headers": ["cloudflare", "cf-ray"]},
     "confirm": [],
     "bugs": ["JA3 blocking of scripted clients — use curl_cffi/browser pass", "origin IP discovery (historical DNS, certs, origin-facing vhosts)"],
     "tools": ["crt.sh origin hunt", "SecurityTrails-style history"]},
]

GENERIC_PROBES = [["GET", "/robots.txt"], ["GET", "/.git/HEAD"], ["GET", "/.env"], ["GET", "/.svn/entries"], ["GET", "/backup.zip"], ["GET", "/composer.json"], ["GET", "/package.json"], ["GET", "/crossdomain.xml"], ["GET", "/phpinfo.php"]]


def fetch(url, method="GET", timeout=15):
    try:
        from curl_cffi import requests as cr
        r = cr.request(method, url, impersonate="chrome124", timeout=timeout, verify=False, allow_redirects=False)
        return {"status": r.status_code, "headers": dict(r.headers), "body": r.text[:60000]}
    except Exception as e:
        return {"status": None, "err": str(e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--probe", action="store_true", help="send tech-confirmation probes (paced)")
    ap.add_argument("--out", default="footprint_plan.md")
    a = ap.parse_args()
    base = a.url.rstrip("/")

    home = fetch(base + "/")
    if home["status"] is None:
        print(f"[!] unreachable: {home['err']}")
        return 1
    robots = fetch(base + "/robots.txt")
    nf = fetch(base + "/definitely-not-a-page-" + hashlib.md5(base.encode()).hexdigest()[:8])

    sig = {
        "headers": " ".join(f"{k}:{v}" for k, v in (home.get("headers") or {}).items()),
        "cookies": (home.get("headers") or {}).get("set-cookie", "") or "",
        "body": (home.get("body") or "") + " " + (robots.get("body") or "")[:5000],
        "404_status": nf["status"],
        "404_body": (nf.get("body") or "")[:300],
    }
    print(f"[*] home {home['status']} | server={home['headers'].get('server','?')} | xpb={home['headers'].get('x-powered-by','?')} | 404→{nf['status']}")

    detected = []
    for rule in RULES:
        hit = False
        m = rule["match"]
        for key in m.get("header_or_body", []) or []:
            if key.lower() in sig["headers"].lower() or key.lower() in sig["body"].lower():
                hit = True
        for key in m.get("headers", []) or []:
            if key.lower() in sig["headers"].lower():
                hit = True
        for key in m.get("body", []) or []:
            if key.lower() in sig["body"].lower():
                hit = True
        for key in m.get("cookies", []) or []:
            if key.lower() in sig["cookies"].lower():
                hit = True
        if hit:
            detected.append(rule)

    L = [f"# Footprint plan — {base}", f"\nServer: {home['headers'].get('server','?')} | X-Powered-By: {home['headers'].get('x-powered-by','?')} | 404 shape: {nf['status']} {sig['404_body'][:80]!r}\n"]
    L.append(f"## Detected stack ({len(detected)}): " + (", ".join(r["tech"] for r in detected) or "nothing matched — fingerprint manually (favicon hash, JS bundles)"))
    for r in detected:
        L.append(f"\n### {r['tech']}")
        L.append("**Known bug families:**")
        L += [f"- {b}" for b in r["bugs"]]
        L.append("**Confirm probes:** " + " ".join(f"{m} {p}" for m, p in r["confirm"]))
        L.append("**Tools:**")
        L += [f"- `{t.format(base)}`" for t in r["tools"]]

    # generic exposure probes (cheap, always run)
    L.append("\n### Generic exposure checks")
    for m, p in GENERIC_PROBES:
        rr = fetch(base + p)
        if rr["status"] in (200, 301, 302):
            tag = "INTERESTING"
            interesting = True
        elif rr["status"] == 403:
            tag = "blocked(bypass?)"
            interesting = False  # still logged below as note
        else:
            tag = "clean"
            interesting = False
        print(f"    {p:25s} {rr['status']} {tag}")
        if interesting or rr["status"] == 403:
            L.append(f"- `{p}` → {rr['status']} ({tag})")

    if a.probe:
        L.append("\n### Tech-confirmation probes (paced)")
        for r in detected:
            for method, path in r["confirm"]:
                rr = fetch(base + path, method)
                print(f"    [{r['tech']}] {method} {path} -> {rr['status']}")
                L.append(f"- `{method} {path}` ({r['tech']}) → {rr['status']}")
                time.sleep(1.3)

    open(a.out, "w", encoding="utf-8").write("\n".join(L))
    print(f"\n[+] plan saved: {a.out}")
    print("[i] next: read references/tech-matrix.md in this skill for the per-tech deep dive + tool usage (shortscan, wpscan, nuclei tags)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
