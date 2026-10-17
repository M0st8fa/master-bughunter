---
name: bb-xss
description: Hunt Cross-Site Scripting in modern SPAs — DOM XSS via source→sink analysis, reflected, stored, and postMessage-based XSS, plus CSP evaluation and CSP-bypass chains. Use whenever the user mentions XSS, cross-site scripting, innerHTML/dangerouslySetInnerHTML sinks, DOM manipulation bugs, postMessage abuse, markdown/rendering engines, or wants to test whether user input executes in a victim's browser.
---

# XSS Hunter (SPA-era)

Modern apps rarely reflect raw input server-side; XSS moved into the DOM and into rich-rendering engines. XSS is the biggest single class in the paid corpus (1,740 records) — hunt sinks, not just reflection.

## Real-bug anchors (what actually paid — query bb-disclosures for more)
- **$16,000** Stored XSS **in markdown** via the DesignReferenceFilter — rendering pipelines that accept rich text.
- **$13,950** Stored XSS in Notes **with CSP bypass** for gitlab.com — the bypass was the payout multiplier.
- **$13,950** XSS in **ZenTao integration** affecting self-hosted instances without strict CSP — integrations inherit weak CSP.
- **$13,950** `/add_contacts` `/remove_contacts` **quick commands** XSS from custom input — chat command parsers.
Delta lesson: the money is in **stored XSS via rich-render/markdown/integration surfaces** and in **demonstrated CSP bypasses**. A reflected XSS behind a strict nonce CSP is worth little; the same payload in a markdown note rendered for other users is $10k+.

## Sink-driven approach
1. Grep bundles (js-recon or raw grep) for sinks:
   `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval(`, `new Function(`, `setTimeout("string")`, `dangerouslySetInnerHTML`, `v-html`, jQuery `$()`, `element.src =`, `location.href =`, `location.assign(`
2. Trace backwards: what reaches the sink? Sources: `location.*` (hash/search/path), `postMessage`, `document.referrer`, `localStorage`, URL params, API responses (stored).
3. Test the chain end-to-end: the payload must EXECUTE — `alert(1)`/`print()`/marker fetch — not just land in HTML.
4. **WAF check before sink work**: edge WAFs often block `<script>`-shaped payloads with 403 while the app itself escapes nothing — `</script>`-style breakouts may be dead at the edge while attribute/handler vectors pass. Map which characters survive first (send one probe per pattern, watch for WAF 403 vs app 400 vs 200).

## Context-aware payloads
- HTML body: `<img src=x onerror=print()>`
- Attribute: `" onfocus=print() autofocus="`
- JS string: `'-print()-'` / `";print()//`
- Template literal: `${print()}`
- URL param in href/src: `javascript:print()` (needs user click — say so)
- JSON API field rendered client-side → stored XSS vector (profile name, review title, file name, address nickname, **order/customer notes**)
- Markdown/rich text: `[x](javascript:print())`, `![x](y"onerror=print())`, HTML-in-markdown leftovers, reference-style link processors

## postMessage XSS
- Grep `addEventListener("message"` — check for `origin` validation and `e.data` flowing to sinks/DOM.
- PoC: `victim.com` page + attacker page running `victimWindow.postMessage(payload, "*")`. Missing origin check + sink = usually High.

## Payload library (bundled)
`assets/payloads.txt` — 3,964-entry XSS payload list (orwagodfather/XSS-Payloads). Grep by context instead of spraying blind:
```bash
grep -i 'onerror'  <path-to-skill>/assets/payloads.txt | grep -i svg   # event-handler vectors (HTML sinks)
grep -i 'javascript:' <path-to-skill>/assets/payloads.txt               # scheme vectors (href/src sinks)
grep -iE 'autofocus|onfocus|onmouseover' <path-to-skill>/assets/payloads.txt  # low-interaction vectors
```
Encoded variants (single/double URL-encoding, unicode) are included — useful against WAFs that decode once.

## CSP reality check
- Read the CSP header before hunting reflection effort: `script-src 'unsafe-inline'` = game on; strict nonce + no unsafe-inline = server-reflected XSS mostly dead, pivot to DOM/file-upload/markdown.
- A demonstrated **CSP bypass** (JSONP endpoints, gadget chains, `base-uri`/`object-src` gaps, Angular template injection under permissive CSP) multiplies the payout — the $13.9k gitlab note XSS was priced by its bypass.
- `default-src https:` still allows `javascript:` URIs in some contexts; check `object-src`, `base-uri`.
- **User input landing IN a CSP meta tag** (e.g. site-builder "trusted sites" features): browsers honor only the FIRST duplicated directive, so injecting `; connect-src evil` fails — but injecting an ALREADY-WHITELISTED value followed by a new directive makes the backend APPEND new origins into the existing directive: `https://evil.target.com;%20connect-src https://mainsite/api` → `connect-src 'self' https://evil.target.com; https://mainsite/api;` — bypass achieved ($3.5k: out-of-scope subdomain XSS + CORS-trusting API + this append trick = ATO).
- **JSONP under CSP**: `www&#x2e;google&#x2e;com/complete/search?client=chrome&q=hello&callback=alert#1` — HTML-entity dots survive into `script-src` allowlists that string-match `www.google.com`.

## Script-context & template breakouts
- Any server value embedded in inline JS via `json.dumps()`/`JSON.stringify()` (Python defaults escape quotes but NOT `/`): `</script><svg onload=print()>` breaks out of the script element into raw HTML — paid on cPanel/Mailman (`?mpidentity=` reflected into `var pageData = {...}`).
- "Sanitizing" regexes that assume a match shape: `preg_replace('~^(\d\.?\d).*~s', ...)` returns the input UNCHANGED on no-match — a rogue MySQL server version string `1');print()//` rode a no-match straight into a nonce'd script block (Adminer). If a regex's output is only safe when it MATCHES, feed it a non-matching payload.
- DOM XSS, postMessage type confusion, parser differentials, sanitizer exfil → use the **bb-domxss** skill (deeper source→sink methodology).
- Input concatenated into `fetch()`/XHR paths = **CSPT**: traverse into `/cdn-cgi/image/onerror=redirect/https://sibling.target.com/<path>` — Cloudflare's 307 forwards method+body+headers cross-origin (cookies per SameSite; `Authorization` is dropped → cookie-auth targets only).

## Verdict + impact
- Self-XSS in your own profile without a way to make a victim render it = rejected (pre-declared on most programs). Need a delivery: shared object (review, cart share, ticket message, file name shown to staff, group-order note) or a CSRF-forced save.
- Evidence: executing payload screenshot/console proof + the exact URL/request that planted it.
- Chain upward (bb-chains): XSS + non-HttpOnly session cookie → ATO; XSS on authenticated app → action-on-behalf-of-victim PoC (add own test item, change nothing destructive).
