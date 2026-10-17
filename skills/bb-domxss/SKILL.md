---
name: bb-domxss
description: Hunt DOM XSS through source→sink analysis in JavaScript — location/postMessage/window.name taint into innerHTML, eval, location-assignment, jQuery and framework sinks; filter and WAF bypasses (character-strip splitting, parser differentials), postMessage type-confusion, DOM clobbering, and turning "sanitized" injection into token exfiltration. Use whenever the user mentions DOM XSS, client-side XSS, source/sink, location.hash injection, unsafe innerHTML, sink analysis, javascript: URI in redirects, or when reflected XSS is blocked but input still reaches client-side code.
---

# DOM XSS Hunter

DOM XSS lives entirely client-side: attacker-controlled data (source) flows through JS into a dangerous API (sink) without server reflection. Server-side WAFs and output encoding are irrelevant — which is exactly why it thrives in modern SPAs. Methodology: mine sinks → trace sources → build the chain → prove execution → chain to impact.

Techniques below are distilled from Voorivex Team research (blog.voorivex.team) plus classic source→sink discipline. Advanced material (filter bypasses, parser differentials, postMessage type confusion, exfil-without-JS) is in `references/advanced-dom-xss.md` — read it when the basic chain is filtered, sanitized, or you need ATO impact.

## Step 1 — Mine sinks in JS bundles

Pull every bundle (js-recon skill does this in one pass) and grep for sinks, grouped by exploitability:

**Direct execution (best):**
```
eval(  new Function(  setTimeout("  setInterval("  Function(  script.src =
```
**HTML injection (script tags do NOT execute via these — use event-handler payloads):**
```
innerHTML  outerHTML  insertAdjacentHTML  document.write(  document.writeln(
dangerouslySetInnerHTML  v-html  jQuery $(...) with string  .html(  .append(  .prepend(
```
**URL/scheme sinks (javascript: URI territory):**
```
location =  location.href =  location.assign(  location.replace(  location.protocol =
element.src =  element.href =  element.data =  window.open(  $(location).attr(
form.action =  iframe.srcdoc =  a.setAttribute('href',
```
**jQuery-specific:** `$location.hash`, `$(url)`, `$.ajax({url: hash})`, `element.attr('href', hash)`.

Also grep for **validation adjacent to sinks** — a `replace()` stripping characters near a `location =` assignment is a filter you can characterize (see bypass section below).

## Step 2 — Trace the sources that feed them

| Source | Reaches the page via |
|---|---|
| `location.hash` / `location.search` / `location.pathname` | URL — fully attacker-controlled, survives WAFs (never sent to server for `#`) |
| `document.referrer` | linking page / OAuth provider redirects |
| `postMessage` (`message` events) | any window that holds a reference — parent, opener, iframe |
| `window.name` | previous page in the same tab (attacker sets it then navigates) |
| `localStorage` / `sessionStorage` / cookies (non-HttpOnly) | anything previously stored — often another XSS or a second-order param |
| URLSearchParams / URL API reads | same as location.* but through a parser — see parser differentials |
| API responses | stored XSS territory (bb-xss skill) |

Trace forward from source OR backward from sink — whichever the bundle makes easier. Confirm the taint path actually executes on page load vs. requires an interaction (click, message event).

## Step 3 — Sink-appropriate payloads

**HTML sinks (`innerHTML` etc.) — no `<script>` execution; event handlers instead:**
```html
<img src=x onerror=print()>
<svg onload=print()>
<body onpageshow=print()>
<details open ontoggle=print()>
```

**Direct JS sinks (`eval`, `new Function`, string `setTimeout`):** the param value IS code — `print()` / `alert(origin)` directly.

**location/href/src sinks — `javascript:` URI scheme:**
```
javascript:print()//
javascript:print(origin)//anything  (// comments out trailing path junk)
```
Note `//` suffix: sinks that append a path/URL after your input (`location = base + param`) turn your payload into a comment. If a filter strips characters (`.` `/` `<` `>` `'` `"` `\`), split the scheme with the stripped chars: `ja.va.sc.ri.pt.:al.er.t(or.ig.in)` reassembles after the strip (real $-grade bypass from a WAF + replace() pair).

**postMessage sinks:** craft the exact message shape the handler expects — see type-confusion techniques in the advanced reference (arrays with named properties defeat many checks).

**Fuzzing corpus:** `assets/payloads.txt` (3,964 entries, orwagodfather/XSS-Payloads). Use it context-aware, not blind:
```bash
grep -i 'onerror'  assets/payloads.txt | grep -i svg     # event-handler vectors for HTML sinks
grep -i 'javascript:' assets/payloads.txt                 # scheme vectors for URL sinks
grep -iE 'autofocus|onfocus' assets/payloads.txt          # no-interaction attribute vectors
```

## Step 4 — Prove execution, then chain

- Execution proof: payload calls `print()` / `alert(origin)` / marker fetch to your own domain. "Landing in HTML" is not XSS.
- Chain to ATO for payout (bb-chains discipline):
  - Non-HttpOnly session cookie or browser-recognition cookie → steal + replay. When 2FA gates everything, hunt the device-recognition cookie (often non-HttpOnly) — presenting it with a fresh session skips 2FA ("same browser").
  - OAuth SDK present in the same window → re-initialize it with your own callback: `google.accounts.id.initialize({client_id, callback: r => exfil(r.credential), auto_select: true})` then `google.accounts.id.prompt()` — auto-select One Tap steals the JWT credential with zero further interaction.
  - XSS on an OAuth redirect_uri page → the token is in the same URL as your payload — exfiltrate the URL itself (referrer techniques in the advanced reference).

## Quick calls

- **DOM clobbering**: no sink found but HTML injection exists? Clobber `config`/`settings` objects (`<a id=config><a id=config href="x:">`) to change app behavior upstream of a decision.
- **Sanitizer present (DOMPurify)?** Don't hunt a bypass first — hunt *parsing side effects* and exfil channels: DOMPurify allowlists `<style>` and `style=` by default; CSS can leak the page URL (token!) via attribute selectors and referrer-policy modifiers. Full playbook: `references/advanced-dom-xss.md`.
- **Server validates the param but client consumes it separately?** Parser differential territory (Express `qs` vs `URLSearchParams`) — server sees the clean value, browser executes yours. Advanced reference.
- **Verdict**: DOM XSS with no victim delivery is self-XSS. Need a link/QR/message that plants the source (URL with payload, postMessage from an embedded iframe, stored value) — document the delivery path in the report.
