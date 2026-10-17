---
name: target-intelligence
description: Build a complete Target Intelligence Document for a domain from passive sources only — JS bundle analysis, Wayback historical URLs, API docs, HTTP headers, robots/sitemaps, certificate transparency — mapping the app's architecture, auth flows, business logic, hidden endpoints, and a prioritized attack surface into one structured markdown file. Use whenever the user provides a domain and asks to understand, map, document, or analyze a target before hunting, says "build target intel", "build docs", "understand the app first", or wants a pre-hunt briefing another agent can hunt from.
---

# Target Intelligence Skill

## YOUR MISSION

You are a senior application security researcher. Your job is NOT to find vulnerabilities yet. Your job is to deeply understand this application — how it works, what it does, how users interact with it, and where the interesting complexity lives. A perfect output here makes vulnerability finding trivial in the next step.

Think like a developer who built this app, not like a scanner.

## RULES

1. **Authorized targets only** — confirm the domain is in a program's published scope before collecting anything
2. **Passive only** — no active scanning, no authenticated requests unless the user explicitly approves
3. **Specific always** — reference actual URLs, parameter names, code snippets
4. **No generic statements** — "might have XSS" is useless; "parameter `q` on `/search` reflects unencoded" is useful
5. **Document gaps** — if a source was unavailable, say so and why
6. **Think like a developer** — understand the app before hunting it
7. **Flag the unusual** — anything that deviates from standard patterns deserves attention
8. **Separate observation from hypothesis** — facts go in the document; "this might be vulnerable because..." goes in the attack surface section

## Companion skills (delegate, don't reimplement)

| Need | Skill |
|---|---|
| Broad multi-source passive recon (subdomains, URLs, IPs) | **recon-engine** |
| JS download + endpoint/secret extraction in one pass | **js-recon** (Phase 2 workhorse) |
| Deep 10-section JS audit incl. GraphQL/authz/upload surface | **js-audit** |
| Tech-stack fingerprint → known-CVE pivot | **footprinting** |
| OAuth `registration_endpoint` found in `.well-known` | **bb-oauth** (DCR attacks) |
| Hunting AFTER this document is built | **bb-pipeline** + bb-* class skills |

## PHASE 1 — PASSIVE COLLECTION

Collect everything available without active or authenticated requests. Work through each source in order; skip unavailable sources and note why.

### 1.1 Basic Fingerprinting
```bash
# Technologies and headers
curl -sk -I "https://{TARGET}" | grep -iE "server|x-powered|x-framework|cf-ray|x-cdn"

# Robots and sitemap
curl -sk "https://{TARGET}/robots.txt"
curl -sk "https://{TARGET}/sitemap.xml"
curl -sk "https://{TARGET}/sitemap_index.xml"

# Security files
curl -sk "https://{TARGET}/.well-known/security.txt"
curl -sk "https://{TARGET}/.well-known/openid-configuration"
curl -sk "https://{TARGET}/.well-known/oauth-authorization-server"
```
⚠️ If `.well-known/oauth-authorization-server` (or openid-configuration) exposes a `registration_endpoint`, flag it — that's an open OAuth Dynamic Client Registration candidate (bb-oauth MCP section).

### 1.2 JavaScript Collection
Collect ALL JS files from:
- The main page HTML (extract `<script src="">`)
- Wayback Machine historical JS bundles
- Common paths: `/static/js/`, `/assets/js/`, `/dist/`, `/build/`
- Source maps if available: `*.js.map`

```bash
# Get JS files from main page
curl -sk "https://{TARGET}" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//'

# Wayback JS files
curl -sk "https://web.archive.org/cdx/search/cdx?url={TARGET}/*.js&output=text&fl=original&collapse=urlkey"
```

### 1.3 Historical URL Collection
```bash
# Wayback Machine - all URLs
curl -sk "https://web.archive.org/cdx/search/cdx?url=*.{TARGET}/*&collapse=urlkey&output=text&fl=original"

# Filter for interesting paths
grep -iE "\.(json|xml|yaml|env|config|bak|sql|php|asp|aspx|jsp)$|/api/|/admin/|/internal/|/debug/|/graphql|/swagger|/v[0-9]/"
```

### 1.4 Public API Documentation
Check these locations:
- `https://{TARGET}/api-docs`
- `https://{TARGET}/swagger.json`
- `https://{TARGET}/swagger-ui.html`
- `https://{TARGET}/openapi.json`
- `https://{TARGET}/api/docs`
- `https://{TARGET}/graphql` (introspection)
- Developer portal: `developers.{TARGET}`, `dev.{TARGET}`, `api.{TARGET}`

### 1.5 Certificate Transparency
```bash
# Subdomains via CN search
curl -sk "https://crt.sh/?q=%.{TARGET}&output=json" | jq -r ".[].name_value" | sort -u

# Bonus — Organization-field search finds root domains CN search misses
# (lookup the org name from an existing cert first)
curl -s "https://crt.sh/?O={ORG_NAME}&output=json" | jq -r ".[].common_name" | tr A-Z a-z | sort -u
```

## PHASE 2 — JAVASCRIPT DEEP ANALYSIS

For EVERY JS file collected, extract the following. This is the most important phase — JS files contain the application's entire logic. (The js-recon/js-audit skills automate much of this — use them for bulk work, and read the interesting bundles by hand.)

### 2.1 Endpoint Extraction
Extract ALL URLs, paths, and API calls:

```
Patterns to find:
- fetch("/api/...")
- axios.get("/...")
- $.ajax({url: "..."})
- "/api/v1/" + variable
- `${BASE_URL}/endpoint`
- router.get("/path", ...)
- app.post("/path", ...)
- path: "/something"
- endpoint: "..."
- url: "https://..."
```

Group endpoints by:
- **Authentication** (login, logout, register, reset, verify, oauth, token, session)
- **User/Account** (profile, settings, preferences, account, me)
- **Core Features** (whatever the app does — tracks, orders, products, etc.)
- **Admin/Internal** (admin, internal, management, dashboard, ops)
- **Payment/Billing** (pay, stripe, checkout, subscribe, upgrade, invoice)
- **File Operations** (upload, download, export, import, attachment)
- **API/Integration** (webhook, callback, oauth, integrate, connect)
- **Debug/Dev** (debug, test, dev, staging, health, status, metrics)

### 2.2 Authentication & Authorization Analysis
```
Find and document:
- How tokens are generated and stored (localStorage, cookie, memory)
- Token format (JWT, opaque, session ID)
- Token expiry and refresh mechanism
- Where Authorization header is set
- Role/permission checks in frontend code
- What happens when token expires
- OAuth flows and redirect URIs  (→ bb-oauth)
- Any hardcoded credentials or API keys
```

### 2.3 Business Logic Mapping
Read the JS like a developer. Understand:
```
- What are the main user flows? (signup → onboard → use → pay → cancel)
- What sequential steps exist? (wizard steps, multi-page forms)
- What validations happen client-side only?
- What parameters control pricing, access, or permissions?  (→ bb-bizlogic)
- What feature flags or A/B test conditions exist?
- What admin-only functions are exposed in JS?
- What async operations happen? (uploads, processing, webhooks)
```

### 2.4 Secrets & Sensitive Data
```bash
# Search patterns
grep -iE "(api_key|apikey|api-key|secret|token|password|passwd|credential|private_key)" js_file.js
grep -E "AKIA[0-9A-Z]{16}" js_file.js          # AWS Access Key
grep -E "sk_live_[a-zA-Z0-9]+" js_file.js       # Stripe live key
grep -E "eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+" js_file.js  # JWT
grep -E "(firebase|firebaseio|firebaseapp)" js_file.js
grep -E "['\"]([a-zA-Z0-9]{32,})['\"]" js_file.js  # Generic long tokens
grep -E "10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\." js_file.js  # Internal IPs
```

### 2.5 Interesting Patterns
```
Flag these for attack surface:
- eval(), innerHTML, document.write() → XSS sinks  (→ bb-domxss)
- location.href = userInput → Open redirect
- fetch(userInput) → SSRF  (→ bb-ssrf)
- __proto__, constructor → Prototype pollution
- postMessage handlers → check origin validation  (→ bb-domxss)
- WebSocket connections → check auth
- setTimeout(string) → code injection
- dangerouslySetInnerHTML → React XSS
- v-html → Vue XSS
```

## PHASE 3 — APPLICATION UNDERSTANDING

After collecting and analyzing all data, synthesize:

### 3.1 What Does This App Actually Do?
Write 3-5 sentences explaining:
- What is the core product/service?
- Who are the users? (consumers, businesses, developers)
- What is the monetization model?
- What sensitive data does it handle? (PII, payments, health, financial)
- What integrations does it have?

### 3.2 What Are The Most Critical Business Flows?
Identify 3-7 flows that, if broken or abused, would cause the most damage. Map every step including the API calls:

```
FLOW: User Purchase Premium Subscription
Step 1: User clicks "Upgrade" → GET /api/v1/plans
Step 2: User selects plan → frontend stores plan_id
Step 3: User enters payment → POST /api/v1/checkout {plan_id, payment_token}
Step 4: Backend charges card → calls Stripe API
Step 5: Backend updates user role → UPDATE users SET role='premium'
Step 6: Frontend redirects → GET /api/v1/me (returns new role)

⚠️ Interesting: plan_id comes from frontend — is it validated server-side?
⚠️ Interesting: role update — is there a race condition window?  (→ bb-race)
```

### 3.3 What Is Unique Or Complex About This App?
Note anything unusual:
- Custom authentication schemes
- Complex multi-tenant architecture
- Unusual file handling  (→ bb-upload)
- Real-time features (WebSockets, SSE)
- Microservices with different auth requirements
- Mobile API vs web API differences

## PHASE 4 — ATTACK SURFACE MAPPING

Based on everything collected, identify the highest-value targets. DO NOT test yet — just map.

### Priority Matrix
Rate each finding:
- **Impact**: What's the worst case if this is vulnerable?
- **Likelihood**: How likely is it to actually be vulnerable?
- **Uniqueness**: Would most hunters find this? (low uniqueness = crowded)

### Attack Surface Categories

**🔴 CRITICAL PRIORITY**
```
- Admin panels and internal tools
- Payment and billing endpoints
- Authentication bypass candidates
- File upload endpoints
- OAuth redirect_uri parameters
- Password reset flows
- Account takeover vectors
```

**🟠 HIGH PRIORITY**
```
- IDOR candidates (numeric IDs, UUIDs in parameters)
- Endpoints with role/permission parameters
- Mass assignment candidates (object spreading)
- SSRF candidates (url=, redirect=, fetch= parameters)
- Historical endpoints that may still work
- Undocumented API endpoints found in JS
```

**🟡 MEDIUM PRIORITY**
```
- XSS candidates in reflected parameters
- Business logic abuse opportunities
- Race condition candidates
- Information disclosure endpoints
- GraphQL introspection findings
```

## PHASE 5 — OUTPUT DOCUMENT

Write the final Target Intelligence Document using the EXACT structure in `references/output-template.md` (read it now). Be specific — reference actual URLs, parameter names, and code snippets. No generic statements.

Save it as:
```
target-intel/{TARGET}/intelligence-{DATE}.md
```

## HOW TO USE

Input — just the domain:
```
"Build target intelligence for soundcloud.com"
"Document this target: fivetran.com"
"Understand the app at realestate.com.au before I start hunting"
```

After the document is built, hunt from it:
```
"Now read target-intel/soundcloud.com/intelligence-*.md and hunt for IDOR vulnerabilities"
```

Or hand it to another agent:
```
"Here is the target intelligence document for soundcloud.com: [paste document]
Hunt for business logic vulnerabilities based on this."
```
