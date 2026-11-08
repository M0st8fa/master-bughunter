# Bugcrowd VRT — Classification & Reward-Prioritization Map

Official source: **https://bugcrowd.com/vulnerability-rating-taxonomy**
(machine-readable: https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json).
Snapshot: release **2026-07-08**, captured 2026-11-08. Web-focused subset below — the
public VRT also covers mobile/automotive/blockchain/AD/AI; consult the source for those.

## 1. Priority semantics

- **P1–P4**: decreasing reward priority. **P5**: typically ineligible — do not submit
  without a demonstrated chain (bb-chains discipline).
- **No priority shown** (`(no default)`): Bugcrowd leaves the default to the program.
  These are commonly paid when impact is proven — justify with impact or check the brief.
- **Programs override the public VRT** (added/removed entries, custom priorities,
  out-of-scope lists). The public VRT is the **baseline**: always read the program's own
  VRT table on the brief before submitting. A P5-baseline entry that the program
  explicitly lists as in-scope is reportable; a P1-baseline entry the program excluded is not.
- VRT **complements** CVSS — keep both in the report (VRT for platform triage, CVSS for severity).

## 2. Classify a finding

1. Pick the **deepest matching variant** (category → subcategory → variant).
2. Write the full path + priority in the report:
   `VRT: Broken Access Control > Insecure Direct Object References (IDOR) > Modify/View Sensitive Information (Iterable Object Identifiers) [P1]`
3. If no variant fits, use the closest category and justify in one line. Never invent VRT entries.
4. Record the same string in the finding record (`vrt` field, `schemas/finding.schema.json`).

## 3. Reward-focused hunting priorities (hunt these FIRST on Bugcrowd programs)

### P1 — highest reward band
| VRT entry | Hunt via |
|---|---|
| Server-Side Injection > Remote Code Execution [1] | bb-rce |
| Server-Side Injection > SQL Injection [1] | bb-sqli |
| Server-Side Injection > XML External Entity (XXE) [1] · File Inclusion > Local [1] | bb-rce |
| Broken Access Control > IDOR > **Modify/View Sensitive Information (Iterable Object Identifiers)** [1] | bb-authz, idor-runner |
| Broken Authentication and Session Management > Authentication Bypass [1] | bb-authz, bb-oauth |
| Server Security Misconfiguration > Using Default Credentials [1] | footprinting, bb-authz |
| Server Security Misconfiguration > Exposed Portal > Admin Portal [1] | bb-authz force-browse |
| Sensitive Data Exposure > Disclosure of Secrets > For Publicly Accessible Asset [1] | js-audit, bb-pii |
| Sensitive Data Exposure > PII Leakage/Exposure (no default; P1-class with customer data) | bb-pii |
| Cloud Security > IAM > Publicly Accessible IAM Credentials [1] | cloud-security |
| Insecure OS/Firmware > Command Injection [1] · Hardcoded Password > Privileged User [1] | bb-rce, footprinting |

### P2 — next band
| VRT entry | Hunt via |
|---|---|
| IDOR > Modify Sensitive Information (Iterable) [2] | idor-runner |
| Stored XSS > Non-Privileged User to Anyone [2] | bb-xss |
| SSRF > Internal Secrets Exposure [2] | bb-ssrf |
| CSRF > Application-Wide [2] | bb-csrf |
| OAuth Misconfiguration > Account Takeover [2] | bb-oauth |
| Sensitive Data Exposure > Weak Password Reset Implementation > Token Leakage via Host Header Poisoning [2] | bb-authz |
| Cloud Security > IAM > Overly Permissive IAM Roles [2] | cloud-security |
| Active Directory > Kerberoasting / ASREPRoasting [2] | footprinting (AD contexts) |

### No default priority — commonly paid when impact is proven
Privilege Escalation (BAC) · Cache Deception · Cache Poisoning (bb-cache) · Race Condition
(bb-race) · Path Traversal · Server-Side Template Injection > Custom · HTTP Request
Smuggling · Unsafe Cross-Origin Resource Sharing · Subdomain Takeover · Publicly Accessible
Cloud Storage · Sensitive Data Exposure > PII Leakage/Exposure · WAF Bypass · Request
Smuggling. Frame these with the strongest impact evidence you can produce — the program
decides the tier.

## 4. Priority deltas that shape tactics (exact VRT math)

- **IDOR: iterable [1]/[3] vs GUID [4].** Predictable/sequential IDs are the money — run
  bb-authz V10 (predictability) and the idor-runner matrix before accepting a GUID-P4 ceiling.
- **XSS: Stored non-priv→anyone [2] vs Reflected non-self [3] vs Self [5].** Hunt the
  stored/delivery path (shared objects, staff-rendered fields) — reflected alone is P3.
- **SSRF: DNS-query-only [5] vs Internal Data [3] vs Internal Secrets [2].** A pingback is
  worthless — always escalate to internal proof before reporting.
- **Open Redirect: GET-based [4], every other transport [5].** Never submit without the
  OAuth/ATO chain (bb-chains).
- **CSRF: Application-Wide [2] vs single authenticated action (no default) vs Logout [5].**
- **No Rate Limiting: Login/Registration/SMS [4], Change Password [5]** — pair with OTP/ATO
  impact or it's P4-at-best.

## 5. P5 / auto-reject entries (never submit without a demonstrated chain)

Lack of Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, …) ·
Cookie-Based / IE-Only / Self / TRACE XSS · CSRF Token Not Unique Per Request · Flash-based
anything · Logout CSRF · GraphQL Introspection Enabled · Internal IP Disclosure · Mixed
Content · JSON Hijacking · Non-Sensitive Token in URL · Fingerprinting/Banner/Software
Version Disclosure · Directory Listing (non-sensitive) · Username/Email Enumeration
(Brute Force [5] / Non-Brute Force [4] under BAC) · Open Redirect (Flash/POST/Header/Tabnabbing) ·
Outdated Software Version · Unpatched JS Libraries · Missing DNSSEC · Bitsquatting ·
Same-Site Scripting · Reflected File Download · No Account Lockout · No 2FA Implementation ·
Weak/No Password Policy · Excessive JWT Lifetime · Weak JWT Hashing · Session-invalidation
minors (Long Timeout, Concurrent Logins, Logout server-side-only) · Missing Secure/HttpOnly
flag (non-session cookie) · Autocomplete/Save-Password flags · CSV Injection · Captcha
Brute Force · SSRF External DNS-Query-Only / External Low Impact · Insecure SSL (cert
errors, cipher suites, forward secrecy) · Publicly-accessible robots.txt · Sensitive
Information Disclosed in JWT · Clickjacking (non-sensitive action).

This list **supersedes nothing** — it is the VRT-backed version of the bb-chains
always-rejected list; bb-chains governs when a chain makes a P5 entry conditionally valid.

## 6. Refresh procedure

1. Fetch the JSON above; compare `metadata.release_date` with the snapshot date in this header.
2. Diff the changed entries; update §3–§5 tables (keep exact variant strings).
3. Update the snapshot date; log the change in the repo `CHANGELOG.md`.
