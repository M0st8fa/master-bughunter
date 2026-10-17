# Target Intelligence Document Template

Fill EVERY section. Reference actual URLs, parameter names, and code snippets — no generic statements. Delete these instructions; keep the structure.

---

# 🎯 TARGET INTELLIGENCE: {TARGET}

**Generated:** {DATE}
**Scope:** {SCOPE}
**Sources Used:** {LIST_SOURCES}

---

## 📋 EXECUTIVE OVERVIEW

### What Is This Application?
{3-5 sentence description}

### Technology Stack
| Layer | Technology | Version | Notes |
|-------|-----------|---------|-------|
| Frontend | | | |
| Backend | | | |
| CDN/WAF | | | |
| Auth | | | |
| Database hints | | | |
| Third-party | | | |

### Sensitive Data Handled
{PII, payments, health data, etc.}

---

## 🗺️ ASSET MAP

### Domains & Subdomains
```
{TARGET}                    → Main application
api.{TARGET}               → API server
admin.{TARGET}             → ⚠️ Admin panel
cdn.{TARGET}               → Static assets
auth.{TARGET}              → Authentication service
...
```

### IP Addresses
{List IPs and hosting providers}

---

## 🔐 AUTHENTICATION & SESSION

### How Login Works
{Step by step, with actual endpoint names}

### Token Mechanics
```
Type: JWT / Session Cookie / Opaque Token
Storage: localStorage / sessionStorage / Cookie
Cookie flags: HttpOnly={yes/no}, Secure={yes/no}, SameSite={value}
Expiry: {time}
Refresh: {how}
```

### OAuth / SSO
{If present — providers, flows, redirect URIs found}

### Password Reset Flow
{Steps with endpoints}

### ⚠️ Auth Observations
{Anything unusual or potentially weak}

---

## 💼 BUSINESS LOGIC FLOWS

### Flow 1: {Most Critical Flow Name}
```
Step 1: {action} → {endpoint} {method}
  Parameters: {param1}, {param2}
Step 2: {action} → {endpoint} {method}
  Parameters: {param1}, {param2}
...
⚠️ Note: {anything interesting}
```

### Flow 2: {Second Most Critical}
{same format}

{Repeat for all critical flows}

---

## 🗂️ ENDPOINT INVENTORY

### Authentication Endpoints
```
POST /api/v1/auth/login          → Login with email/password
POST /api/v1/auth/logout         → Invalidate session
POST /api/v1/auth/refresh        → Refresh JWT
POST /api/v1/auth/forgot         → Initiate password reset
PUT  /api/v1/auth/reset          → Complete password reset
POST /api/v1/auth/register       → New account creation
```

### User/Account Endpoints
```
GET    /api/v1/me                → Current user profile
PUT    /api/v1/me                → Update profile
DELETE /api/v1/users/{id}        → Delete account
GET    /api/v1/users/{id}/...    → User sub-resources
```

### Core Feature Endpoints
{Group by feature}

### Admin/Internal Endpoints
```
⚠️ These were found in JS or historical data:
GET /admin/...
GET /internal/...
GET /api/v1/admin/...
```

### Undocumented Endpoints
```
🔍 Found in JS but not in public docs:
{list}
```

---

## 📜 JAVASCRIPT ANALYSIS FINDINGS

### Secrets Found
```
{KEY_TYPE}: {VALUE_REDACTED_LAST_4} — found in {filename}
```

### Internal URLs & Infrastructure
```
{any internal IPs, hostnames, microservice URLs}
```

### Interesting Code Patterns
```javascript
// {what it does and why it's interesting}
{code snippet}
```

### Client-Side Validations (Server-Side Bypass Candidates)
```
{validation that only happens in JS — no server check found}
```

---

## 🎯 ATTACK SURFACE SUMMARY

### 🔴 CRITICAL — Test These First
```
1. {endpoint or feature}
   Why: {specific reason}
   How to test: {specific approach}

2. {endpoint or feature}
   Why: {specific reason}
   How to test: {specific approach}
```

### 🟠 HIGH — High Value Targets
```
1. {endpoint or feature}
   Parameter: {specific parameter}
   Test for: {vulnerability type}
```

### 🟡 MEDIUM — Worth Investigating
```
{list}
```

### 💡 UNIQUE OPPORTUNITIES
{Things most hunters would miss — complex business logic, unusual flows, second-order effects, race conditions}

---

## 📎 RAW DATA APPENDIX

### All Endpoints Found
{complete list}

### All JS Files Analyzed
{list with URLs}

### Historical Endpoints (Wayback)
{endpoints found historically that may still exist}

### GraphQL Schema (if applicable)
{types, queries, mutations found}

---
*This document contains passive reconnaissance only.
No active requests were made to test for vulnerabilities.
All findings require authorized validation before reporting.*
