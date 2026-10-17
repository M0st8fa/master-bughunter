#!/usr/bin/env python3
"""js_audit.py — deep JavaScript bundle auditor for bug bounty recon.

Input: one or more .js files / a directory / (optional) --url to fetch first.
Output: --out report (markdown) + --json machine file.

Buckets (see SKILL.md): REST endpoints, GraphQL, auth mechanisms, hidden/debug
endpoints, admin surface, uploads, websockets, secrets, third parties, business
logic, and vuln-mapping leads (SQLi-prone, mass assignment, missing server
validation, auth weaknesses, authz-in-UI-only, client-controlled identity
headers, input-validation bypass, rate-limit hints) with manual next steps.
"""
import argparse, base64, json, math, os, re, sys, collections

# ---------------------------------------------------------------- helpers
def read_sources(paths, url=None):
    srcs = []
    if url:
        try:
            from curl_cffi import requests as cr
            r = cr.get(url, impersonate="chrome124", timeout=30, verify=False)
            srcs.append((url.split("/")[-1] or "index.js", r.text))
        except Exception as e:
            print(f"[!] fetch {url} failed: {e}", file=sys.stderr)
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    if f.endswith((".js", ".mjs", ".cjs", ".map", ".html")):
                        fp = os.path.join(root, f)
                        try:
                            srcs.append((fp, open(fp, encoding="utf-8", errors="replace").read()))
                        except Exception:
                            pass
        elif os.path.isfile(p):
            try:
                srcs.append((p, open(p, encoding="utf-8", errors="replace").read()))
            except Exception:
                pass
    return srcs


def ctx(text, i, before=90, after=110):
    return re.sub(r"\s+", " ", text[max(0, i - before):i + after]).strip()


def shannon(s):
    if not s:
        return 0.0
    freq = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        k = json.dumps(x, sort_keys=True) if not isinstance(x, str) else x
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out

# ---------------------------------------------------------------- patterns
SECRET_PATTERNS = [
    ("AWS access key", r"\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b", "HIGH"),
    ("AWS secret key", r"(?i)aws.{0,25}['\"]([0-9a-zA-Z/+]{40})['\"]", "HIGH"),
    ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "CHECK"),
    ("Firebase key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b", "HIGH"),
    ("Stripe secret", r"\bsk_live_[0-9a-zA-Z]{24,}\b", "HIGH"),
    ("Stripe webhook secret", r"\bwhsec_[0-9a-zA-Z]{24,}\b", "HIGH"),
    ("Stripe publishable", r"\bpk_(live|test)_[0-9a-zA-Z]{24,}\b", "PUBLIC"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "HIGH"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "HIGH"),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{22,}", "HIGH"),
    ("Twilio key", r"\bSK[0-9a-fA-F]{32}\b", "HIGH"),
    ("NPM token", r"\bnpm_[A-Za-z0-9]{36}\b", "HIGH"),
    ("Private key block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "HIGH"),
    ("OpenAI key", r"\bsk-[A-Za-z0-9_-]{20,}\b", "CHECK"),
    ("JWT literal", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "CHECK"),
    ("DB connection string", r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^\s\"'`]{8,}", "HIGH"),
    ("Generic secret assignment", r"(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|passwd|password|access[_-]?token|auth[_-]?token)\b['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", "CHECK"),
]
PUBLIC_HINTS = re.compile(r"(?i)(pk_live|publishable|public[_-]?key|browser[_-]?key|datadog|sentry|dsn|GTM-|G-[A-Z0-9]{8}|intercom|algolia|client[_-]?id|app[_-]?id)")

WS_RE = re.compile(r"\bwss?://[^\s\"'`<>]+")
PATH_RE = re.compile(r"[\"'`]((?:/[a-z0-9_\-]+){2,6})(?:\?|\$|\{[\"'`])?", re.I)
PATH_SINGLE = re.compile(r"[\"'](/(?:api|rest|graphql|gql|v\d|auth|oauth|user|admin|internal|account|order|payment|billing|upload|file|document|report|export|partner|merchant|seller|customer)[a-z0-9_\-/.{}]*)[\"']", re.I)
GQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z][A-Za-z0-9_]*)")
GQL_BACKTICK = re.compile(r"gql`([^`]{5,400})`")
ADMIN_PATH_HINT = re.compile(r"(?i)(admin|backoffice|internal|backoffice|impersonat|sudo|superuser)")
DEBUG_PATH_HINT = re.compile(r"(?i)(debug|dev-|staging|test|qa|mock|feature[_-]?flag|toggle|actuator|swagger|openapi|graphiql|playground|console|metrics|health|monitor|trace|pprof)")
UPLOAD_HINT = re.compile(r"(?i)(multipart|form-?data|new FormData\(|type=[\"']file|\.upload\(|uploadUrl|presign)")
AUTH_HINT = re.compile(r"(?i)(Authorization|Bearer\s|Basic\s+[A-Za-z0-9+/=]|client_id|redirect_uri|response_type|openid|/connect/|/oauth|/login|/logout|/token|/refresh|grant_type|introspect|sessionStorage|localStorage)")
XHEADER_RE = re.compile(r"[\"'`](X-[A-Za-z][A-Za-z0-9\-]{2,})[\"'`]")
IDENTITY_HDR = re.compile(r"(?i)(X-(User|Account|Org|Customer|Tenant|Admin|Forwarded|Original|Rewrite|API-Key|Auth))")
SQL_HINT = re.compile(r'(?i)((SELECT\s[^\n]{1,80}\sFROM\s|INSERT\s+INTO\s|UPDATE\s+[a-z_\-.]{2,40}\s+SET\s|DELETE\s+FROM\s)[^\n]{0,120}(\$\{|["\']\s*\+|\+\s*["\']))|(\.(?:raw|whereRaw|queryRaw|orderByRaw)\s*\(|sequelize\.query\s*\(|knex\.query\s*\()')
MONEY_RE = re.compile(r"(?i)\b(price|unitPrice|total|amount|discount|coupon|promo|voucher|refund|payout|withdraw|balance|credit|debit|quantity|currency|giftcard|cashback)\b")
STATE_RE = re.compile(r"(?i)\b(status|state|confirmed|paid|pending|shipped|delivered|cancelled|approved|verified|enabled)\b")
ROLE_KEY_RE = re.compile(r"(?i)[\"']?(role|roles|isAdmin|admin|permissions|scopes|plan|tier|isStaff|isSuperuser|entitlements|privileges)[\"']?\s*:")
UI_ROLE_GATE_RE = re.compile(r"(?i)(isAdmin|hasRole|role\s*===?\s*[\"'](admin|staff|support)|v-if=[\"'][^\"']*role|ngIf[^\"']*role)")
VALIDATION_LIB_RE = re.compile(r"(?i)\b(zod|yup|joi|class-validator|vee-validate|formik|validatejs|ajv)\b")
SANITIZE_HINT = re.compile(r"(?i)(maxlength|pattern=|sanitize|DOMPurify|escapeHtml|encodeURI\()")
RATE_HINT = re.compile(r"(?i)(429|retry-?after|backoff|too many requests|rate.?limit|throttl)")
SOURCemap_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
WEBPACK_CHUNKS = re.compile(r"[\"'`]([a-zA-Z0-9_\-./]+\.[0-9a-f]{8,}\.js)[\"'`]")
EXTERNAL_HOST_RE = re.compile(r"\bhttps?://([a-z0-9.\-]+\.[a-z]{2,12})")


def audit(srcs):
    R = collections.defaultdict(list)
    for fname, text in srcs:
        n = len(text)

        # ---- 1. REST endpoints (grouped by first path segment)
        paths = set()
        for m in PATH_SINGLE.finditer(text):
            paths.add(m.group(1))
        for m in PATH_RE.finditer(text):
            p = m.group(1)
            if re.search(r"(?i)(api|rest|v\d|service|gateway|bff)", p):
                paths.add(re.sub(r"\$\{[^}]*\}", "{ID}", p))
        for p in sorted(paths):
            group = "/" + (p.strip("/").split("/")[0] if p.count("/") > 1 else "root")
            R["rest"].append({"group": group, "path": p, "src": fname})

        # ---- 2. GraphQL
        for m in GQL_OP_RE.finditer(text):
            R["graphql"].append({"op": m.group(2), "type": m.group(1), "src": fname})
        for m in GQL_BACKTICK.finditer(text):
            body = m.group(1)[:200]
            for mm in GQL_OP_RE.finditer(body):
                R["graphql"].append({"op": mm.group(2), "type": mm.group(1), "src": fname})

        # ---- 3. Auth mechanisms
        for m in AUTH_HINT.finditer(text):
            seg = ctx(text, m.start())
            if any(k in seg.lower() for k in ("authorization", "bearer", "client_id", "redirect_uri", "grant_type", "connect/", "oauth", "/token", "/refresh", "localstorage", "sessionstorage")):
                R["auth"].append({"signal": m.group(0)[:40], "ctx": seg, "src": fname})
        for m in re.finditer(r"(?i)(Authorization[\"']\s*[,:]\s*[\"'`][^\"'`]{3,60})", text):
            R["auth"].append({"signal": "header-set", "ctx": m.group(0)[:150], "src": fname})

        # ---- 4/5. hidden+debug / admin
        for p in paths:
            if DEBUG_PATH_HINT.search(p):
                R["hidden"].append({"path": p, "src": fname})
            if ADMIN_PATH_HINT.search(p):
                R["admin"].append({"path": p, "src": fname})
        for m in UI_ROLE_GATE_RE.finditer(text):
            R["admin"].append({"uigate": m.group(0)[:60], "ctx": ctx(text, m.start()), "src": fname})

        # ---- 6. uploads
        for m in UPLOAD_HINT.finditer(text):
            R["upload"].append({"ctx": ctx(text, m.start()), "src": fname})
        for p in paths:
            if re.search(r"(?i)(upload|file|attach|import|avatar|image|document|export|presign)", p):
                R["upload"].append({"path": p, "src": fname})

        # ---- 7. websockets
        for m in WS_RE.finditer(text):
            R["websocket"].append({"url": m.group(0), "src": fname})
        for m in re.finditer(r"(?i)(new WebSocket\(|socket\.io|io\(|stomp|pusher|pubnub|ably\.|\.subscribe\()", text):
            R["websocket"].append({"lib": m.group(0)[:30], "ctx": ctx(text, m.start()), "src": fname})

        # ---- 8. secrets
        for label, rx, sev in SECRET_PATTERNS:
            for m in re.finditer(rx, text):
                val = m.group(0)
                s = sev
                if s == "CHECK" and PUBLIC_HINTS.search(ctx(text, m.start(), 40, 10)):
                    s = "PUBLIC"
                R["secrets"].append({"type": label, "sev": s, "value": (val[:28] + "…" + val[-6:]) if len(val) > 40 else val, "ctx": ctx(text, m.start(), 50, 30), "src": fname})
        # JWT decode
        for m in re.finditer(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", text):
            try:
                pl = json.loads(base64.urlsafe_b64decode(m.group(0).split(".")[1] + "=="))
                exp = pl.get("exp")
                import time as _t
                stale = (exp or 0) < _t.time() if exp else None
                R["secrets"].append({"type": "JWT(decoded)", "sev": "CHECK", "claims": {k: pl[k] for k in list(pl)[:8]}, "expired": stale, "src": fname})
            except Exception:
                pass
        # entropy candidates
        for m in re.finditer(r"[\"'`][A-Za-z0-9+/_\-]{32,120}[\"'`]", text):
            v = m.group(0)[1:-1]
            if shannon(v) > 4.9 and not PUBLIC_HINTS.search(ctx(text, m.start(), 40, 5)) and not re.match(r"^[0-9a-f]{32,}$|^[A-F0-9]{16}$", v) is None is None:
                if not re.fullmatch(r"[0-9a-f]{32,64}", v):  # pure content hashes = noise
                    continue
            if shannon(v) > 5.0:
                R["secrets"].append({"type": "high-entropy candidate", "sev": "CAND", "value": v[:20] + "…" + v[-6:], "ctx": ctx(text, m.start(), 40, 10), "src": fname})

        # ---- 9. third parties
        for m in EXTERNAL_HOST_RE.finditer(text):
            h = m.group(1)
            if not re.match(r"^w{3}\.|^cdn\.|^static", h):
                R["thirdparty"].append({"host": h, "src": fname})

        # ---- 10. business logic
        for m in MONEY_RE.finditer(text):
            seg = ctx(text, m.start(), 60, 120)
            if re.search(r"(?i)(post|put|patch|fetch|axios|request|body|payload|cart|checkout|order)", seg):
                R["bizlogic"].append({"field": m.group(1), "ctx": seg, "src": fname})
        for m in STATE_RE.finditer(text):
            seg = ctx(text, m.start(), 40, 90)
            if re.search(r"(?i)(state|status).{0,20}(===|:|=\s)", seg):
                R["bizlogic"].append({"statefield": m.group(1), "ctx": seg[:110], "src": fname})

        # ---- vuln mapping
        for m in SQL_HINT.finditer(text):
            R["vuln_sqli"].append({"ctx": ctx(text, m.start(), 40, 160), "src": fname})
        for m in ROLE_KEY_RE.finditer(text):
            seg = ctx(text, m.start(), 20, 140)
            low = seg.lower()
            if "aria-" in low or re.search(r"role\s*[:=]\s*[\"']?(list|alert|button|dialog|menu|tab|option|group|search|navigation|textbox|switch|progressbar)", low):
                continue  # aria/UI role, not an entitlement key
            if re.search(r"(?i)(post|put|patch|body|payload|json)", ctx(text, m.start(), 250, 250)):
                R["vuln_massassign"].append({"key": m.group(1), "ctx": seg, "src": fname})
        for m in VALIDATION_LIB_RE.finditer(text):
            R["vuln_clientside_validation"].append({"lib": m.group(1), "ctx": ctx(text, m.start(), 40, 120), "src": fname})
        for m in XHEADER_RE.finditer(text):
            h = m.group(1)
            cat = "IDENTITY" if IDENTITY_HDR.search(h) else "custom"
            R["vuln_headers"].append({"header": h, "cat": cat, "ctx": ctx(text, m.start(), 30, 90), "src": fname})
        for m in SANITIZE_HINT.finditer(text):
            R["vuln_inputbypass"].append({"hint": m.group(0)[:40], "ctx": ctx(text, m.start(), 30, 90), "src": fname})
        for m in RATE_HINT.finditer(text):
            R["vuln_ratelimit"].append({"ctx": ctx(text, m.start(), 40, 120), "src": fname})
        for m in re.finditer(r"(?i)localStorage\.(set|get)Item\(([\"'][^\"']*(token|jwt|auth)[\"'])", text):
            R["vuln_authweak"].append({"issue": "token in localStorage", "ctx": ctx(text, m.start(), 30, 90), "src": fname})

        # ---- build artifacts
        for m in SOURCemap_RE.finditer(text):
            R["artifacts"].append({"sourcemap": m.group(1)[:80], "src": fname})
        if ".map" in fname:
            try:
                j = json.loads(text)
                if j.get("sourcesContent"):
                    R["artifacts"].append({"note": f"{fname}: FULL ORIGINAL SOURCE EMBEDDED ({len(j['sourcesContent'])} files)", "src": fname})
            except Exception:
                pass
        for m in WEBPACK_CHUNKS.finditer(text):
            R["artifacts"].append({"chunk": m.group(1), "src": fname})

    # dedupe + cap noisy buckets
    caps = {"rest": 400, "auth": 40, "thirdparty": 150, "bizlogic": 60, "vuln_headers": 60, "websocket": 40, "upload": 40}
    out = {}
    for k, v in R.items():
        v = dedupe(v)
        if k == "secrets":
            seen, vv = set(), []
            for e in v:
                key = (e.get("type"), e.get("value") or json.dumps(e.get("claims"), sort_keys=True))
                if key not in seen:
                    seen.add(key)
                    vv.append(e)
            v = vv
        out[k] = v[: caps.get(k, 80)]
    # group third parties by domain
    tp = collections.Counter(e["host"] for e in out.get("thirdparty", []))
    out["thirdparty_grouped"] = [{"host": h, "n": n} for h, n in tp.most_common(60)]
    return out


MANUAL = {
    "rest": "Grouped above. For each non-GET verb: replay unauthenticated, then cross-account (idor-runner), then with tampered body fields.",
    "graphql": "Run every mutation with other-own-account IDs (field-level BOLA). Check CSRF if cookie-auth: cross-origin fetch with text/plain content-type.",
    "auth": "Map: which endpoints need no Bearer? Test token-from-account-A against account-B resources. If OTP/refresh endpoints appear, check rate limits + enumeration.",
    "hidden": "Force-browse each hidden/debug path unauthenticated AND with a normal user token (admin route exposure = UI-gated-only authz check).",
    "admin": "Admin routes shipped to the client = the UI hides them, the API may not. Try direct navigation + API calls with normal-user session.",
    "upload": "For each upload path: extension/ctype polyglots, path control in filename, SVG-with-script, then check where uploads are SERVED (execution?).",
    "websocket": "Connect unauthenticated; with account-A token subscribe to account-B channels; check token-in-URL (leaks in logs).",
    "secrets": "HIGH: verify reach ONLY if program rules allow credential verification; otherwise report as-is with redaction. CHECK: confirm scope before claiming. PUBLIC: note and move on.",
    "bizlogic": "Every money field the CLIENT sends: tamper replay (negative/zero/other-currency). Every state field: try illegal transitions directly via API.",
    "vuln_sqli": "Server-side SQL in client bundles means leaked source (already a finding) — note the concat spots as confirmed-unparameterized queries.",
    "vuln_massassign": "Send the flagged role/plan/permission keys in profile-update + registration bodies from a normal account; check what sticks; revert.",
    "vuln_clientside_validation": "Validation found only in client libs: replay the backing request with invalid values directly — server must reject, else validation bypass.",
    "vuln_headers": "IDENTITY headers set from the client: replay requests varying them (other own account's values). X-Forwarded/X-Original-URL: admin-path bypass probes.",
    "vuln_inputbypass": "Client-side length/pattern/sanitize controls: bypass by direct API replay with out-of-contract values.",
    "vuln_ratelimit": "Endpoints with 429 handling: measure actual limits, then test OTP/coupon/payout endpoints at realistic rates within program rules.",
    "vuln_authweak": "Token in localStorage: note for XSS chaining (bb-xss). Client-only logout: replay old token after logout.",
    "artifacts": "Sourcemaps present = original source disclosure (check program's stance). Chunk list: fetch the unfetched chunks and re-audit them.",
}


def to_markdown(A, out_name):
    L = [f"# JS Audit Report — {len(A.get('rest', []))} endpoints, {len(A.get('secrets', []))} secret candidates\n"]
    sections = [
        ("rest", "1. REST API endpoints (grouped)"), ("graphql", "2. GraphQL operations"),
        ("auth", "3. Auth/authz mechanisms"), ("hidden", "4. Hidden/debug/undocumented endpoints"),
        ("admin", "5. Admin functionality"), ("upload", "6. File upload surface"),
        ("websocket", "7. WebSockets"), ("secrets", "8. Secrets/keys/tokens"),
        ("thirdparty_grouped", "9. Third-party services"), ("bizlogic", "10. Business logic signals"),
        ("vuln_sqli", "V: SQLi-prone spots"), ("vuln_massassign", "V: Mass-assignment keys"),
        ("vuln_clientside_validation", "V: Client-only validation"), ("vuln_authweak", "V: Auth weaknesses"),
        ("vuln_headers", "V: Client-controlled headers"), ("vuln_inputbypass", "V: Input-validation bypass hints"),
        ("vuln_ratelimit", "V: Rate-limit signals"), ("artifacts", "Build artifacts"),
    ]
    for key, title in sections:
        items = A.get(key, [])
        L.append(f"\n## {title} ({len(items)})")
        if not items:
            L.append("_none found_")
            continue
        if key == "rest":
            grp = collections.defaultdict(list)
            for e in items:
                grp[e["group"]].append(e["path"])
            for g in sorted(grp):
                L.append(f"\n**{g}** ({len(grp[g])}):")
                L += [f"- `{p}`" for p in grp[g][:40]]
        elif key == "secrets":
            for e in items:
                val = e.get("value") or json.dumps(e.get("claims"))[:60]
                L.append(f"- **[{e['sev']}]** {e['type']}: `{val}` — {e.get('ctx', '')[:100]} ({e['src']})")
        elif key == "thirdparty_grouped":
            L += [f"- {e['host']} ×{e['n']}" for e in items]
        else:
            for e in items[:40]:
                L.append(f"- {json.dumps(e, ensure_ascii=False)[:220]}")
        if key in MANUAL:
            L.append(f"\n> **Next steps:** {MANUAL[key]}")
    open(out_name, "w", encoding="utf-8").write("\n".join(L))
    return out_name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="*", help="js files or directories")
    ap.add_argument("--url", help="fetch a bundle URL first")
    ap.add_argument("--out", default="js_audit_report.md")
    ap.add_argument("--json", default="js_audit_report.json")
    a = ap.parse_args()
    if not a.inputs and not a.url:
        ap.error("give files/dirs or --url")
    srcs = read_sources(a.inputs, a.url)
    print(f"[*] auditing {len(srcs)} files, {sum(len(t) for _, t in srcs)//1024} KB total")
    A = audit(srcs)
    to_markdown(A, a.out)
    json.dump(A, open(a.json, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"[+] {a.out} + {a.json}")
    for k in ("rest", "graphql", "secrets", "hidden", "admin", "upload", "websocket", "vuln_massassign", "vuln_headers", "vuln_sqli", "artifacts"):
        print(f"    {k:24s} {len(A.get(k, []))}")


if __name__ == "__main__":
    main()
