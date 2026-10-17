#!/usr/bin/env bash
# BadRecon API discovery — maps the REST surface of a BadRecon deployment.
# Usage: api_discover.sh <base_url> [auth_header]
#   base_url      e.g. http://vps.example.com:8000  (no trailing slash)
#   auth_header   optional, e.g. "Authorization: Bearer <token>"
BASE="${1%/}"
AUTH="${2:+-H $2}"
[ -z "$BASE" ] && { echo "usage: $0 <base_url> [auth_header]"; exit 1; }

UA="BadRecon-Skill/1.0"

echo "== BadRecon API discovery: $BASE =="

# 1. API documentation surfaces (instant API map if present)
for p in /docs /api/docs /redoc /swagger /swagger.json /openapi.json /api/openapi.json /api/v1/openapi.json; do
  code=$(curl -s -A "$UA" $AUTH -o /tmp/br_probe -w "%{http_code}" --max-time 8 "$BASE$p" 2>/dev/null)
  size=$(wc -c < /tmp/br_probe 2>/dev/null | tr -d ' ')
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "DOC  $code ($size b) $p"
done

# 2. Health/service probes (confirm app + worker + queue are alive)
for p in / /health /healthz /api /api/health /status /api/status; do
  code=$(curl -s -A "$UA" $AUTH -o /tmp/br_probe -w "%{http_code}" --max-time 8 "$BASE$p" 2>/dev/null)
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "LIVE $code $p"
done

# 3. Resource probes (common REST shapes for targets/scans/exports)
for p in /api/targets /targets /api/target /api/scans /scans /api/scan-jobs /api/jobs \
         /api/subdomains /api/urls /api/findings /api/ips /api/technologies \
         /api/scans/{id}/export /api/export; do
  path="${p/\{id\}/1}"
  code=$(curl -s -A "$UA" $AUTH -o /tmp/br_probe -w "%{http_code}" --max-time 8 "$BASE$path" 2>/dev/null)
  case "$code" in
    200|201) echo "RES  $code $path  <-- usable" ;;
    401|403) echo "AUTH $code $path  <-- exists, needs credentials" ;;
    405)     echo "METH $code $path  <-- exists, wrong method (try POST)" ;;
  esac
done

echo "== done =="
echo "Next: use DOC endpoints (openapi) for the full API map; RES/AUTH/METH hits confirm resource paths."
