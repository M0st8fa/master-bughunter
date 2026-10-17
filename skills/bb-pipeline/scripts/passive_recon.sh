#!/usr/bin/env bash
# Passive subdomain recon — queries public sources only; never touches the target.
# Usage: passive_recon.sh <apex-domain> [output-dir]
set -u
DOMAIN="${1:?usage: passive_recon.sh <apex-domain> [output-dir]}"
OUT="${2:-recon/subdomains}"
mkdir -p "$OUT"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/152"

curl -s --max-time 90 "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" -o "$OUT/certspotter.json" &
curl -s --max-time 60 "https://crt.name/v1/search?apex=${DOMAIN}" -o "$OUT/crtname.txt" &
curl -s --max-time 90 "https://rapiddns.io/s/${DOMAIN}" -o "$OUT/rapiddns.html" &
curl -s --max-time 120 "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&collapse=urlkey&output=text&fl=original&limit=5000" -o "$OUT/wayback_all.txt" &
curl -s --max-time 60 "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=1000" -o "$OUT/urlscan.json" &
curl -s --max-time 60 "https://ctl.shodan.io/api/v1/domain/${DOMAIN}/hostnames" -o "$OUT/shodanctl.json" &
# VirusTotal passive DNS (needs own API key in $VT_KEY)
[ -n "${VT_KEY:-}" ] && curl -s --max-time 60 "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VT_KEY}&domain=${DOMAIN}" -o "$OUT/vt_domain.json" &
wait

# Aggregate unique subdomains
{ cat "$OUT/certspotter.json" 2>/dev/null | tr ',' '\n' | grep -oE "\"[a-zA-Z0-9._-]+\.${DOMAIN}\"" | tr -d '"';
  grep -ohE "[a-zA-Z0-9._-]+\.${DOMAIN}" "$OUT"/* 2>/dev/null; } \
  | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | grep -v '^$' | sort -u > "$OUT/all_subs_raw.txt"
echo "unique subdomains: $(wc -l < "$OUT/all_subs_raw.txt") -> $OUT/all_subs_raw.txt"
echo "Classify against program scope BEFORE touching anything."
