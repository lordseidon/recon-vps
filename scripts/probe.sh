#!/bin/bash

# probe.sh — Batch probe subdomains → JSON (headers, body, tech, status, WAF)
# Usage: ./probe.sh [subs.txt] [output.json] [--waf]
# When called from recon pipeline with just a domain arg, uses RECON_OUTPUT_DIR

set -euo pipefail

SCAN_DIR="${RECON_OUTPUT_DIR:-.}"
SUBS_FILE="${SCAN_DIR}/all-subdomains.txt"
OUTPUT="${SCAN_DIR}/probe-output.json"
WAF_MODE=""

if [ -f "$1" ]; then
    SUBS_FILE="$1"
fi
if [ "${2:-}" = "--waf" ] || [ "${3:-}" = "--waf" ]; then
    WAF_MODE="yes"
fi

if [ ! -f "$SUBS_FILE" ]; then
    echo "Error: No subdomain file found at $SUBS_FILE"
    exit 1
fi

echo "========================================"
echo "  PROBE — $(wc -l < "$SUBS_FILE") targets"
[ "$WAF_MODE" = "yes" ] && echo "  WAF detection: ENABLED"
echo "========================================"

GOBIN="$HOME/go/bin"

[ -x "$GOBIN/httpx" ] || { echo "Error: $GOBIN/httpx not found"; exit 1; }

$GOBIN/httpx -l "$SUBS_FILE" \
    -json \
    -include-response \
    -tech-detect \
    -status-code \
    -title \
    -threads 50 \
    -rate-limit 30 \
    -timeout 10 \
    -o "$OUTPUT"

jq -s '.' "$OUTPUT" > "${OUTPUT}.tmp" 2>/dev/null && mv "${OUTPUT}.tmp" "$OUTPUT"

LIVE=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
echo ""
echo "  Live hosts: ${LIVE}"

# ── WAF Detection ──
if [ "$WAF_MODE" = "yes" ] && command -v wafw00f &>/dev/null && [ "$LIVE" -gt 0 ]; then
    echo ""
    echo "  Running WAF detection..."

    jq -r '.[].url' "$OUTPUT" 2>/dev/null | sort -u > "${OUTPUT}.urls"

    > "${OUTPUT}.waf"
    COUNT=0
    while read url; do
        COUNT=$((COUNT + 1))
        printf "    [%s/%s] %s" "$COUNT" "$LIVE" "$url"
        result=$(wafw00f "$url" 2>/dev/null | grep -E "is behind|No WAF|identified" | head -1 || echo "unknown")
        printf " → %s\n" "$result"
        echo "$url|$result" >> "${OUTPUT}.waf"
    done < "${OUTPUT}.urls"

    python3 -c "
import json
with open('$OUTPUT') as f:
    data = json.load(f)
waf_map = {}
with open('${OUTPUT}.waf') as f:
    for line in f:
        parts = line.strip().split('|', 1)
        if len(parts) == 2:
            waf_map[parts[0]] = parts[1].strip()
for entry in data:
    url = entry.get('url', '')
    entry['waf'] = waf_map.get(url, 'not checked')
with open('$OUTPUT', 'w') as f:
    json.dump(data, f, indent=2)
print(f'  → WAF results merged into $OUTPUT')
"

    rm -f "${OUTPUT}.urls" "${OUTPUT}.waf"
fi

echo ""
echo "========================================"
echo "  DONE — ${LIVE} live hosts → $OUTPUT"
echo "========================================"
