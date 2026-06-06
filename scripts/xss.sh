#!/bin/bash

# xss.sh — Scan parameterized URLs with dalfox
# Usage: ./xss.sh <domain>

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./xss.sh <domain>"
    exit 1
fi

INDIR="$RECON_OUTPUT_DIR"
KATANA_JSON="$INDIR/linkgather/katana.json"
OUTFILE="$INDIR/xss-findings.json"

[ -f "$KATANA_JSON" ] || { echo "Error: $KATANA_JSON not found. Run linkgatherer.sh first."; exit 1; }

command -v dalfox &>/dev/null || { echo "Error: dalfox not found."; exit 1; }

echo "========================================"
echo "  XSS SCAN — $DOMAIN (dalfox)"
echo "========================================"

# Extract parameterized URLs from katana.json
python3 -c "
import json, sys

with open('$KATANA_JSON') as f:
    data = json.load(f)

# Reflection patterns — params likely to be reflected in page
reflection_params = ['id', 'page', 'q', 'search', 'query', 's', 'keyword', 'cat',
                     'category', 'redirect', 'url', 'return', 'next', 'callback',
                     'file', 'path', 'name', 'type', 'sort', 'order', 'filter',
                     'lang', 'view', 'action', 'token', 'key']

targets = set()
for entry in data:
    for url in entry['extracted_urls']:
        if '?' not in url:
            continue
        url_lower = url.lower()
        for param in reflection_params:
            if f'{param}=' in url_lower or f'&{param}=' in url_lower:
                targets.add(url)
                break

# Save to file
with open('$INDIR/.xss-targets.txt', 'w') as f:
    for t in sorted(targets):
        f.write(t + '\n')

print(f'  Parameterized URLs with reflection patterns: {len(targets)}')
" 2>&1

TARGET_COUNT=$(wc -l < "$INDIR/.xss-targets.txt" 2>/dev/null || echo 0)

if [ "$TARGET_COUNT" -eq 0 ]; then
    echo "  No suitable targets with reflection parameters found."
    rm -f "$INDIR/.xss-targets.txt"
    exit 0
fi

echo ""
echo "  Scanning with dalfox..."
> "$OUTFILE"
COUNT=0
FOUND=0

while read url; do
    COUNT=$((COUNT + 1))
    printf "    [%s/%s] %s" "$COUNT" "$TARGET_COUNT" "$url"

    result=$(dalfox url "$url" --silence --no-color --delay 100 --timeout 10 --only-custom-payload "1" 2>&1)
    if echo "$result" | grep -qi "\[POC\]"; then
        echo " !! XSS FOUND"
        FOUND=$((FOUND + 1))
        python3 -c "
import json, sys
with open('$OUTFILE', 'a') as f:
    f.write(json.dumps({'url':'$url', 'poc':'''$result'''}) + '\n')
" 2>/dev/null
    else
        echo " → clean"
    fi
done < "$INDIR/.xss-targets.txt"

rm -f "$INDIR/.xss-targets.txt"

# Convert to JSON array
if [ -s "$OUTFILE" ]; then
    jq -s '.' "$OUTFILE" > "${OUTFILE}.tmp" 2>/dev/null && mv "${OUTFILE}.tmp" "$OUTFILE"
fi

echo ""
echo "========================================"
echo "  DONE — ${COUNT} scanned, ${FOUND} found"
echo "  Output: $OUTFILE"
echo "========================================"
