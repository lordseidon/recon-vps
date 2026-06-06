#!/bin/bash

# takeover.sh — Check subdomains for takeover with subjack
# Usage: ./takeover.sh <domain>

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./takeover.sh <domain>"
    exit 1
fi

INDIR="$RECON_OUTPUT_DIR"
SUBS_FILE="$INDIR/all-subdomains.txt"
[ -f "$SUBS_FILE" ] || SUBS_FILE="$INDIR/resolved_domain.txt"
[ -f "$SUBS_FILE" ] || { echo "Error: No subdomain list found. Run recon.sh first."; exit 1; }

GOBIN="$HOME/go/bin"
SUBJACK="$GOBIN/subjack"
[ -x "$SUBJACK" ] || { echo "Error: subjack not found at $SUBJACK"; exit 1; }

OUTFILE="$INDIR/takeover.json"
TOTAL=$(wc -l < "$SUBS_FILE")

echo "========================================"
echo "  TAKEOVER CHECK — $DOMAIN"
echo "  Targets: ${TOTAL} subdomains"
echo "========================================"

export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

"$SUBJACK" -w "$SUBS_FILE" \
    -ssl \
    -timeout 15 \
    -t 50 \
    -m \
    -v \
    -o "$OUTFILE" 2>&1

echo ""
echo "========================================"
echo "  DONE — $OUTFILE"
echo "========================================"

if [ -f "$OUTFILE" ]; then
    python3 -c "
import json
with open('$OUTFILE') as f:
    data = json.load(f)
vuln = [d for d in data if d.get('vulnerable')]
safe = [d for d in data if not d.get('vulnerable')]
print(f'  Total: {len(data)}  |  Vulnerable: {len(vuln)}  |  Safe: {len(safe)}')
if vuln:
    print()
    for v in vuln:
        svc = v.get('service', 'unknown')
        print(f'  !! {v[\"subdomain\"]} → {svc}')
" 2>/dev/null
fi
