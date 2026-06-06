#!/bin/bash

# dork.sh — Generate Google dorks for all resolved subdomains → JSON
# Usage: ./dork.sh <domain>

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./dork.sh <domain>"
    exit 1
fi

INDIR="$RECON_OUTPUT_DIR"
SUBS_FILE="$INDIR/resolved_domain.txt"
[ -f "$SUBS_FILE" ] || { echo "Error: $SUBS_FILE not found. Run recon.sh first."; exit 1; }

OUTFILE="$INDIR/dorks.json"
TOTAL=$(wc -l < "$SUBS_FILE")

echo "========================================"
echo "  DORK GENERATOR — $DOMAIN"
echo "  Targets: ${TOTAL} subdomains"
echo "========================================"

# Let Python do all the heavy lifting
python3 -c "
import json, sys, os

subs = [l.strip() for l in open('$SUBS_FILE') if l.strip() and '.' in l]
total = len(subs)

# Dork templates — {sub} will be replaced
templates = [
    'site:{sub} inurl:id=',
    'site:{sub} inurl:?id=',
    'site:{sub} inurl:?page=',
    'site:{sub} inurl:?cat=',
    'site:{sub} inurl:?query=',
    'site:{sub} inurl:?cid=',
    'site:{sub} intitle:upload',
    'site:{sub} inurl:upload',
    'site:{sub} inurl:file-upload',
    'site:{sub} intitle:\"index of\"',
    'site:{sub} \"index of\" \"parent directory\"',
    'site:{sub} \"index of\" /admin',
    'site:{sub} \"index of\" /backup',
    'site:{sub} \"index of\" /uploads',
    'site:{sub} filetype:env',
    'site:{sub} filetype:conf',
    'site:{sub} filetype:sql',
    'site:{sub} filetype:log',
    'site:{sub} filetype:bak',
    'site:{sub} filetype:backup',
    'site:{sub} inurl:.git/config',
    'site:{sub} inurl:.env',
    'site:{sub} inurl:wp-config.php',
    'site:{sub} inurl:config.php',
    'site:{sub} intitle:phpinfo',
    'site:{sub} inurl:login',
    'site:{sub} inurl:signin',
    'site:{sub} inurl:admin',
    'site:{sub} intitle:login',
    'site:{sub} intitle:\"sign in\"',
    'site:{sub} inurl:/admin/',
    'site:{sub} inurl:/dashboard',
    'site:{sub} inurl:/wp-admin/',
    'site:{sub} inurl:url=https',
    'site:{sub} inurl:url=http',
    'site:{sub} inurl:u=https',
    'site:{sub} inurl:u=http',
    'site:{sub} inurl:redirect?https',
    'site:{sub} inurl:redirect?http',
    'site:{sub} inurl:redirect=https',
    'site:{sub} inurl:redirect=http',
    'site:{sub} inurl:redirectUrl=http',
    'site:{sub} inurl:link=http',
    'site:{sub} ext:pdf',
    'site:{sub} ext:doc',
    'site:{sub} ext:xls',
    'site:{sub} ext:csv',
    'site:{sub} ext:txt intext:password',
    'site:{sub} ext:txt intext:username',
    'site:{sub} intext:\"sql syntax\"',
    'site:{sub} intext:\"mysql error\"',
    'site:{sub} intext:\"stack trace\"',
    'site:{sub} intext:debug',
    'site:{sub} intitle:exception',
    'site:{sub} intitle:error',
    'site:{sub} intext:\"@{sub}\"',
    'site:{sub} intext:\"api key\"',
    'site:{sub} intext:\"secret\"',
    'site:{sub} intext:\"token\"',
    'site:{sub} intext:\"password\"',
    'site:{sub} \"powered by\"',
]

result = {}
for i, sub in enumerate(subs, 1):
    dorks = [t.replace('{sub}', sub) for t in templates]
    result[sub] = dorks
    print(f'[{i}/{total}] {sub} → {len(dorks)} dorks', file=sys.stderr)

with open('$OUTFILE', 'w') as f:
    json.dump(result, f, indent=2)

print(f'', file=sys.stderr)
print(f'Done. {len(result)} subdomains → $OUTFILE', file=sys.stderr)
" 2>&1

echo ""
echo "========================================"
echo "  DONE — $OUTFILE"
echo "========================================"
