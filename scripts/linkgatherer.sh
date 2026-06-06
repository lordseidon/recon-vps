#!/bin/bash

# linkgatherer.sh — Crawl subs with katana headless → JS → trufflehog
# Usage: ./linkgatherer.sh <domain> [depth]

set -euo pipefail

DOMAIN="${1:-}"
DEPTH="${2:-5}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./linkgatherer.sh <domain> [depth]"
    exit 1
fi

INDIR="$RECON_OUTPUT_DIR"
OUTDIR="$INDIR/linkgather"
mkdir -p "$OUTDIR"
GOBIN="$HOME/go/bin"

DOMAINS_FILE="$INDIR/resolved_domain.txt"
[ -f "$DOMAINS_FILE" ] || { echo "Error: $DOMAINS_FILE not found. Run recon.sh first."; exit 1; }

TOTAL=$(wc -l < "$DOMAINS_FILE")
echo "========================================"
echo "  LINKGATHER — $DOMAIN (depth $DEPTH)"
echo "  Targets: ${TOTAL} subdomains"
echo "========================================"

# ── 1. Katana Headless Crawl ─────────────────────────────────────────
echo ""
echo "[1/3] Crawling with katana (headless, depth $DEPTH)..."

> "$OUTDIR/katana-js.txt"
COUNT=0
TOTAL_URLS=0

# Build JSON per subdomain as we go
echo "[" > "$OUTDIR/katana.json"
FIRST=1

while read sub; do
    [ -z "$sub" ] && continue
    COUNT=$((COUNT + 1))
    printf "[%s/%s] %s" "$COUNT" "$TOTAL" "$sub"

    sub_out="$OUTDIR/.katana-$sub.txt"
    timeout $((DEPTH * 30)) "$GOBIN/katana" -u "https://$sub" \
        -headless -silent -nc \
        -depth "$DEPTH" \
        -js-crawl -jsluice -kf all \
        -o "$sub_out" 2>/dev/null || true

    url_count=$(wc -l < "$sub_out" 2>/dev/null || echo 0)
    TOTAL_URLS=$((TOTAL_URLS + url_count))

    # Filter target domain only URLs
    grep -i "\.$DOMAIN" "$sub_out" 2>/dev/null | sort -u > "${sub_out}.clean"

    clean_count=$(wc -l < "${sub_out}.clean" 2>/dev/null || echo 0)

    if [ "$clean_count" -gt 0 ]; then
        printf " → %s URLs (%s on-target)\n" "$url_count" "$clean_count"

        # Build JSON entry for this subdomain using Python for proper escaping
        [ $FIRST -eq 1 ] && FIRST=0 || echo "," >> "$OUTDIR/katana.json"
        python3 -c "
import json, sys
urls = [l.strip() for l in open('${sub_out}.clean') if l.strip()]
obj = {'base_url': '$sub', 'extracted_urls': urls}
print('  ' + json.dumps(obj, indent=2).replace('\n', '\n  ') + '', end='')
" >> "$OUTDIR/katana.json"

        # Track JS files
        grep '\.js$' "${sub_out}.clean" 2>/dev/null | while read js_url; do
            echo "$sub $js_url" >> "$OUTDIR/katana-js.txt"
        done
    else
        printf " → %s URLs (0 on-target)\n" "$url_count"
    fi

    rm -f "$sub_out" "${sub_out}.clean"
done < "$DOMAINS_FILE"

echo "" >> "$OUTDIR/katana.json"
echo "]" >> "$OUTDIR/katana.json"

sort -u -o "$OUTDIR/katana-js.txt" "$OUTDIR/katana-js.txt" 2>/dev/null || true
URL_COUNT=$TOTAL_URLS
JS_COUNT=$(wc -l < "$OUTDIR/katana-js.txt" 2>/dev/null || echo 0)

# Build api-endpoints.txt from target domain only
grep -oP 'https?://[^"]+' "$OUTDIR/katana.json" 2>/dev/null | sed 's|https\?://||' | grep -iE '/api/|/graphql|/auth|/oauth|/token|/login|/signin|/signup|\?[a-z]+=|\.json$|\.env|swagger|openapi|/v[0-9]+/' | sort -u > "$OUTDIR/api-endpoints.txt"

echo ""
echo "  Total URLs: ${URL_COUNT}  |  JS files: ${JS_COUNT}"

# ── 2. Download & Scan JS Files ──────────────────────────────────────
echo ""
echo "[2/3] Scanning JS files with trufflehog..."

JS_DIR="$OUTDIR/js"
mkdir -p "$JS_DIR"
> "$OUTDIR/secrets.jsonl"

JS_DOWNLOADED=0
while read sub url; do
    js_name=$(basename "$url" | cut -d'?' -f1)
    dest="$JS_DIR/${sub}__${js_name}"
    curl -sk --max-time 10 "$url" -o "$dest" 2>/dev/null || continue
    [ -f "$dest" ] || continue
    [ "$(wc -c < "$dest" 2>/dev/null)" -gt 50 ] || { rm -f "$dest"; continue; }
    JS_DOWNLOADED=$((JS_DOWNLOADED + 1))
done < "$OUTDIR/katana-js.txt"

echo "  Downloaded: ${JS_DOWNLOADED} JS files"

# Run trufflehog on JS directory
if [ -x "$GOBIN/trufflehog" ] && [ "$JS_DOWNLOADED" -gt 0 ]; then
    "$GOBIN/trufflehog" filesystem "$JS_DIR" --json 2>/dev/null | grep '"DetectorName"' > "$OUTDIR/secrets.jsonl" || true
    SECRETS=$(wc -l < "$OUTDIR/secrets.jsonl" 2>/dev/null || echo 0)
    echo "  Secrets found: ${SECRETS}"

    # Build trufflehog JSON
    if [ "$SECRETS" -gt 0 ]; then
        jq -s '.' "$OUTDIR/secrets.jsonl" > "$OUTDIR/trufflehog.json" 2>/dev/null
    else
        echo '[]' > "$OUTDIR/trufflehog.json"
    fi
else
    echo "  trufflehog not found or no JS files, skipping"
    echo '[]' > "$OUTDIR/trufflehog.json"
fi

# ── 3. Build API Endpoints from katana.json ───────────────────────────
echo ""
echo "[3/3] Extracting API endpoints..."
API_COUNT=$(wc -l < "$OUTDIR/api-endpoints.txt" 2>/dev/null || echo 0)
echo "  API endpoints: ${API_COUNT}"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  LINKGATHER COMPLETE"
echo "========================================"
echo "  URLs crawled:     ${URL_COUNT}"
echo "  JS files:          ${JS_DOWNLOADED}"
echo "  Secrets:           ${SECRETS:-0}"
echo "  API endpoints:     ${API_COUNT}"
echo ""
echo "  Files in $OUTDIR/:"
ls -lh "$OUTDIR/"*.json "$OUTDIR/"*.txt 2>/dev/null | awk '{printf "    %s  %s\n", $5, $9}'
