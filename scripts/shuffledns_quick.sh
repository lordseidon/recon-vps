#!/bin/bash
# shuffledns_quick.sh — validates DNS before full recon
DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then exit 1; fi

GOBIN="$HOME/go/bin"
WORDLIST="/opt/wordlists/subdomains.txt"
RESOLVERS="/root/resolvers.txt"
OUTDIR="${RECON_OUTPUT_DIR:-/tmp}"
mkdir -p "$OUTDIR"

echo "========================================"
echo "  DNS VALIDATION — $DOMAIN (quick)"
echo "========================================"

# Test with 100-word sample first
head -100 "$WORDLIST" > "$OUTDIR/.dns-test-words.txt"

"$GOBIN/shuffledns" -d "$DOMAIN" \
    -w "$OUTDIR/.dns-test-words.txt" \
    -r "$RESOLVERS" \
    -mode bruteforce \
    -silent \
    -o "$OUTDIR/.dns-test-results.txt" 2>&1

RESULT=$(wc -l < "$OUTDIR/.dns-test-results.txt" 2>/dev/null || echo 0)
rm -f "$OUTDIR/.dns-test-words.txt" "$OUTDIR/.dns-test-results.txt"

if [ "$RESULT" -eq 0 ]; then
    echo "DNS VALIDATION FAILED — 0 results. Check massdns/dns."
    exit 1
fi

echo "DNS VALIDATION OK — $RESULT subs resolved with 100-word sample"
echo "========================================"

# Now run full shuffledns
"$GOBIN/shuffledns" -d "$DOMAIN" \
    -w "$WORDLIST" \
    -r "$RESOLVERS" \
    -mode bruteforce \
    -o "$OUTDIR/shuffledns.txt" 2>&1

FULL_RESULT=$(wc -l < "$OUTDIR/shuffledns.txt" 2>/dev/null || echo 0)
echo "Full results: $FULL_RESULT subs"
