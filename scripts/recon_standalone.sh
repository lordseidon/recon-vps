#!/bin/bash

# recon.sh — subfinder + amass + shuffledns + altdns + dnsx + httpx
# Usage: ./recon.sh <domain>

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./recon.sh <domain>"
    exit 1
fi

OUTDIR="$HOME/recon/$DOMAIN"
mkdir -p "$OUTDIR"
GOBIN="$HOME/go/bin"

echo "========================================"
echo "  RECON — $DOMAIN"
echo "========================================"

# ── 1. Subdomain Enumeration ──────────────────────────────────────────
echo ""
echo "[1/4] Enumerating subdomains..."

echo "  → subfinder"
subfinder -d "$DOMAIN" -es digitorus -silent -o "$OUTDIR/subfinder.txt"

echo "  → amass (10 min timeout, fast sources only)"
timeout 600 amass enum -passive -d "$DOMAIN" -include crtsh,certspotter,riddler,dnsdumpster,hackertarget,sitedossier,commoncrawl,wayback,chaos,github,binaryedge,bufferover,cebaidu,c99 -o "$OUTDIR/amass.txt" 2>/dev/null || true

cat "$OUTDIR/subfinder.txt" "$OUTDIR/amass.txt" 2>/dev/null | sort -u > "$OUTDIR/all-subdomains.txt"
PASSIVE=$(wc -l < "$OUTDIR/all-subdomains.txt")
echo "  subfinder: $(wc -l < "$OUTDIR/subfinder.txt")  |  amass: $(wc -l < "$OUTDIR/amass.txt" 2>/dev/null || echo 0)  |  unique: ${PASSIVE}"

# ── 2. Active DNS brute-force ─────────────────────────────────────────
echo ""
echo "[2/4] DNS brute-force (shuffledns)..."

$GOBIN/shuffledns -d "$DOMAIN" \
    -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt \
    -r /opt/wordlists/resolvers.txt \
    -mode bruteforce \
    -o "$OUTDIR/shuffledns.txt" 2>&1 | grep -E "\[INF\]|resolved|output"

BRUTE=$(wc -l < "$OUTDIR/shuffledns.txt" 2>/dev/null || echo 0)
echo "  Brute-force found: ${BRUTE}"

# Merge all sources
cat "$OUTDIR/all-subdomains.txt" "$OUTDIR/shuffledns.txt" 2>/dev/null | sort -u > "$OUTDIR/all-subdomains-merged.txt"
mv "$OUTDIR/all-subdomains-merged.txt" "$OUTDIR/all-subdomains.txt"
TOTAL=$(wc -l < "$OUTDIR/all-subdomains.txt")
echo "  Total after brute: ${TOTAL}"

# ── 2b. Permutation Discovery (altdns) ──────────────────────────────────
ALTDNS_WORDS="$HOME/recon/wordlists/altdns-words.txt"
echo ""
echo "[2b/5] Subdomain permutation discovery (altdns)..."

if command -v altdns &>/dev/null && [ -f "$ALTDNS_WORDS" ]; then
    # Clean subdomain names for input (strip amass verbose output)
    grep -oP '^[a-zA-Z0-9.-]+\.'"$DOMAIN"'$' "$OUTDIR/all-subdomains.txt" | sort -u > "$OUTDIR/.altdns-input.txt"
    INPUT_COUNT=$(wc -l < "$OUTDIR/.altdns-input.txt")
    echo "  Input subs: ${INPUT_COUNT} | wordlist: $(wc -l < "$ALTDNS_WORDS")"

    altdns -i "$OUTDIR/.altdns-input.txt" \
        -w "$ALTDNS_WORDS" \
        -o "$OUTDIR/altdns-permutations.txt" 2>/dev/null
    PERMS=$(wc -l < "$OUTDIR/altdns-permutations.txt" 2>/dev/null || echo 0)
    echo "  Permutations: ${PERMS}"

    # Resolve with dnsx
    echo "  Resolving with dnsx..."
    $GOBIN/dnsx -l "$OUTDIR/altdns-permutations.txt" \
        -a -resp -nc -silent \
        -r /opt/wordlists/resolvers.txt \
        -o "$OUTDIR/altdns-resolved.txt" 2>/dev/null

    RESOLVED_PERMS=$(wc -l < "$OUTDIR/altdns-resolved.txt" 2>/dev/null || echo 0)
    echo "  Resolved: ${RESOLVED_PERMS}"

    # Filter wildcard IPs — keep only subs whose IP appears ≤2 times
    # Extract sub:ip pairs, count IP frequency, keep only rare-IP subs
    grep -oP '^\S+.*?\d+\.\d+\.\d+\.\d+' "$OUTDIR/altdns-resolved.txt" 2>/dev/null \
        | awk '{sub=$1; for(i=1;i<=NF;i++) if($i~/^[0-9]+\.[0-9]+\./) {ip=$i; gsub(/[\[\]]/,"",ip); print ip, sub}}' \
        > "$OUTDIR/.altdns-ip-sub.txt"

    # IPs appearing >2 times are wildcards — exclude them
    awk '{print $1}' "$OUTDIR/.altdns-ip-sub.txt" | sort | uniq -c | awk '$1 > 2 {print $2}' > "$OUTDIR/.altdns-wildcard-ips.txt"

    > "$OUTDIR/altdns-valid.txt"
    while read ip sub; do
        if ! grep -qxF "$ip" "$OUTDIR/.altdns-wildcard-ips.txt" 2>/dev/null; then
            echo "$sub" >> "$OUTDIR/altdns-valid.txt"
        fi
    done < "$OUTDIR/.altdns-ip-sub.txt"
    sort -u -o "$OUTDIR/altdns-valid.txt" "$OUTDIR/altdns-valid.txt"
    rm -f "$OUTDIR/.altdns-ip-sub.txt" "$OUTDIR/.altdns-wildcard-ips.txt"

    ALTDNS_NEW=$(wc -l < "$OUTDIR/altdns-valid.txt" 2>/dev/null || echo 0)

    # Count truly new subs (not already in all-subdomains.txt)
    comm -23 <(sort "$OUTDIR/altdns-valid.txt") <(sort "$OUTDIR/all-subdomains.txt") > "$OUTDIR/altdns-new.txt" 2>/dev/null || true
    ALTDNS_NEW=$(wc -l < "$OUTDIR/altdns-new.txt" 2>/dev/null || echo 0)
    echo "  New subs (non-wildcard, unique): ${ALTDNS_NEW}"

    # Merge new discoveries
    if [ "$ALTDNS_NEW" -gt 0 ]; then
        cat "$OUTDIR/all-subdomains.txt" "$OUTDIR/altdns-new.txt" | sort -u > "$OUTDIR/.merged.txt"
        mv "$OUTDIR/.merged.txt" "$OUTDIR/all-subdomains.txt"
        echo "  Merged → total now: $(wc -l < "$OUTDIR/all-subdomains.txt")"
    fi

    rm -f "$OUTDIR/.altdns-input.txt"
else
    echo "  altdns or wordlist not found, skipping"
    ALTDNS_NEW=0
fi

# ── 3. DNS Resolution (find which subs actually resolve) ────────────────
echo ""
echo "[3/5] Resolving with dnsx..."

$GOBIN/dnsx -l "$OUTDIR/all-subdomains.txt" \
    -a -resp -nc -silent \
    -r /opt/wordlists/resolvers.txt \
    -o "$OUTDIR/resolved-dns.txt" 2>/dev/null

DNS_RESOLVED=$(wc -l < "$OUTDIR/resolved-dns.txt" 2>/dev/null || echo 0)
echo "  DNS resolved: ${DNS_RESOLVED}"

# ── 4. HTTP Probing ────────────────────────────────────────────────────
echo ""
echo "[4/5] Probing HTTP with httpx..."

$GOBIN/httpx -l "$OUTDIR/all-subdomains.txt" \
    -silent -nc \
    -tech-detect -status-code -title \
    -threads 50 -rate-limit 20 -timeout 10 \
    -o "$OUTDIR/resolved.txt"

LIVE=$(wc -l < "$OUTDIR/resolved.txt" 2>/dev/null || echo 0)
echo "  Live: ${LIVE}"

# Extract clean domain names only (HTTP-responsive)
awk '{print $1}' "$OUTDIR/resolved.txt" | sed 's|https\?://||' | cut -d: -f1 | sort -u > "$OUTDIR/resolved_domain.txt"
echo "  HTTP-live domains: $(wc -l < "$OUTDIR/resolved_domain.txt")"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  DONE — ${TOTAL} subs, ${DNS_RESOLVED} DNS, ${LIVE} HTTP"
echo "  (passive +${PASSIVE:-0}, brute +${BRUTE}, altdns +${ALTDNS_NEW:-0})"
echo "========================================"
