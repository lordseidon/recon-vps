#!/bin/bash

# recon.sh — Full recon pipeline: passive + active + resolve + IP analysis
# Usage: ./recon.sh example.com [--skip-passive] [--test]

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./recon.sh <domain> [--skip-passive] [--test]"
    exit 1
fi

SKIP_PASSIVE=""
TEST_MODE=""
STEP=""
for arg in "${@:2}"; do
    case "$arg" in
        --skip-passive) SKIP_PASSIVE="yes" ;;
        --test) TEST_MODE="yes" ;;
        --step) STEP="${3:-}" ; shift ;;
        --step=*) STEP="${arg#*=}" ;;
    esac
done

OUTDIR="$HOME/recon/$DOMAIN"
mkdir -p "$OUTDIR"

# Paths to dependencies
GOBIN="$HOME/go/bin"
WORDLIST="/usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt"
RESOLVERS="$HOME/recon/wordlists/resolvers.txt"
ALTDNS_WORDS="$HOME/recon/wordlists/altdns-words.txt"

if [ "$TEST_MODE" = "yes" ]; then
    WORDLIST="$HOME/recon/wordlists/test-200.txt"
    echo "[TEST MODE] 200 wordlist, slow steps skipped"
fi

# Step selection helper
step_match() {
    local want="$1"
    [ -z "$STEP" ] && return 0        # no filter → run all
    [ "$want" = "$STEP" ] && return 0  # match → run
    return 1                           # no match → skip
}

# Init all variables to prevent "unbound variable" when skipping steps
PASSIVE=0
SHUFFLE=0
ALTDNS=0
RESOLVED=0
CNAME=0
TAKEOVER=0
UNIQUE_IPS=0
WAYBACK=0
LIVE=0

echo "========================================"
echo "  RECON START — $DOMAIN"
echo "  Output: $OUTDIR"
echo "========================================"

if [ "$SKIP_PASSIVE" != "yes" ]; then

# ── 1. Passive Subdomain Enumeration ──────────────────────────────────
if step_match "1"; then
echo ""
echo "[1/6] Passive subdomain enumeration..."

echo "  → subfinder"
subfinder -d "$DOMAIN" -es digitorus -silent -o "$OUTDIR/subfinder.txt" &
echo "  → amass (10 min timeout)"
if [ "$TEST_MODE" = "yes" ]; then
    timeout 30 amass enum -passive -d "$DOMAIN" -o "$OUTDIR/amass.txt" || true
else
    timeout 600 amass enum -passive -d "$DOMAIN" -o "$OUTDIR/amass.txt" &
fi
echo "  → crt.sh"
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/^\*\.//g' \
    | sort -u > "$OUTDIR/crtsh.txt" &

wait
echo "  subfinder:  $(wc -l < "$OUTDIR/subfinder.txt" 2>/dev/null || echo 0)"
echo "  amass:      $(wc -l < "$OUTDIR/amass.txt" 2>/dev/null || echo 0)"
echo "  crt.sh:     $(wc -l < "$OUTDIR/crtsh.txt" 2>/dev/null || echo 0)"

fi  # step 1

# ── 1b. ASN & CIDR Discovery ──────────────────────────────────────────
if step_match "1b"; then
echo ""
echo "[1b/7] ASN & IP range discovery..."

# Extract org name from whois (first word of domain before the TLD)
ORG_NAME=$(echo "$DOMAIN" | cut -d. -f1 | sed 's/^./\U&/')
echo "  → searching ASNs for: $ORG_NAME"

# Find ASNs via amass intel (timeout 5 min)
timeout 300 amass intel -org "$ORG_NAME" 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | sort -u > "$OUTDIR/asn-cidrs.txt" || true
ASN_CIDRS=$(wc -l < "$OUTDIR/asn-cidrs.txt" 2>/dev/null || echo 0)

if [ "$ASN_CIDRS" -gt 0 ]; then
    echo "  → ${ASN_CIDRS} CIDR ranges discovered from ASN"
    cat "$OUTDIR/asn-cidrs.txt" >> "$OUTDIR/owned-ranges.txt"
else
    echo "  → no CIDRs found via amass intel, using whois fallback..."
    # Fallback: whois on the domain to find IP range
    whois "$DOMAIN" 2>/dev/null | grep -iE "inetnum|route|NetRange|cidr|netrange" | grep -oP '\d+\.\d+\.\d+\.\d+((/\d+)|(\s*-\s*\d+\.\d+\.\d+\.\d+))' | head -5 >> "$OUTDIR/asn-cidrs.txt" || true
fi

fi  # step 1b

else
    echo ""
    echo "[SKIP] Passive steps skipped, using existing data"
fi

# ── 2. Active DNS Brute-force ─────────────────────────────────────────
echo ""
if step_match "2"; then
echo "[2/7] Active DNS brute-force (shuffledns)..."

# Merge passive results first for resolving baseline
cat "$OUTDIR/subfinder.txt" "$OUTDIR/amass.txt" "$OUTDIR/crtsh.txt" 2>/dev/null \
    | sort -u > "$OUTDIR/.passive-merged.txt"
PASSIVE=$(wc -l < "$OUTDIR/.passive-merged.txt")
echo "  Passive baseline: ${PASSIVE} subs"

$GOBIN/shuffledns -d "$DOMAIN" \
    -w "$WORDLIST" \
    -r "$RESOLVERS" \
    -mode bruteforce \
    -t 50 -wt 5 \
    -silent \
    -o "$OUTDIR/shuffledns.txt" 2>/dev/null &
PID_SHUFFLE=$!

# While shuffledns runs, resolve passive subs with dnsx
echo "  Resolving passive subs with dnsx..."
if [ "$TEST_MODE" = "yes" ]; then
    timeout 30 $GOBIN/dnsx -l "$OUTDIR/.passive-merged.txt" \
        -a -aaaa -silent \
        -r "$RESOLVERS" \
        -o "$OUTDIR/dnsx-passive.txt" 2>/dev/null || true
else
    $GOBIN/dnsx -l "$OUTDIR/.passive-merged.txt" \
        -a -aaaa -silent \
        -r "$RESOLVERS" \
        -o "$OUTDIR/dnsx-passive.txt" 2>/dev/null &
    PID_DNSX=$!
fi

if [ "$TEST_MODE" = "yes" ]; then
    wait $PID_SHUFFLE 2>/dev/null || true
    SHUFFLE=$(wc -l < "$OUTDIR/shuffledns.txt" 2>/dev/null || echo 0)
    echo "  shuffledns: ${SHUFFLE} new subs found"
    echo "  dnsx passive resolution done"
else
    wait $PID_SHUFFLE
    SHUFFLE=$(wc -l < "$OUTDIR/shuffledns.txt" 2>/dev/null || echo 0)
    echo "  shuffledns: ${SHUFFLE} new subs found"
    wait $PID_DNSX
    echo "  dnsx passive resolution done"
fi

fi  # step 2

# ── 2b. Permutation Discovery (altdns) ─────────────────────────────────
if step_match "2b"; then
if [ "$TEST_MODE" != "yes" ]; then
echo ""
echo "[2b/7] Subdomain permutation discovery (altdns)..."

# Feed passive + brute-force subs into altdns for permutation generation
cat "$OUTDIR/subfinder.txt" "$OUTDIR/amass.txt" "$OUTDIR/crtsh.txt" "$OUTDIR/shuffledns.txt" 2>/dev/null \
    | sort -u > "$OUTDIR/.pre-permutation.txt"

if command -v altdns &>/dev/null; then
    altdns -i "$OUTDIR/.pre-permutation.txt" \
        -o "$OUTDIR/altdns-permutations.txt" \
        -w "$ALTDNS_WORDS" 2>/dev/null &
    PID_ALTDNS=$!
    PERMS=$(wc -l < "$OUTDIR/altdns-permutations.txt" 2>/dev/null || echo 0)
    wait $PID_ALTDNS 2>/dev/null || true
    PERMS=$(wc -l < "$OUTDIR/altdns-permutations.txt" 2>/dev/null || echo 0)
    echo "  ${PERMS} permutations generated, resolving with dnsx..."
    if [ "$TEST_MODE" = "yes" ]; then
        timeout 30 $GOBIN/dnsx -l "$OUTDIR/altdns-permutations.txt" \
            -a -silent \
            -r "$RESOLVERS" \
            -o "$OUTDIR/altdns-resolved.txt" 2>/dev/null || true
    else
        $GOBIN/dnsx -l "$OUTDIR/altdns-permutations.txt" \
            -a -silent \
            -r "$RESOLVERS" \
            -o "$OUTDIR/altdns-resolved.txt" 2>/dev/null
    fi
    ALTDNS=$(wc -l < "$OUTDIR/altdns-resolved.txt" 2>/dev/null || echo 0)
    echo "  altdns resolved: ${ALTDNS}"
else
    echo "  altdns not found, skipping"
    ALTDNS=0
    > "$OUTDIR/altdns-resolved.txt"
fi

rm -f "$OUTDIR/.pre-permutation.txt"

else
    echo "  → skipped (test mode)"
    ALTDNS=0
    > "$OUTDIR/altdns-resolved.txt"
fi
fi

# ── 3. Merge All Subdomains ────────────────────────────────────────────
if step_match "3"; then
echo ""
echo "[3/7] Merging all subdomain sources..."

cat "$OUTDIR/subfinder.txt" "$OUTDIR/amass.txt" "$OUTDIR/crtsh.txt" \
    "$OUTDIR/shuffledns.txt" "$OUTDIR/altdns-resolved.txt" 2>/dev/null \
    | sort -u > "$OUTDIR/all-subdomains.txt"

TOTAL=$(wc -l < "$OUTDIR/all-subdomains.txt")
echo "  Total unique subdomains: $TOTAL"
echo "  (Passive: ${PASSIVE}  +  Brute: ${SHUFFLE}  +  Permutations: ${ALTDNS})"
rm -f "$OUTDIR/.passive-merged.txt"

fi  # step 3

# ── 4. Resolve ALL subdomains with dnsx ────────────────────────────────
if step_match "4"; then
echo ""
echo "[4/7] Resolving all ${TOTAL} subdomains with dnsx..."

# A records (IP resolution)
$GOBIN/dnsx -l "$OUTDIR/all-subdomains.txt" \
    -a -resp -nc \
    -r "$RESOLVERS" \
    -o "$OUTDIR/resolved.txt" 2>/dev/null

RESOLVED=$(wc -l < "$OUTDIR/resolved.txt" 2>/dev/null || echo 0)

# CNAME records (subdomain takeover detection)
$GOBIN/dnsx -l "$OUTDIR/all-subdomains.txt" \
    -cname -silent \
    -r "$RESOLVERS" \
    -o "$OUTDIR/resolved-cname.txt" 2>/dev/null

CNAME=$(wc -l < "$OUTDIR/resolved-cname.txt" 2>/dev/null || echo 0)
echo "  A records: ${RESOLVED}  |  CNAME records: ${CNAME}"

# Check for dangling CNAMEs (potential subdomain takeover)
TAKEOVER_SERVICES="trafficmanager|azurewebsites|cloudapp|aws|herokuapp|bitbucket|surge|cargo|firebaseapp|netlify|zendesk|uservoice|freshdesk|helpscout|statuspage|readme|shopify|myshopify|launchrock|webflow|unbounce|wufoo|tictail|hatenablog|github\.io|pantheon"
> "$OUTDIR/takeover-candidates.txt"
grep -iE "$TAKEOVER_SERVICES" "$OUTDIR/resolved-cname.txt" 2>/dev/null > "$OUTDIR/takeover-candidates.txt" || true
TAKEOVER=$(wc -l < "$OUTDIR/takeover-candidates.txt" 2>/dev/null || echo 0)
echo "  Subdomain takeover candidates: ${TAKEOVER}"
[ "$TAKEOVER" -gt 0 ] && echo "    → see ${OUTDIR}/takeover-candidates.txt"

# Extract unique IPs from dnsx -resp output: "host [A] [ip]"
grep -oP '\[\d+\.\d+\.\d+\.\d+\]' "$OUTDIR/resolved.txt" 2>/dev/null \
    | tr -d '[]' \
    | sort -uV > "$OUTDIR/ips.txt" || true

UNIQUE_IPS=$(wc -l < "$OUTDIR/ips.txt" 2>/dev/null || echo 0)
echo "  Resolved: ${RESOLVED} entries  |  Unique IPs: ${UNIQUE_IPS}"

fi  # step 4

# ── 5. Wayback URL Discovery ──────────────────────────────────────────
if step_match "5"; then
echo ""
echo "[5/7] Historical URL discovery..."

if [ "$TEST_MODE" = "yes" ]; then
    echo "  → skipped (test mode)"
    WAYBACK=0
else

# Prefer gau (hits 4 sources), fallback to waybackurls
if command -v gau &>/dev/null; then
    echo "  → using gau (Wayback + CommonCrawl + URLScan + OTX)"
    cat "$OUTDIR/all-subdomains.txt" | gau --subs 2>/dev/null | sort -u > "$OUTDIR/gau-urls.txt"
    WAYBACK=$(wc -l < "$OUTDIR/gau-urls.txt" 2>/dev/null || echo 0)
    cp "$OUTDIR/gau-urls.txt" "$OUTDIR/wayback-urls.txt"
elif command -v "$GOBIN/gau" &>/dev/null; then
    echo "  → using gau (Wayback + CommonCrawl + URLScan + OTX)"
    cat "$OUTDIR/all-subdomains.txt" | "$GOBIN/gau" --subs 2>/dev/null | sort -u > "$OUTDIR/gau-urls.txt"
    WAYBACK=$(wc -l < "$OUTDIR/gau-urls.txt" 2>/dev/null || echo 0)
    cp "$OUTDIR/gau-urls.txt" "$OUTDIR/wayback-urls.txt"
else
    echo "  → using waybackurls (Wayback only)"
    cat "$OUTDIR/all-subdomains.txt" | while read sub; do
        $GOBIN/waybackurls "$sub" 2>/dev/null
    done | sort -u > "$OUTDIR/wayback-urls.txt"
    WAYBACK=$(wc -l < "$OUTDIR/wayback-urls.txt" 2>/dev/null || echo 0)
fi

fi
echo "  Historical URLs found: ${WAYBACK}"

# Extract new IPs/endpoints from wayback URLs (skip if file missing)
if [ -f "$OUTDIR/wayback-urls.txt" ] && [ -s "$OUTDIR/wayback-urls.txt" ]; then
grep -oP "https?://[^/\"]+" "$OUTDIR/wayback-urls.txt" 2>/dev/null \
    | sed 's|https\?://||' \
    | sort -u > "$OUTDIR/wayback-hosts.txt"

# Resolve wayback-discovered hosts too
if [ -s "$OUTDIR/wayback-hosts.txt" ]; then
    $GOBIN/dnsx -l "$OUTDIR/wayback-hosts.txt" \
        -a -silent \
        -r "$RESOLVERS" \
        -o "$OUTDIR/wayback-resolved.txt" 2>/dev/null
    grep -oP '\[\d+\.\d+\.\d+\.\d+\]' "$OUTDIR/wayback-resolved.txt" 2>/dev/null \
        | tr -d '[]' \
        | sort -uV >> "$OUTDIR/ips.txt" || true
    sort -uV -o "$OUTDIR/ips.txt" "$OUTDIR/ips.txt"
    UNIQUE_IPS_AFTER=$(wc -l < "$OUTDIR/ips.txt")
    echo "  IPs after wayback: ${UNIQUE_IPS_AFTER} (+$((UNIQUE_IPS_AFTER - UNIQUE_IPS)) new)"
    UNIQUE_IPS=$UNIQUE_IPS_AFTER
fi
fi

fi  # step 5

# ── 6. Subnet Analysis & Ownership ─────────────────────────────────────
if step_match "6"; then
echo ""
echo "[6/7] IP analysis & ownership..."

# Count IPs per /24
awk -F. '{print $1"."$2"."$3}' "$OUTDIR/ips.txt" \
    | sort | uniq -c | sort -rn > "$OUTDIR/subnet-count.txt"

echo "  Top /24 subnets:"
head -10 "$OUTDIR/subnet-count.txt" | while read count octet; do
    printf "    %s.0/24 → %s IPs\n" "$octet" "$count"
done

# Separate owned vs external (merge with ASN CIDRs from step 1b)
>> "$OUTDIR/owned-ranges.txt"
> "$OUTDIR/external-ips.txt"
> "$OUTDIR/internal-ips.txt"

while read count octet; do
    sample_ip=$(grep "^${octet}\." "$OUTDIR/ips.txt" 2>/dev/null | head -1)
    [ -z "$sample_ip" ] && continue

    whois_out=$(whois "$sample_ip" 2>/dev/null)
    domain_lower=$(echo "$DOMAIN" | tr '.' '|')

    if echo "$whois_out" | grep -qiE "$domain_lower"; then
        echo "${octet}.0/24" >> "$OUTDIR/owned-ranges.txt"
        what="owned"
    elif echo "$whois_out" | grep -qiE "amazon|aws|google|cloud|microsoft|azure|cloudflare|akamai|fastly"; then
        echo "$sample_ip" >> "$OUTDIR/external-ips.txt"
        what="external"
    elif echo "$sample_ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)'; then
        echo "$sample_ip" >> "$OUTDIR/internal-ips.txt"
        what="internal"
    else
        echo "$sample_ip" >> "$OUTDIR/external-ips.txt"
        what="external"
    fi
    printf "    %s.0/24 → %s IPs → %s\n" "$octet" "$count" "$what"
done < "$OUTDIR/subnet-count.txt"

sort -u -o "$OUTDIR/owned-ranges.txt" "$OUTDIR/owned-ranges.txt" 2>/dev/null || true
sort -u -o "$OUTDIR/external-ips.txt" "$OUTDIR/external-ips.txt" 2>/dev/null || true
sort -u -o "$OUTDIR/internal-ips.txt" "$OUTDIR/internal-ips.txt" 2>/dev/null || true

fi  # step 6

# ── 7. Live probing + technology detection ───────────────────────────
if step_match "7"; then
echo ""
echo "[7/7] Probing live subdomains with httpx (tech detection)..."

# Extract just subdomain names from resolved.txt
grep -oP '^\S+' "$OUTDIR/resolved.txt" 2>/dev/null | sort -u > "$OUTDIR/.resolved-subs.txt"

if command -v "$GOBIN/httpx" &>/dev/null; then
    "$GOBIN/httpx" -l "$OUTDIR/.resolved-subs.txt" \
        -silent \
        -tech-detect \
        -status-code \
        -title \
        -o "$OUTDIR/httpx-tech.txt" 2>/dev/null || true

    LIVE=$(wc -l < "$OUTDIR/httpx-tech.txt" 2>/dev/null || echo 0)
    echo "  Live subdomains: ${LIVE} (of ${RESOLVED} resolved)"
else
    echo "  httpx not found, skipping"
    LIVE=0
fi
rm -f "$OUTDIR/.resolved-subs.txt"

fi  # step 7

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  RECON COMPLETE"
echo "========================================"
echo "  Subdomains (passive):    ${PASSIVE}"
echo "  Subdomains (brute):      ${SHUFFLE}"
echo "  Subdomains (permutation): ${ALTDNS}"
echo "  Subdomains (total):      ${TOTAL}"
echo "  Resolved to IPs:         ${RESOLVED}"
echo "  Live (httpx):            ${LIVE:-0}"
echo "  Unique IPs:              ${UNIQUE_IPS}"
echo "  Wayback URLs:             ${WAYBACK}"
echo "  Owned ranges:            $(wc -l < "$OUTDIR/owned-ranges.txt" 2>/dev/null || echo 0)"
echo "  External/cloud IPs:      $(wc -l < "$OUTDIR/external-ips.txt" 2>/dev/null || echo 0)"
echo ""
echo "  Files:"
ls -lh "$OUTDIR/" 2>/dev/null | tail -n +2 | awk '{printf "    %s  %s\n", $5, $9}'
echo ""
echo "  Next:"
echo "    sudo ./portscan.sh"
echo "    cat $OUTDIR/all-subdomains.txt | httpx -silent | nuclei -as -rl 5 -o $OUTDIR/nuclei.txt"
