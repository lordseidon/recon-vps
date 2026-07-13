#!/bin/bash

# recon.sh — subfinder + amass + shuffledns (brute + recursive) + alterx/altdns + dnsx + httpx
VENV_BIN="/opt/recon_web/.venv/bin"
export PATH="$VENV_BIN:$PATH"
# Usage: ./recon.sh <domain>

set -euo pipefail

# Passive recon enabled by default. Set to "true" to skip subfinder/amass.
RECON_SKIP_PASSIVE="${RECON_SKIP_PASSIVE:-}"
RECON_SKIP_AMASS="${RECON_SKIP_AMASS:-}"

# ── Tunables ──────────────────────────────────────────────────────────
# Permutation engine: alterx | altdns | skip  (auto-detects if unset)
PERM_TOOL="${PERM_TOOL:-}"
# Hard cap on permutations to resolve. Empty = unlimited (no truncation).
PERM_MAX="${PERM_MAX:-}"
# Space-separated brute-force wordlists (first existing ones are merged).
BRUTE_WORDLISTS="${BRUTE_WORDLISTS:-/opt/wordlists/subdomains.txt}"
# Small curated list for the recursive deeper-level brute pass.
RECURSIVE_WORDLIST="${RECURSIVE_WORDLIST:-/opt/wordlists/recursive.txt}"
# Resolver list used by shuffledns/dnsx.
RESOLVERS="${RESOLVERS:-/root/resolvers.txt}"

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./recon.sh <domain>"
    exit 1
fi

OUTDIR="${RECON_OUTPUT_DIR:-$HOME/recon/$DOMAIN}"
mkdir -p "$OUTDIR"
GOBIN="$HOME/go/bin"

echo "========================================"
echo "  RECON — $DOMAIN"
echo "========================================"

# ── 1. Subdomain Enumeration ──────────────────────────────────────────
echo ""
echo "[1/4] Enumerating subdomains..."

echo "  → subfinder"
if [ "${RECON_SKIP_PASSIVE:-}" = "true" ]; then
    echo "  → subfinder skipped (RECON_SKIP_PASSIVE=true)"
    touch "$OUTDIR/subfinder.txt"
else
subfinder -d "$DOMAIN" -es digitorus -silent -o "$OUTDIR/subfinder.txt"
fi

echo "  → amass (10 min timeout, fast sources only)"
if [ "${RECON_SKIP_AMASS:-}" = "true" ] || [ "${RECON_SKIP_PASSIVE:-}" = "true" ]; then
    echo "  → amass skipped (skip flag set)"
else
timeout 600 amass enum -passive -d "$DOMAIN" -include crtsh,certspotter,riddler,dnsdumpster,hackertarget,sitedossier,commoncrawl,wayback,chaos,github,binaryedge,bufferover,cebaidu,c99 -o "$OUTDIR/amass.txt" 2>/dev/null || true
fi

# Ensure amass.txt exists (may be skipped)
touch "$OUTDIR/amass.txt" 2>/dev/null || true
cat "$OUTDIR/subfinder.txt" "$OUTDIR/amass.txt" 2>/dev/null | sort -u > "$OUTDIR/all-subdomains.txt"
PASSIVE=$(wc -l < "$OUTDIR/all-subdomains.txt")
echo "  subfinder: $(wc -l < "$OUTDIR/subfinder.txt")  |  amass: $(wc -l < "$OUTDIR/amass.txt" 2>/dev/null || echo 0)  |  unique: ${PASSIVE}"

# ── 2. Active DNS brute-force ─────────────────────────────────────────
echo ""
mkdir -p "$OUTDIR"
echo "[2/6] DNS brute-force (shuffledns)..."

# Merge all requested wordlists that exist into one temp list
BRUTE_MERGED="$OUTDIR/.brute-wordlist.txt"
> "$BRUTE_MERGED"
for wl in $BRUTE_WORDLISTS; do
    [ -f "$wl" ] && cat "$wl" >> "$BRUTE_MERGED"
done
sort -u -o "$BRUTE_MERGED" "$BRUTE_MERGED" 2>/dev/null || true
if [ ! -s "$BRUTE_MERGED" ]; then
    echo "  No brute wordlist found ($BRUTE_WORDLISTS), skipping brute-force"
    touch "$OUTDIR/shuffledns.txt"
else
    echo "  Wordlist words: $(wc -l < "$BRUTE_MERGED")"
    $GOBIN/shuffledns -d "$DOMAIN" \
        -w "$BRUTE_MERGED" \
        -r "$RESOLVERS" \
        -mode bruteforce \
        -o "$OUTDIR/shuffledns.txt" 2>&1 | grep -E "[INF]|resolved|output" || true
fi
rm -f "$BRUTE_MERGED"

BRUTE=$(wc -l < "$OUTDIR/shuffledns.txt" 2>/dev/null || echo 0)
echo "  Brute-force found: ${BRUTE}"

# Merge all sources
cat "$OUTDIR/all-subdomains.txt" "$OUTDIR/shuffledns.txt" 2>/dev/null | sort -u > "$OUTDIR/all-subdomains-merged.txt"
mv "$OUTDIR/all-subdomains-merged.txt" "$OUTDIR/all-subdomains.txt"
# Clean: keep only valid subdomain lines (strip amass ASN/netblock noise)
grep -oP '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$OUTDIR/all-subdomains.txt" | sort -u > "$OUTDIR/.clean-subs.txt" 2>/dev/null || true
mv "$OUTDIR/.clean-subs.txt" "$OUTDIR/all-subdomains.txt" 2>/dev/null || true
TOTAL=$(wc -l < "$OUTDIR/all-subdomains.txt")
echo "  Total after brute: ${TOTAL}"

# ── 2b. Recursive deeper-level brute-force ──────────────────────────────
echo ""
echo "[2b/6] Recursive brute-force (one label deeper)..."
RECURSIVE_NEW=0
if [ -f "$RECURSIVE_WORDLIST" ] && [ -s "$RECURSIVE_WORDLIST" ]; then
    # Parent zones = subs with >=3 labels below the apex (e.g. dev.corp.target.com → corp.target.com)
    grep -oP '^[a-zA-Z0-9.-]+\.'"$DOMAIN"'$' "$OUTDIR/all-subdomains.txt" 2>/dev/null \
        | awk -F. -v apex="$DOMAIN" '{n=split(apex,a,"."); if (NF > n+1) {p=$2; for(i=3;i<=NF;i++) p=p"."$i; print p}}' \
        | sort -u > "$OUTDIR/.recursive-parents.txt" || true
    PARENTS=$(wc -l < "$OUTDIR/.recursive-parents.txt" 2>/dev/null || echo 0)
    echo "  Parent zones: ${PARENTS} | wordlist: $(wc -l < "$RECURSIVE_WORDLIST")"

    > "$OUTDIR/recursive-brute.txt"
    while read parent; do
        [ -z "$parent" ] && continue
        $GOBIN/shuffledns -d "$parent" \
            -w "$RECURSIVE_WORDLIST" \
            -r "$RESOLVERS" \
            -mode bruteforce -silent 2>/dev/null \
            >> "$OUTDIR/recursive-brute.txt" || true
    done < "$OUTDIR/.recursive-parents.txt"
    sort -u -o "$OUTDIR/recursive-brute.txt" "$OUTDIR/recursive-brute.txt" 2>/dev/null || true

    comm -23 <(sort "$OUTDIR/recursive-brute.txt") <(sort "$OUTDIR/all-subdomains.txt") > "$OUTDIR/.recursive-new.txt" 2>/dev/null || true
    RECURSIVE_NEW=$(wc -l < "$OUTDIR/.recursive-new.txt" 2>/dev/null || echo 0)
    echo "  New subs (recursive): ${RECURSIVE_NEW}"
    if [ "$RECURSIVE_NEW" -gt 0 ]; then
        cat "$OUTDIR/all-subdomains.txt" "$OUTDIR/.recursive-new.txt" | sort -u > "$OUTDIR/.merged.txt"
        mv "$OUTDIR/.merged.txt" "$OUTDIR/all-subdomains.txt"
    fi
    rm -f "$OUTDIR/.recursive-parents.txt" "$OUTDIR/.recursive-new.txt"
else
    echo "  Recursive wordlist not found ($RECURSIVE_WORDLIST), skipping"
fi

# ── 2c. Permutation Discovery (alterx / altdns) ─────────────────────────
ALTDNS_WORDS="/opt/wordlists/altdns-words.txt"
echo ""
echo "[2c/6] Subdomain permutation discovery..."

# Auto-detect permutation tool if not forced
if [ -z "$PERM_TOOL" ]; then
    if command -v alterx &>/dev/null; then PERM_TOOL="alterx"
    elif command -v altdns &>/dev/null; then PERM_TOOL="altdns"
    else PERM_TOOL="skip"; fi
fi

ALTDNS_NEW=0
PERM_INPUT="$OUTDIR/.perm-input.txt"
PERM_LIST="$OUTDIR/permutations.txt"

# Clean subdomain names for input (strip amass verbose output & IP-octet junk)
grep -oP '^[a-zA-Z0-9.-]+\.'"$DOMAIN"'$' "$OUTDIR/all-subdomains.txt" \
    | grep -vP '^\d{1,3}\.\d{1,3}\.' \
    | sort -u > "$PERM_INPUT" 2>/dev/null || true
INPUT_COUNT=$(wc -l < "$PERM_INPUT" 2>/dev/null || echo 0)

if [ "$PERM_TOOL" = "alterx" ] && command -v alterx &>/dev/null; then
    echo "  Engine: alterx | input subs: ${INPUT_COUNT}"
    alterx -l "$PERM_INPUT" -silent -o "$PERM_LIST" 2>/dev/null || true
elif [ "$PERM_TOOL" = "altdns" ] && command -v altdns &>/dev/null && [ -f "$ALTDNS_WORDS" ]; then
    echo "  Engine: altdns | input subs: ${INPUT_COUNT} | wordlist: $(wc -l < "$ALTDNS_WORDS")"
    altdns -i "$PERM_INPUT" -w "$ALTDNS_WORDS" -o "$PERM_LIST" 2>/dev/null || true
else
    echo "  No permutation engine available ($PERM_TOOL), skipping"
    PERM_TOOL="skip"
fi

if [ "$PERM_TOOL" != "skip" ] && [ -s "$PERM_LIST" ]; then
    PERMS=$(wc -l < "$PERM_LIST" 2>/dev/null || echo 0)
    # Optional explicit cap (default: unlimited)
    if [ -n "$PERM_MAX" ]; then
        head -n "$PERM_MAX" "$PERM_LIST" > "$PERM_LIST.capped" && mv "$PERM_LIST.capped" "$PERM_LIST"
        echo "  Permutations: ${PERMS} (capped to ${PERM_MAX})"
    else
        echo "  Permutations: ${PERMS} (no cap)"
    fi

    # Resolve with shuffledns (massdns) — native wildcard filtering, no arbitrary IP-frequency heuristic
    echo "  Resolving permutations with shuffledns (wildcard-filtered)..."
    $GOBIN/shuffledns -d "$DOMAIN" \
        -list "$PERM_LIST" \
        -r "$RESOLVERS" \
        -mode resolve -strict-wildcard -silent \
        -o "$OUTDIR/permutations-resolved.txt" 2>/dev/null || true

    comm -23 <(sort "$OUTDIR/permutations-resolved.txt") <(sort "$OUTDIR/all-subdomains.txt") > "$OUTDIR/permutations-new.txt" 2>/dev/null || true
    ALTDNS_NEW=$(wc -l < "$OUTDIR/permutations-new.txt" 2>/dev/null || echo 0)
    echo "  New subs (permutation, wildcard-filtered): ${ALTDNS_NEW}"

    if [ "$ALTDNS_NEW" -gt 0 ]; then
        cat "$OUTDIR/all-subdomains.txt" "$OUTDIR/permutations-new.txt" | sort -u > "$OUTDIR/.merged.txt"
        mv "$OUTDIR/.merged.txt" "$OUTDIR/all-subdomains.txt"
        echo "  Merged → total now: $(wc -l < "$OUTDIR/all-subdomains.txt")"
    fi
fi
rm -f "$PERM_INPUT"

# ── 3. DNS Resolution (find which subs actually resolve) ────────────────
echo ""
echo "[3/6] Resolving with dnsx..."

# Ensure only clean subdomain lines
grep -oP '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$OUTDIR/all-subdomains.txt" | sort -u > "$OUTDIR/.resolv-input.txt" 2>/dev/null || true
$GOBIN/dnsx -l "$OUTDIR/.resolv-input.txt" \
    -a -resp -nc -silent \
    -r "$RESOLVERS" \
    -o "$OUTDIR/resolved-dns.txt" 2>/dev/null
rm -f "$OUTDIR/.resolv-input.txt"

DNS_RESOLVED=$(wc -l < "$OUTDIR/resolved-dns.txt" 2>/dev/null || echo 0)
echo "  DNS resolved: ${DNS_RESOLVED}"

# ── 4. HTTP Probing ────────────────────────────────────────────────────
echo ""
echo "[4/6] Probing HTTP with httpx..."

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
TOTAL=$(wc -l < "$OUTDIR/all-subdomains.txt" 2>/dev/null || echo 0)
echo ""
echo "========================================"
echo "  DONE — ${TOTAL} subs, ${DNS_RESOLVED} DNS, ${LIVE} HTTP"
echo "  (passive +${PASSIVE:-0}, brute +${BRUTE}, recursive +${RECURSIVE_NEW:-0}, perm +${ALTDNS_NEW:-0})"
echo "========================================"
