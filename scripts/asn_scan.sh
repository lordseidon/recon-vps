#!/bin/bash

# asn_scan.sh — ASN → CIDRs → port scan → TLS certs → reverse DNS
# Usage: ./asn_scan.sh <"Organization Name"> [domain-for-filtering]

set -euo pipefail

ORG_NAME="${1:-}"
FILTER_DOMAIN="${2:-}"

if [ -z "$ORG_NAME" ]; then
    echo "Usage: ./asn_scan.sh \"Organization Name\" [domain-to-filter]"
    exit 1
fi

DIR_NAME=$(echo "$ORG_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/-$//')
OUTDIR="${RECON_OUTPUT_DIR:-$HOME/recon/$DIR_NAME}"
mkdir -p "$OUTDIR/asn"

echo "========================================"
echo "  ASN SCAN — $ORG_NAME"
[ -n "$FILTER_DOMAIN" ] && echo "  Domain filter: $FILTER_DOMAIN"
echo "========================================"

# ── 1. Discover ASN + CIDRs ──────────────────────────────────────────
echo ""
if [ -f "$OUTDIR/asn/cidrs.txt" ] && [ -s "$OUTDIR/asn/cidrs.txt" ]; then
    echo "[1/4] CIDRs already discovered, skipping ASN lookup"
else
echo "[1/4] Discovering ASN ranges for: $ORG_NAME"
> "$OUTDIR/asn/cidrs.txt"

echo "  → amass intel"
timeout 120 amass intel -org "$ORG_NAME" 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | sort -uV >> "$OUTDIR/asn/cidrs.txt" || true

echo "  → hackertarget"
# First get ASN numbers (hackertarget returns comma-separated, not AS-prefixed)
ASNS=$(curl -s "https://api.hackertarget.com/aslookup/?q=${ORG_NAME// /%20}" 2>/dev/null | grep -oP '"\d+"' | tr -d '"' | sort -u || true)
for num in $ASNS; do
    asn="AS${num}"
    curl -s "https://api.hackertarget.com/aslookup/?q=${asn}" 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | sort -uV >> "$OUTDIR/asn/cidrs.txt" || true
    # Also try BGPView API for more CIDRs
    curl -s "https://api.bgpview.io/asn/${asn}/prefixes" 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for p in d.get('data',{}).get('ipv4_prefixes',[]):
        print(p.get('prefix',''))
except: pass
" 2>/dev/null | sort -uV >> "$OUTDIR/asn/cidrs.txt" || true
done

echo "  → whois fallback"
if [ -n "$FILTER_DOMAIN" ]; then
    set +e
    # Resolve domain to IPs, then whois each IP for CIDR
    IPS=$(dig +short "$FILTER_DOMAIN" A 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u || true)
    for ip in $IPS; do
        whois "$ip" 2>/dev/null | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | head -5
    done | sort -uV >> "$OUTDIR/asn/cidrs.txt" 2>/dev/null || true
    set -e
fi
fi

sort -uV -o "$OUTDIR/asn/cidrs.txt" "$OUTDIR/asn/cidrs.txt" 2>/dev/null || true
CIDR_COUNT=$(wc -l < "$OUTDIR/asn/cidrs.txt" 2>/dev/null || echo 0)
echo "  CIDRs: ${CIDR_COUNT}"
[ "$CIDR_COUNT" -eq 0 ] && { echo "  No CIDRs found. Exiting."; exit 0; }

# ── 2. Port Scan CIDRs ────────────────────────────────────────────────
echo ""
echo "[2/4] Port scanning CIDRs (naabu, top 1000, skip CDN)..."

MAX_CIDRS="${ASN_MAX_CIDRS:-0}"  # 0 = no limit, scan all CIDRs
> "$OUTDIR/asn/ips-open.txt"
COUNT=0
SCANNED=0
while read cidr; do
    [ -z "$cidr" ] && continue
    if [ "$MAX_CIDRS" -gt 0 ] && [ "$SCANNED" -ge "$MAX_CIDRS" ]; then
        echo "    Max CIDR limit ($MAX_CIDRS) reached, stopping"
        break
    fi
    COUNT=$((COUNT + 1))
    SCANNED=$((SCANNED + 1))
    printf "    [%s/%s] %s " "$COUNT" "$CIDR_COUNT" "$cidr"
    timeout 180 naabu -host "$cidr" -top-ports 1000 -ec -silent -nc -json -o "$OUTDIR/asn/.naabu.jsonl" 2>/dev/null || true
    python3 -c "
import json
with open('$OUTDIR/asn/.naabu.jsonl') as f:
    ips = set(json.loads(l)['ip'] for l in f if l.strip())
[print(ip) for ip in sorted(ips)]
" >> "$OUTDIR/asn/ips-open.txt" 2>/dev/null
    host_count=$(wc -l < "$OUTDIR/asn/ips-open.txt" 2>/dev/null || echo 0)
    echo "→ ${host_count} total IPs"
    rm -f "$OUTDIR/asn/.naabu.jsonl"
done < "$OUTDIR/asn/cidrs.txt"

sort -uV -o "$OUTDIR/asn/ips-open.txt" "$OUTDIR/asn/ips-open.txt" 2>/dev/null || true
IP_COUNT=$(wc -l < "$OUTDIR/asn/ips-open.txt" 2>/dev/null || echo 0)
echo "  Open IPs: ${IP_COUNT}"
[ "$IP_COUNT" -eq 0 ] && { echo "  No open IPs. Exiting."; exit 0; }

# ── 3. TLS Certificate Grabbing (Caduceus on open IPs) ───────────────
echo ""
echo "[3/4] Pulling TLS certificates (Caduceus on ${IP_COUNT} IPs)..."

CADUCEUS="$HOME/go/bin/caduceus"
> "$OUTDIR/asn/tls-domains.txt"  # ensure file exists even if caduceus missing
if [ -x "$CADUCEUS" ]; then
    "$CADUCEUS" -i "$OUTDIR/asn/ips-open.txt" \
        -p "443,8443,4443,9443,8080" \
        -t 4 -c 100 \
        -j > "$OUTDIR/asn/certs.jsonl" 2>/dev/null || true
    "$CADUCEUS" -i "$OUTDIR/asn/ips-open.txt" \
        -p "443,8443,4443,9443,8080" \
        -t 4 -c 100 \
        -wc > "$OUTDIR/asn/wildcards.txt" 2>/dev/null || true

    CERT_COUNT=$(wc -l < "$OUTDIR/asn/certs.jsonl" 2>/dev/null || echo 0)
    echo "  Certs: ${CERT_COUNT}"

    python3 -c "
import json
domains = []
with open('$OUTDIR/asn/certs.jsonl') as f:
    for line in f:
        try:
            cert = json.loads(line)
            sans = cert.get('san','') + ',' + cert.get('cn','')
            for d in sans.replace('DNS:','').split(','):
                d = d.strip()
                if d and '.' in d and len(d)>3: domains.append(d)
        except: pass
fd = '$FILTER_DOMAIN'
if fd: domains = [d for d in domains if fd in d]
with open('$OUTDIR/asn/tls-domains.txt','w') as f:
    for d in sorted(set(domains)): f.write(d+'\n')
" 2>/dev/null
else
    echo "  Caduceus not found"
fi

TLS_COUNT=$(wc -l < "$OUTDIR/asn/tls-domains.txt" 2>/dev/null || echo 0)
echo "  TLS domains matching filter: ${TLS_COUNT}"

# ── 4. Reverse DNS + Cert Discovery (amass enum -cidr) ────────────────
echo ""
echo "[4/4] Reverse DNS + cert discovery (amass enum -cidr)..."

if [ -n "$FILTER_DOMAIN" ] && [ "$CIDR_COUNT" -gt 0 ]; then
    > "$OUTDIR/asn/cidr-subs.txt"
    COUNT=0
    AMASS_SCANNED=0
    while read cidr; do
        [ -z "$cidr" ] && continue
        if [ "$MAX_CIDRS" -gt 0 ] && [ "$AMASS_SCANNED" -ge "$MAX_CIDRS" ]; then
            echo "    Max CIDR limit ($MAX_CIDRS) reached, stopping"
            break
        fi
        COUNT=$((COUNT + 1))
        AMASS_SCANNED=$((AMASS_SCANNED + 1))
        printf "    [%s/%s] %s" "$COUNT" "$CIDR_COUNT" "$cidr"
        timeout 60 amass enum -passive -d "$FILTER_DOMAIN" -cidr "$cidr" 2>/dev/null \
            | grep -oP '[a-zA-Z0-9.-]+\.'"$FILTER_DOMAIN"'' \
            | sort -u >> "$OUTDIR/asn/cidr-subs.txt" || true
        new=$(wc -l < "$OUTDIR/asn/cidr-subs.txt" 2>/dev/null || echo 0)
        printf " → %s total\n" "$new"
    done < "$OUTDIR/asn/cidrs.txt"
    sort -u -o "$OUTDIR/asn/cidr-subs.txt" "$OUTDIR/asn/cidr-subs.txt" 2>/dev/null || true
    CIDR_SUBS=$(wc -l < "$OUTDIR/asn/cidr-subs.txt" 2>/dev/null || echo 0)
    echo "  CIDR subs: ${CIDR_SUBS}"

    DOMAIN_DIR="${RECON_OUTPUT_DIR:-$HOME/recon}"
    if [ -f "$DOMAIN_DIR/all-subdomains.txt" ] && [ "$CIDR_SUBS" -gt 0 ]; then
        comm -23 <(sort "$OUTDIR/asn/cidr-subs.txt") <(sort "$DOMAIN_DIR/all-subdomains.txt") > "$OUTDIR/asn/cidr-new-subs.txt" 2>/dev/null || true
        CIDR_NEW=$(wc -l < "$OUTDIR/asn/cidr-new-subs.txt" 2>/dev/null || echo 0)
        echo "  New subs: ${CIDR_NEW}"
    else
        CIDR_NEW=0
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  ASN SCAN COMPLETE"
echo "========================================"
echo "  CIDRs:        ${CIDR_COUNT}"
echo "  Open IPs:     ${IP_COUNT}"
echo "  TLS certs:    ${CERT_COUNT:-0}"
echo "  TLS domains:  ${TLS_COUNT}"
echo "  CIDR subs:    ${CIDR_SUBS:-0}"
echo "  New subs:     ${CIDR_NEW:-0}"
echo ""
echo "  Output: $OUTDIR/asn/"
ls -lh "$OUTDIR/asn/" 2>/dev/null | awk 'NR>1{printf "    %s  %s\n", $5, $9}'
