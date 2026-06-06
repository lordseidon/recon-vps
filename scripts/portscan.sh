#!/bin/bash

# portscan.sh — Port scan subdomains with naabu
# Usage: ./portscan.sh <domain> [-scan 1k|10k|all]

set -euo pipefail

BASE="${RECON_OUTPUT_DIR:-$HOME/recon}"
DOMAIN="${1:-}"
SCAN_MODE="10k"

# Parse -scan flag from remaining args
for arg in "${@:2}"; do
    [[ "$arg" =~ ^(1k|10k|all)$ ]] && SCAN_MODE="$arg" && break
done

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./portscan.sh <domain> [-scan 1k|10k|all]"
    exit 1
fi

case "$SCAN_MODE" in
    1k)   PORTS_FLAG="-top-ports 1000"; PORTS_LABEL="top 1k" ;;
    10k)  PORTS_FLAG="-port 1-10000"; PORTS_LABEL="ports 1-10000" ;;
    all)  PORTS_FLAG="-top-ports full"; PORTS_LABEL="all (65535)" ;;
    *)    echo "Invalid scan mode: $SCAN_MODE. Use 1k, 10k, or all."; exit 1 ;;
esac

INDIR="$BASE"
SUBS_FILE="$INDIR/all-subdomains.txt"
[ -f "$SUBS_FILE" ] || { echo "Error: $SUBS_FILE not found. Run recon.sh first."; exit 1; }
OUTDIR="$INDIR/ports"
mkdir -p "$OUTDIR"

[ -f "$SUBS_FILE" ] || { echo "Error: $SUBS_FILE not found. Run recon.sh first."; exit 1; }

# Extract clean subdomains from all-subdomains
grep -oP '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$SUBS_FILE" | sort -u > "$OUTDIR/.subs-to-scan.txt" 2>/dev/null || true
TOTAL=$(wc -l < "$OUTDIR/.subs-to-scan.txt")

echo "========================================"
echo "  PORT SCAN — $DOMAIN (naabu, $PORTS_LABEL)"
echo "  Targets: ${TOTAL} subdomains"
echo "========================================"

# ── Run naabu ─────────────────────────────────────────────────────────
echo ""
echo "Scanning with naabu..."

# Naabu can take hostnames directly (-list)
naabu -list "$OUTDIR/.subs-to-scan.txt" \
    $PORTS_FLAG \
    -ec \
    -silent \
    -nc \
    -json \
    -o "$OUTDIR/naabu-raw.json" 2>/dev/null

RAW=$(wc -l < "$OUTDIR/naabu-raw.json" 2>/dev/null || echo 0)
echo "  Raw results: ${RAW}"

# ── Build open-ports.json ─────────────────────────────────────────────
# Naabu outputs: {"host":"sub.mtn.ng","ip":"1.2.3.4","port":443}
# Group by hostname
python3 -c "
import json

with open('$OUTDIR/naabu-raw.json') as f:
    raw = [json.loads(line) for line in f if line.strip()]

grouped = {}
for r in raw:
    host = r.get('host', r.get('ip', ''))
    port = str(r['port'])
    grouped.setdefault(host, set()).add(port)

result = [{'subdomain': h, 'ports': sorted(p, key=int)} for h, p in sorted(grouped.items())]

with open('$OUTDIR/open-ports.json', 'w') as f:
    json.dump(result, f, indent=2)

print(f'  Hosts with open ports: {len(result)}')
total_ports = sum(len(e['ports']) for e in result)
print(f'  Total open ports: {total_ports}')
"

# ── Summary ───────────────────────────────────────────────────────────
rm -f "$OUTDIR/.subs-to-scan.txt"

echo ""
echo "========================================"
echo "  PORT SCAN DONE"
echo "========================================"
echo "  Output: $OUTDIR/open-ports.json"
echo ""
echo "  Next: ./nuclei.sh $DOMAIN"
