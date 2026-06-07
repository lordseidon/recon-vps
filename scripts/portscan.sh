#!/bin/bash

# portscan.sh — Port scan subdomains with naabu
# Runs top-1000 first, then continues 1-10000 in background
# Usage: ./portscan.sh <domain>

set -euo pipefail

BASE="${RECON_OUTPUT_DIR:-$HOME/recon}"
DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./portscan.sh <domain>"
    exit 1
fi

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
echo "  PORT SCAN — $DOMAIN (naabu, top-1000 + background 1-10000)"
echo "  Targets: ${TOTAL} subdomains"
echo "========================================"

# ── Run naabu (top-1000) ─────────────────────────────────────────────
echo ""
echo "Scanning with naabu (top-1000)..."

naabu -list "$OUTDIR/.subs-to-scan.txt" \
    -top-ports 1000 \
    -ec \
    -silent \
    -nc \
    -json \
    -o "$OUTDIR/naabu-raw.json" 2>/dev/null

RAW=$(wc -l < "$OUTDIR/naabu-raw.json" 2>/dev/null || echo 0)
echo "  Raw results: ${RAW}"

# ── Build open-ports.json ─────────────────────────────────────────────
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

# ── Background full port scan (1-10000) ───────────────────────────────
FULL_OUT="$OUTDIR/naabu-full.json"
FULL_PIDFILE="$OUTDIR/.naabu-full.pid"

if [ -f "$FULL_OUT" ] && [ -s "$FULL_OUT" ]; then
    echo ""
    echo "Full port scan already completed, skipping background run"
elif [ -f "$FULL_PIDFILE" ] && kill -0 $(cat "$FULL_PIDFILE") 2>/dev/null; then
    echo ""
    echo "Full port scan still running in background (PID $(cat "$FULL_PIDFILE"))"
else
    echo ""
    echo "Starting background full port scan (1-10000) for ${TOTAL} targets..."
    > "$FULL_OUT"
    nohup bash -c "
        naabu -list '$OUTDIR/.subs-to-scan.txt' \
            -port 1-10000 \
            -ec \
            -silent \
            -nc \
            -json \
            -o '$FULL_OUT' 2>/dev/null
        python3 -c \"
import json
with open('$FULL_OUT') as f:
    raw = [json.loads(line) for line in f if line.strip()]
grouped = {}
for r in raw:
    host = r.get('host', r.get('ip', ''))
    port = str(r['port'])
    grouped.setdefault(host, set()).add(port)
result = [{'subdomain': h, 'ports': sorted(p, key=int)} for h, p in sorted(grouped.items())]
with open('$OUTDIR/open-ports-full.json', 'w') as f:
    json.dump(result, f, indent=2)
# Merge into main open-ports.json for DB import
imported = set()
with open('$OUTDIR/open-ports.json') as f:
    existing = json.load(f)
    for e in existing:
        grouped.setdefault(e['subdomain'], set()).update(e['ports'])
merged = [{'subdomain': h, 'ports': sorted(p, key=int)} for h, p in sorted(grouped.items())]
with open('$OUTDIR/open-ports.json', 'w') as f:
    json.dump(merged, f, indent=2)
total = sum(len(m['ports']) for m in merged)
print(f'Full scan: {len(merged)} hosts, {total} ports total')
\"
        rm -f '$FULL_PIDFILE'
    " > /dev/null 2>&1 &
    BG_PID=$!
    echo "$BG_PID" > "$FULL_PIDFILE"
    echo "  Background full scan started (PID $BG_PID)"
fi

# ── Summary ───────────────────────────────────────────────────────────
rm -f "$OUTDIR/.subs-to-scan.txt"

echo ""
echo "========================================"
echo "  PORT SCAN DONE"
echo "========================================"
echo "  Output: $OUTDIR/open-ports.json"
echo ""
echo "  Next: ./nuclei.sh $DOMAIN"
