#!/bin/bash

# nuclei.sh — Run nuclei on subdomain:port combos from portscan output
# Usage: ./nuclei.sh [domain]

set -euo pipefail

SCAN_DIR="${RECON_OUTPUT_DIR:-$HOME/recon}"
DOMAIN_ARG="${1:-}"

echo "========================================"
echo "  NUCLEI SCAN (auto-scan mode, rl:30)"
echo "========================================"

PORTS_JSON="${SCAN_DIR}/ports/open-ports.json"
[ -f "$PORTS_JSON" ] || { echo "  no open-ports.json found, run portscan.sh first"; exit 1; }

OUTDIR="${SCAN_DIR}/nuclei"
mkdir -p "$OUTDIR"

jq -r '.[] | .subdomain as $s | .ports[] | "\($s):\(.)"' "$PORTS_JSON" 2>/dev/null > "${OUTDIR}/.targets-all.txt"
TOTAL=$(wc -l < "${OUTDIR}/.targets-all.txt" 2>/dev/null || echo 0)

# Check for resume file from previous partial run
if [ -f "${OUTDIR}/.targets-remaining.txt" ]; then
    cp "${OUTDIR}/.targets-remaining.txt" "${OUTDIR}/.targets.txt"
    echo "  Resuming from previous run — $(wc -l < ${OUTDIR}/.targets.txt) targets remaining"
else
    cp "${OUTDIR}/.targets-all.txt" "${OUTDIR}/.targets.txt"
fi
TOTAL=$(wc -l < "${OUTDIR}/.targets.txt" 2>/dev/null || echo 0)

if [ "$TOTAL" -eq 0 ]; then
    echo "  no web targets found"
    rm -f "${OUTDIR}/.targets.txt"
    exit 0
fi

echo ""
echo "── ${TOTAL} targets ──────────────────────────────"

nuclei -l "${OUTDIR}/.targets.txt" \
    -as \
    -nh \
    -rl 30 \
    -timeout 15 \
    -bs 5 -c 5 \
    -o "$OUTDIR/findings.txt" 2>&1

FINDINGS=$(wc -l < "$OUTDIR/findings.txt" 2>/dev/null || echo 0)
echo "   → ${FINDINGS} findings"
echo "   → $OUTDIR/findings.txt"

rm -f "${OUTDIR}/.targets.txt"

echo ""
echo "========================================"
echo "  DONE"
echo "========================================"
