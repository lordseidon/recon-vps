#!/bin/bash

# nuclei.sh — Run nuclei on subdomain:port combos
# Usage: ./nuclei.sh <subdomain> [-p port1,port2,...]
#   If -p is given, scans only those ports on the given subdomain
#   Otherwise reads all subdomain:port combos from ports/open-ports.json

set -euo pipefail

SUB="${1:-}"
CUSTOM_PORTS=""

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--ports) CUSTOM_PORTS="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ -z "$SUB" ]; then
    echo "Usage: ./nuclei.sh <subdomain> [-p port1,port2,...]"
    exit 1
fi

SCAN_DIR="${RECON_OUTPUT_DIR:-$HOME/recon}"

echo "========================================"
echo "  NUCLEI SCAN — $SUB"
echo "========================================"

OUTDIR="${SCAN_DIR}/nuclei"
mkdir -p "$OUTDIR"

if [ -n "$CUSTOM_PORTS" ]; then
    IFS=',' read -ra ports <<< "$CUSTOM_PORTS"
    > "${OUTDIR}/.targets.txt"
    for p in "${ports[@]}"; do
        p=$(echo "$p" | xargs)  # trim whitespace
        echo "${SUB}:${p}" >> "${OUTDIR}/.targets.txt"
    done
else
    PORTS_JSON="${SCAN_DIR}/ports/open-ports.json"
    [ -f "$PORTS_JSON" ] || { echo "  no open-ports.json found"; exit 1; }
    jq -r '.[] | .subdomain as $s | .ports[] | "\($s):\(.)"' "$PORTS_JSON" 2>/dev/null > "${OUTDIR}/.targets-all.txt"
    cp "${OUTDIR}/.targets-all.txt" "${OUTDIR}/.targets.txt"
fi

TOTAL=$(wc -l < "${OUTDIR}/.targets.txt" 2>/dev/null || echo 0)
if [ "$TOTAL" -eq 0 ]; then
    echo "  no targets found"
    rm -f "${OUTDIR}/.targets.txt"
    exit 0
fi

echo "  ${TOTAL} targets"
echo ""

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
