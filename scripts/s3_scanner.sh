#!/bin/bash

# s3_scanner.sh — S3 bucket scanning on recon output
# Usage: ./s3_scanner.sh <domain>

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: ./s3_scanner.sh <domain>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" pwd)"
RECON_SCRIPTS_DIR="${RECON_SCRIPTS_DIR:-$SCRIPT_DIR}"

# Load API keys
if [ -f "$RECON_SCRIPTS_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
else
    echo "Error: $RECON_SCRIPTS_DIR/.env not found. Add your AWS keys there."
    exit 1
fi

if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    echo "Error: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set in .env"
    echo "  Get free keys: https://aws.amazon.com/ → IAM → Create Access Key"
    exit 1
fi

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_REGION="${AWS_REGION:-us-east-1}"

INDIR="$RECON_OUTPUT_DIR"
if [ ! -d "$INDIR" ]; then
    echo "Error: $INDIR not found. Run recon.sh first."
    exit 1
fi

SUBS_FILE="$INDIR/all-subdomains.txt"
if [ ! -f "$SUBS_FILE" ]; then
    echo "Error: $SUBS_FILE not found. Run recon.sh first."
    exit 1
fi

OUTDIR="$INDIR/s3"
mkdir -p "$OUTDIR"

TOTAL=$(wc -l < "$SUBS_FILE")
echo "========================================"
echo "  S3 BUCKET SCAN — $DOMAIN"
echo "  Targets: ${TOTAL} subdomains"
echo "========================================"

# Check for S3Scanner
if ! python3 -c "import S3Scanner" 2>/dev/null; then
    if [ ! -f "$HOME/tools/S3Scanner/s3scanner.py" ]; then
        echo ""
        echo "S3Scanner not found. Install it:"
        echo "  git clone https://github.com/sa7mon/S3Scanner ~/tools/S3Scanner"
        echo "  pip3 install -r ~/tools/S3Scanner/requirements.txt"
        exit 1
    fi
    S3SCANNER="$HOME/tools/S3Scanner/s3scanner.py"
else
    S3SCANNER="s3scanner"
fi

# ── 0. Check if AWS is in scope at all ──────────────────────────────────
echo ""
echo "[0/2] Checking for AWS presence..."

AWS_INDICATORS=0

# Check CNAME records for AWS services
if grep -qiE "amazonaws|aws|s3.amazonaws|cloudfront" "$INDIR/resolved-cname.txt" 2>/dev/null; then
    AWS_INDICATORS=$((AWS_INDICATORS + 1))
    echo "  ✓ AWS CNAME records found"
fi

# Check if any IPs belong to AWS
if grep -qiE '^3\.|^13\.|^18\.|^34\.|^35\.|^43\.|^44\.|^46\.|^50\.|^51\.|^52\.|^54\.|^64\.|^70\.|^99\.' "$INDIR/ips.txt" 2>/dev/null; then
    AWS_INDICATORS=$((AWS_INDICATORS + 1))
    echo "  ✓ IPs in AWS ranges detected"
fi

# Check HTTP responses for S3 headers (from httpx if available)
if grep -qiE "x-amz-|Server: AmazonS3|s3.amazonaws" "$INDIR/ports/httpx.txt" 2>/dev/null; then
    AWS_INDICATORS=$((AWS_INDICATORS + 1))
    echo "  ✓ S3/Amazon headers in HTTP responses"
fi

if [ "$AWS_INDICATORS" -eq 0 ]; then
    echo "  ✗ No AWS indicators found — skipping S3 scan"
    exit 0
fi

echo "  ${AWS_INDICATORS} AWS indicator(s) found — proceeding with S3 scan"

echo ""
echo "[1/2] Scanning for open S3 buckets..."

python3 "$S3SCANNER" \
    -l "$SUBS_FILE" \
    -o "$OUTDIR/s3-buckets.txt" \
    2>&1 | grep --line-buffered -E "Found|bucket|open|Error" || true

BUCKETS=$(wc -l < "$OUTDIR/s3-buckets.txt" 2>/dev/null || echo 0)
echo ""
echo "  Open buckets found: ${BUCKETS}"

# Dump bucket contents
if [ "$BUCKETS" -gt 0 ] && [ -s "$OUTDIR/s3-buckets.txt" ]; then
    echo ""
    echo "[2/2] Enumerating bucket contents..."

    > "$OUTDIR/s3-contents.txt"

    while IFS= read -r bucket; do
        [ -z "$bucket" ] && continue
        echo "  → $bucket"
        echo "=== $bucket ===" >> "$OUTDIR/s3-contents.txt"
        aws s3 ls "s3://$bucket" --no-sign-request 2>/dev/null >> "$OUTDIR/s3-contents.txt" || {
            echo "    (requires authentication)" >> "$OUTDIR/s3-contents.txt"
        }
        echo "" >> "$OUTDIR/s3-contents.txt"
    done < "$OUTDIR/s3-buckets.txt"

    echo "  Contents saved to $OUTDIR/s3-contents.txt"
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  S3 SCAN COMPLETE"
echo "========================================"
echo "  Buckets found: ${BUCKETS}"
[ -f "$OUTDIR/s3-buckets.txt" ] && echo "  Bucket list:  $OUTDIR/s3-buckets.txt"
[ -f "$OUTDIR/s3-contents.txt" ] && echo "  Contents:     $OUTDIR/s3-contents.txt"
echo ""
echo "  Tip: download full bucket contents with:"
echo "    for b in \$(cat $OUTDIR/s3-buckets.txt); do"
echo "      aws s3 sync s3://\$b $OUTDIR/dump/\$b --no-sign-request"
echo "    done"
