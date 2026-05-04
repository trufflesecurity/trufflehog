#!/bin/bash
set -euo pipefail

# Corpora Testing Script
# Automates the manual corpora testing workflow for detector validation.
#
# Usage: ./scripts/test_corpora.sh /path/to/contents.jsonl.zstd

# Check for required argument
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <corpora_file.jsonl.zstd>"
    echo "Example: $0 /path/to/contents.jsonl.zstd"
    exit 1
fi

CORPORA_FILE="$1"

# Validate input file exists
if [[ ! -f "$CORPORA_FILE" ]]; then
    echo "Error: Corpora file not found: $CORPORA_FILE"
    exit 1
fi

# Check dependencies
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is required but not installed."
        exit 1
    fi
}

check_dependency zstd
check_dependency jq
check_dependency duckdb
check_dependency go

# Derive output paths from input file location
CORPORA_DIR="$(dirname "$CORPORA_FILE")"
CORPORA_BASENAME="$(basename "$CORPORA_FILE" .jsonl.zstd)"
OUTPUT_JSONL="${CORPORA_DIR}/${CORPORA_BASENAME}_results.jsonl"
OUTPUT_LOG="${CORPORA_DIR}/${CORPORA_BASENAME}_trufflehog.log"

# Get repository root (where this script lives in scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TRUFFLEHOG_BIN="${REPO_ROOT}/trufflehog"

echo "=== Corpora Testing Script ==="
echo "Input: $CORPORA_FILE"
echo "Output JSONL: $OUTPUT_JSONL"
echo "Output Log: $OUTPUT_LOG"
echo ""

# Step 1: Build TruffleHog
echo "=== Building TruffleHog ==="
cd "$REPO_ROOT"
CGO_ENABLED=0 go build -o "$TRUFFLEHOG_BIN" .
echo "Built: $TRUFFLEHOG_BIN"
echo ""

# Step 2: Run the pipeline
# Note: TruffleHog returns non-zero exit code when secrets are found, so we allow failure here
echo "=== Running TruffleHog on corpora ==="
set +e
unzstd -c "$CORPORA_FILE" | jq -r .content | "$TRUFFLEHOG_BIN" \
    --no-update \
    --log-level=4 \
    --filter-tokenize \
    --json \
    --print-avg-detector-time \
    stdin > "$OUTPUT_JSONL" 2> "$OUTPUT_LOG"
SCAN_EXIT_CODE=$?
set -e
echo "TruffleHog scan complete (exit code: $SCAN_EXIT_CODE)."
echo ""

# Step 3: Run DuckDB SQL analysis
echo "=== Detector Statistics ==="
duckdb -c "
SELECT
    DetectorName,
    COUNT(*) AS count
FROM read_json('$OUTPUT_JSONL', format='newline_delimited', ignore_errors=true)
GROUP BY DetectorName
ORDER BY count DESC;
"

echo ""
echo "=== Done ==="
echo "Results saved to: $OUTPUT_JSONL"
echo "Log saved to: $OUTPUT_LOG"