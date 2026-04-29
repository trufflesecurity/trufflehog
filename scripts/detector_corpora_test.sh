#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <corpora_file.jsonl.zstd> [<corpora_file2.jsonl.zstd> ...]"
    exit 1
fi

OUTPUT_JSONL="/tmp/corpora_results.jsonl"
> "$OUTPUT_JSONL"

# Captures trufflehog stderr (incl. --print-avg-detector-time output) for downstream phases.
STDERR_FILE="/tmp/corpora-stderr.txt"
> "$STDERR_FILE"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TRUFFLEHOG_BIN="${REPO_ROOT}/trufflehog"

CGO_ENABLED=0 go build -o "$TRUFFLEHOG_BIN" "$REPO_ROOT"

scan() {
    local input="$1"
    set +e
    unzstd -c "$input" | jq -r .content | "$TRUFFLEHOG_BIN" \
        --no-update \
        --log-level=3 \
        --concurrency=6 \
        --json \
        --print-avg-detector-time \
        stdin >> "$OUTPUT_JSONL" 2>> "$STDERR_FILE"
    set -e
}

for CORPORA_FILE in "$@"; do
    if [[ "$CORPORA_FILE" == s3://* ]]; then
        aws s3 cp "$CORPORA_FILE" - | scan /dev/stdin
    else
        scan "$CORPORA_FILE"
    fi
done

duckdb -c "
CREATE TABLE t AS FROM read_json_auto('$OUTPUT_JSONL', ignore_errors=true);

SELECT
    t.DetectorName detector,
    COUNT(*) total,
    SUM(CASE WHEN Verified AND VerificationError IS NULL THEN 1 ELSE 0 END) verified,
    SUM(CASE WHEN NOT Verified AND VerificationError IS NULL THEN 1 ELSE 0 END) unverified,
    SUM(CASE WHEN VerificationError IS NOT NULL THEN 1 ELSE 0 END) \"unknown\"
FROM t
GROUP BY all
ORDER BY total DESC, detector
LIMIT 50;
"
