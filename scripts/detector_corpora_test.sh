#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <corpora_file.jsonl.zstd> [<corpora_file2.jsonl.zstd> ...]"
    exit 1
fi

# CI sets OUTPUT_JSONL to per-run paths and skips the human-readable DuckDB
# summary. Local invocations leave it unset and get the summary table for
# debugging.
if [[ -z "${OUTPUT_JSONL+x}" ]]; then
    OUTPUT_JSONL="/tmp/corpora_results.jsonl"
    RUN_DUCKDB_SUMMARY=1
else
    RUN_DUCKDB_SUMMARY=0
fi
> "$OUTPUT_JSONL"

# Captures trufflehog stderr (incl. --print-avg-detector-time output) for downstream phases.
STDERR_FILE="${STDERR_FILE:-/tmp/corpora-stderr.txt}"
> "$STDERR_FILE"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TRUFFLEHOG_BIN="${TRUFFLEHOG_BIN:-${REPO_ROOT}/trufflehog}"

if [[ ! -x "$TRUFFLEHOG_BIN" ]]; then
    CGO_ENABLED=0 go build -o "$TRUFFLEHOG_BIN" "$REPO_ROOT"
fi

# When set, scope the scan to specific detectors. Comma-separated, lowercase
# proto enum names with optional ".v<n>" suffix (matches the format produced
# by scripts/detect_changed_detectors.sh).
INCLUDE_DETECTORS="${INCLUDE_DETECTORS:-}"
INCLUDE_FLAG=()
if [[ -n "$INCLUDE_DETECTORS" ]]; then
    INCLUDE_FLAG=(--include-detectors="$INCLUDE_DETECTORS")
fi

# When set, total uncompressed content bytes streamed to trufflehog (across
# all datasets in this run) are written to this path. Used by the diff
# script to compute blast-radius density. Awk inline-counts the post-jq
# stream so we don't double-read; END block runs before stdin EOF
# propagates out of the pipeline, so the value is written by the time the
# scan exits.
CORPUS_BYTES_FILE="${CORPUS_BYTES_FILE:-}"
TOTAL_BYTES=0

# --no-verification and --allow-verification-overlap are paired intentionally.
# This bench measures per-detector regex behavior in isolation:
#   - --no-verification: avoids network-flake noise (rate limits, transient 5xx
#     errors) that would otherwise produce verified/unverified deltas
#     indistinguishable from real regex regressions. Verifier behavior is
#     covered by detector unit tests.
#   - --allow-verification-overlap: bypasses the engine's cross-detector
#     overlap routing (pkg/engine/engine.go:862-872 + likelyDuplicate). That
#     routing exists for verification safety — when one chunk has matches from
#     multiple detectors, it dedups near-identical results so the same secret
#     isn't sent to multiple verifiers. With verification off, the routing has
#     no purpose, but its dedup side-effect (silently dropping a detector's
#     other matches in a multi-match chunk) makes a regex change in detector A
#     shift raw match counts in unrelated detector B, contaminating the diff.
#     Bypassing it gives each detector independent regex measurement.
scan() {
    local input="$1"
    local bytes_tmp=""
    if [[ -n "$CORPUS_BYTES_FILE" ]]; then
        bytes_tmp=$(mktemp)
    fi
    set +e
    if [[ -n "$bytes_tmp" ]]; then
        unzstd -c "$input" | jq -r .content \
            | awk -v BF="$bytes_tmp" '{ b += length($0) + 1; print } END { printf "%d", b > BF; close(BF) }' \
            | "$TRUFFLEHOG_BIN" \
                --no-update \
                --no-verification \
                --allow-verification-overlap \
                --log-level=3 \
                --concurrency=6 \
                --json \
                --print-avg-detector-time \
                "${INCLUDE_FLAG[@]}" \
                stdin >> "$OUTPUT_JSONL" 2>> "$STDERR_FILE"
    else
        unzstd -c "$input" | jq -r .content | "$TRUFFLEHOG_BIN" \
            --no-update \
            --no-verification \
            --allow-verification-overlap \
            --log-level=3 \
            --concurrency=6 \
            --json \
            --print-avg-detector-time \
            "${INCLUDE_FLAG[@]}" \
            stdin >> "$OUTPUT_JSONL" 2>> "$STDERR_FILE"
    fi
    set -e
    if [[ -n "$bytes_tmp" ]]; then
        TOTAL_BYTES=$((TOTAL_BYTES + $(cat "$bytes_tmp")))
        rm -f "$bytes_tmp"
    fi
}

for CORPORA_FILE in "$@"; do
    if [[ "$CORPORA_FILE" == s3://* ]]; then
        aws s3 cp "$CORPORA_FILE" - | scan /dev/stdin
    else
        scan "$CORPORA_FILE"
    fi
done

if [[ -n "$CORPUS_BYTES_FILE" ]]; then
    echo "$TOTAL_BYTES" > "$CORPUS_BYTES_FILE"
fi

if [[ "$RUN_DUCKDB_SUMMARY" == "1" ]]; then
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
fi
