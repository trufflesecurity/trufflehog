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

# Captures trufflehog stderr (incl. --print-avg-detector-time output) for postmortem inspection.
STDERR_FILE="${STDERR_FILE:-/tmp/corpora-stderr.txt}"
> "$STDERR_FILE"

REPO_ROOT="$(git rev-parse --show-toplevel)"
TRUFFLEHOG_BIN="${TRUFFLEHOG_BIN:-${REPO_ROOT}/trufflehog}"

if [[ ! -x "$TRUFFLEHOG_BIN" ]]; then
    CGO_ENABLED=0 go build -o "$TRUFFLEHOG_BIN" "$REPO_ROOT"
fi

# When set, scope the scan to specific detectors. Comma-separated, lowercase
# proto enum names with optional ".v<n>" suffix (matches the format produced
# by scripts/test/detect_changed_detectors.sh).
INCLUDE_DETECTORS="${INCLUDE_DETECTORS:-}"
INCLUDE_FLAG=()
if [[ -n "$INCLUDE_DETECTORS" ]]; then
    INCLUDE_FLAG=(--include-detectors="$INCLUDE_DETECTORS")
fi

# --no-verification avoids network calls against a large corpus where thousands
# of matches could trigger API calls, dominating runtime. Verifier behavior is
# covered by detector unit and integration tests.
scan() {
    local input="$1"
    # jq stderr is folded into STDERR_FILE so benign "Broken pipe" notices
    # (trufflehog exits before jq finishes draining the corpus) don't pollute
    # CI logs. Real jq parse errors land in the same file for postmortem.
    set +e
    unzstd -c "$input" 2>> "$STDERR_FILE" \
        | jq -r .content 2>> "$STDERR_FILE" \
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
    set -e
}

for CORPORA_FILE in "$@"; do
    if [[ "$CORPORA_FILE" == s3://* ]]; then
        aws s3 cp "$CORPORA_FILE" - | scan /dev/stdin
    else
        scan "$CORPORA_FILE"
    fi
done

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
