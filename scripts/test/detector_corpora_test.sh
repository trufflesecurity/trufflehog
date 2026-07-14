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

if [[ -n "${OUTPUT_JSONL_MAIN:-}" ]]; then
    > "$OUTPUT_JSONL_MAIN"
fi

# --no-verification avoids network calls against a large corpus where thousands
# of matches could trigger API calls, dominating runtime. Verifier behavior is
# covered by detector unit and integration tests.
#
# Dual-binary mode: when TRUFFLEHOG_BIN_MAIN / OUTPUT_JSONL_MAIN /
# INCLUDE_DETECTORS_MAIN are set, the corpus stream is teed to both the PR
# binary (stdout side) and the main binary (process substitution) so S3 is
# only downloaded once.
scan() {
    local input="$1"
    set +e

    local main_include_flag=()
    if [[ -n "${INCLUDE_DETECTORS_MAIN:-}" ]]; then
        main_include_flag=(--include-detectors="$INCLUDE_DETECTORS_MAIN")
    fi

    local rc=0
    if [[ -n "${TRUFFLEHOG_BIN_MAIN:-}" ]]; then
        # Single S3 download teed to both binaries simultaneously.
        unzstd -c "$input" \
            | jq -r .content \
            | tee >(
                "${TRUFFLEHOG_BIN_MAIN}" \
                    --no-update \
                    --no-verification \
                    --allow-verification-overlap \
                    --log-level=3 \
                    --concurrency=8 \
                    --json \
                    --archive-timeout=2h \
                    "${main_include_flag[@]}" \
                    stdin >> "${OUTPUT_JSONL_MAIN}"
              ) \
            | "$TRUFFLEHOG_BIN" \
                --no-update \
                --no-verification \
                --allow-verification-overlap \
                --log-level=3 \
                --concurrency=8 \
                --json \
                --print-avg-detector-time \
                --archive-timeout=2h \
                "${INCLUDE_FLAG[@]}" \
                stdin >> "$OUTPUT_JSONL"
        rc=$?
        wait
    else
        unzstd -c "$input" \
            | jq -r .content \
            | "$TRUFFLEHOG_BIN" \
                --no-update \
                --no-verification \
                --allow-verification-overlap \
                --log-level=3 \
                --concurrency=8 \
                --json \
                --print-avg-detector-time \
                --archive-timeout=2h \
                "${INCLUDE_FLAG[@]}" \
                stdin >> "$OUTPUT_JSONL"
        rc=$?
    fi
    set -e
    return $rc
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
    COUNT(*) total
FROM t
GROUP BY all
ORDER BY total DESC, detector
LIMIT 50;
"
fi
