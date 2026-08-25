#!/usr/bin/env bash
set -euo pipefail

# Measures what a detector's Keywords() prefilter costs on a corpus.
# See cmd/keywordbench for what the numbers mean.

usage() {
  cat <<'USAGE'
Usage: scripts/keywordbench.sh [options] [-- extra keywordbench flags]

  -c, --corpus PATH   corpus file; .zst/.zstd/.gz are decompressed, .jsonl is
                      unwrapped with jq. Omit to read stdin.
  -t, --target NAME   detector to audit in depth, e.g. Resend
  -a, --alt WORDS     comma-separated candidate keywords to A/B against -target
  -d, --detect        also run the regexes, for yield and CPU cost (much slower)
  -l, --limit-mb N    stop after N MB of corpus
  -n, --top N         rows per table (default 40)
  -j, --workers N     concurrent workers (default: all cores)
  -o, --out DIR       write report.txt and the CSVs here (default ./keywordbench-out)
      --jq EXPR       field to extract from JSONL (default .content)
      --jsonl         force JSONL unwrapping (needed when reading stdin)
      --raw           never unwrap, even for a .jsonl file
  -h, --help          this

Examples:
  scripts/keywordbench.sh -c contents.jsonl.zstd -t Resend -d
  scripts/keywordbench.sh -c contents.jsonl.zstd -t Resend -a resend -d -l 2000
  unzstd -c contents.jsonl.zstd | jq -r .content | scripts/keywordbench.sh -t Resend
USAGE
}

corpus="" target="" alt="" limit="" top="" workers=""
out="keywordbench-out" jq_expr=".content" detect=0 force_jsonl=0 force_raw=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--corpus)   corpus="$2"; shift 2 ;;
    -t|--target)   target="$2"; shift 2 ;;
    -a|--alt)      alt="$2"; shift 2 ;;
    -l|--limit-mb) limit="$2"; shift 2 ;;
    -n|--top)      top="$2"; shift 2 ;;
    -j|--workers)  workers="$2"; shift 2 ;;
    -o|--out)      out="$2"; shift 2 ;;
    --jq)          jq_expr="$2"; shift 2 ;;
    -d|--detect)   detect=1; shift ;;
    --jsonl)       force_jsonl=1; shift ;;
    --raw)         force_raw=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    --)            shift; break ;;
    *)             echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# The tool resolves main.go from the working directory for its feature-flag drift
# check, and go build needs the module root anyway.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Outputs are written under a temporary prefix and promoted only on success, so an
# interrupted or failed run cannot destroy the previous results.
stamp="in-progress.$$"
args=(-csv "$out/$stamp")
[[ -n "$target" ]]  && args+=(-target "$target")
[[ -n "$alt" ]]     && args+=(-alt "$alt")
[[ -n "$limit" ]]   && args+=(-limit-mb "$limit")
[[ -n "$top" ]]     && args+=(-top "$top")
[[ -n "$workers" ]] && args+=(-workers "$workers")
[[ "$detect" -eq 1 ]] && args+=(-detect)
args+=("$@")

if [[ -n "$corpus" && ! -r "$corpus" ]]; then
  echo "corpus not readable: $corpus" >&2
  exit 1
fi

# Decide how to get plain text out of the corpus before anything expensive runs.
reader=(cat)
stripped="$corpus"
if [[ -n "$corpus" ]]; then
  case "$corpus" in
    *.zst|*.zstd) reader=(unzstd -c "$corpus"); stripped="${corpus%.*}" ;;
    *.gz)         reader=(gzip -dc "$corpus");  stripped="${corpus%.*}" ;;
    *)            reader=(cat "$corpus") ;;
  esac
fi

unwrap=0
if [[ "$force_raw" -eq 0 ]]; then
  case "$stripped" in
    *.jsonl|*.ndjson|*.json) unwrap=1 ;;
  esac
  [[ "$force_jsonl" -eq 1 ]] && unwrap=1
fi

for cmd in "${reader[0]}" go; do
  command -v "$cmd" >/dev/null || { echo "required command not found: $cmd" >&2; exit 1; }
done
if [[ "$unwrap" -eq 1 ]] && ! command -v jq >/dev/null; then
  echo "jq is required to unwrap JSONL; install it, or pass --raw" >&2
  exit 1
fi

# Reading stdin from a terminal looks like a hang, so refuse it up front.
if [[ -z "$corpus" && -t 0 ]]; then
  echo "no corpus given and stdin is a terminal, so this would wait forever." >&2
  echo "pass a corpus:   make keywordbench CORPUS=contents.jsonl.zstd TARGET=Resend" >&2
  echo "or pipe one in:  unzstd -c corpus.zstd | jq -r .content | $0 -t Resend" >&2
  exit 2
fi

mkdir -p "$out"

# Write this run's outputs under a temporary prefix and promote them only once the
# benchmark succeeds. Clearing the old files up front instead would mean an
# interrupted or failed run destroys the previous results and leaves nothing in
# their place.

tmpdir="$(mktemp -d)"
bin="$tmpdir/keywordbench"
# An EXIT trap alone does not fire when bash is killed by SIGINT, which leaks the
# built binary on every Ctrl-C.
trap 'rm -rf "$tmpdir"; rm -f "$out/$stamp"-*' EXIT
trap 'rm -rf "$tmpdir"; rm -f "$out/$stamp"-*; echo >&2; echo "interrupted; previous results in $out are untouched" >&2; exit 130' INT TERM

echo "building keywordbench..." >&2
CGO_ENABLED=0 go build -o "$bin" ./cmd/keywordbench

mode="keyword-only"
[[ "$detect" -eq 1 ]] && mode="keyword+regex"
echo "scanning ${corpus:-stdin} ($mode)..." >&2
set +e
if [[ "$unwrap" -eq 1 ]]; then
  "${reader[@]}" | jq -r "$jq_expr" | "$bin" "${args[@]}" | tee -i "$out/$stamp-report.txt"
else
  "${reader[@]}" | "$bin" "${args[@]}" | tee -i "$out/$stamp-report.txt"
fi
stages=("${PIPESTATUS[@]}")
set -e

# --limit-mb and Ctrl-C both make the benchmark stop reading on purpose, killing
# every upstream stage with SIGPIPE (141) or SIGINT (130). Treating those as
# failures would report a broken run for a report that is complete, so judge each
# stage on its own.
last=$(( ${#stages[@]} - 1 ))
bench=$(( last - 1 ))
for (( i = 0; i < bench; i++ )); do
  if [[ ${stages[i]} -ne 0 && ${stages[i]} -ne 141 && ${stages[i]} -ne 130 ]]; then
    echo "reading the corpus failed (exit ${stages[i]})" >&2
    exit 1
  fi
done
if [[ ${stages[bench]} -ne 0 ]]; then
  echo "keywordbench failed (exit ${stages[bench]})" >&2
  exit "${stages[bench]}"
fi
if [[ ${stages[last]} -ne 0 ]]; then
  echo "could not write $out/report.txt (exit ${stages[last]})" >&2
  exit "${stages[last]}"
fi

# Every stage succeeded, so it is now safe to replace the previous run's files.
mv -f "$out/$stamp-report.txt" "$out/report.txt"
for name in detectors keywords; do
  [[ -f "$out/$stamp-$name.csv" ]] && mv -f "$out/$stamp-$name.csv" "$out/keywordbench-$name.csv"
done

echo >&2
echo "report:  $out/report.txt" >&2
echo "csv:     $out/keywordbench-detectors.csv, $out/keywordbench-keywords.csv" >&2
