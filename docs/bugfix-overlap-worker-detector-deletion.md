# Bug Fix: Overlap Worker Silently Drops Non-Duplicate Secrets

## Summary

The verification overlap worker in `pkg/engine/engine.go` silently drops unique secrets when a chunk contains multiple secrets from the same detector, and one of those secrets overlaps with a different detector's result.

## Root Cause

When a chunk matches multiple detectors (e.g., `GoogleGeminiAPIKey` and `YoutubeApiKey`), the overlap worker runs each detector to check for cross-detector duplicates via `likelyDuplicate()`. If one of a detector's results is flagged as a duplicate, the code deletes the **entire detector** from further processing:

```go
delete(detectorKeysWithResults, detector.Key)
```

This means any **other, non-duplicate results** from that same detector on different match spans are silently lost — they never reach `detectChunk` for full processing.

Because detectors are iterated from a Go map (non-deterministic order), which detector gets deleted changes between runs. This causes unique secrets to randomly appear or disappear across scans of the same data.

## How to Reproduce

Create a test file containing multiple secrets that match both `GoogleGeminiAPIKey` (regex: `AIzaSy[A-Za-z0-9_-]{33}`) and `YoutubeApiKey` (requires a `youtube` keyword prefix). The key ingredient is:

1. A secret that matches **both** detectors (the overlap trigger)
2. A separate secret that matches **only one** of those detectors (the victim)

Example file (`/tmp/overlap-test.txt`):

```
# Config file for testing

youtube_api_key = AIzaSyFAKE1aaBBccDDeeFFggHHiiJJkkLLmmNNO

other_api_key = AIzaSyFAKE2xxYYzzAAbbCCddEEffGGhhIIjjKKL
```

Line 3 contains a key prefixed with `youtube`, so it matches both `YoutubeApiKey` and `GoogleGeminiAPIKey`. Line 5 contains a key that only matches `GoogleGeminiAPIKey` (no `youtube` prefix).

Run the scan multiple times and observe the flapping:

```bash
for i in $(seq 1 10); do
  RESULTS=$(trufflehog filesystem /tmp/overlap-test.txt --no-verification --json 2>/dev/null)
  COUNT=$(echo "$RESULTS" | wc -l)
  UNIQUE=$(echo "$RESULTS" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    r = json.loads(line.strip())
    seen.add((r.get('DetectorType'), r.get('Raw')))
print(len(seen))
")
  echo "Run $i: $COUNT results, $UNIQUE unique secrets"
done
```

**Before fix:** The unique count flaps — sometimes the second key (`AIzaSyFAKE2...`) is missing because `GoogleGeminiAPIKey` lost the overlap coin flip on the first key and the entire detector was deleted.

**After fix:** The result count and unique count are stable across all runs.

## The Fix

Instead of deleting the entire detector when one of its results is a cross-detector duplicate, we now track the specific duplicate result and pass it through to `detectChunk` via an `overlapSecrets` set on the `detectableChunk` struct.

The overlap worker still emits the duplicate result with `errOverlap` (preserving existing behavior). The detector remains in `detectorKeysWithResults` and flows to `detectChunk` for full processing. In `detectChunk`, results whose raw value matches an entry in `overlapSecrets` are skipped, preventing double-reporting. All other results from that detector are processed normally.

This gives us proper deduplication with no silent data loss:
- Duplicate results: emitted exactly once (from the overlap worker, with `errOverlap`)
- Non-duplicate results: emitted exactly once (from `detectChunk`)
- No results lost

## Impact

Any file containing:
- Multiple secrets matching the same detector (e.g., multiple Google API keys)
- At least one of those secrets also matching a different detector (e.g., a key near the word "youtube")

...is affected. The non-overlapping secrets randomly disappear depending on Go map iteration order, making scan results non-deterministic.

## Files Changed

- `pkg/engine/engine.go`:
  - Added `overlapSecrets` field to `detectableChunk` struct
  - Replaced `delete(detectorKeysWithResults, detector.Key)` in `verificationOverlapWorker` with per-result tracking via `overlapEmitted` map
  - Added overlap secret filtering in `detectChunk` result loop
