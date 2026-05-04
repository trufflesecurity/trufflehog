#!/usr/bin/env bash
#
# detect_changed_detectors.sh — Phase 2
#
# Emits the list of detectors changed between two git refs, formatted for
# trufflehog's --include-detectors flag (comma-separated, lowercase protobuf
# enum names, optional ".v<n>" version suffix).
#
# Source of truth for each detector's identifier:
#   - Proto enum name comes from the detector's Type() implementation in its
#     source files (e.g. `return detectorspb.DetectorType_AzureBatch` →
#     `azurebatch`). Necessary because the package directory often differs
#     from the enum name (azure_batch vs AzureBatch, npmtokenv2 vs NpmToken,
#     close vs closecrm, etc.).
#   - Version comes from the directory suffix only (`/v<n>`). Detectors that
#     encode the version in the dir name (e.g. `npmtokenv2`) are emitted
#     without a version suffix; trufflehog then matches all versions of that
#     proto type — wider scope but correct.
#
# "New detector" detection compares pkg/engine/defaults/defaults.go imports
# between the two refs. A detector imported at HEAD but not at BASE is new.
#
# Modes:
#   (none)       List all changed detectors at HEAD, one per line, in
#                <name>[.v<n>] form.
#   --pr-csv     Same set as default mode, comma-joined.
#   --main-csv   Changed detectors that also exist at BASE (excludes new),
#                comma-joined. Use as --include-detectors for the main build.
#   --new-only   Just the new detectors (in HEAD but not BASE), one per line.
#
# Env:
#   BASE_REF   default origin/main
#   HEAD_REF   default HEAD

set -euo pipefail

MODE="${1:-list}"
BASE_REF="${BASE_REF:-origin/main}"
HEAD_REF="${HEAD_REF:-HEAD}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Resolve BASE to a concrete commit. Workflow already runs `git fetch origin
# main`; locally that may not be true, so we fall back to `main` if the
# remote-tracking ref is missing.
if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
    if git rev-parse --verify main >/dev/null 2>&1; then
        BASE_REF=main
    else
        echo "error: cannot resolve BASE_REF=$BASE_REF and no local 'main'" >&2
        exit 1
    fi
fi

MERGE_BASE=$(git merge-base "$BASE_REF" "$HEAD_REF")

# Step 1 — changed detector dirs (relative to repo root).
# Pattern: pkg/detectors/<name>(/v<n>)?/<file>.go, excludes _test.go and
# files inside common/, custom_detectors/.
mapfile -t CHANGED_DIRS < <(
    git diff --name-only "$MERGE_BASE...$HEAD_REF" -- 'pkg/detectors/**/*.go' \
        | grep -Ev '_test\.go$' \
        | grep -Ev '^pkg/detectors/(common|custom_detectors)/' \
        | sed -E 's|^(pkg/detectors/[^/]+(/v[0-9]+)?)/[^/]+\.go$|\1|' \
        | sort -u
)

# Step 2 — defaults.go imports at each ref. Each line has form
#   "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/<name>(/v<n>)?"
# We extract just the <name>(/v<n>)? portion to use as the dir identifier.
parse_defaults_imports() {
    local ref="$1"
    git show "$ref:pkg/engine/defaults/defaults.go" 2>/dev/null \
        | grep -oE '"github\.com/trufflesecurity/trufflehog/v3/pkg/detectors/[^"]+"' \
        | sed -E 's|.*/pkg/detectors/||; s|"$||' \
        | sort -u
}

mapfile -t HEAD_IMPORTS < <(parse_defaults_imports "$HEAD_REF")
mapfile -t BASE_IMPORTS < <(parse_defaults_imports "$MERGE_BASE")

# Set difference: detectors imported at HEAD but not at BASE. The dir
# identifier (e.g. "github/v2", "stripe") matches the form we extracted in
# step 1, so we can intersect directly without re-mapping.
NEW_DIRS_FILE=$(mktemp)
trap 'rm -f "$NEW_DIRS_FILE"' EXIT
comm -23 \
    <(printf '%s\n' "${HEAD_IMPORTS[@]+"${HEAD_IMPORTS[@]}"}") \
    <(printf '%s\n' "${BASE_IMPORTS[@]+"${BASE_IMPORTS[@]}"}") \
    > "$NEW_DIRS_FILE"

is_new_detector() {
    grep -qxF "$1" "$NEW_DIRS_FILE"
}

# Step 2b — skip detectors whose diff doesn't touch regex patterns or Keywords.
# Corpora results only change when the matching logic changes; verification,
# redaction, or structural changes don't affect match counts.
has_pattern_change() {
    local dir="$1"

    # Fast path: regex or Keywords() signature on a changed line.
    git diff "$MERGE_BASE...$HEAD_REF" -- "$dir"/*.go 2>/dev/null \
        | grep -qE '^[+-][^+-].*(regexp\.|MustCompile|Keywords)' && return 0

    # Slow path: compare the Keywords() function body between refs to catch
    # changes to the return value (e.g. []string{"old"} → []string{"new"})
    # where the changed lines don't mention "Keywords" themselves.
    local file
    while IFS= read -r file; do
        [[ "$file" == *_test.go ]] && continue
        local head_body base_body
        head_body=$(git show "$HEAD_REF:$file" 2>/dev/null \
            | awk '/func[[:space:]].*Keywords\(\)[[:space:]]*\[\]string/,/^[[:space:]]*\}/' \
            | tail -n +2)
        base_body=$(git show "$MERGE_BASE:$file" 2>/dev/null \
            | awk '/func[[:space:]].*Keywords\(\)[[:space:]]*\[\]string/,/^[[:space:]]*\}/' \
            | tail -n +2)
        [[ "$head_body" != "$base_body" ]] && return 0
    done < <(git diff --name-only "$MERGE_BASE...$HEAD_REF" -- "$dir"/*.go 2>/dev/null)

    return 1
}

# Step 3 — for a dir, derive `<protoname>[.v<n>]`.
detector_id_for_dir() {
    local dir="$1"
    local version=""
    if [[ "$dir" =~ ^pkg/detectors/[^/]+/v([0-9]+)$ ]]; then
        version=".v${BASH_REMATCH[1]}"
    fi

    # Extract proto enum name. Multiple matches are possible (a detector may
    # also reference related types in helpers); the Type() return is by far
    # the most common, so the modal value wins.
    local proto
    proto=$(
        grep -E 'return[[:space:]]+\S*DetectorType_[A-Za-z0-9]+' "$dir"/*.go 2>/dev/null \
            | grep -v '_test\.go' \
            | grep -oE 'DetectorType_[A-Za-z0-9]+' \
            | sort | uniq -c | sort -rn \
            | head -1 \
            | awk '{print $2}' \
            | sed 's/^DetectorType_//' \
            | tr '[:upper:]' '[:lower:]'
    )
    if [[ -z "$proto" ]]; then
        return 1
    fi
    echo "${proto}${version}"
}

# Step 4 — emit per mode.
emit_list() {
    local dir id
    for dir in "${CHANGED_DIRS[@]:-}"; do
        [[ -z "$dir" ]] && continue
        has_pattern_change "$dir" || continue
        if id=$(detector_id_for_dir "$dir"); then
            echo "$id"
        else
            echo "warning: could not resolve detector id for $dir" >&2
        fi
    done | sort -u
}

emit_main_list() {
    local dir id
    for dir in "${CHANGED_DIRS[@]:-}"; do
        [[ -z "$dir" ]] && continue
        has_pattern_change "$dir" || continue
        # Strip `pkg/detectors/` prefix to get the import-path form, then
        # check against the new-detector set.
        local import_form="${dir#pkg/detectors/}"
        if is_new_detector "$import_form"; then
            continue
        fi
        if id=$(detector_id_for_dir "$dir"); then
            echo "$id"
        fi
    done | sort -u
}

emit_new_list() {
    local dir id
    for dir in "${CHANGED_DIRS[@]:-}"; do
        [[ -z "$dir" ]] && continue
        has_pattern_change "$dir" || continue
        local import_form="${dir#pkg/detectors/}"
        if ! is_new_detector "$import_form"; then
            continue
        fi
        if id=$(detector_id_for_dir "$dir"); then
            echo "$id"
        fi
    done | sort -u
}

case "$MODE" in
    list)       emit_list ;;
    --pr-csv)   emit_list | paste -sd, - ;;
    --main-csv) emit_main_list | paste -sd, - ;;
    --new-only) emit_new_list ;;
    *)          echo "Usage: $0 [--pr-csv|--main-csv|--new-only]" >&2; exit 2 ;;
esac
