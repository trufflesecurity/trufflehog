#!/usr/bin/env bash
set -euo pipefail

# NOTE: Version and args must match .github/workflows/lint.yml
GOLANGCI_LINT_VERSION="v2.11.4"

LINT_ARGS="--enable bodyclose,copyloopvar,misspell --timeout 10m"

GOBIN="$(go env GOPATH)/bin"
GOLANGCI_LINT="${GOBIN}/golangci-lint"

# Extract and compare the exact version to avoid substring matches (e.g. 2.11.4 matching 2.11.40).
check_version() {
    local bin="$1"
    local installed
    installed=$("${bin}" version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [[ "${installed}" == "${GOLANGCI_LINT_VERSION#v}" ]]
}

# Check PATH first, then fall back to GOPATH/bin, otherwise install.
if command -v golangci-lint &>/dev/null && check_version "$(command -v golangci-lint)"; then
    GOLANGCI_LINT="$(command -v golangci-lint)"
    echo "golangci-lint ${GOLANGCI_LINT_VERSION} found at ${GOLANGCI_LINT}"
elif [[ -x "${GOLANGCI_LINT}" ]] && check_version "${GOLANGCI_LINT}"; then
    echo "golangci-lint ${GOLANGCI_LINT_VERSION} found at ${GOLANGCI_LINT}"
else
    echo "Installing golangci-lint ${GOLANGCI_LINT_VERSION}..."
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "${GOBIN}" "${GOLANGCI_LINT_VERSION}"
fi

# shellcheck disable=SC2086
"${GOLANGCI_LINT}" run ${LINT_ARGS}
