#!/usr/bin/env bash
set -euo pipefail

GOLANGCI_LINT_VERSION="v2.11.4"
LINT_ARGS="--disable errcheck,staticcheck --enable bodyclose,copyloopvar,misspell --timeout 10m"

# Check if golangci-lint is installed and matches the required version.
if command -v golangci-lint &>/dev/null; then
    INSTALLED=$(golangci-lint version 2>&1 || true)
    if echo "$INSTALLED" | grep -q "${GOLANGCI_LINT_VERSION#v}"; then
        echo "golangci-lint ${GOLANGCI_LINT_VERSION} found"
    else
        echo "golangci-lint version mismatch (want ${GOLANGCI_LINT_VERSION}, got: ${INSTALLED})"
        echo "Installing golangci-lint ${GOLANGCI_LINT_VERSION}..."
        go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@"${GOLANGCI_LINT_VERSION}"
    fi
else
    echo "golangci-lint not found, installing ${GOLANGCI_LINT_VERSION}..."
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@"${GOLANGCI_LINT_VERSION}"
fi

# shellcheck disable=SC2086
golangci-lint run ${LINT_ARGS}
