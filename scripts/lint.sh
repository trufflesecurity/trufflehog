#!/usr/bin/env bash
set -euo pipefail

GOLANGCI_LINT_VERSION="v2.11.4"

# TODO: Re-enable errcheck and staticcheck once pre-existing issues are resolved.
LINT_ARGS="--disable errcheck,staticcheck --enable bodyclose,copyloopvar,misspell --timeout 10m"

GOBIN="$(go env GOPATH)/bin"
GOLANGCI_LINT="${GOBIN}/golangci-lint"

# Install the required version if missing or mismatched.
if [[ -x "${GOLANGCI_LINT}" ]] && "${GOLANGCI_LINT}" version 2>&1 | grep -q "${GOLANGCI_LINT_VERSION#v}"; then
    echo "golangci-lint ${GOLANGCI_LINT_VERSION} found"
else
    echo "Installing golangci-lint ${GOLANGCI_LINT_VERSION}..."
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@"${GOLANGCI_LINT_VERSION}"
fi

# shellcheck disable=SC2086
"${GOLANGCI_LINT}" run ${LINT_ARGS}
