#!/usr/bin/env bash
set -eu

function cleanup {
  rm -rf pkg/detectors/test
}
trap cleanup EXIT

export CGO_ENABLED=0

export FORCE_PASS_DIFF=true

echo "████████████ Testing generate Detector"
go run hack/generate/generate.go detector Test
go test ./pkg/detectors/test -benchmem -bench .
echo ""
