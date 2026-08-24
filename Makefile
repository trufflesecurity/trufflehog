PROTOS_IMAGE ?= trufflesecurity/protos:1.22

.PHONY: check
.PHONY: lint
.PHONY: test
.PHONY: test-race
.PHONY: run
.PHONY: install
.PHONY: protos
.PHONY: protos-windows
.PHONY: vendor
.PHONY: dogfood
.PHONY: man
.PHONY: keywordbench
.PHONY: keywordbench-lint

dogfood:
	CGO_ENABLED=0 go run . git file://. --json --log-level=2

install:
	CGO_ENABLED=0 go install .

check:
	go fmt $(shell go list ./... | grep -v /vendor/)
	go vet $(shell go list ./... | grep -v /vendor/)

lint:
	./scripts/lint.sh

test-failing:
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/) | grep FAIL

test:
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/)

test-integration:
	CGO_ENABLED=0 go test -timeout=5m -tags=integration $(shell go list ./... | grep -v /vendor/)

test-race:
	CGO_ENABLED=1 go test -timeout=5m -race $(shell go list ./... | grep -v /vendor/)

test-detectors:
	CGO_ENABLED=0 go test -tags=detectors -timeout=5m $(shell go list ./... | grep pkg/detectors)

test-community:
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/ | grep -v pkg/sources | grep -v pkg/analyzer/analyzers)

bench:
	CGO_ENABLED=0 go test $(shell go list ./pkg/secrets/... | grep -v /vendor/) -benchmem -run=xxx -bench .

run:
	CGO_ENABLED=0 go run . git file://. --json

run-debug:
	CGO_ENABLED=0 go run . git file://. --json --log-level=2

protos:
	docker run --rm -u "$(shell id -u)" -v "$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"

protos-windows:
	docker run --rm -v "$(shell cygpath -w $(shell pwd))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; ./scripts/gen_proto.sh"

release-protos-image:
	docker buildx build --push --platform=linux/amd64,linux/arm64 \
	-t ${PROTOS_IMAGE} -f hack/Dockerfile.protos .

man:
	@mkdir -p docs/man
	CGO_ENABLED=0 go run . --generate-man-page > docs/man/trufflehog.1

# Measures what a detector's Keywords() prefilter costs, ranked against every
# other shipped detector. See cmd/keywordbench.
#   make keywordbench CORPUS=contents.jsonl.zstd TARGET=Resend
#   make keywordbench CORPUS=contents.jsonl.zstd TARGET=Resend ALT=resend LIMIT_MB=2000
CORPUS ?=
TARGET ?=
ALT ?=
LIMIT_MB ?=
TOP ?=
WORKERS ?=
OUT ?= keywordbench-out
DETECT ?= 1

KWBENCH_FLAGS = $(if $(CORPUS),--corpus $(CORPUS)) $(if $(TARGET),--target $(TARGET)) \
	$(if $(ALT),--alt $(ALT)) $(if $(LIMIT_MB),--limit-mb $(LIMIT_MB)) \
	$(if $(TOP),--top $(TOP)) $(if $(WORKERS),--workers $(WORKERS)) \
	$(if $(filter-out 0,$(DETECT)),--detect)

keywordbench:
	./scripts/keywordbench.sh $(KWBENCH_FLAGS) --out $(OUT) $(ARGS)

# Static keyword checks only: no corpus, runs in a second. Good for a PR check.
keywordbench-lint:
	@test -n "$(TARGET)" || { echo "usage: make keywordbench-lint TARGET=Resend"; exit 2; }
	CGO_ENABLED=0 go run ./cmd/keywordbench -static -target $(TARGET)

test-release:
	goreleaser release --clean --skip=publish,sign --snapshot
