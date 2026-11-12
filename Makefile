.DEFAULT_GOAL := help

.PHONY: help
.PHONY: run
.PHONY: run-debug
.PHONY: dogfood
.PHONY: install
.PHONY: check
.PHONY: lint
.PHONY: test-failing
.PHONY: test
.PHONY: test-integration
.PHONY: test-race
.PHONY: test-detectors
.PHONY: test-community
.PHONY: bench
.PHONY: protos
.PHONY: protos-windows
.PHONY: release-protos-image
.PHONY: man
.PHONY: test-release

PROTOS_IMAGE ?= trufflesecurity/protos:1.22

help: ## Display this help message
	@echo "Usage: make [target]"
	@echo
	@echo "Targets:"
	@awk '/^[a-zA-Z0-9_-]+:.*## / {printf "%s : %s\n", $$1, substr($$0, index($$0, "##") + 3)}' $(MAKEFILE_LIST) | sort | column -t -s ':'
	@echo

run: ## Run a git scan on this repository
	CGO_ENABLED=0 go run . git file://. --json

run-debug: ## Run a git scan on this repository with enhanced logging (level 2)
	CGO_ENABLED=0 go run . git file://. --json --log-level=2

dogfood: run-debug

install: ## Run go install
	CGO_ENABLED=0 go install .

check: ## Run go fmt and go vet
	go fmt $(shell go list ./... | grep -v /vendor/)
	go vet $(shell go list ./... | grep -v /vendor/)

lint: ## Run the linter
	./scripts/lint.sh

test-failing: ## Run tests, displaying only the failures
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/) | grep FAIL

test: ## Run tests
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/)

test-integration: ## Run integration tests
	CGO_ENABLED=0 go test -timeout=5m -tags=integration $(shell go list ./... | grep -v /vendor/)

test-race: ## Run the go race condition checker
	CGO_ENABLED=1 go test -timeout=5m -race $(shell go list ./... | grep -v /vendor/)

test-detectors: ## Run detector tests
	CGO_ENABLED=0 go test -tags=detectors -timeout=5m $(shell go list ./... | grep pkg/detectors)

test-community: ## Run a subset of tests intended for use by the OSS community
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/ | grep -v pkg/sources | grep -v pkg/analyzer/analyzers)

bench: ## Run benchmarks
	CGO_ENABLED=0 go test $(shell go list ./pkg/secrets/... | grep -v /vendor/) -benchmem -run=xxx -bench .

protos: ## Regenerate protocol buffer code
	docker run --rm -u "$(shell id -u)" -v "$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"

protos-windows: ## Regenerate protocol buffer code on Windows
	docker run --rm -v "$(shell cygpath -w $(shell pwd))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; ./scripts/gen_proto.sh"

release-protos-image: ## Build a Docker image suitable for generating the protocol buffer code
	docker buildx build --push --platform=linux/amd64,linux/arm64 \
	-t ${PROTOS_IMAGE} -f hack/Dockerfile.protos .

man: ## Build man pages
	@mkdir -p docs/man
	CGO_ENABLED=0 go run . --generate-man-page > docs/man/trufflehog.1

test-release: ## Test a goreleaser release
	goreleaser release --clean --skip=publish,sign --snapshot
