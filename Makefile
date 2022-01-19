PROTOS_IMAGE=us-docker.pkg.dev/thog-artifacts/public/go-ci-1.17-1

.PHONY: check
.PHONY: test
.PHONY: test-race
.PHONY: run
.PHONY: install
.PHONY: protos
.PHONY: protos-windows
.PHONY: vendor

install:
	CGO_ENABLED=0 go install .

check:
	go fmt $(shell go list ./... | grep -v /vendor/)
	go vet $(shell go list ./... | grep -v /vendor/)

test-failing:
	CGO_ENABLED=0 go test -timeout=30s $(shell go list ./... | grep -v /vendor/) | grep FAIL

test:
	CGO_ENABLED=0 go test -timeout=30s $(shell go list ./... | grep -v /vendor/)

test-race:
	CGO_ENABLED=1 go test -timeout=30s -race $(shell go list ./... | grep -v /vendor/)

bench:
	CGO_ENABLED=0 go test $(shell go list ./pkg/secrets/... | grep -v /vendor/) -benchmem -run=xxx -bench .

run:
	CGO_ENABLED=0 go run . git file://. --json

run-debug:
	CGO_ENABLED=0 go run . git file://. --json --debug

protos:
	docker run -u "$(shell id -u)" -v "$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"
