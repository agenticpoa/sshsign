# sshsign Makefile
#
# Standard targets for the most-used commands. The `help` target is
# the default — run `make` with no args to see what's available.

.DEFAULT_GOAL := help

# Binary names
SERVER_BIN := sshsign-server
CLI_BIN    := sshsign

# Go test invocation. count=1 disables the result cache; race catches
# concurrency bugs in the SSH session / rate limiter paths.
GOTEST := go test ./... -count=1
GOTEST_RACE := $(GOTEST) -race
FUZZ_TIME ?= 60s

.PHONY: help
help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## build server and CLI binaries
	go build -o $(SERVER_BIN) ./cmd/sshsign-server
	go build -o $(CLI_BIN) ./cmd/sshsign

.PHONY: test
test: ## run tests with the race detector (preferred)
	$(GOTEST_RACE)

.PHONY: test-short
test-short: ## run tests without the race detector (faster)
	$(GOTEST)

.PHONY: test-fuzz
test-fuzz: ## run fuzz targets for $(FUZZ_TIME) each
	go test ./internal/server/... -run='^$$' -fuzz=FuzzParseJSONArg -fuzztime=$(FUZZ_TIME)
	go test ./internal/server/... -run='^$$' -fuzz=FuzzFixBareJSONKeys -fuzztime=$(FUZZ_TIME)
	go test ./internal/server/... -run='^$$' -fuzz=FuzzDecodeB64JSON -fuzztime=$(FUZZ_TIME)

.PHONY: bench
bench: ## run microbenchmarks
	go test -bench=. -benchtime=5x -run='^$$' ./internal/crypto/...

.PHONY: vet
vet: ## go vet across all packages
	go vet ./...

.PHONY: lint
lint: ## run golangci-lint (requires golangci-lint installed locally)
	golangci-lint run --timeout=5m

.PHONY: cover
cover: ## generate and open an HTML coverage report
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

.PHONY: clean
clean: ## remove build artifacts (NOT the database)
	rm -f $(SERVER_BIN) $(CLI_BIN) coverage.out

.PHONY: ci
ci: vet test ## what CI runs locally: vet + race tests
