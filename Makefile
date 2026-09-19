# Build and quality gates for n0passtemps.
#
# CGO stays off everywhere: the SQLite driver is modernc.org/sqlite (pure Go),
# so both binaries link statically and need no C toolchain on any target.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

MODULE      ?= github.com/Socold/n0passtemps
BIN_DIR     ?= bin
DIST_DIR    ?= dist
COVER_FILE  ?= coverage.out
IMAGE       ?= ghcr.io/socold/n0passtemps
DOCKERFILE  ?= deploy/Dockerfile

BINARIES ?= n0passtemps-server n0passtemps-wizard

# amd64 and arm64 on the three host operating systems the project supports.
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

MIGRATIONS_DIR ?= internal/store/migrations

# Build tag guarding the tests that require a live PostgreSQL instance.
INTEGRATION_TAG ?= integration
# Consumed by the integration tests; kept identical to the CI service container
# and to deploy/docker-compose.postgres.yml so a failure reproduces locally.
TEST_POSTGRES_URL ?= postgres://n0passtemps:n0passtemps@127.0.0.1:5432/n0passtemps_test?sslmode=disable

# Tool versions are pinned so a lint or scan result is reproducible across
# machines and across time. Override to try a newer release.
GOLANGCI_LINT_VERSION ?= v2.13.2
# Kept in step with .github/workflows/security.yml: the gosec configuration in
# .gosec.json uses globals a release before v2.29.0 would ignore, which would
# make a local run and a CI run disagree.
GOSEC_VERSION         ?= v2.29.0
GOVULNCHECK_VERSION   ?= v1.1.4
GITLEAKS_VERSION      ?= v8.30.0

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
# Read from the commit rather than from date(1): the same source tree must
# produce the same binary whenever and wherever it is built.
BUILD_DATE ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)

VERSION_PKG := $(MODULE)/internal/version

# -s -w drop the symbol table and DWARF sections, which cuts roughly a third of
# the binary size and removes local build paths from the artefact.
LDFLAGS ?= -s -w \
	-X '$(VERSION_PKG).Version=$(VERSION)' \
	-X '$(VERSION_PKG).Commit=$(COMMIT)' \
	-X '$(VERSION_PKG).BuildDate=$(BUILD_DATE)'

# -trimpath removes the absolute module path from the binary, which both shrinks
# it and keeps builds identical between a developer machine and the runner.
GOFLAGS_BUILD ?= -trimpath

export CGO_ENABLED := 0

# Reports a missing tool with the exact command that installs the pinned
# version, instead of failing later on an opaque "command not found". Kept to a
# single logical line: make runs every recipe line in its own shell.
define require_tool
command -v $(1) >/dev/null 2>&1 || { echo "$(1) is not on PATH; install the pinned version with:"; echo "  go install $(2)"; exit 1; }
endef

.PHONY: help build build-all test test-race test-integration cover lint sec \
	secrets fmt fmt-check vet tidy migrate-check docker setup-wizard clean ci

help: ## List the available targets
	@awk 'BEGIN { FS = ":.*?## " } \
		/^[a-zA-Z0-9_-]+:.*?## / { printf "  %-16s %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)

build: ## Compile both binaries for the host platform into bin/
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do \
		echo "build $(BIN_DIR)/$$b"; \
		go build $(GOFLAGS_BUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$b ./cmd/$$b; \
	done

build-all: ## Cross-compile both binaries for every supported platform into dist/
	@mkdir -p $(DIST_DIR)
	@for p in $(PLATFORMS); do \
		os=$${p%%/*}; arch=$${p##*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		for b in $(BINARIES); do \
			out="$(DIST_DIR)/$$b-$(VERSION)-$$os-$$arch$$ext"; \
			echo "build $$out"; \
			GOOS=$$os GOARCH=$$arch go build $(GOFLAGS_BUILD) \
				-ldflags "$(LDFLAGS)" -o "$$out" ./cmd/$$b; \
		done; \
	done

test: ## Run the unit tests
	go test $(GOFLAGS_BUILD) ./...

test-race: ## Run the unit tests under the race detector
	go test $(GOFLAGS_BUILD) -race ./...

test-integration: ## Run the PostgreSQL integration tests (build tag 'integration')
	N0PASSTEMPS_TEST_POSTGRES_DSN='$(TEST_POSTGRES_URL)' \
		go test $(GOFLAGS_BUILD) -tags=$(INTEGRATION_TAG) -count=1 ./...

cover: ## Write coverage.out and print the total statement coverage
	go test $(GOFLAGS_BUILD) -covermode=atomic -coverprofile=$(COVER_FILE) ./...
	@go tool cover -func=$(COVER_FILE) | tail -n 1

lint: ## Run golangci-lint with the repository configuration
	@$(call require_tool,golangci-lint,github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION))
	golangci-lint run ./...

# gosec runs without -no-fail: a clean report is the baseline, so a new finding
# stops the build rather than waiting to be noticed in a report. -conf carries
# the G101 entropy thresholds and the requirement that a suppression names a
# rule and a reason; see CONTRIBUTING.md.
sec: ## Run the static security analyser and the vulnerability database check
	@$(call require_tool,gosec,github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION))
	@$(call require_tool,govulncheck,golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION))
	gosec -conf .gosec.json -exclude-generated ./...
	govulncheck ./...

secrets: ## Scan the working tree and history for committed secrets
	@$(call require_tool,gitleaks,github.com/gitleaks/gitleaks/v8@$(GITLEAKS_VERSION))
	gitleaks detect --config .gitleaks.toml --redact --verbose

fmt: ## Rewrite the sources with gofmt
	@files=$$(git ls-files '*.go'); \
	if [ -n "$$files" ]; then gofmt -s -w $$files; fi

fmt-check: ## Fail when a source file is not gofmt-clean
	@files=$$(git ls-files '*.go'); \
	if [ -z "$$files" ]; then exit 0; fi; \
	out=$$(gofmt -s -l $$files); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

vet: ## Run go vet
	go vet ./...

tidy: ## Reconcile go.mod and go.sum with the imports actually used
	go mod tidy
	go mod verify

migrate-check: ## Assert the SQLite and PostgreSQL migrations declare the same tables and indexes
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	for engine in sqlite postgres; do \
		dir="$(MIGRATIONS_DIR)/$$engine"; \
		{ \
			grep -hoiE 'create table( if not exists)? +[a-z0-9_]+' "$$dir"/*.sql \
				| awk '{ print "table " tolower($$NF) }'; \
			grep -hoiE 'create( unique)? index( if not exists)? +[a-z0-9_]+' "$$dir"/*.sql \
				| awk '{ print "index " tolower($$NF) }'; \
		} | sort -u > "$$tmp/$$engine"; \
	done; \
	if ! diff -u --label sqlite --label postgres "$$tmp/sqlite" "$$tmp/postgres"; then \
		echo "migration sets diverge: a schema object exists for one engine only"; \
		exit 1; \
	fi; \
	echo "migration parity: $$(wc -l < "$$tmp/sqlite") objects declared for both engines"

docker: ## Build the server image from deploy/Dockerfile
	docker build \
		--file $(DOCKERFILE) \
		--build-arg VERSION='$(VERSION)' \
		--build-arg REVISION='$(COMMIT)' \
		--build-arg BUILD_DATE='$(BUILD_DATE)' \
		--tag $(IMAGE):$(VERSION) \
		.

setup-wizard: ## Run the interactive setup tool (writes config.toml, docker-compose.yml, .env)
	go run ./cmd/n0passtemps-wizard

clean: ## Remove build output and coverage data
	rm -rf $(BIN_DIR) $(DIST_DIR) $(COVER_FILE) coverage.html

ci: fmt-check vet lint migrate-check test-race cover sec secrets build ## Run the full gate, in the order CI runs it
	@echo "ci gate passed for $(VERSION)"
