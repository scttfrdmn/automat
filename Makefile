# Copyright 2026 Scott Friedman
# SPDX-License-Identifier: Apache-2.0

BINARY  := automat
PKG     := github.com/scttfrdmn/automat
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Single static binary, no cgo (CLAUDE.md project facts).
export CGO_ENABLED := 0

GOFLAGS_BUILD := -trimpath -ldflags "-s -w -X $(PKG)/internal/version.Version=$(VERSION)"

.PHONY: all build test lint fmt vet tidy clean catalogs catalogs-check golden smoke integration help

all: build test lint

build: ## Build the static binary into bin/
	go build $(GOFLAGS_BUILD) -o bin/$(BINARY) ./cmd/automat

test: ## Run all tests
	go test ./...

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format all Go source
	gofmt -l -w .

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy and verify module deps
	go mod tidy
	go mod verify

catalogs: ## Recompile vendored catalogs from the curated sources in gen/sources
	go run ./gen/catalog -out catalogs

catalogs-check: ## Verify the vendored catalogs match a fresh compile
	go run ./gen/catalog -check

golden: ## Regenerate golden files (review the diff before committing)
	AUTOMAT_UPDATE_GOLDEN=1 go test ./... -count=1

clean:
	rm -rf bin dist

# Live AWS testing. Never run from CI. Requires an explicit profile and is
# read-only unless pointed at an explicitly named sandbox org (CLAUDE.md rule 1).
#
# No file in this tree carries a `smoke` build tag yet (AUDIT-2 carry-forward
# item 3), so this currently runs zero tests and exits 0. That is not a pass --
# it means the manual checklist in docs/smoke.md has not been automated at all.
# TestMakefileSmokeClaimIsStillTrue fails the day a smoke-tagged test is added
# and this comment is not updated to match.
smoke: ## Manual live smoke test (requires AUTOMAT_SMOKE_PROFILE); see docs/smoke.md -- no automated test carries the smoke tag yet
ifndef AUTOMAT_SMOKE_PROFILE
	$(error AUTOMAT_SMOKE_PROFILE must be set explicitly; see docs/smoke.md)
endif
	@echo "No test in this tree carries the smoke build tag yet -- this will run zero tests."
	@echo "The manual checklist is docs/smoke.md; it has not been automated."
	go test -tags=smoke -count=1 ./internal/... -run 'Smoke'


# Emulator-backed tests, in a separate Go module (docs/testing-strategy.md,
# CLAUDE.md). The module's go directive is ahead of this one's; a dependency's
# floor propagates to `go install` for everyone in the same module regardless of
# which files import it, so the emulator stays out of automat's own go.mod.
# Never part of the default `make test` gate.
integration: ## Run the emulator-backed integration tests (separate module, own go.mod)
	cd test/integration && go test ./...

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-10s %s\n", $$1, $$2}'
