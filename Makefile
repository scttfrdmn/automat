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

# Live AWS testing. Never run from CI. Requires two explicit variables and is
# read-only except against the sandbox organization AUTOMAT_SMOKE_ORG names,
# checked at runtime against what the credentials actually resolve to
# (CLAUDE.md rule 1; docs/smoke.md rule 2).
#
# internal/smoke automates docs/smoke.md's checklist (TestSmokeChecklist).
# TestMakefileSmokeClaimIsStillTrue fails the day this comment stops matching
# what carries the tag -- keep the two in step.
smoke: ## Live smoke test against a sandbox org (requires AUTOMAT_SMOKE_PROFILE, AUTOMAT_SMOKE_ORG); see docs/smoke.md
ifndef AUTOMAT_SMOKE_PROFILE
	$(error AUTOMAT_SMOKE_PROFILE must be set explicitly; see docs/smoke.md)
endif
ifndef AUTOMAT_SMOKE_ORG
	$(error AUTOMAT_SMOKE_ORG must be set explicitly; see docs/smoke.md)
endif
	go test -tags=smoke -count=1 ./internal/... -run 'Smoke' -v


# Emulator-backed tests, in a separate Go module (docs/testing-strategy.md,
# CLAUDE.md). The module's go directive is ahead of this one's; a dependency's
# floor propagates to `go install` for everyone in the same module regardless of
# which files import it, so the emulator stays out of automat's own go.mod.
# Never part of the default `make test` gate.
integration: ## Run the emulator-backed integration tests (separate module, own go.mod)
	cd test/integration && go test ./...

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-10s %s\n", $$1, $$2}'
