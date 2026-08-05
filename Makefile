# Copyright 2026 Scott Friedman
# SPDX-License-Identifier: Apache-2.0

BINARY  := automat
PKG     := github.com/scttfrdmn/automat
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Single static binary, no cgo (CLAUDE.md project facts).
export CGO_ENABLED := 0

GOFLAGS_BUILD := -trimpath -ldflags "-s -w -X $(PKG)/internal/version.Version=$(VERSION)"

.PHONY: all build test lint fmt vet tidy clean catalogs golden smoke help

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

catalogs: ## Recompile vendored catalogs from cached upstream sources
	go run ./gen/catalog -out catalogs

golden: ## Regenerate golden files (review the diff before committing)
	go test ./... -update

clean:
	rm -rf bin dist

# Live AWS testing. Never run from CI. Requires an explicit profile and is
# read-only unless pointed at an explicitly named sandbox org (CLAUDE.md rule 1).
smoke: ## Manual live smoke test (requires AUTOMAT_SMOKE_PROFILE)
ifndef AUTOMAT_SMOKE_PROFILE
	$(error AUTOMAT_SMOKE_PROFILE must be set explicitly; see docs/smoke.md)
endif
	go test -tags=smoke -count=1 ./internal/... -run 'Smoke'

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-10s %s\n", $$1, $$2}'
