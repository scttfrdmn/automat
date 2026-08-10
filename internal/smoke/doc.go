// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

// Package smoke automates docs/smoke.md's checklist: the eight questions
// docs/open-questions.md files under "Awaiting a live org" (Q9, Q7, Q8,
// Q12, Q5, Q6, Q13, Q24), which no fake and no emulator can answer because
// they are questions about undocumented real-AWS behavior, not about
// automat's own reaction to a state transition it already knows the shape
// of (docs/testing-strategy.md's own distinction between fakes and the
// emulator).
//
// # This is CLAUDE.md rule 1's one documented exception
//
// Every file in this package carries `//go:build smoke`, so none of it
// compiles into `go build ./...`, `go test ./...`, or any ordinary CI run —
// only `go test -tags=smoke` reaches it, and only `make smoke` sets that
// flag. This package calls REAL AWS. It is read-only except against an
// organization it has independently verified, at run time, is the sandbox
// named by AUTOMAT_SMOKE_ORG (docs/smoke.md rule 2: "checked at run time
// against the org the credentials actually resolve to — not against a flag
// saying it is the sandbox"). Nothing here has any business running in a
// laptop's or a CI runner's ambient credentials, which is why
// AUTOMAT_SMOKE_PROFILE has no default and no fallback (rule 1).
//
// # Why a separate package rather than smoke-tagged files inside internal/org
//
// This package imports real aws-sdk-go-v2 service clients directly
// (organizations.NewFromConfig, iam.NewFromConfig) and constructs
// internal/org.Ensurer and internal/org.Reclaimer around them exactly the
// way cmd/automat does — but from outside internal/org, so that no
// live-AWS-shaped code sits beside the fake-tested production code it
// exercises. This mirrors test/integration's separation without needing a
// second Go module: unlike the emulator, calling real AWS introduces no new
// dependency-floor problem (every client here is already a direct
// dependency of the main module, imported today by cmd/automat/globals.go),
// so a build tag is sufficient isolation and a second go.mod would be
// solving a problem this case does not have.
//
// # What this package does not do
//
// It does not edit docs/open-questions.md. Per docs/smoke.md rule 4, the
// output of a run is a human decision, not a test result — this package
// writes structured Findings (see findings.go) that a person reads and
// then, by hand, narrows or deletes the corresponding entry. Of the eight
// questions, only Q8's resource-tag check and half of Q13 (the
// re-vend-is-a-no-op check) are genuinely boolean; the rest are latency
// distributions, exact exception shapes, or "which of several
// already-handled outcomes occurred" — none of which t.Fatal/t.Error can
// express, which is why Finding exists at all.
package smoke
