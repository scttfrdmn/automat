// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package verify checks a vended account or OU against what it should be, and
// says so per DESIGN §12 layer.
//
// # Two layers, not four
//
// DESIGN §12 names four verification layers: policy, detective, procedural, and
// freshness. Only the first and last are checkable against what automat's own
// `vend` actually produces today. The detective layer (Config recorder,
// conformance pack) and the procedural layer (attestation stubs) both check
// something DESIGN §7 step 5 — internal/baseline — was meant to install, and
// that package does not exist yet: `vend` performs steps 1-4 and 6, and its own
// plan output already discloses step 5 as not done. A verify that claimed to
// check a recorder that was never created would not be conservative, it would
// be wrong, so this package has no function for either layer and
// `cmd/automat/verify.go` says so in its own output rather than staying silent
// about the gap.
//
// # The policy layer compares content, not a tag
//
// DESIGN §12 describes matching an attached policy to the artifact that
// produced it "by name and content-hash tag". No content-hash tag exists on any
// SCP automat writes today — internal/org.EnsurePolicy names a policy and owns
// it by a fixed owner tag, never a hash of its content. So CheckPolicy compares
// the attached document's parsed structure against a fresh
// internal/compilesets.Pack of the same inputs, using the exact comparator
// internal/org already relies on for its own drift detection during a vend's
// idempotent re-runs (org.SameDocument) — a stronger check than a tag lookup
// would have been, since it catches drift a stale tag could miss.
//
// # Read-only by construction
//
// CheckPolicy takes an awsapi.OrgVerifyAPI, which carries no write method at
// all (internal/awsapi/api.go). A bug in this package's comparison logic
// cannot mutate an organization no matter what it does.
//
// # What this package does not do
//
// It does not load an environment profile, a control artifact, or a catalog.
// Those are cmd/automat/verify.go's job, the same way loading them is
// cmd/automat/vend.go's job and not internal/org's — this package receives
// already-resolved values (a compilesets.Packed, a review-by date) and reports
// on them, so it has no opinion about where they came from.
package verify
