// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package verify checks a vended account or OU against what it should be, and
// says so per DESIGN §12 layer.
//
// # Four layers, now that internal/baseline exists
//
// DESIGN §12 names four verification layers: policy, detective, procedural, and
// freshness. All four are checkable now that internal/baseline (DESIGN §7 step
// 5) actually installs what the detective and procedural layers check against —
// ROADMAP.md's "internal/baseline, slices 2-9" item 9. CheckPolicy compares
// attached SCPs against a fresh compile (policy.go). CheckDetective
// (detective.go) compares the AWS Config recorder, delivery channel, and
// conformance pack against what an environment profile describes, reusing
// internal/baseline's own exported comparators (SameRecorderConfig,
// SameInputParameters) so "matches" means exactly what it means to the Ensure*
// method that would correct a drift. CheckProcedural (procedural.go) reads the
// local attestation-stub directory EnsureAttestationStubs writes into and
// reports each stub's presence, emptiness, and staleness against its own
// declared frequency, using no AWS call at all. CheckFreshness (freshness.go)
// compares an environment profile's review_by date against now.
//
// Both CheckDetective and CheckProcedural follow the same "opt-in, and not
// opted into" discipline `cmd/automat/verify.go`'s checkMirrorDrift established
// for the evidence-mirror layer: a profile that never enabled the Config
// recorder, whose compile binds no Config rule, or that names no procedural
// control at all produces no finding for the corresponding piece — not a
// failure, because nothing was asked for. "Nothing to check" and "checked,
// found nothing" are different claims, and both types' own Clean() methods
// hold that distinction rather than a caller having to re-derive it.
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
// CheckPolicy takes an awsapi.OrgVerifyAPI, and CheckDetective takes an
// awsapi.ConfigVerifyAPI — both carry no write method at all
// (internal/awsapi/api.go). A bug in either function's comparison logic
// cannot mutate an organization or an account's Config setup no matter what
// it does. CheckProcedural holds the analogous property for the filesystem:
// it opens the attestation-stub directory read-only
// (internal/safeio.OpenDirUnder), and creates nothing even when the
// directory is absent.
//
// # What this package does not do
//
// It does not load an environment profile, a control artifact, or a catalog.
// Those are cmd/automat/verify.go's job, the same way loading them is
// cmd/automat/vend.go's job and not internal/org's — this package receives
// already-resolved values (a compilesets.Packed, a review-by date) and reports
// on them, so it has no opinion about where they came from.
package verify
