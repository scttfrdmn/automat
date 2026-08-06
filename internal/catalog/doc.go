// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package catalog resolves the ids in an environment profile to the documents
// they name.
//
// It is DESIGN §7 step 1's first half and nothing else: `control_sets: ["cmmc-l1"]`
// becomes a loaded, hash-verified `*artifact.Artifact`, and
// `obligations: [{id: "dfars-7012", ...}]` becomes the facts
// `envprofile.CheckObligations` needs. What happens next — Merge, Narrow, Pack — is
// internal/compilesets', and this package deliberately does not reach into it: a
// resolver that also compiled would make "which documents did this vend read" a
// question with no separable answer.
//
// # Why this exists as a package
//
// Nothing resolved an id to a document before it. An environment profile names
// control sets by id because a hand-written operator document cannot carry a path —
// a path is machine-specific, and a profile is a document an institution publishes
// for its departments to vend against. So the id-to-document step is automat's, and
// it is a security boundary rather than a lookup: the id comes out of a file in the
// threat model, and it becomes a path.
//
// # Three refusals
//
//   - An id that is not a catalog id is refused BEFORE it becomes a path.
//     `envprofile.Validate` already patterns `control_sets[]`, and this checks again
//     anyway: a resolver that trusted its caller's validation would be one call away
//     from `../../etc/passwd` the day something else resolves an id. The check is
//     against the same character class the schema publishes, so the two cannot drift
//     into disagreeing about what an id is.
//   - An id with no document is a hard error naming what IS available. A vend that
//     silently skipped an unresolvable control set would produce an account whose
//     birth certificate claims a posture nothing enforced.
//   - The content hash is verified on load, by artifact.Load's default. The catalogs
//     are embedded in the binary, so this is not about a file changing underneath —
//     it is that a catalog whose declared hash does not cover its own controls is
//     the one document in this pipeline nobody downstream re-checks, since every SCP
//     tag and evidence record quotes the declared value.
//
// # baseline-protection is always compiled in
//
// ResolveControlSets appends `baseline-protection` whether or not the profile names
// it, because DESIGN §7 step 4 requires it at every vend and because the packer
// requires it whenever the profile sets `permitted.*`: the region and service Deny
// shapes need `region_deny_exempt_services`, and `baseline-protection.json` is the
// artifact that supplies it. A profile could not opt out of the meta-control by
// omission even if it wanted to, which is the point of a meta-control.
//
// # Embedded, not read from disk
//
// The documents come from the `catalogs` package's embedded tree by default, so a
// binary installed with `go install` vends the same posture as one run from a source
// checkout. Options.FS overrides it, for tests and for an institution vending
// against a catalog it compiled itself — an explicit argument at the call site
// rather than a package variable something reassigned.
package catalog
