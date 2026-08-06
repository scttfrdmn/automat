// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package artifact defines the control artifact, environment profile, and evidence
// manifest types, and the load/validate/canonicalize/hash operations over them.
//
// Its role in the vend pipeline is to be the contract everything else speaks.
// `gen/` compiles upstream catalogs into a control artifact; `compilesets`
// unions artifacts into a new artifact; `vend` reads an artifact plus a profile
// and enforces them; `evidence` records what it did, naming the artifact by the
// content hash this package computes. The JSON Schemas in schema/ are the
// published form of these types; the schema conformance test keeps the two
// honest about each other.
//
// Canonicalization is the load-bearing piece. Two artifacts with the same
// controls must hash identically regardless of key order, member ordering, or
// whitespace in the file they came from, because that hash goes into account
// tags, SCP tags, and evidence manifests, and `verify` compares against it
// later.
package artifact
