// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package classprofile defines the CLASSIFICATION profile: one institution's data
// classification levels, what each level means, and what its published policy
// requires at that level.
//
// The third of automat's three profile document types, and the second that is a
// reading of policy rather than a description of something being built. A
// classification profile is a SIBLING to the obligation profile, not a variant of
// it: an obligation profile answers "under what instrument, assessed how", and this
// one answers "which of this institution's levels is this environment rated for".
//
// # Its role in the vend pipeline
//
// It supplies the vocabulary for the sentence `vend` is ultimately built to print —
// "this account is rated for P4 - High" — which ROADMAP names as the tool's primary
// framing, because rating a resource for a level is the idiom institutions already
// use (Harvard's FASRC rates Cannon DSL1-2 and routes DSL3 elsewhere; Stanford's Yen
// is Low/Moderate with other systems for High).
//
// This package supplies the document only. The environment profile's reference TO a
// level is a separate change and deliberately not in this one, so that the document
// type can be reviewed on its own terms before anything depends on it. What the
// reference will need is already here: LevelByID resolves a level within a profile,
// and ContentHash gives the reference a subject that cannot be rewritten under it.
//
// # automat never classifies data
//
// There is no matcher, no trigger expression, and no evaluable form in this package
// or in the schema, and their absence is the design rather than an omission. An
// automated "this dataset is Level 4" would be wrong in the permissive direction
// exactly when it matters most, and it would be believed, because it came from a tool
// that is right about everything else. Determination is a human role the profile
// NAMES (Determination.Roles), and Determination.AutomatDetermines is pinned false at
// both layers so a profile cannot opt into the tool deciding.
//
// The level examples are a bounded reading aid for a person, exactly as an obligation
// profile's `applicability.hints` are, and a test refuses predicate syntax anywhere
// in the document. If a matcher starts taking shape here, that is a thing to stop and
// flag rather than a field to add.
//
// # Composition is the union law on a different lattice
//
// Every published scheme in the six-institution sample shares one rule: highest water
// mark. An element meeting two definitions takes the higher, and a dataset takes the
// highest of any element it contains. Join reports it, and CompositionRuleAssociates
// documents why it is the same principle DESIGN §9 states for control sets —
//
//	union of controls · intersection of permitted behavior · join of classification levels
//
// Three operations, one law: the stricter reading wins, so composing inputs can never
// relax what any single input required. `compile` holds idempotence, commutativity,
// associativity, and monotonicity as property tests over control sets; Join holds the
// same four over levels, because it is the same algebra on a total order.
//
// # Where the source is silent, the profile is silent
//
// A derived profile is automat's reading of somebody else's published policy, so
// Validate requires every control, level, and rule in one to carry a CitationRef into
// a hashed source. That is the load-bearing constraint of the whole document type:
// filling a gap with a sensible-looking control silently converts "UC's policy says"
// into "automat thinks UC should say". Correspondingly, a derived profile may carry
// only `interpreted-by` attestations and may not claim to be maintained — automat
// proposes a format for institutional classification and must never become the
// registry, the standards owner, or the upstream for any institution's scheme.
//
// The six published schemes the model was derived from, the cosigning path by which an
// institution replaces automat's reading with its own, and the boundary above stated as
// four things to check rather than a tone: docs/institutional-profiles.md.
package classprofile
