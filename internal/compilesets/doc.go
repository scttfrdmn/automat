// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package compilesets merges control sets into policy and packs the preventive
// half into service control policies that fit AWS's quotas.
//
// Its place in the vend pipeline is between `compile` and the SCP ensure step:
// artifacts in, a small deterministic set of SCP documents out, ready to attach
// to the OU. DESIGN §16 calls the packer "a real piece of work, not a
// serialization detail", and the reason is the quota — five SCPs per target and
// 5120 characters each, which a real union of cmmc-l1 plus 800-171 plus a campus
// baseline meets in ordinary use.
//
// # The governing law
//
// DESIGN §9: union of controls = intersection of permitted behavior. Everything
// here is judged against one question — can any merge WIDEN what is permitted? —
// and the answer has to be no for reasons that survive a hostile reading, not
// because the tests happen to pass.
//
// The reason it is answerable at all is that IAM's Deny composition is already a
// meet. Adding a Deny statement to a policy can only deny more, so
// *concatenation is inherently monotone* and needs no argument. That makes
// concatenation the primitive here, and it makes every risk in this package a
// risk of the OPPOSITE operation: combining two statements into one. A merge is
// a size optimization, and a size optimization that loses a constraint is how a
// packer widens a policy while every input file stays correct.
//
// # The normal form
//
// Rather than search for merges, mergeStatements computes what the statement set
// means and rebuilds the smallest set with that meaning. A statement set is a
// disjunction — a call is denied iff some statement names its action and does not
// exempt its principal — so for each (guard, action) pair the only thing that
// matters is
//
//	E(guard, action) = the INTERSECTION of the exemption sets of every statement
//	                   naming that action under that guard
//
// and the set denies (principal, action) exactly when the action is named and the
// principal is not in E. Grouping actions by their E value reproduces the behavior
// exactly, merges as far as any merge could, and is confluent because intersection
// is — so DESIGN §9's four properties hold by construction. The guard is effect,
// resource, and condition together: a different resource is a different scope and
// a different condition is a different guard, and combining across either would
// apply the union of the actions under whichever survived.
//
// The intersection is the load-bearing choice. An exemption is the only thing in a
// catalog that widens a policy, so it survives only where every control set
// constraining that action agrees to it: two sets both denying
// config:StopConfigurationRecorder, one exempting a break-glass role and one not,
// must produce a statement exempting NOBODY. Concatenating there is the defect
// DESIGN §10 names, and the one this package could most plausibly commit.
//
// Two consequences worth stating, because both are visible in the output:
//
//   - Per ACTION, not per statement. An action never inherits another action's
//     exemptions, so the case a pairwise merger has to refuse — two statements
//     differing in both their actions and their exemptions — is handled here
//     rather than skipped. Refusing it was safe but over-strict, and an
//     over-strict SCP breaks legitimate research work instead of announcing
//     itself.
//   - Grouped by exemption principals AND reasons. Two actions exempting the same
//     principal for differently worded reasons do not share a statement. That
//     costs a policy slot and buys determinism: the reason text is what a
//     reviewer reads to judge whether a hole is justified, and if it depended on
//     which actions happened to group together, a later union that split the
//     group would silently reword it.
//
// A merged statement's Sid is derived from its own content rather than inherited
// from any input, and that is not cosmetic: a guard group holds every statement
// sharing an effect, resource, and condition, so all of an artifact's unconditional
// Denies on "*" land in one group. Inheriting the seeding statement's Sid gave
// several statements in one document the same name — which IAM rejects outright —
// and gave a statement denying iam:CreateUser the name ProtectCloudTrail. See
// derivedSid; the origins list is where provenance actually lives.
//
// An earlier version of this package merged pairwise to a fixed point instead —
// find two statements differing along exactly one axis, combine them, repeat.
// Every merge it made was exact and it was still wrong, because greedy pairwise
// merging is not confluent: whichever pair merges first changes what remains
// mergeable, so (A ∪ B) ∪ C collapsed statements that A ∪ (B ∪ C) left separate.
// Same denied behavior, different document. The property tests caught it on their
// first run, which is the argument for having written them before trusting the
// code.
//
// # Why the property tests compare behavior, not bytes
//
// Idempotence, commutativity, associativity, and monotonicity (DESIGN §9) are
// asserted over the set of denied (principal, action, resource, region) tuples,
// not over the rendered document. The binning step is a bin-packing heuristic:
// it may legitimately group the same statements into different policies given
// the same inputs in a different order, while denying exactly the same behavior.
// Asserting byte equality there would be asserting a property of the heuristic
// and calling it a property of the semantics.
//
// Determinism is a separate claim and gets a separate test: the same input in
// the same order produces the same bytes, which is what makes golden files and
// re-runnable vends possible.
//
// # What this package does not do
//
// Full union semantics — crosswalk dedupe, Config-rule parameter resolution,
// conflict reports, override files — is Phase 4 and lives with
// artifact.RuleParameter.Resolve. This package handles the SCP half, which
// Phase 2 needs because a vend cannot attach a control it cannot fit.
package compilesets
