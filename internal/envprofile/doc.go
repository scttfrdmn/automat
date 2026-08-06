// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package envprofile defines the ENVIRONMENT profile: `vend`'s per-vend input,
// and the only one of automat's three profile document types that describes
// something being built rather than a reading of policy (DESIGN §7a).
//
// Its role in the vend pipeline is to be the document `vend` starts from. It names
// the control sets to compile, where the account lands, the permitted-behavior
// boundary inside it, the in-account baseline, and the obligation profiles the
// environment is being built to satisfy. `verify` reads the same document to ask
// whether what is attached still matches it, and the evidence manifest names it by
// id and content hash — which is why the hash is defined here rather than
// recomputed by each consumer.
//
// # Why this is not part of internal/artifact
//
// That package's doc comment once claimed it held these types, and putting them
// there would have collided on the noun this project has already renamed a schema
// over (Q14). `artifact.Attestation` is a procedural control's stub — a template
// and a cadence — while an environment profile's attestation is a provenance
// predicate over a content hash. Two unrelated documents' "attestation" in one
// package is exactly the ambiguity the environment-profile rename existed to
// remove. internal/evidence made the same call for the same reason, down to
// carrying its own Problem and ValidationError.
//
// # What this package refuses to decide
//
// Two checks here are cross-document, and both fail closed rather than defaulting:
//
//   - An obligation reference's `revision_determination` is required exactly when
//     the referenced obligation profile declares `revision_policy:
//     operator-determined`. The schema cannot express that — it would have to read
//     the other document — so CheckObligations does, and automat ships no default
//     revision. A tool that silently picks one has made a compliance determination
//     on an institution's behalf.
//   - An attestation's `content_sha256` must be this document's hash.
//     VerifyAttestationSubjects recomputes it, because an attestation whose subject
//     is only implicit is one that can be moved to a different document.
//
// The permitted-behavior sets are enforced elsewhere on purpose: they may only ever
// NARROW what the compiled control sets require, so the intersection and the
// refusal both live with the packer that has the property tests for it
// (compilesets.Narrow).
package envprofile
