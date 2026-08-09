// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package assess renders `automat assess`'s CMMC L1 MET/NOT MET summary —
// DESIGN's Phase 4, Stage 3 of docs/assessment-reporting.md's staged build.
//
// # Two facts that shape what this package can do today
//
// `catalogs/cmmc-l1.json` carries no SCP fragments — its fifteen controls are
// config-rule and/or procedural only — and no `awsapi` interface reads AWS
// Config's compliance state. `internal/verify` has no procedural layer either
// (it is scoped to policy+freshness, docs/cli-surface.md D4, because
// internal/baseline — the thing that would deploy a Config recorder or an
// attestation stub — does not exist). So this package contributes zero
// machine evidence for any CMMC L1 practice: every objective's evidence
// class is `operator`, and the rendered summary says so in a fixed sentence
// rather than staying silent about it. The result document's shape
// (schema/assessment-result-v1.schema.json's `evidence_pointer` field) does
// not need to change when a Config-read interface or `internal/baseline`
// eventually exist — they would only start populating rows this package
// already has a place for.
//
// # The first Go-typed reader of an obligation profile
//
// `internal/catalog.ResolveObligations` and `envprofile.ObligationFacts`
// deliberately read only two-and-a-half fields out of an obligation
// profile's raw JSON — ROADMAP names `assess` as the first consumer that
// needs the whole document, and Profile (obligation.go) is that reader.
// Nothing upstream of this package changes: catalog.ResolveObligations still
// returns facts, not a typed profile, because CheckObligations' job (does an
// environment profile's reference match a shipped profile) has nothing to do
// with rendering an assessment.
//
// # What this package does not do
//
// It does not decide which profiles apply to an operator — `--profile`
// names one, chosen by the human running the command, the same
// "operator declares, automat never infers" discipline the profile's own
// `applicability` field states. It does not read AWS at all beyond a single
// `sts:GetCallerIdentity` call for evidence attribution — Stage 3 has no
// machine evidence to read AWS for. It does not render an 800-171A
// worksheet or an SPRS score; those are Stages 1 and 2, gated on a
// hand-transcribed weight table (docs/open-questions.md Q10) that is real
// off-computer work, not code, and out of scope here.
package assess
