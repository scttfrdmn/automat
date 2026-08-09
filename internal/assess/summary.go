// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"fmt"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// NoMachineEvidenceYet is the fixed disclosure sentence a renderer of this
// package's Result states once, alongside L1Summary, rather than repeating
// per row: cmmc-l1's catalog has no SCP fragments, and no AWS Config read
// path exists yet, so there is no machine evidence for any of the fifteen
// practices in this build (internal/assess's own package doc, and
// docs/assessment-reporting.md's "What automat can and cannot contribute").
// Not written into any ObjectiveRow's EvidencePointer: that field is for
// where machine evidence came from, and schema/assessment-result-v1's own
// doc comment is explicit that it stays absent, as a capability fact rather
// than a per-objective observation, when there is none to point to.
const NoMachineEvidenceYet = "automat contributes no machine evidence for this catalog yet — " +
	"cmmc-l1's controls carry no SCP fragments and no AWS Config read path exists in this build. " +
	"Every row below is an operator determination or the silence Invariant 3 renders NOT MET."

// SummarizeL1 computes an assessment-result document for the CMMC L1
// obligation profile against art's controls and det's determinations.
//
// Purely a function of its three inputs — no AWS read beyond what the
// caller already did to obtain art (cmd/automat/assess.go's one
// GetCallerIdentity call is for evidence attribution, not for anything this
// function consults). det may be nil: an assessment run with no
// determinations file at all is legitimate (every objective silently NOT
// MET), and schema/assessment-result-v1.schema.json's own $comment says an
// absent `determinations` field is the honest way to record that, not an
// empty-but-present one.
func SummarizeL1(profile *Profile, art *artifact.Artifact, det *Determinations,
	account ResultAccount, toolVersion, renderedAt string) (*Result, error) {
	if profile.Meta.ID != "cmmc-l1" {
		return nil, fmt.Errorf("SummarizeL1 is the CMMC L1 renderer; profile %q is not cmmc-l1 — "+
			"assess's other two shipped profiles (dfars-7012, nih-cadr-dua) have no Stage 3 renderer yet",
			profile.Meta.ID)
	}
	if err := validateResultAccount(account); err != nil {
		return nil, err
	}
	profileHash, err := profile.ContentHash()
	if err != nil {
		return nil, fmt.Errorf("hash obligation profile %s: %w", profile.Meta.ID, err)
	}
	if det != nil {
		if err := det.ValidateAgainst(profile); err != nil {
			return nil, err
		}
	}

	result := &Result{
		SchemaVersion: "1.0.0",
		RenderedAt:    renderedAt,
		ToolVersion:   toolVersion,
		Account:       account,
		Profile:       DocRef{ID: profile.Meta.ID, ContentSHA256: profileHash},
		Artifact:      DocRef{ID: art.Meta.ID, ContentSHA256: art.Meta.ContentHash},
		PolicyCaveat:  profile.PolicyCaveat,
	}
	if det != nil {
		detHash, err := det.ContentHash()
		if err != nil {
			return nil, fmt.Errorf("hash operator determinations: %w", err)
		}
		result.Determinations = &DocRef{ID: "operator-determinations", ContentSHA256: detHash}
	}

	catalogObjectives := make(map[string]bool, len(art.Controls))
	metCount, notMetCount := 0, 0
	for _, c := range art.Controls {
		catalogObjectives[c.ID] = true
		// EvidencePointer stays absent: there is no machine evidence to point
		// to for any objective in this build (NoMachineEvidenceYet states
		// that fact once, at the document level, rather than per row — see
		// schema/assessment-result-v1.schema.json's own doc comment on
		// evidence_pointer).
		row := ObjectiveRow{
			ID:            c.ID,
			EvidenceClass: EvidenceOperator,
			Resolved:      profile.Determinations.UnderstatementValue,
		}
		if det != nil {
			if d, ok := det.ForObjective(c.ID); ok {
				row.Determination = d.ID
				row.Resolved = d.Value
			}
		}
		if row.Resolved == profile.Determinations.UnderstatementValue {
			notMetCount++
		} else {
			metCount++
		}
		result.Objectives = append(result.Objectives, row)
	}

	// A determination naming an objective id the catalog does not have would
	// otherwise be dropped with no effect and no error: ForObjective simply
	// never matches it, the practice it was meant to address stays at the
	// profile's understatement value, and the operator's own claim vanishes
	// without a trace. That never overstates (Invariant 2 still holds — the
	// row stays NOT MET), but a determination that silently does nothing is
	// its own defect: an operator who typo'd MP.L1-b.1.vii as MP.L1-b1.vii
	// believes they addressed media disposal and the rendered summary agrees
	// with nothing they said. Refusing to run is the same discipline
	// ValidateAgainst already applies to a value outside the vocabulary —
	// this is a reference outside the catalog, checked here because only
	// SummarizeL1 has both the determinations and the artifact in hand.
	if det != nil {
		for _, d := range det.List {
			for _, obj := range d.Objectives {
				if !catalogObjectives[obj] {
					return nil, fmt.Errorf("operator determination %q names objective %q, which is not "+
						"one of cmmc-l1's fifteen practices in control artifact %s — check for a typo; "+
						"a determination naming an objective the catalog does not have is silently "+
						"dropped otherwise, and the practice it was meant to address would stay NOT MET "+
						"with no record of why", d.ID, obj, art.Meta.ID)
				}
			}
		}
	}

	result.L1Summary = L1Summary{
		MetCount:            metCount,
		NotMetCount:         notMetCount,
		Total:               len(art.Controls),
		AffirmationPossible: notMetCount == 0,
	}
	return result, nil
}
