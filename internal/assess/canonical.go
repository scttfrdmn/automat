// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// ContentHash returns the SHA-256 of the profile's canonicalized content —
// implementing exactly the scope
// schema/obligation-profile-v1.schema.json's own $comment (Q15) names:
// every top-level field except schema_version and signatures, all included.
// That comment notes no Go type existed yet to enforce it; this package is
// that Go type's first reader with a reason to compute the hash (assess
// needs profile.content_sha256 for schema/assessment-result-v1.schema.json).
func (p *Profile) ContentHash() (string, error) {
	payload := struct {
		Meta            ProfileMeta        `json:"profile"`
		Status          string             `json:"status"`
		ReviewBy        string             `json:"review_by"`
		Citations       []Citation         `json:"citations"`
		ControlCatalogs []CatalogReference `json:"control_catalogs"`
		Assessment      Assessment         `json:"assessment"`
		Determinations  DeterminationSpec  `json:"determinations"`
		POAM            POAMPolicy         `json:"poam"`
		Scoring         Scoring            `json:"scoring"`
		Submission      Submission         `json:"submission"`
		Applicability   Applicability      `json:"applicability"`
		PolicyCaveat    string             `json:"policy_caveat"`
		Sources         []HashedReference  `json:"sources"`
	}{
		Meta:            p.Meta,
		Status:          p.Status,
		ReviewBy:        p.ReviewBy,
		Citations:       p.Citations,
		ControlCatalogs: p.ControlCatalogs,
		Assessment:      p.Assessment,
		Determinations:  p.Determinations,
		POAM:            p.POAM,
		Scoring:         p.Scoring,
		Submission:      p.Submission,
		Applicability:   p.Applicability,
		PolicyCaveat:    p.PolicyCaveat,
		Sources:         p.Sources,
	}
	b, err := artifact.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
