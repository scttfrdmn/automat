// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/catalog"
)

// EnforcementBucket is the report bucket a single control lands in for
// DESIGN §12's "structural honesty" statement.
//
// This is a DIFFERENT computation from artifact.Artifact.Breakdown(): that
// one counts a control once per enforcement class it carries (so its counts
// can sum to more than the control total — see its own doc comment), which is
// what gen/catalog needs at compile time to show a maintainer every class a
// control was assigned. A verify report instead needs a PARTITION: every
// control lands in exactly one bucket, so "N enforced, M documented, K
// continuous" can be added up into "of T total" without double-counting. That
// is a reporting policy belonging to this package (internal/verify/doc.go's
// "already-resolved inputs, no opinion about where they came from"), not a
// fact about the artifact format, so it lives here rather than as a second
// method on artifact.Artifact.
type EnforcementBucket string

// The three buckets. Every control carries exactly one.
const (
	// BucketEnforced means automat itself enforces the control preventively:
	// a service control policy, either the control set's own (EnforcementSCP)
	// or the meta-control guarding automat's own baseline
	// (EnforcementBaselineProtection).
	BucketEnforced EnforcementBucket = "enforced"
	// BucketDocumented means the control requires a documented process automat
	// tracks with an attestation stub but does not enforce or watch
	// (EnforcementProcedural).
	BucketDocumented EnforcementBucket = "documented"
	// BucketContinuous means the control requires continuous evidence
	// collection outside this tool's scope: AWS Config observes it, but
	// nothing in this build watches an account after `vend` creates it
	// (EnforcementConfigRule; DESIGN §12, internal/baseline not yet built).
	BucketContinuous EnforcementBucket = "continuous"
)

// AllEnforcementBuckets lists every bucket in canonical (report) order.
var AllEnforcementBuckets = []EnforcementBucket{BucketEnforced, BucketDocumented, BucketContinuous}

// bucketFor assigns a control to exactly one bucket, in priority order:
//
//  1. Enforces(SCP) or Enforces(BaselineProtection) -> BucketEnforced.
//  2. else Enforces(Procedural) -> BucketDocumented.
//  3. else Enforces(ConfigRule) -> BucketContinuous.
//
// The procedural-over-config-rule tiebreak (step 2 before step 3) is not
// arbitrary. gen/MAPPING-NOTES.md's "Curated bindings" section names three
// cmmc-l1 controls that carry both config-rule and procedural classes
// (AC.L1-b.1.iv, SC.L1-b.1.xi, SI.L1-b.1.xiv) and says explicitly that each
// keeps its procedural attestation because "the rules observe a symptom of
// the requirement, not the requirement itself" — dropping the stub would
// claim more coverage than the curated rule delivers. A control whose
// strongest true statement is "a documented process" must report as
// documented even though a Config rule also happens to watch a symptom of it,
// or this report would overstate automat's own enforcement the same way
// dropping the attestation would have.
//
// A control matching none of the three classes falls into no bucket and is a
// programming error in the artifact (every shipped control carries at least
// one enforcement class) rather than a case this function is expected to
// handle silently — see StructuralHonesty's own doc comment.
func bucketFor(c artifact.Control) (EnforcementBucket, bool) {
	switch {
	case c.Enforces(artifact.EnforcementSCP), c.Enforces(artifact.EnforcementBaselineProtection):
		return BucketEnforced, true
	case c.Enforces(artifact.EnforcementProcedural):
		return BucketDocumented, true
	case c.Enforces(artifact.EnforcementConfigRule):
		return BucketContinuous, true
	default:
		return "", false
	}
}

// ControlEnforcement is one control's bucket assignment, identified by the
// control set it came from and its own id — the pair an operator needs to go
// find the control again in the compiled artifact.
type ControlEnforcement struct {
	ControlSet string
	ControlID  string
	Bucket     EnforcementBucket
}

// StructuralHonestyReport is DESIGN §12's structural-honesty statement:
// every control from every resolved control set, partitioned into exactly one
// of the three buckets, plus the rollup counts a report renders.
type StructuralHonestyReport struct {
	// ControlSetIDs are the control sets this report was computed from, in
	// catalog.Resolved's own order (sorted, deduplicated, baseline-protection
	// always present).
	ControlSetIDs []string
	// Controls is one entry per control across every resolved set, in
	// ControlSetIDs order and then artifact order within each set.
	Controls []ControlEnforcement
	// Total is len(Controls).
	Total int
	// Enforced, Documented, and Continuous are the three bucket counts.
	// Enforced + Documented + Continuous always equals Total: this is a
	// partition, not the double-counting artifact.Breakdown produces.
	Enforced   int
	Documented int
	Continuous int
}

// StructuralHonesty computes the structural-honesty breakdown over an
// already-resolved set of control-set artifacts.
//
// Takes *catalog.Resolved directly rather than a profile or a set of ids,
// matching this package's stated architecture (internal/verify/doc.go): the
// caller (cmd/automat/verify.go) has already resolved the environment
// profile's control sets to loaded artifacts for its own compile, and this
// function reports on that resolution rather than doing a second one.
func StructuralHonesty(sets *catalog.Resolved) (*StructuralHonestyReport, error) {
	if sets == nil {
		return nil, fmt.Errorf("cannot compute the structural-honesty breakdown: no resolved control sets were given")
	}
	if len(sets.IDs) != len(sets.Artifacts) {
		return nil, fmt.Errorf("cannot compute the structural-honesty breakdown: %d control set ids but "+
			"%d loaded artifacts — catalog.Resolved's ids and artifacts must stay positionally aligned",
			len(sets.IDs), len(sets.Artifacts))
	}

	report := &StructuralHonestyReport{ControlSetIDs: sets.IDs}
	for i, a := range sets.Artifacts {
		id := sets.IDs[i]
		for _, c := range a.Controls {
			bucket, ok := bucketFor(c)
			if !ok {
				return nil, fmt.Errorf("cannot compute the structural-honesty breakdown: control %s in "+
					"control set %s carries none of the known enforcement classes; every control this "+
					"tool ships must declare at least one so this report can state its limits truthfully",
					c.ID, id)
			}
			report.Controls = append(report.Controls, ControlEnforcement{
				ControlSet: id, ControlID: c.ID, Bucket: bucket,
			})
			switch bucket {
			case BucketEnforced:
				report.Enforced++
			case BucketDocumented:
				report.Documented++
			case BucketContinuous:
				report.Continuous++
			}
		}
	}
	report.Total = len(report.Controls)
	return report, nil
}

// String renders the rollup sentence DESIGN §12 describes, following the same
// one-paragraph style FreshnessStatus.String uses for a plain-text report.
func (r *StructuralHonestyReport) String() string {
	ids := make([]string, len(r.ControlSetIDs))
	copy(ids, r.ControlSetIDs)
	sort.Strings(ids)
	return fmt.Sprintf(
		"compiled from: %s\n%d controls total: %d enforced by this tool, %d require a documented "+
			"process outside this tool, %d require continuous evidence collection outside this tool's "+
			"scope",
		strings.Join(ids, ", "), r.Total, r.Enforced, r.Documented, r.Continuous)
}
