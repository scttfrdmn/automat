// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/catalog"
)

// TestStructuralHonestyOverTheShippedCatalogs pins the real numbers DESIGN
// §12's example sentence describes, computed from the two catalogs every
// vend compiles: cmmc-l1 (15 controls) plus baseline-protection (7 controls,
// always resolved — catalog.BaselineProtectionID).
//
// Verified directly against catalogs/cmmc-l1.json and
// catalogs/baseline-protection.json rather than assumed: all 7
// baseline-protection controls carry only EnforcementBaselineProtection
// (Enforced); of cmmc-l1's 15, 9 carry only EnforcementConfigRule
// (Continuous), 3 carry only EnforcementProcedural (Documented), and 3 carry
// BOTH EnforcementConfigRule and EnforcementProcedural — the curated
// bindings gen/MAPPING-NOTES.md's "Curated bindings" section names
// (AC.L1-b.1.iv, SC.L1-b.1.xi, SI.L1-b.1.xiv) — which the priority rule
// resolves to Documented. So cmmc-l1 contributes 9 continuous and 3+3=6
// documented. Total: 7 enforced, 6 documented, 9 continuous, 22 total.
//
// If this test ever fails because the real catalogs changed, that is the
// signal working as intended — this pin exists so a change to what automat
// actually enforces cannot pass silently.
func TestStructuralHonestyOverTheShippedCatalogs(t *testing.T) {
	sets, err := catalog.ResolveControlSets([]string{"cmmc-l1"}, catalog.Options{})
	if err != nil {
		t.Fatalf("ResolveControlSets: %v", err)
	}

	report, err := StructuralHonesty(sets)
	if err != nil {
		t.Fatalf("StructuralHonesty: %v", err)
	}

	if report.Total != 22 {
		t.Errorf("Total = %d, want 22", report.Total)
	}
	if report.Enforced != 7 {
		t.Errorf("Enforced = %d, want 7", report.Enforced)
	}
	if report.Documented != 6 {
		t.Errorf("Documented = %d, want 6", report.Documented)
	}
	if report.Continuous != 9 {
		t.Errorf("Continuous = %d, want 9", report.Continuous)
	}
	if sum := report.Enforced + report.Documented + report.Continuous; sum != report.Total {
		t.Errorf("Enforced+Documented+Continuous = %d, want Total %d", sum, report.Total)
	}
}

// TestBucketPriorityFavorsDocumentedOverContinuous holds the tiebreak
// gen/MAPPING-NOTES.md's "Curated bindings" section calls for: a control
// carrying both EnforcementConfigRule and EnforcementProcedural must land in
// BucketDocumented, not BucketContinuous, because "those rules observe a
// symptom of the requirement, not the requirement itself" — a Config rule
// that merely watches a symptom must not upgrade a control's strongest true
// statement from "documented process" to "continuously observed".
func TestBucketPriorityFavorsDocumentedOverContinuous(t *testing.T) {
	c := artifact.Control{
		ID: "both",
		Enforcement: []artifact.EnforcementClass{
			artifact.EnforcementConfigRule,
			artifact.EnforcementProcedural,
		},
	}
	bucket, ok := bucketFor(c)
	if !ok {
		t.Fatal("bucketFor reported no bucket for a control carrying config-rule and procedural")
	}
	if bucket != BucketDocumented {
		t.Errorf("bucket = %s, want %s (procedural takes priority over config-rule per "+
			"gen/MAPPING-NOTES.md's curated-bindings rationale)", bucket, BucketDocumented)
	}
}

// TestBucketPriorityFavorsEnforcedOverEverything holds the top of the
// priority order: a control carrying scp or baseline-protection alongside
// either of the other two classes must still land in BucketEnforced, since a
// preventive control automat itself attaches is a stronger statement than
// either a documented process or an outside detective mapping.
func TestBucketPriorityFavorsEnforcedOverEverything(t *testing.T) {
	tests := []struct {
		name string
		c    artifact.Control
	}{
		{"scp+config-rule", artifact.Control{Enforcement: []artifact.EnforcementClass{
			artifact.EnforcementSCP, artifact.EnforcementConfigRule,
		}}},
		{"scp+procedural", artifact.Control{Enforcement: []artifact.EnforcementClass{
			artifact.EnforcementSCP, artifact.EnforcementProcedural,
		}}},
		{"baseline-protection+config-rule", artifact.Control{Enforcement: []artifact.EnforcementClass{
			artifact.EnforcementBaselineProtection, artifact.EnforcementConfigRule,
		}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bucket, ok := bucketFor(tc.c)
			if !ok {
				t.Fatal("bucketFor reported no bucket")
			}
			if bucket != BucketEnforced {
				t.Errorf("bucket = %s, want %s", bucket, BucketEnforced)
			}
		})
	}
}

// TestStructuralHonestyTotalAlwaysSums holds the partition property that
// distinguishes this report from artifact.Artifact.Breakdown(): no matter
// what mix of classes the resolved artifacts carry, Enforced + Documented +
// Continuous must equal Total exactly, because every control lands in
// exactly one bucket.
func TestStructuralHonestyTotalAlwaysSums(t *testing.T) {
	tests := []struct {
		name string
		sets *catalog.Resolved
	}{
		{
			name: "single set, mixed classes",
			sets: &catalog.Resolved{
				IDs: []string{"set-a"},
				Artifacts: []*artifact.Artifact{
					{
						Meta: artifact.Meta{ID: "set-a"},
						Controls: artifact.Controls{
							{ID: "1", Enforcement: []artifact.EnforcementClass{artifact.EnforcementSCP}},
							{ID: "2", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule}},
							{ID: "3", Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural}},
							{ID: "4", Enforcement: []artifact.EnforcementClass{
								artifact.EnforcementConfigRule, artifact.EnforcementProcedural,
							}},
							{ID: "5", Enforcement: []artifact.EnforcementClass{
								artifact.EnforcementSCP, artifact.EnforcementConfigRule, artifact.EnforcementProcedural,
							}},
						},
					},
				},
			},
		},
		{
			name: "two sets",
			sets: &catalog.Resolved{
				IDs: []string{"set-a", "set-b"},
				Artifacts: []*artifact.Artifact{
					{
						Meta: artifact.Meta{ID: "set-a"},
						Controls: artifact.Controls{
							{ID: "1", Enforcement: []artifact.EnforcementClass{artifact.EnforcementBaselineProtection}},
						},
					},
					{
						Meta: artifact.Meta{ID: "set-b"},
						Controls: artifact.Controls{
							{ID: "1", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule}},
							{ID: "2", Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural}},
						},
					},
				},
			},
		},
		{
			name: "empty",
			sets: &catalog.Resolved{IDs: nil, Artifacts: nil},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := StructuralHonesty(tc.sets)
			if err != nil {
				t.Fatalf("StructuralHonesty: %v", err)
			}
			if sum := report.Enforced + report.Documented + report.Continuous; sum != report.Total {
				t.Errorf("Enforced(%d)+Documented(%d)+Continuous(%d) = %d, want Total %d",
					report.Enforced, report.Documented, report.Continuous, sum, report.Total)
			}
			if report.Total != len(report.Controls) {
				t.Errorf("Total = %d, want len(Controls) = %d", report.Total, len(report.Controls))
			}
		})
	}
}

// TestStructuralHonestyRejectsAnUnclassifiedControl holds the failure mode
// bucketFor's own doc comment names: a control carrying none of the three
// recognized classes must fail loudly rather than be silently omitted from
// the report, since silence here would understate Total.
func TestStructuralHonestyRejectsAnUnclassifiedControl(t *testing.T) {
	sets := &catalog.Resolved{
		IDs: []string{"broken"},
		Artifacts: []*artifact.Artifact{
			{
				Meta: artifact.Meta{ID: "broken"},
				Controls: artifact.Controls{
					{ID: "unclassified", Enforcement: nil},
				},
			},
		},
	}
	if _, err := StructuralHonesty(sets); err == nil {
		t.Fatal("StructuralHonesty succeeded over a control with no enforcement class, want an error")
	}
}
