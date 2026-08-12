// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/automat/internal/artifact"
	"github.com/scttfrdmn/automat/internal/catalog"
	"github.com/scttfrdmn/automat/internal/verify"
)

// syntheticControlSets builds a small, HAND-BUILT catalog.Resolved for the
// golden scenarios below — not the real shipped catalogs. This is
// deliberate: the golden fixtures pin the renderer's OUTPUT SHAPE, and a
// fixture built from catalogs/cmmc-l1.json would silently change if that
// catalog's own enforcement assignments ever changed, coupling a renderer
// test to catalog content the way the original bare &catalog.Resolved{IDs:
// [...]} (with Artifacts left nil) was written to avoid.
//
// The mix is chosen to exercise verify.StructuralHonesty's bucket-priority
// rule in the same fixture that exercises the renderer: baseline-protection
// controls land in Enforced, a config-rule-only control lands in Continuous,
// a procedural-only control lands in Documented, and a control carrying BOTH
// config-rule and procedural (mirroring cmmc-l1's three curated bindings,
// gen/MAPPING-NOTES.md) lands in Documented, not Continuous.
func syntheticControlSets() *catalog.Resolved {
	return &catalog.Resolved{
		IDs: []string{"baseline-protection", "cmmc-l1"},
		Artifacts: []*artifact.Artifact{
			{
				Meta: artifact.Meta{ID: "baseline-protection"},
				Controls: artifact.Controls{
					{ID: "BP-1", Enforcement: []artifact.EnforcementClass{artifact.EnforcementBaselineProtection}},
					{ID: "BP-2", Enforcement: []artifact.EnforcementClass{artifact.EnforcementBaselineProtection}},
				},
			},
			{
				Meta: artifact.Meta{ID: "cmmc-l1"},
				Controls: artifact.Controls{
					{ID: "C-1", Enforcement: []artifact.EnforcementClass{artifact.EnforcementConfigRule}},
					{ID: "C-2", Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural}},
					{ID: "C-3", Enforcement: []artifact.EnforcementClass{
						artifact.EnforcementConfigRule, artifact.EnforcementProcedural,
					}},
				},
			},
		},
	}
}

// Golden files for `automat verify`'s printed report — ROADMAP's Phase 4
// accept criterion ("`verify` golden reports for compliant / drifted /
// freshness-lapsed scenarios").
//
// # Why "freshness-lapsed" and not "findings-only"
//
// ROADMAP's original wording named a third scenario "findings-only".
// "Findings" is DESIGN §12's term for the detective layer — resource
// noncompliance, distinct from policy drift — and verify does not check that
// layer (D4: internal/baseline does not exist, so there is nothing in a
// vended account for it to check against). There is no "findings-only"
// output verify's two shipped layers (policy, freshness) can produce. The
// one real distinct-output case left is a clean policy layer against a
// lapsed review_by — freshness warns independently of drift — so that is
// the third scenario, per an explicit maintainer decision reinterpreting
// ROADMAP's line rather than building a scenario with no code behind it.
//
// Rendered directly from renderVerifyReport rather than through the full
// CLI: the property under test is the renderer's output shape, and driving
// it through runCLI would make every scenario also exercise AWS clients,
// evidence writing, and exit-code plumbing that this test has no interest
// in and TestVerify* (verify_test.go) already covers.
const updateGoldenEnv = "AUTOMAT_UPDATE_GOLDEN"

func updateGolden() bool { return os.Getenv(updateGoldenEnv) == "1" }

var verifyGoldenScenarios = []struct {
	dir   string
	build func() (accountID, target string, sets *catalog.Resolved, policy *verify.PolicyReport, freshness verify.FreshnessStatus)
}{
	{
		dir: "compliant",
		build: func() (string, string, *catalog.Resolved, *verify.PolicyReport, verify.FreshnessStatus) {
			sets := syntheticControlSets()
			policy := &verify.PolicyReport{
				Target: "ou-exam-golden01",
				Expected: []verify.PolicyStatus{
					{Name: "automat-golden-1", Attached: true, Owned: true, Matches: true, PolicyID: "p-golden01"},
				},
			}
			freshness := verify.CheckFreshness("environment profile golden-clean", "2099-12-31",
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			return "111122223333", "ou-exam-golden01", sets, policy, freshness
		},
	},
	{
		dir: "drifted",
		build: func() (string, string, *catalog.Resolved, *verify.PolicyReport, verify.FreshnessStatus) {
			sets := syntheticControlSets()
			policy := &verify.PolicyReport{
				Target: "ou-exam-golden02",
				Expected: []verify.PolicyStatus{
					{Name: "automat-golden-1", Attached: true, Owned: true, Matches: false, PolicyID: "p-golden02"},
					{Name: "automat-golden-2", Attached: false},
				},
				Orphans: []string{"automat-golden-old (p-golden00)"},
			}
			freshness := verify.CheckFreshness("environment profile golden-drifted", "2099-12-31",
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			return "444455556666", "ou-exam-golden02", sets, policy, freshness
		},
	},
	{
		dir: "freshness-lapsed",
		build: func() (string, string, *catalog.Resolved, *verify.PolicyReport, verify.FreshnessStatus) {
			sets := syntheticControlSets()
			policy := &verify.PolicyReport{
				Target: "ou-exam-golden03",
				Expected: []verify.PolicyStatus{
					{Name: "automat-golden-1", Attached: true, Owned: true, Matches: true, PolicyID: "p-golden03"},
				},
			}
			freshness := verify.CheckFreshness("environment profile golden-stale", "2020-01-01",
				time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			return "777788889999", "ou-exam-golden03", sets, policy, freshness
		},
	},
}

func TestVerifyReportMatchesGolden(t *testing.T) {
	for _, sc := range verifyGoldenScenarios {
		t.Run(sc.dir, func(t *testing.T) {
			accountID, target, sets, policy, freshness := sc.build()
			honesty, herr := verify.StructuralHonesty(sets)
			if herr != nil {
				t.Fatalf("verify.StructuralHonesty: %v", herr)
			}
			var sb strings.Builder
			// mirrorReports is nil in every existing scenario: none configures a
			// mirror bucket, and renderVerifyReport omits the section entirely in
			// that case (its own doc comment) — these golden files predate slice
			// 2 and must stay byte-identical for an account with no mirror
			// configured. TestVerifyReportMatchesGoldenWithMirror below covers the
			// new section's own output shape.
			if err := renderVerifyReport(&sb, accountID, target, policy, freshness, honesty, nil); err != nil {
				t.Fatalf("renderVerifyReport: %v", err)
			}
			got := sb.String()

			path := filepath.Join("testdata", "golden", "verify", sc.dir+".txt")
			if updateGolden() {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil { //nolint:gosec // reviewed, committed fixture
					t.Fatalf("write %s: %v", path, err)
				}
				t.Logf("updated %s (%d bytes)", path, len(got))
				return
			}

			want, err := os.ReadFile(path) //nolint:gosec // fixed testdata path
			if err != nil {
				t.Fatalf("read %s: %v — run `AUTOMAT_UPDATE_GOLDEN=1 go test ./cmd/automat/`", path, err)
			}
			if got != string(want) {
				t.Errorf("verify report for %q does not match %s.\n"+
					"--- want ---\n%s\n--- got ---\n%s\n"+
					"If the change is intended, run `AUTOMAT_UPDATE_GOLDEN=1 go test ./cmd/automat/` "+
					"and review the diff: this is what an operator reads to decide whether an account drifted.",
					sc.dir, path, want, got)
			}
		})
	}
}

// TestVerifyGoldenFilesCoverEveryScenario stops a scenario from being added
// without a golden file, or a golden file surviving after its scenario was
// removed — the same discipline internal/bundle and internal/compilesets
// hold for their own golden sets.
func TestVerifyGoldenFilesCoverEveryScenario(t *testing.T) {
	if updateGolden() {
		t.Skip("writing golden files")
	}
	entries, err := os.ReadDir(filepath.Join("testdata", "golden", "verify"))
	if err != nil {
		t.Fatalf("read testdata/golden/verify: %v", err)
	}
	want := map[string]bool{}
	for _, sc := range verifyGoldenScenarios {
		want[sc.dir+".txt"] = true
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("testdata/golden/verify/%s has no scenario in verifyGoldenScenarios; either the "+
				"scenario was removed and the file is stale, or the file was added by hand", e.Name())
		}
		delete(want, e.Name())
	}
	for name := range want {
		t.Errorf("scenario for %s has no golden file; run `AUTOMAT_UPDATE_GOLDEN=1 go test ./cmd/automat/`",
			name)
	}
}
