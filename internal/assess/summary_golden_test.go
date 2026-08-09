// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"os"
	"path/filepath"
	"testing"
)

// Golden files for RenderL1Summary's printed output — ROADMAP's Stage 3
// accept criterion, following the same convention cmd/automat's own
// verify_golden_test.go establishes: AUTOMAT_UPDATE_GOLDEN=1 regenerates the
// fixtures, and TestSummaryGoldenFilesCoverEveryScenario stops a scenario
// from being added without one or a stale file from surviving its removal.
//
// Two scenarios, not three: this build has no machine evidence to render
// (internal/assess's own package doc), so there is no "partially-evidenced"
// case distinct from "gapped" the way verify's drifted/freshness-lapsed
// split is distinct. "gapped" — no determinations file at all — is the
// scenario every one of the fifteen practices renders NOT MET through, and
// covers the three no-AWS-surface practices (media disposal, both
// physical-access practices) as part of the same run rather than a separate
// case, since none of the fifteen has machine evidence in this build.
const assessUpdateGoldenEnv = "AUTOMAT_UPDATE_GOLDEN"

func assessUpdateGolden() bool { return os.Getenv(assessUpdateGoldenEnv) == "1" }

var summaryGoldenScenarios = []struct {
	dir   string
	build func(t *testing.T) *Result
}{
	{
		dir: "compliant",
		build: func(t *testing.T) *Result {
			profile := validCMMCL1(t)
			art := loadCMMCL1Artifact(t)
			det := &Determinations{SchemaVersion: "1.0.0"}
			for _, c := range art.Controls {
				det.List = append(det.List, Determination{
					ID:               "met-" + c.ID,
					Objectives:       []string{c.ID},
					Value:            "MET",
					Statement:        "Reviewed and confirmed in place by the account's senior official.",
					Date:             "2026-08-01",
					ResponsibleParty: "Jane Researcher, PI",
				})
			}
			account := ResultAccount{
				ID:             "111122223333",
				ScopeStatement: "This AWS account is the entire system boundary for this assessment.",
			}
			result, err := SummarizeL1(profile, art, det, account, "golden-test", "2026-08-09T00:00:00Z")
			if err != nil {
				t.Fatalf("SummarizeL1: %v", err)
			}
			return result
		},
	},
	{
		dir: "gapped",
		build: func(t *testing.T) *Result {
			profile := validCMMCL1(t)
			art := loadCMMCL1Artifact(t)
			account := ResultAccount{
				ID:             "444455556666",
				ScopeStatement: "This AWS account is the entire system boundary for this assessment.",
			}
			result, err := SummarizeL1(profile, art, nil, account, "golden-test", "2026-08-09T00:00:00Z")
			if err != nil {
				t.Fatalf("SummarizeL1: %v", err)
			}
			return result
		},
	},
}

func TestL1SummaryMatchesGolden(t *testing.T) {
	for _, sc := range summaryGoldenScenarios {
		t.Run(sc.dir, func(t *testing.T) {
			result := sc.build(t)
			data, err := RenderL1Summary(result)
			if err != nil {
				t.Fatalf("RenderL1Summary: %v", err)
			}
			got := string(data)

			path := filepath.Join("testdata", "golden", "l1-summary", sc.dir+".txt")
			if assessUpdateGolden() {
				if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
					t.Fatal(mkErr)
				}
				if wErr := os.WriteFile(path, []byte(got), 0o644); wErr != nil { //nolint:gosec // reviewed, committed fixture
					t.Fatalf("write %s: %v", path, wErr)
				}
				t.Logf("updated %s (%d bytes)", path, len(got))
				return
			}

			want, err := os.ReadFile(path) //nolint:gosec // fixed testdata path
			if err != nil {
				t.Fatalf("read %s: %v — run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/assess/`", path, err)
			}
			if got != string(want) {
				t.Errorf("L1 summary for %q does not match %s.\n"+
					"--- want ---\n%s\n--- got ---\n%s\n"+
					"If the change is intended, run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/assess/` "+
					"and review the diff: this is what an affirming official reads.",
					sc.dir, path, want, got)
			}
		})
	}
}

// TestSummaryGoldenFilesCoverEveryScenario mirrors
// TestVerifyGoldenFilesCoverEveryScenario's discipline.
func TestSummaryGoldenFilesCoverEveryScenario(t *testing.T) {
	if assessUpdateGolden() {
		t.Skip("writing golden files")
	}
	entries, err := os.ReadDir(filepath.Join("testdata", "golden", "l1-summary"))
	if err != nil {
		t.Fatalf("read testdata/golden/l1-summary: %v", err)
	}
	want := map[string]bool{}
	for _, sc := range summaryGoldenScenarios {
		want[sc.dir+".txt"] = true
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("testdata/golden/l1-summary/%s has no scenario in summaryGoldenScenarios; either the "+
				"scenario was removed and the file is stale, or the file was added by hand", e.Name())
		}
		delete(want, e.Name())
	}
	for name := range want {
		t.Errorf("scenario for %s has no golden file; run `AUTOMAT_UPDATE_GOLDEN=1 go test ./internal/assess/`",
			name)
	}
}
