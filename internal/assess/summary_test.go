// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"path/filepath"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

const cmmcL1ArtifactPath = "../../catalogs/cmmc-l1.json"

func loadCMMCL1Artifact(t *testing.T) *artifact.Artifact {
	t.Helper()
	a, err := artifact.Load(filepath.Join(cmmcL1ArtifactPath), artifact.LoadOptions{})
	if err != nil {
		t.Fatalf("artifact.Load(%s): %v", cmmcL1ArtifactPath, err)
	}
	return a
}

func testAccount() ResultAccount {
	return ResultAccount{
		ID:             "111122223333",
		ScopeStatement: "This AWS account is the entire system boundary for this assessment.",
	}
}

// TestSummarizeL1RendersNotMetOnSilence is Invariant 3's load-bearing
// assertion: with no determinations file at all, every one of the fifteen
// L1 practices renders NOT MET and no affirmation is possible. Not
// "pending", not "in progress" — docs/assessment-reporting.md is explicit
// that inventing a third state would be inventing the comfortable one.
func TestSummarizeL1RendersNotMetOnSilence(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	result, err := SummarizeL1(profile, art, nil, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	if result.L1Summary.MetCount != 0 {
		t.Errorf("MetCount = %d, want 0 — silence must never read as MET", result.L1Summary.MetCount)
	}
	if result.L1Summary.NotMetCount != len(art.Controls) {
		t.Errorf("NotMetCount = %d, want %d (every practice)", result.L1Summary.NotMetCount, len(art.Controls))
	}
	if result.L1Summary.AffirmationPossible {
		t.Error("AffirmationPossible = true with zero determinations, want false")
	}
	for _, row := range result.Objectives {
		if row.Resolved != "NOT MET" {
			t.Errorf("objective %s resolved %q, want NOT MET", row.ID, row.Resolved)
		}
		if row.EvidenceClass != EvidenceOperator {
			t.Errorf("objective %s evidence_class = %q, want operator — this build has no machine evidence path",
				row.ID, row.EvidenceClass)
		}
		if row.Determination != "" {
			t.Errorf("objective %s carries a determination reference %q with no determinations file given",
				row.ID, row.Determination)
		}
	}
}

// TestSummarizeL1NeverWritesMETItself is Invariant 2's renderer-level check:
// the profile-level property test
// (TestTheUnderstatementAsymmetryHoldsUnderEveryProfile) already holds this
// over every shipped profile, but does not touch this renderer. This test
// confirms the renderer itself never emits MET for an objective the
// determinations file did not name.
func TestSummarizeL1NeverWritesMETItself(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	det := &Determinations{
		SchemaVersion: "1.0.0",
		List: []Determination{
			{
				ID:               "media-disposal-2026",
				Objectives:       []string{"MP.L1-b.1.vii"},
				Value:            "MET",
				Statement:        "All removable media is degaussed before reuse per our written procedure.",
				Date:             "2026-08-01",
				ResponsibleParty: "Jane Researcher, PI",
			},
		},
	}
	result, err := SummarizeL1(profile, art, det, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	for _, row := range result.Objectives {
		if row.ID == "MP.L1-b.1.vii" {
			if row.Resolved != "MET" {
				t.Errorf("objective with a MET determination resolved %q, want MET", row.Resolved)
			}
			if row.Determination != "media-disposal-2026" {
				t.Errorf("Determination = %q, want media-disposal-2026", row.Determination)
			}
			continue
		}
		if row.Resolved == "MET" {
			t.Errorf("objective %s resolved MET with no determination naming it — "+
				"automat may only ever write NOT MET on its own (Invariant 2)", row.ID)
		}
	}
	if result.L1Summary.MetCount != 1 {
		t.Errorf("MetCount = %d, want 1", result.L1Summary.MetCount)
	}
	if result.L1Summary.AffirmationPossible {
		t.Error("AffirmationPossible = true with 14 practices still NOT MET, want false")
	}
}

// TestSummarizeL1AffirmationPossibleOnlyWhenEveryPracticeIsMet exercises the
// other side: every one of the fifteen practices covered by a MET
// determination is the only shape that may report AffirmationPossible true.
func TestSummarizeL1AffirmationPossibleOnlyWhenEveryPracticeIsMet(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	det := &Determinations{SchemaVersion: "1.0.0"}
	for _, c := range art.Controls {
		det.List = append(det.List, Determination{
			ID:               "met-" + c.ID,
			Objectives:       []string{c.ID},
			Value:            "MET",
			Statement:        "Reviewed and confirmed in place.",
			Date:             "2026-08-01",
			ResponsibleParty: "Jane Researcher, PI",
		})
	}
	result, err := SummarizeL1(profile, art, det, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	if result.L1Summary.NotMetCount != 0 {
		t.Errorf("NotMetCount = %d, want 0", result.L1Summary.NotMetCount)
	}
	if !result.L1Summary.AffirmationPossible {
		t.Error("AffirmationPossible = false with every practice MET, want true")
	}
	if result.L1Summary.Total != len(art.Controls) {
		t.Errorf("Total = %d, want %d", result.L1Summary.Total, len(art.Controls))
	}
}

func TestSummarizeL1RefusesANonCMMCL1Profile(t *testing.T) {
	path := filepath.Join("..", "..", "catalogs", "obligations", "dfars-7012.json")
	profile, err := LoadProfile(path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadProfile(%s): %v", path, err)
	}
	art := loadCMMCL1Artifact(t)
	if _, err := SummarizeL1(profile, art, nil, testAccount(), "dev", "2026-08-09T00:00:00Z"); err == nil {
		t.Fatal("SummarizeL1 accepted a non-cmmc-l1 profile, want a refusal")
	}
}

func TestSummarizeL1RefusesADeterminationValueOutsideTheVocabulary(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	det := &Determinations{
		SchemaVersion: "1.0.0",
		List: []Determination{
			{
				ID:               "bad",
				Objectives:       []string{"MP.L1-b.1.vii"},
				Value:            "PARTIALLY MET",
				Statement:        "x",
				Date:             "2026-08-01",
				ResponsibleParty: "Jane Researcher, PI",
			},
		},
	}
	if _, err := SummarizeL1(profile, art, det, testAccount(), "dev", "2026-08-09T00:00:00Z"); err == nil {
		t.Fatal("SummarizeL1 accepted a determination value outside cmmc-l1's vocabulary, want a refusal")
	}
}

// TestSummarizeL1CarriesThePolicyCaveat is the substance check
// docs/policy-caveat.md requires on every assess output.
func TestSummarizeL1CarriesThePolicyCaveat(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	result, err := SummarizeL1(profile, art, nil, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	if missing := missingCaveatSubstance(result.PolicyCaveat); len(missing) > 0 {
		t.Errorf("Result.PolicyCaveat is missing %v (docs/policy-caveat.md)", missing)
	}
}

func TestSummarizeL1DeterminationsReferenceIsAbsentWhenNoneGiven(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	result, err := SummarizeL1(profile, art, nil, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	if result.Determinations != nil {
		t.Error("Result.Determinations is present with no determinations file given, want absent — " +
			"an absent field is the honest 'nothing determined yet' state, not an empty reference")
	}
}

func TestSummarizeL1DeterminationsReferenceIsPresentWhenGiven(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	det := &Determinations{
		SchemaVersion: "1.0.0",
		List: []Determination{
			{
				ID:               "media-disposal-2026",
				Objectives:       []string{"MP.L1-b.1.vii"},
				Value:            "MET",
				Statement:        "All removable media is degaussed before reuse per our written procedure.",
				Date:             "2026-08-01",
				ResponsibleParty: "Jane Researcher, PI",
			},
		},
	}
	result, err := SummarizeL1(profile, art, det, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err != nil {
		t.Fatalf("SummarizeL1: %v", err)
	}
	if result.Determinations == nil {
		t.Fatal("Result.Determinations is absent with a determinations file given, want present")
	}
	wantHash, err := det.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if result.Determinations.ContentSHA256 != wantHash {
		t.Errorf("Determinations.ContentSHA256 = %s, want %s", result.Determinations.ContentSHA256, wantHash)
	}
}

// TestSummarizeL1RefusesAMalformedAccountID and
// TestSummarizeL1RefusesAScopeStatementCarryingControlCharacters are AUDIT-5's
// findings: ResultAccount reached Result and RenderL1Summary with no
// validation at all, unlike every other prose field this package renders.
// Concretely, an ANSI escape or a signature-affordance phrase in
// --scope-statement flowed straight into the DRAFT summary before this fix.
func TestSummarizeL1RefusesAMalformedAccountID(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	account := ResultAccount{ID: "not-an-account-id", ScopeStatement: "x"}
	if _, err := SummarizeL1(profile, art, nil, account, "dev", "2026-08-09T00:00:00Z"); err == nil {
		t.Fatal("SummarizeL1 accepted a malformed account id, want a refusal")
	}
}

func TestSummarizeL1RefusesAScopeStatementCarryingControlCharacters(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	account := ResultAccount{
		ID:             "111122223333",
		ScopeStatement: "Every practice resolves MET. Signed: __________ I certify this.\x1b[31m",
	}
	if _, err := SummarizeL1(profile, art, nil, account, "dev", "2026-08-09T00:00:00Z"); err == nil {
		t.Fatal("SummarizeL1 accepted a scope statement carrying an ANSI escape, want a refusal")
	}
}

func TestSummarizeL1RefusesAnEmptyScopeStatement(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	account := ResultAccount{ID: "111122223333", ScopeStatement: ""}
	if _, err := SummarizeL1(profile, art, nil, account, "dev", "2026-08-09T00:00:00Z"); err == nil {
		t.Fatal("SummarizeL1 accepted an empty scope statement, want a refusal")
	}
}

// TestSummarizeL1RefusesADeterminationNamingAnObjectiveTheCatalogDoesNotHave
// is AUDIT-5's other finding: a typo'd objective id in a determinations file
// used to be silently dropped — ForObjective never matched it, the practice
// stayed NOT MET, and the operator's own claim vanished with no error and no
// trace. That never overstated compliance, but a determination that
// silently does nothing is its own defect.
func TestSummarizeL1RefusesADeterminationNamingAnObjectiveTheCatalogDoesNotHave(t *testing.T) {
	profile := validCMMCL1(t)
	art := loadCMMCL1Artifact(t)
	det := &Determinations{
		SchemaVersion: "1.0.0",
		List: []Determination{
			{
				ID:               "typo-det",
				Objectives:       []string{"MP.L1-b1.vii"}, // missing the dot before b1
				Value:            "MET",
				Statement:        "All removable media is degaussed before reuse.",
				Date:             "2026-08-01",
				ResponsibleParty: "Jane Researcher, PI",
			},
		},
	}
	result, err := SummarizeL1(profile, art, det, testAccount(), "dev", "2026-08-09T00:00:00Z")
	if err == nil {
		t.Fatalf("SummarizeL1 accepted a determination naming an objective outside cmmc-l1's "+
			"catalog, want a refusal (result: %+v)", result)
	}
}
