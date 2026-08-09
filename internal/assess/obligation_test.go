// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"os"
	"path/filepath"
	"testing"
)

const cmmcL1Path = "../../catalogs/obligations/cmmc-l1.json"

func TestLoadProfileLoadsTheShippedCMMCL1Profile(t *testing.T) {
	p, err := LoadProfile(cmmcL1Path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadProfile(%s): %v", cmmcL1Path, err)
	}
	if p.Meta.ID != "cmmc-l1" {
		t.Errorf("Meta.ID = %q, want cmmc-l1", p.Meta.ID)
	}
	if p.Determinations.UnderstatementValue != "NOT MET" {
		t.Errorf("UnderstatementValue = %q, want NOT MET", p.Determinations.UnderstatementValue)
	}
	if p.POAM.Permitted {
		t.Error("POAM.Permitted = true, want false for CMMC L1")
	}
	if p.Determinations.PartialCredit {
		t.Error("Determinations.PartialCredit = true, want false for CMMC L1")
	}
	if len(p.ControlCatalogs) != 1 || p.ControlCatalogs[0].RevisionPolicy != "pinned" {
		t.Errorf("ControlCatalogs = %+v, want one pinned entry", p.ControlCatalogs)
	}
	if !p.Applicability.DeclaredByOperator {
		t.Error("Applicability.DeclaredByOperator = false, want true")
	}
}

// TestLoadProfileLoadsEveryShippedProfile confirms this package's reader —
// the first Go-typed one an obligation profile has had — actually parses
// and validates all three profiles this project ships, not just the one
// Stage 3 renders against. dfars-7012 and nih-cadr-dua exercise shapes
// cmmc-l1 does not: a permitted POA&M, a dfars-110-weighted scoring method
// with an all-zero placeholder weight-table hash (Q10, not yet
// transcribed), and nih-cadr-dua's operator-determined revision policy.
func TestLoadProfileLoadsEveryShippedProfile(t *testing.T) {
	for _, name := range []string{"cmmc-l1", "dfars-7012", "nih-cadr-dua"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "catalogs", "obligations", name+".json")
			p, err := LoadProfile(path, LoadOptions{})
			if err != nil {
				t.Fatalf("LoadProfile(%s): %v", path, err)
			}
			if p.Meta.ID != name {
				t.Errorf("Meta.ID = %q, want %q", p.Meta.ID, name)
			}
		})
	}
}

func TestLoadProfileRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	writeFile(t, bad, `{"schema_version":"1.0.0","profile":{"id":"x","title":"x","issuing_authority":"x"},"typo":true}`)
	if _, err := LoadProfile(bad, LoadOptions{}); err == nil {
		t.Fatal("LoadProfile accepted a document with an unknown field, want a refusal")
	}
}

func TestLoadProfileRejectsDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "dup.json")
	// review_by stated twice — DisallowUnknownFields does not catch a key
	// known twice, which is exactly the shape RejectDuplicateKeys exists for.
	writeFile(t, bad, `{"schema_version":"1.0.0","review_by":"2020-01-01","review_by":"2099-01-01"}`)
	if _, err := LoadProfile(bad, LoadOptions{}); err == nil {
		t.Fatal("LoadProfile accepted a document with a duplicate key, want a refusal")
	}
}

func TestValidateReportsEveryMissingRequiredField(t *testing.T) {
	p := &Profile{}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted an empty profile")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error is a %T, not *ValidationError", err)
	}
	if len(ve.Problems) < 5 {
		t.Errorf("got %d problems, want several — Validate should report every issue in one pass, "+
			"not stop at the first: %v", len(ve.Problems), ve.Problems)
	}
}

func TestValidateRefusesAPinnedRevisionOnAnOperatorDeterminedCatalog(t *testing.T) {
	p := validCMMCL1(t)
	p.ControlCatalogs[0].RevisionPolicy = RevisionOperatorDetermined
	p.ControlCatalogs[0].Revision = "Revision 2"
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted a pinned revision on an operator-determined catalog, want a refusal " +
			"— a pinned revision there is a default wearing a different hat")
	}
}

func TestValidateRefusesAnUnderstatementValueOutsideTheVocabulary(t *testing.T) {
	p := validCMMCL1(t)
	p.Determinations.UnderstatementValue = "PARTIALLY MET"
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted an understatement_value not in determinations.values, want a refusal")
	}
}

func TestValidateRefusesAWeightTableOnANoneScoringMethod(t *testing.T) {
	p := validCMMCL1(t)
	p.Scoring.WeightTable = &HashedReference{ID: "x", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted a weight_table alongside scoring.method=none, want a refusal")
	}
}

func TestValidateRefusesADFARSScoringMethodWithNoWeightTable(t *testing.T) {
	p := validCMMCL1(t)
	p.Scoring.Method = "dfars-110-weighted"
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted a scoring method with no weight table, want a refusal")
	}
}

func TestValidateRefusesDeclaredByOperatorFalse(t *testing.T) {
	p := validCMMCL1(t)
	p.Applicability.DeclaredByOperator = false
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted declared_by_operator=false, want a refusal")
	}
}

func TestIsUnderstatementValue(t *testing.T) {
	d := DeterminationSpec{Values: []string{"MET", "NOT MET"}, UnderstatementValue: "NOT MET"}
	if !d.IsUnderstatementValue("NOT MET") {
		t.Error("IsUnderstatementValue(\"NOT MET\") = false, want true")
	}
	if d.IsUnderstatementValue("MET") {
		t.Error("IsUnderstatementValue(\"MET\") = true, want false")
	}
}

// validCMMCL1 loads the shipped profile as a starting point for a mutation
// test, so each test asserts one field's constraint against an otherwise
// valid document rather than against a hand-built one that might already be
// invalid for an unrelated reason.
func validCMMCL1(t *testing.T) *Profile {
	t.Helper()
	p, err := LoadProfile(cmmcL1Path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadProfile(%s): %v", cmmcL1Path, err)
	}
	return p
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
