// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"path/filepath"
	"testing"
)

func validDeterminations() *Determinations {
	return &Determinations{
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
}

func TestDeterminationsValidateAcceptsAValidDocument(t *testing.T) {
	if err := validDeterminations().Validate(); err != nil {
		t.Fatalf("Validate rejected a document this test considers valid: %v", err)
	}
}

func TestDeterminationsValidateRejectsEmptyList(t *testing.T) {
	d := validDeterminations()
	d.List = nil
	if err := d.Validate(); err == nil {
		t.Fatal("Validate accepted a document with no determinations, want a refusal")
	}
}

func TestDeterminationsValidateRejectsWhitespaceInID(t *testing.T) {
	d := validDeterminations()
	d.List[0].ID = "media disposal 2026"
	if err := d.Validate(); err == nil {
		t.Fatal("Validate accepted an id containing a space, want a refusal — " +
			"CLAUDE.md rule 8 round-trip ids must not carry whitespace")
	}
}

func TestDeterminationsValidateRejectsDuplicateID(t *testing.T) {
	d := validDeterminations()
	d.List = append(d.List, Determination{
		ID:               "media-disposal-2026",
		Objectives:       []string{"MP.L1-b.1.viii"},
		Value:            "MET",
		Statement:        "Second entry reusing the first's id.",
		Date:             "2026-08-01",
		ResponsibleParty: "Jane Researcher, PI",
	})
	if err := d.Validate(); err == nil {
		t.Fatal("Validate accepted two determinations sharing one id, want a refusal")
	}
}

func TestDeterminationsValidateRejectsConflictingObjectiveClaims(t *testing.T) {
	d := validDeterminations()
	d.List = append(d.List, Determination{
		ID:               "media-disposal-second-look",
		Objectives:       []string{"MP.L1-b.1.vii"},
		Value:            "NOT MET",
		Statement:        "A second, conflicting determination over the same objective.",
		Date:             "2026-08-02",
		ResponsibleParty: "Someone Else",
	})
	if err := d.Validate(); err == nil {
		t.Fatal("Validate accepted two determinations claiming the same objective, want a refusal — " +
			"one objective may not carry two conflicting determinations")
	}
}

func TestDeterminationsValidateRejectsMissingStatement(t *testing.T) {
	d := validDeterminations()
	d.List[0].Statement = ""
	if err := d.Validate(); err == nil {
		t.Fatal("Validate accepted a determination with no statement, want a refusal — " +
			"a reader evaluates a sentence, not a bare value")
	}
}

func TestDeterminationsValidateAcceptsAWellFormedRevisionDetermination(t *testing.T) {
	d := validDeterminations()
	d.RevisionDetermination = &RevisionDetermination{
		Catalog:      "nist-sp-800-171",
		Revision:     "Revision 2",
		DeterminedBy: "Jane Researcher, PI",
		DeterminedAt: "2026-08-01",
		Statement:    "Our office has determined Revision 2 applies to this data use agreement.",
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate rejected a well-formed revision_determination: %v", err)
	}
}

func TestDeterminationsValidateRejectsAnIncompleteRevisionDetermination(t *testing.T) {
	d := validDeterminations()
	d.RevisionDetermination = &RevisionDetermination{Catalog: "nist-sp-800-171"}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate accepted a revision_determination missing its other required fields")
	}
}

func TestDeterminationsValidateAgainstRejectsAValueOutsideTheProfileVocabulary(t *testing.T) {
	p := validCMMCL1(t)
	d := validDeterminations()
	d.List[0].Value = "PARTIALLY MET"
	if err := d.ValidateAgainst(p); err == nil {
		t.Fatal("ValidateAgainst accepted a determination value outside cmmc-l1's vocabulary, want a refusal")
	}
}

func TestDeterminationsValidateAgainstAcceptsAValueInTheProfileVocabulary(t *testing.T) {
	p := validCMMCL1(t)
	d := validDeterminations()
	if err := d.ValidateAgainst(p); err != nil {
		t.Fatalf("ValidateAgainst rejected a value that is in cmmc-l1's own vocabulary: %v", err)
	}
}

func TestDeterminationsValidateAgainstRequiresARevisionDeterminationWhenTheProfileLeavesItOperatorDetermined(t *testing.T) {
	path := filepath.Join("..", "..", "catalogs", "obligations", "nih-cadr-dua.json")
	p, err := LoadProfile(path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadProfile(%s): %v", path, err)
	}
	d := &Determinations{
		SchemaVersion: "1.0.0",
		List: []Determination{
			{
				ID:               "placeholder",
				Objectives:       []string{"3.1.1"},
				Value:            "MET",
				Statement:        "placeholder statement",
				Date:             "2026-08-01",
				ResponsibleParty: "Jane Researcher, PI",
			},
		},
	}
	if err := d.ValidateAgainst(p); err == nil {
		t.Fatal("ValidateAgainst accepted a determinations document with no revision_determination " +
			"against a profile that leaves its catalog revision operator-determined")
	}
}

func TestDeterminationsFindReturnsTheMatchingDetermination(t *testing.T) {
	d := validDeterminations()
	got, ok := d.Find("media-disposal-2026")
	if !ok {
		t.Fatal("Find did not find the determination this document names")
	}
	if got.Value != "MET" {
		t.Errorf("Find returned Value = %q, want MET", got.Value)
	}
	if _, ok := d.Find("does-not-exist"); ok {
		t.Error("Find reported finding an id this document does not have")
	}
}

func TestDeterminationsForObjectiveReturnsTheMatchingDetermination(t *testing.T) {
	d := validDeterminations()
	got, ok := d.ForObjective("MP.L1-b.1.vii")
	if !ok {
		t.Fatal("ForObjective did not find the determination naming this objective")
	}
	if got.ID != "media-disposal-2026" {
		t.Errorf("ForObjective returned ID = %q, want media-disposal-2026", got.ID)
	}
	if _, ok := d.ForObjective("AC.L1-b.1.i"); ok {
		t.Error("ForObjective reported finding an objective this document does not name")
	}
}

func TestDeterminationsContentHashIsStableAcrossEquivalentDocuments(t *testing.T) {
	a := validDeterminations()
	b := validDeterminations()
	ha, err := a.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	hb, err := b.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if ha != hb {
		t.Errorf("two equivalent documents hashed differently: %s vs %s", ha, hb)
	}
	b.List[0].Value = "NOT MET"
	hc, err := b.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if hc == ha {
		t.Error("changing a determination's value did not change the content hash")
	}
}

func TestLoadDeterminationsRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	writeFile(t, bad, `{"schema_version":"1.0.0","determinations":[],"typo":true}`)
	if _, err := LoadDeterminations(bad, LoadOptions{SkipValidate: true}); err == nil {
		t.Fatal("LoadDeterminations accepted a document with an unknown field, want a refusal")
	}
}

func TestLoadDeterminationsRejectsDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "dup.json")
	writeFile(t, bad, `{"schema_version":"1.0.0","schema_version":"1.0.1","determinations":[]}`)
	if _, err := LoadDeterminations(bad, LoadOptions{SkipValidate: true}); err == nil {
		t.Fatal("LoadDeterminations accepted a document with a duplicate key, want a refusal")
	}
}

func TestLoadDeterminationsLoadsAWellFormedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "good.json")
	writeFile(t, path, `{
		"schema_version": "1.0.0",
		"determinations": [
			{
				"id": "media-disposal-2026",
				"objectives": ["MP.L1-b.1.vii"],
				"value": "MET",
				"statement": "All removable media is degaussed before reuse per our written procedure.",
				"date": "2026-08-01",
				"responsible_party": "Jane Researcher, PI"
			}
		]
	}`)
	d, err := LoadDeterminations(path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadDeterminations(%s): %v", path, err)
	}
	if len(d.List) != 1 || d.List[0].ID != "media-disposal-2026" {
		t.Errorf("LoadDeterminations = %+v, want one determination media-disposal-2026", d.List)
	}
}
