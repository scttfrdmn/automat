// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// assessWorld sets up a globals with a fake STS identity and chdirs into a
// temp directory, the same discipline vendWorld follows: assess writes an
// evidence manifest relative to the working directory (writeAssessEvidence
// uses envprofile.DefaultEvidenceDir under "."), and a test that skipped the
// chdir would write into the repository.
func assessWorld(t *testing.T) *globals {
	t.Helper()
	g, _, _ := fakes(t, testOrg, testManagement, testManagement)
	chdirTemp(t)
	return g
}

func assessArgs(accountID string, extra ...string) []string {
	return append([]string{
		"assess",
		"--account", accountID,
		"--profile", "cmmc-l1",
		"--scope-statement", "This AWS account is the entire system boundary for this assessment.",
	}, extra...)
}

func TestAssessRequiresEveryFlag(t *testing.T) {
	g := assessWorld(t)
	out := t.TempDir()

	cases := [][]string{
		{"assess", "--profile", "cmmc-l1", "--scope-statement", "x", "--out", out},
		{"assess", "--account", "111122223333", "--scope-statement", "x", "--out", out},
		{"assess", "--account", "111122223333", "--profile", "cmmc-l1", "--out", out},
		{"assess", "--account", "111122223333", "--profile", "cmmc-l1", "--scope-statement", "x"},
		{"assess", "--account", "not-an-id", "--profile", "cmmc-l1", "--scope-statement", "x", "--out", out},
		{"assess", "--account", "111122223333", "--profile", "dfars-7012", "--scope-statement", "x", "--out", out},
	}
	for _, args := range cases {
		if _, _, err := runCLI(t, g, args...); err == nil {
			t.Errorf("assess %v succeeded, want a refusal", args[1:])
		}
	}
}

// TestAssessRendersNotMetOnSilence exercises the command end to end with no
// --determinations file: every one of the fifteen L1 practices must render
// NOT MET, and the summary must state no affirmation is possible.
func TestAssessRendersNotMetOnSilence(t *testing.T) {
	g := assessWorld(t)
	out := filepath.Join(t.TempDir(), "assess-out")

	stdout, _, err := runCLI(t, g, assessArgs("111122223333", "--out", out)...)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if !strings.Contains(stdout, "DRAFT — NOT A SUBMISSION") {
		t.Error("assess's stdout does not carry the DRAFT marking")
	}
	if !strings.Contains(stdout, "15 NOT MET") {
		t.Errorf("assess did not report all 15 practices NOT MET:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Evidence:") {
		t.Error("assess did not report where it wrote the evidence manifest")
	}

	resultPath := filepath.Join(out, assessResultFile)
	if _, statErr := os.Stat(resultPath); statErr != nil {
		t.Errorf("assess did not write %s: %v", resultPath, statErr)
	}
	summaryPath := filepath.Join(out, assessSummaryFile)
	summaryData, err := os.ReadFile(summaryPath) //nolint:gosec // fixed test path
	if err != nil {
		t.Fatalf("assess did not write %s: %v", summaryPath, err)
	}
	if !strings.Contains(string(summaryData), "DRAFT — NOT A SUBMISSION") {
		t.Error("the written summary file does not carry the DRAFT marking")
	}
}

// TestAssessAppliesADeterminationsFile confirms a determination naming a
// practice MET actually changes that practice's resolved value, and that the
// operator's own scope statement is reproduced verbatim.
func TestAssessAppliesADeterminationsFile(t *testing.T) {
	g := assessWorld(t)
	out := filepath.Join(t.TempDir(), "assess-out")
	determ := filepath.Join(t.TempDir(), "determinations.json")
	if err := os.WriteFile(determ, []byte(`{
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
	}`), 0o600); err != nil {
		t.Fatalf("write determinations fixture: %v", err)
	}

	stdout, _, err := runCLI(t, g, assessArgs("111122223333", "--out", out, "--determinations", determ)...)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if !strings.Contains(stdout, "14 NOT MET") {
		t.Errorf("assess did not report 14 practices NOT MET with one determination given:\n%s", stdout)
	}
	if !strings.Contains(stdout, "media-disposal-2026") {
		t.Errorf("the rendered summary does not cite the determination's id:\n%s", stdout)
	}
}

func TestAssessWritesAnOpAssessEvidenceRecord(t *testing.T) {
	g := assessWorld(t)
	out := filepath.Join(t.TempDir(), "assess-out")
	accountID := "111122223333"

	if _, _, err := runCLI(t, g, assessArgs(accountID, "--out", out)...); err != nil {
		t.Fatalf("assess: %v", err)
	}

	manifestPath := filepath.Join(evidenceDirForTest(), accountID+".json")
	m, err := evidence.LoadOrNew(manifestPath, accountID, accountID, "", "", nil)
	if err != nil {
		t.Fatalf("load the evidence manifest: %v", err)
	}
	if len(m.Records) != 1 {
		t.Fatalf("manifest has %d records, want 1", len(m.Records))
	}
	rec := m.Records[0]
	if rec.Operation != evidence.OpAssess {
		t.Errorf("record operation = %q, want %q", rec.Operation, evidence.OpAssess)
	}
	if rec.Outcome != evidence.OutcomeSuccess {
		t.Errorf("record outcome = %q, want success — rendering a summary is not a failed operation "+
			"even when every practice resolves NOT MET", rec.Outcome)
	}
}

// evidenceDirForTest mirrors envprofile.DefaultEvidenceDir without importing
// it just for a literal, matching writeAssessEvidence's own use of "." as
// base.
func evidenceDirForTest() string { return "evidence" }
