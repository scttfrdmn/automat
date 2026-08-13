// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scttfrdmn/automat/internal/compilesets"
)

func testGroup(id, frequency string) compilesets.DedupedAttestation {
	return compilesets.DedupedAttestation{ControlIDs: []string{id}, Frequency: frequency}
}

// chdirTemp changes to a fresh temp directory for the duration of the test —
// CheckProcedural resolves dir relative to the working directory, the same
// convention internal/baseline.EnsureAttestationStubs and every evidence
// path in this codebase already use.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	return dir
}

// writeStub writes a stub file directly, bypassing baseline.EnsureAttestationStubs
// — this package tests CheckProcedural's own read path, not the writer's, so
// the fixture only needs a plain file at the expected location.
func writeStub(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCheckProceduralAllCurrent holds the clean case: every group's stub
// exists, carries content, and is younger than its own frequency's
// staleness threshold.
func TestCheckProceduralAllCurrent(t *testing.T) {
	chdirTemp(t)
	writeStub(t, "compliance", "3.1.1.md", "filled in")
	groups := []compilesets.DedupedAttestation{testGroup("3.1.1", "annual")}

	report, err := CheckProcedural("compliance", groups, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: %+v", report.Stubs)
	}
	if len(report.Stubs) != 1 || !report.Stubs[0].Present || report.Stubs[0].Empty || report.Stubs[0].Stale {
		t.Errorf("got %+v, want present/non-empty/not-stale", report.Stubs)
	}
}

// TestCheckProceduralMissingStub is the "documented control with no
// evidence it was ever attested" finding.
func TestCheckProceduralMissingStub(t *testing.T) {
	chdirTemp(t)
	groups := []compilesets.DedupedAttestation{testGroup("3.1.1", "annual")}

	report, err := CheckProcedural("compliance", groups, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the stub was never written")
	}
	if report.Stubs[0].Present {
		t.Error("Present = true, want false: no stub, and no directory, exists")
	}
}

// TestCheckProceduralEmptyStubIsADifferentFindingFromMissing holds the
// distinction the task calls for explicitly: a stub that exists but was
// never filled in is Present but Empty, not the same finding as a missing
// stub.
func TestCheckProceduralEmptyStubIsADifferentFindingFromMissing(t *testing.T) {
	chdirTemp(t)
	writeStub(t, "compliance", "3.1.1.md", "")
	groups := []compilesets.DedupedAttestation{testGroup("3.1.1", "annual")}

	report, err := CheckProcedural("compliance", groups, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the stub is empty")
	}
	s := report.Stubs[0]
	if !s.Present {
		t.Error("Present = false, want true: the file exists")
	}
	if !s.Empty {
		t.Error("Empty = false, want true: the file carries no content")
	}
}

// TestCheckProceduralStaleStub holds the staleness-vs-frequency comparison:
// a stub whose mtime is older than its frequency's threshold is Stale.
func TestCheckProceduralStaleStub(t *testing.T) {
	dir := chdirTemp(t)
	writeStub(t, "compliance", "3.1.1.md", "filled in")
	old := time.Now().Add(-400 * 24 * time.Hour) // older than annual's 365-day threshold
	if err := os.Chtimes(filepath.Join(dir, "compliance", "3.1.1.md"), old, old); err != nil {
		t.Fatal(err)
	}
	groups := []compilesets.DedupedAttestation{testGroup("3.1.1", "annual")}

	report, err := CheckProcedural("compliance", groups, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if report.Clean() {
		t.Fatal("Clean() = true, want false: the stub is 400 days old against an annual cadence")
	}
	s := report.Stubs[0]
	if !s.Present || s.Empty {
		t.Fatalf("got %+v, want present and non-empty", s)
	}
	if !s.StaleChecked {
		t.Fatal("StaleChecked = false, want true: annual is a time-checkable frequency")
	}
	if !s.Stale {
		t.Error("Stale = false, want true")
	}
}

// TestCheckProceduralCurrentStubJustInsideThreshold is the counter-check:
// a stub just younger than its threshold must NOT be stale, so the test
// above is pinning an actual boundary rather than something that always
// reports stale.
func TestCheckProceduralCurrentStubJustInsideThreshold(t *testing.T) {
	dir := chdirTemp(t)
	writeStub(t, "compliance", "3.1.1.md", "filled in")
	recent := time.Now().Add(-300 * 24 * time.Hour) // younger than annual's 365-day threshold
	if err := os.Chtimes(filepath.Join(dir, "compliance", "3.1.1.md"), recent, recent); err != nil {
		t.Fatal(err)
	}
	groups := []compilesets.DedupedAttestation{testGroup("3.1.1", "annual")}

	report, err := CheckProcedural("compliance", groups, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if !report.Clean() {
		t.Errorf("Clean() = false, want true: %+v", report.Stubs)
	}
}

// TestCheckProceduralOnChangeAndContinuousAreNeverStaleByTime holds the
// staleAfter map's own deliberate absence: neither "on-change" nor
// "continuous" is a calendar fact, so a stub of either cadence must report
// StaleChecked: false regardless of age, and Clean() must not be tripped by
// age alone.
func TestCheckProceduralOnChangeAndContinuousAreNeverStaleByTime(t *testing.T) {
	for _, freq := range []string{"on-change", "continuous"} {
		t.Run(freq, func(t *testing.T) {
			dir := chdirTemp(t)
			writeStub(t, "compliance", "3.1.1.md", "filled in")
			ancient := time.Now().Add(-10 * 365 * 24 * time.Hour)
			if err := os.Chtimes(filepath.Join(dir, "compliance", "3.1.1.md"), ancient, ancient); err != nil {
				t.Fatal(err)
			}
			groups := []compilesets.DedupedAttestation{testGroup("3.1.1", freq)}

			report, err := CheckProcedural("compliance", groups, time.Now())
			if err != nil {
				t.Fatalf("CheckProcedural: %v", err)
			}
			if report.Stubs[0].StaleChecked {
				t.Errorf("StaleChecked = true for frequency %q, want false: staleness is not a calendar "+
					"fact for this cadence", freq)
			}
			if !report.Clean() {
				t.Errorf("Clean() = false, want true: a 10-year-old %q stub must not be reported stale "+
					"by time alone", freq)
			}
		})
	}
}

// TestCheckProceduralNoGroupsIsClean is the "nothing was asked for" case:
// a compile with no procedural control at all must report an empty,
// clean result rather than iterating over nothing and returning an error.
func TestCheckProceduralNoGroupsIsClean(t *testing.T) {
	chdirTemp(t)
	report, err := CheckProcedural("compliance", nil, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if !report.Clean() {
		t.Error("Clean() = false, want true: no groups were given")
	}
	if len(report.Stubs) != 0 {
		t.Errorf("Stubs = %+v, want empty", report.Stubs)
	}
}

// TestCheckProceduralMultipleGroupsIndependent holds that one group's
// finding does not leak into another's — a missing stub for one control and
// a current one for another must each report their own state.
func TestCheckProceduralMultipleGroupsIndependent(t *testing.T) {
	chdirTemp(t)
	writeStub(t, "compliance", "3.1.1.md", "filled in")
	groups := []compilesets.DedupedAttestation{
		testGroup("3.1.1", "annual"),
		testGroup("3.5.2", "annual"),
	}

	report, err := CheckProcedural("compliance", groups, time.Now())
	if err != nil {
		t.Fatalf("CheckProcedural: %v", err)
	}
	if len(report.Stubs) != 2 {
		t.Fatalf("got %d stubs, want 2", len(report.Stubs))
	}
	if !report.Stubs[0].Present {
		t.Error("3.1.1's stub reported absent, want present")
	}
	if report.Stubs[1].Present {
		t.Error("3.5.2's stub reported present, want absent: it was never written")
	}
}
