// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/compilesets"
	"github.com/scttfrdmn/automat/internal/org"
)

func testGroups() []compilesets.DedupedAttestation {
	return []compilesets.DedupedAttestation{
		{
			ControlIDs: []string{"3.1.1"},
			Crosswalk:  map[string]string{"800-171r2": "3.1.1"},
			Template:   "access-control.md",
			Frequency:  "annual",
			Guidance:   "Record how access control is implemented.",
			Origins:    []string{"800-171r2:3.1.1"},
		},
		{
			ControlIDs: []string{"MP.L1-b.1.vii"},
			Crosswalk:  map[string]string{"cmmc-l1": "MP.L1-b.1.vii"},
			Template:   "media-sanitization.md",
			Frequency:  "on-change",
			Guidance:   "Record how media is sanitized before disposal.",
			Origins:    []string{"cmmc-l1:MP.L1-b.1.vii"},
		},
	}
}

// TestEnsureAttestationStubsCreatesOnePerGroup is a fresh vend: N deduped
// groups produce N stub files, each named after the group's own first
// control id, each carrying the group's fields.
func TestEnsureAttestationStubsCreatesOnePerGroup(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	e := &Ensurer{Mode: org.ModeApply}
	groups := testGroups()
	stubs, actions, err := e.EnsureAttestationStubs(groups, "compliance")
	if err != nil {
		t.Fatalf("EnsureAttestationStubs: %v", err)
	}
	if len(stubs) != len(groups) {
		t.Fatalf("got %d stubs, want %d", len(stubs), len(groups))
	}

	entries, err := os.ReadDir(filepath.Join(dir, "compliance"))
	if err != nil {
		t.Fatalf("read compliance dir: %v", err)
	}
	if len(entries) != len(groups) {
		t.Fatalf("got %d files on disk, want %d", len(entries), len(groups))
	}

	wantNames := map[string]bool{"3.1.1.md": true, "MP.L1-b.1.vii.md": true}
	for _, e := range entries {
		if !wantNames[e.Name()] {
			t.Errorf("unexpected file %q", e.Name())
		}
	}

	created := 0
	for _, a := range actions {
		if a.Kind != "attestation stub" {
			t.Errorf("unexpected action kind %q", a.Kind)
		}
		if a.Verb == org.VerbCreate {
			created++
			if !a.Applied {
				t.Errorf("a created stub's action must be Applied: %+v", a)
			}
		}
	}
	if created != len(groups) {
		t.Errorf("got %d create actions, want %d", created, len(groups))
	}

	// Content sanity: the first control id's stub carries its own crosswalk,
	// frequency, and guidance, plus the DRAFT marking and a blank Attestation
	// section.
	data, err := os.ReadFile(filepath.Join(dir, "compliance", "3.1.1.md"))
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"DRAFT", "3.1.1", "800-171r2", "annual",
		"Record how access control is implemented.", "## Attestation",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("stub content missing %q:\n%s", want, content)
		}
	}
}

// TestEnsureAttestationStubsIsIdempotent is a re-vend against a stub an
// operator has already hand-edited: the custom content must survive
// byte-for-byte, and the file's mode must not be touched either.
func TestEnsureAttestationStubsIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	groups := testGroups()
	custom := "DRAFT — attestation not yet completed\n\nHand-written attestation text that must survive.\n"
	if err := os.MkdirAll(filepath.Join(dir, "compliance"), 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	stubPath := filepath.Join(dir, "compliance", "3.1.1.md")
	if err := os.WriteFile(stubPath, []byte(custom), 0o644); err != nil {
		t.Fatalf("seed stub: %v", err)
	}

	e := &Ensurer{Mode: org.ModeApply}
	stubs, actions, err := e.EnsureAttestationStubs(groups, "compliance")
	if err != nil {
		t.Fatalf("EnsureAttestationStubs: %v", err)
	}
	if len(stubs) != len(groups) {
		t.Fatalf("got %d stubs, want %d", len(stubs), len(groups))
	}

	got, err := os.ReadFile(stubPath)
	if err != nil {
		t.Fatalf("read stub after re-vend: %v", err)
	}
	if string(got) != custom {
		t.Fatalf("hand-edited stub was overwritten:\ngot:  %q\nwant: %q", got, custom)
	}

	fi, err := os.Stat(stubPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("existing stub's mode was changed to %#o; automat must not touch the mode of a "+
			"stub it did not create", fi.Mode().Perm())
	}

	var unchanged, created int
	for _, a := range actions {
		switch a.Verb {
		case org.VerbUnchanged:
			unchanged++
			if a.Applied {
				t.Errorf("an unchanged action must not be Applied: %+v", a)
			}
		case org.VerbCreate:
			created++
		}
	}
	if unchanged != 1 {
		t.Errorf("got %d unchanged actions, want 1 (only 3.1.1.md pre-existed)", unchanged)
	}
	if created != 1 {
		t.Errorf("got %d create actions, want 1 (MP.L1-b.1.vii.md is still new)", created)
	}
}

// TestEnsureAttestationStubsWritesIntoAnEmptyExistingFile is the one
// exception to "exists = unchanged": an operator's `touch`, carrying no
// content, is written into rather than skipped.
func TestEnsureAttestationStubsWritesIntoAnEmptyExistingFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := os.MkdirAll(filepath.Join(dir, "compliance"), 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	stubPath := filepath.Join(dir, "compliance", "3.1.1.md")
	if err := os.WriteFile(stubPath, nil, 0o600); err != nil {
		t.Fatalf("seed empty stub: %v", err)
	}

	e := &Ensurer{Mode: org.ModeApply}
	_, actions, err := e.EnsureAttestationStubs(testGroups()[:1], "compliance")
	if err != nil {
		t.Fatalf("EnsureAttestationStubs: %v", err)
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbCreate || !actions[0].Applied {
		t.Fatalf("want one applied create action for the empty pre-existing file, got %+v", actions)
	}

	data, err := os.ReadFile(stubPath)
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	if len(data) == 0 {
		t.Error("the empty file was not written into")
	}
}

// TestEnsureAttestationStubsPlanCreatesNothing is CLAUDE.md rule 5: a plan
// must issue no mutating call, and here specifically must not even create
// the directory that would hold the stubs.
func TestEnsureAttestationStubsPlanCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	e := &Ensurer{Mode: org.ModePlan}
	stubs, actions, err := e.EnsureAttestationStubs(testGroups(), "compliance")
	if err != nil {
		t.Fatalf("EnsureAttestationStubs: %v", err)
	}
	if len(stubs) != 2 {
		t.Fatalf("a plan must still report the stubs it would write, got %d", len(stubs))
	}
	if _, err := os.Stat(filepath.Join(dir, "compliance")); !os.IsNotExist(err) {
		t.Errorf("a plan must not create the attestation directory; stat error = %v", err)
	}
	for _, a := range actions {
		if a.Verb != org.VerbUnknown {
			t.Errorf("a plan must report VerbUnknown, got %v", a.Verb)
		}
		if a.Applied {
			t.Errorf("a plan action must never be Applied: %+v", a)
		}
	}
}

// TestEnsureAttestationStubsNoGroupsIsANoOp confirms an empty input produces
// no actions, no stubs, and no error — a profile whose control sets carry no
// procedural controls at all.
func TestEnsureAttestationStubsNoGroupsIsANoOp(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	e := &Ensurer{Mode: org.ModeApply}
	stubs, actions, err := e.EnsureAttestationStubs(nil, "compliance")
	if err != nil {
		t.Fatalf("EnsureAttestationStubs: %v", err)
	}
	if len(stubs) != 0 || len(actions) != 0 {
		t.Errorf("want no stubs and no actions, got %d stubs, %d actions", len(stubs), len(actions))
	}
	if _, err := os.Stat(filepath.Join(dir, "compliance")); !os.IsNotExist(err) {
		t.Error("no groups means nothing should be created, including the directory")
	}
}

// TestEnsureAttestationStubsRefusesNoDirectory is a narrow input check.
func TestEnsureAttestationStubsRefusesNoDirectory(t *testing.T) {
	e := &Ensurer{Mode: org.ModeApply}
	if _, _, err := e.EnsureAttestationStubs(testGroups(), ""); err == nil {
		t.Fatal("want an error for an empty directory")
	}
}

// TestEnsureAttestationStubsRefusesAnUnsafeControlID confirms CLAUDE.md rule
// 8's round-trip discipline: a control id carrying a character that would
// not survive a command line refuses rather than silently producing a
// filename with a slash, a space, or a quote in it.
func TestEnsureAttestationStubsRefusesAnUnsafeControlID(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	groups := []compilesets.DedupedAttestation{{
		ControlIDs: []string{`bad/"id`},
		Frequency:  "annual",
	}}
	e := &Ensurer{Mode: org.ModeApply}
	if _, _, err := e.EnsureAttestationStubs(groups, "compliance"); err == nil {
		t.Fatal("want an error for a control id that cannot become a safe filename")
	}
}
