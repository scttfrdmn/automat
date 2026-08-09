// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/artifact"
)

func proceduralArtifact(t *testing.T, id string, controls ...artifact.Control) *artifact.Artifact {
	t.Helper()
	a := &artifact.Artifact{
		SchemaVersion: artifact.SchemaVersion,
		Meta: artifact.Meta{
			ID: id, Title: "Test control set " + id, CompiledAt: "2026-01-01T00:00:00Z",
			Sources: artifact.Sources{{Catalog: "test", SHA256: strings.Repeat("0", 64)}},
		},
		Controls: controls,
	}
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("fixture %s: %v", id, err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture %s is not a valid artifact: %v", id, err)
	}
	return a
}

func proceduralControl(id string, crosswalk map[string]string) artifact.Control {
	return artifact.Control{
		ID:          id,
		Title:       "Procedural control " + id,
		Crosswalk:   crosswalk,
		Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural},
		Attestation: &artifact.Attestation{Template: "media-disposal.md", Frequency: "annual"},
	}
}

func TestDedupeAttestationsGroupsBySharedCrosswalkEntry(t *testing.T) {
	a := proceduralArtifact(t, "set-a",
		proceduralControl("MP.L1-b.1.vii", map[string]string{"800-171r2": "3.8.3"}))
	b := proceduralArtifact(t, "set-b",
		proceduralControl("MEDIA-DISPOSAL", map[string]string{"800-171r2": "3.8.3"}))

	groups, err := DedupeAttestations(a, b)
	if err != nil {
		t.Fatalf("DedupeAttestations: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want one deduped practice: %+v", len(groups), groups)
	}
	g := groups[0]
	if len(g.ControlIDs) != 2 {
		t.Errorf("ControlIDs = %v, want both control ids named (\"the stub lists all satisfied IDs\")",
			g.ControlIDs)
	}
	if len(g.Origins) != 2 {
		t.Errorf("Origins = %v, want both artifacts named", g.Origins)
	}
}

func TestDedupeAttestationsTransitiveAcrossThreeCatalogs(t *testing.T) {
	// A cites 800-171r2, B cites 800-171r2 AND cmmc-l1, C cites only cmmc-l1.
	// A and C share no crosswalk entry directly, but both are tied to B —
	// the transitivity DESIGN §9's dedupe rule requires.
	a := proceduralArtifact(t, "set-a",
		proceduralControl("control-a", map[string]string{"800-171r2": "3.8.3"}))
	b := proceduralArtifact(t, "set-b",
		proceduralControl("control-b", map[string]string{"800-171r2": "3.8.3", "cmmc-l1": "MP.L1-b.1.vii"}))
	c := proceduralArtifact(t, "set-c",
		proceduralControl("control-c", map[string]string{"cmmc-l1": "MP.L1-b.1.vii"}))

	groups, err := DedupeAttestations(a, b, c)
	if err != nil {
		t.Fatalf("DedupeAttestations: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want one — A and C are transitively tied through B: %+v", len(groups), groups)
	}
	if len(groups[0].ControlIDs) != 3 {
		t.Errorf("ControlIDs = %v, want all three control ids", groups[0].ControlIDs)
	}
}

func TestDedupeAttestationsNoSharedCrosswalkStaysSeparate(t *testing.T) {
	a := proceduralArtifact(t, "set-a",
		proceduralControl("control-a", map[string]string{"800-171r2": "3.8.3"}))
	b := proceduralArtifact(t, "set-b",
		proceduralControl("control-b", map[string]string{"800-171r2": "3.5.1"}))

	groups, err := DedupeAttestations(a, b)
	if err != nil {
		t.Fatalf("DedupeAttestations: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want two separate practices with no shared crosswalk entry: %+v",
			len(groups), groups)
	}
}

func TestDedupeAttestationsIgnoresNonProceduralControls(t *testing.T) {
	a := proceduralArtifact(t, "set-a", artifact.Control{
		ID: "preventive-only", Title: "t",
		Enforcement: []artifact.EnforcementClass{artifact.EnforcementSCP},
		SCP:         &artifact.SCP{Statements: []artifact.SCPStatement{denyFragment("A", "iam:CreateUser")}},
	})
	groups, err := DedupeAttestations(a)
	if err != nil {
		t.Fatalf("DedupeAttestations: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("got %d groups, want none — the only control is preventive, not procedural", len(groups))
	}
}

func TestDedupeAttestationsNoArtifactsIsEmpty(t *testing.T) {
	groups, err := DedupeAttestations()
	if err != nil {
		t.Fatalf("DedupeAttestations: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("got %d groups, want none", len(groups))
	}
}

func TestDedupeAttestationsConflictOnDisagreeingFrequency(t *testing.T) {
	a := proceduralArtifact(t, "set-a", artifact.Control{
		ID: "control-a", Title: "t", Crosswalk: map[string]string{"800-171r2": "3.8.3"},
		Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural},
		Attestation: &artifact.Attestation{Template: "media-disposal.md", Frequency: "annual"},
	})
	b := proceduralArtifact(t, "set-b", artifact.Control{
		ID: "control-b", Title: "t", Crosswalk: map[string]string{"800-171r2": "3.8.3"},
		Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural},
		Attestation: &artifact.Attestation{Template: "media-disposal.md", Frequency: "quarterly"},
	})

	_, err := DedupeAttestations(a, b)
	if err == nil {
		t.Fatal("DedupeAttestations succeeded despite disagreeing frequencies, want a conflict")
	}
	ac, ok := err.(*AttestationConflict)
	if !ok {
		t.Fatalf("error is a %T, not *AttestationConflict: %v", err, err)
	}
	if ac.Field != "frequency" {
		t.Errorf("Field = %q, want %q", ac.Field, "frequency")
	}
}

func TestDedupeAttestationsConflictOnDisagreeingCrosswalkValue(t *testing.T) {
	// Two controls share the cmmc-l1 crosswalk entry (which is what groups
	// them) but disagree about what 800-171r2 requirement the SAME practice
	// maps to — a genuine catalog authoring disagreement, not resolvable by
	// picking either.
	a := proceduralArtifact(t, "set-a", artifact.Control{
		ID: "control-a", Title: "t",
		Crosswalk:   map[string]string{"cmmc-l1": "MP.L1-b.1.vii", "800-171r2": "3.8.3"},
		Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural},
		Attestation: &artifact.Attestation{Template: "media-disposal.md", Frequency: "annual"},
	})
	b := proceduralArtifact(t, "set-b", artifact.Control{
		ID: "control-b", Title: "t",
		Crosswalk:   map[string]string{"cmmc-l1": "MP.L1-b.1.vii", "800-171r2": "3.8.9"},
		Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural},
		Attestation: &artifact.Attestation{Template: "media-disposal.md", Frequency: "annual"},
	})

	_, err := DedupeAttestations(a, b)
	if err == nil {
		t.Fatal("DedupeAttestations succeeded despite disagreeing crosswalk values, want a conflict")
	}
	if _, ok := err.(*AttestationConflict); !ok {
		t.Fatalf("error is a %T, not *AttestationConflict: %v", err, err)
	}
}
