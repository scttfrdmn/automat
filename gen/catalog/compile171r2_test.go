// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// Tests for the NIST SP 800-171 Revision 2 compiler. Mirrors compile_test.go's
// pattern for cmmc-l1; see that file's header comment for why a golden test is
// the right shape for a vendored catalog.

const golden171r2File = "800-171r2.json"

func compile171r2ForTest(t *testing.T) *artifact.Artifact {
	t.Helper()
	a, err := compileFrom171r2(sourcesDir)
	if err != nil {
		t.Fatalf("compile from %s: %v", sourcesDir, err)
	}
	return a
}

func Test171r2CatalogMatchesGolden(t *testing.T) {
	a := compile171r2ForTest(t)
	got, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(catalogsDir, golden171r2File)

	if updateGolden() {
		if werr := os.WriteFile(path, got, 0o644); werr != nil { //nolint:gosec // reviewed, committed artifact
			t.Fatalf("write %s: %v", path, werr)
		}
		t.Logf("updated %s (content_sha256 %s)", path, a.Meta.ContentHash)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — run `make catalogs`", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s does not match a fresh compile of %s.\n"+
			"If a curated source or the compiler changed on purpose, run `make catalogs` and review the diff.\n"+
			"fresh content_sha256: %s", path, sourcesDir, a.Meta.ContentHash)
	}
}

func Test171r2CompileIsDeterministic(t *testing.T) {
	first := compile171r2ForTest(t)
	firstBytes, err := first.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := range 3 {
		next := compile171r2ForTest(t)
		nextBytes, err := next.MarshalIndented()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(nextBytes) != string(firstBytes) {
			t.Fatalf("compile %d differs from compile 1; the compiler is not deterministic", i+2)
		}
		if next.Meta.ContentHash != first.Meta.ContentHash {
			t.Fatalf("compile %d hashed to %s, want %s", i+2, next.Meta.ContentHash, first.Meta.ContentHash)
		}
	}
}

// Test171r2VendoredCatalogLoadsAndVerifies exercises the path every other
// command will use: load the committed file, validate it, and check its
// declared hash against its actual controls.
func Test171r2VendoredCatalogLoadsAndVerifies(t *testing.T) {
	path := filepath.Join(catalogsDir, golden171r2File)
	a, err := artifact.Load(path, artifact.LoadOptions{})
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if a.Meta.ID != artifact171r2ID {
		t.Errorf("artifact id = %q, want %q", a.Meta.ID, artifact171r2ID)
	}
	if a.SchemaVersion != artifact.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", a.SchemaVersion, artifact.SchemaVersion)
	}
	if err := a.VerifyContentHash(); err != nil {
		t.Errorf("vendored catalog fails its own hash: %v", err)
	}
}

// Test171r2VendoredCatalogSatisfiesPublishedSchema validates the committed
// file against schema/, not against the Go types that produced it — an
// external consumer reads the schema, so that is the contract that matters.
func Test171r2VendoredCatalogSatisfiesPublishedSchema(t *testing.T) {
	sch := publishedSchema(t)

	path := filepath.Join(catalogsDir, golden171r2File)
	data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("%s violates the published schema:\n%v", path, err)
	}
}

// Test171r2CatalogCoversAllOneHundredTenRequirements pins the control set
// itself. NIST SP 800-171 Revision 2 is exactly 110 requirements across 14
// families (docs/open-questions.md Q4) — no more, no fewer.
func Test171r2CatalogCoversAllOneHundredTenRequirements(t *testing.T) {
	a := compile171r2ForTest(t)
	if n := len(a.Controls); n != 110 {
		t.Fatalf("compiled %d controls, want 110", n)
	}

	families := make(map[string]bool)
	for _, c := range a.Controls {
		if c.ID == "" {
			t.Errorf("control has no id")
			continue
		}
		parts := strings.Split(c.ID, ".")
		if len(parts) != 3 {
			t.Errorf("control id %q is not of the form 3.<family>.<n>", c.ID)
			continue
		}
		families[parts[0]+"."+parts[1]] = true
	}
	if n := len(families); n != 14 {
		t.Errorf("controls span %d families, want 14: %v", n, families)
	}
}

// Test171r2EveryControlIsProceduralWithAnAttestation is the load-bearing claim
// for this pass: no AWS-side mapping exists yet (docs/open-questions.md Q4
// step 3 is deferred), so every one of the 110 requirements must be procedural
// with an attestation stub — none may carry config_rules or an scp fragment.
func Test171r2EveryControlIsProceduralWithAnAttestation(t *testing.T) {
	a := compile171r2ForTest(t)
	for _, c := range a.Controls {
		if len(c.Enforcement) != 1 || c.Enforcement[0] != artifact.EnforcementProcedural {
			t.Errorf("control %s enforcement = %v, want exactly [procedural]", c.ID, c.Enforcement)
		}
		if c.Attestation == nil {
			t.Errorf("control %s has no attestation stub", c.ID)
			continue
		}
		if c.Attestation.Frequency != "annual" {
			t.Errorf("control %s attestation frequency = %q, want annual", c.ID, c.Attestation.Frequency)
		}
		if c.SCP != nil {
			t.Errorf("control %s carries an scp fragment; this pass adds none", c.ID)
		}
		if len(c.ConfigRules) != 0 {
			t.Errorf("control %s carries config_rules; this pass adds none (Q4 step 3 is deferred)", c.ID)
		}
	}
}

// Test171r2EveryControlCrosswalksToItself proves the join key
// internal/compilesets.DedupeAttestations needs: this catalog's own id must
// appear as its "800-171r2" crosswalk entry, so a union with cmmc-l1 (whose
// controls also carry an "800-171r2" crosswalk entry) recognizes the shared
// practice.
func Test171r2EveryControlCrosswalksToItself(t *testing.T) {
	a := compile171r2ForTest(t)
	for _, c := range a.Controls {
		if got := c.Crosswalk["800-171r2"]; got != c.ID {
			t.Errorf("control %s crosswalk[800-171r2] = %q, want %q", c.ID, got, c.ID)
		}
	}
}

// Test171r2SourceCheckRejectsAShortRequirementList proves the invariant that
// guards the count is not vacuous.
func Test171r2SourceCheckRejectsAShortRequirementList(t *testing.T) {
	var doc doc171r2
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, source171r2File), &doc); err != nil {
		t.Fatalf("read %s: %v", source171r2File, err)
	}
	doc.Requirements = doc.Requirements[:len(doc.Requirements)-1]
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted 109 requirements; NIST SP 800-171 Revision 2 is exactly 110")
	}
	if !strings.Contains(err.Error(), "110") {
		t.Errorf("error does not name the expected count: %v", err)
	}
}

// Test171r2SourceCheckRejectsAShortFamilyList mirrors the requirement-count
// test for the family list.
func Test171r2SourceCheckRejectsAShortFamilyList(t *testing.T) {
	var doc doc171r2
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, source171r2File), &doc); err != nil {
		t.Fatalf("read %s: %v", source171r2File, err)
	}
	doc.Families = doc.Families[:len(doc.Families)-1]
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted 13 families; NIST SP 800-171 Revision 2 has exactly 14")
	}
	if !strings.Contains(err.Error(), "14") {
		t.Errorf("error does not name the expected count: %v", err)
	}
}

// Test171r2SourceCheckRejectsDuplicateRequirementID proves a duplicate id in
// the curated source is refused rather than silently shadowing a control.
func Test171r2SourceCheckRejectsDuplicateRequirementID(t *testing.T) {
	var doc doc171r2
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, source171r2File), &doc); err != nil {
		t.Fatalf("read %s: %v", source171r2File, err)
	}
	// Keep the count at 110 so the duplicate check, not the count check, is
	// what fires: overwrite the last entry's id with the first's.
	doc.Requirements[len(doc.Requirements)-1].ID = doc.Requirements[0].ID
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted a duplicate requirement id")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

// Test171r2SourceCheckRejectsEmptyRequirementText proves the project's own
// stated principle — a plausible wrong value is worse than an obviously
// absent one, because it produces output — is enforced at load time, not
// left to a reviewer to notice.
func Test171r2SourceCheckRejectsEmptyRequirementText(t *testing.T) {
	var doc doc171r2
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, source171r2File), &doc); err != nil {
		t.Fatalf("read %s: %v", source171r2File, err)
	}
	doc.Requirements[0].Text = ""
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted a requirement with empty text")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

// Test171r2SourceLoaderRequiresUpstreamProvenance mirrors
// TestSourceLoaderRequiresUpstreamProvenance for this catalog's single
// source block.
func Test171r2SourceLoaderRequiresUpstreamProvenance(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*doc171r2)
		wantMsg string
	}{
		{"missing upstream hash", func(d *doc171r2) { d.Source.SHA256 = "" }, "upstream_sha256"},
		{"malformed upstream hash", func(d *doc171r2) { d.Source.SHA256 = "deadbeef" }, "lowercase hex"},
		{"missing uri", func(d *doc171r2) { d.Source.URI = "" }, "uri"},
		{"missing retrieved_at", func(d *doc171r2) { d.Source.RetrievedAt = "" }, "retrieved_at"},
		{"missing catalog", func(d *doc171r2) { d.Source.Catalog = "" }, "catalog"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc doc171r2
			if _, err := readJSONAndHash(filepath.Join(sourcesDir, source171r2File), &doc); err != nil {
				t.Fatalf("read %s: %v", source171r2File, err)
			}
			tc.mutate(&doc)
			err := doc.check()
			if err == nil {
				t.Fatal("check() accepted a source with incomplete provenance")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error does not name the problem (%q): %v", tc.wantMsg, err)
			}
		})
	}
}

// Test171r2SourceLoaderRejectsUnknownFields mirrors
// TestSourceLoaderRejectsUnknownFields: a misspelled key in this source must
// not silently drop what it carries.
func Test171r2SourceLoaderRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(sourcesDir, source171r2File)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", source171r2File, err)
	}
	mangled := strings.Replace(string(data), `"text"`, `"txet"`, 1)
	if mangled == string(data) {
		t.Fatal("test setup: no text key found to misspell")
	}
	path := filepath.Join(dir, source171r2File)
	if werr := os.WriteFile(path, []byte(mangled), 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}

	var doc doc171r2
	_, err = readJSONAndHash(path, &doc)
	if err == nil {
		t.Fatal("readJSONAndHash accepted a source file with a misspelled key")
	}
	if !strings.Contains(err.Error(), "txet") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// Test171r2FamilyTitlesMatchCPRT pins the 14 family titles against
// docs/open-questions.md Q4's own worked example (3.10 "PHYSICAL PROTECTION"),
// so a future re-extraction that silently reorders or renames a family is
// caught here rather than only in the golden diff.
func Test171r2FamilyTitlesMatchCPRT(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sourcesDir, source171r2File)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", source171r2File, err)
	}
	var doc doc171r2
	if uerr := json.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	want := map[string]string{
		"3.10": "PHYSICAL PROTECTION",
		"3.1":  "ACCESS CONTROL",
		"3.14": "SYSTEM AND INFORMATION INTEGRITY",
	}
	got := make(map[string]string, len(doc.Families))
	for _, f := range doc.Families {
		got[f.ID] = f.Title
	}
	for id, title := range want {
		if got[id] != title {
			t.Errorf("family %s title = %q, want %q", id, got[id], title)
		}
	}
}
