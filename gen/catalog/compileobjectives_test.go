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
	"github.com/scttfrdmn/automat/internal/assess"
)

// Tests for the NIST SP 800-171A objectives-catalog compiler. Mirrors
// compile171r2_test.go's pattern; see that file's header comment for why a
// golden test is the right shape for a vendored catalog.

const goldenObjectivesFile = "800-171a-objectives.json"

func compileObjectivesForTest(t *testing.T) *assess.ObjectivesCatalog {
	t.Helper()
	oc, err := compileFromObjectives(sourcesDir)
	if err != nil {
		t.Fatalf("compile from %s: %v", sourcesDir, err)
	}
	return oc
}

func TestObjectivesCatalogMatchesGolden(t *testing.T) {
	oc := compileObjectivesForTest(t)
	got, err := oc.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(catalogsDir, "objectives", goldenObjectivesFile)

	if updateGolden() {
		if werr := os.WriteFile(path, got, 0o644); werr != nil { //nolint:gosec // reviewed, committed artifact
			t.Fatalf("write %s: %v", path, werr)
		}
		t.Logf("updated %s (content_sha256 %s)", path, oc.Catalog.ContentHash)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — run `make catalogs`", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s does not match a fresh compile of %s.\n"+
			"If a curated source or the compiler changed on purpose, run `make catalogs` and review the diff.\n"+
			"fresh content_sha256: %s", path, sourcesDir, oc.Catalog.ContentHash)
	}
}

func TestObjectivesCompileIsDeterministic(t *testing.T) {
	first := compileObjectivesForTest(t)
	firstBytes, err := first.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := range 3 {
		next := compileObjectivesForTest(t)
		nextBytes, err := next.MarshalIndented()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(nextBytes) != string(firstBytes) {
			t.Fatalf("compile %d differs from compile 1; the compiler is not deterministic", i+2)
		}
		if next.Catalog.ContentHash != first.Catalog.ContentHash {
			t.Fatalf("compile %d hashed to %s, want %s", i+2, next.Catalog.ContentHash, first.Catalog.ContentHash)
		}
	}
}

// TestObjectivesVendoredCatalogLoadsAndVerifies exercises the path every
// other command will use: load the committed file, validate it, and check
// its declared hash against its actual requirements.
func TestObjectivesVendoredCatalogLoadsAndVerifies(t *testing.T) {
	path := filepath.Join(catalogsDir, "objectives", goldenObjectivesFile)
	oc, err := assess.LoadObjectivesCatalog(path, assess.ObjectivesLoadOptions{})
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if oc.Catalog.ID != catalogObjectivesID {
		t.Errorf("catalog id = %q, want %q", oc.Catalog.ID, catalogObjectivesID)
	}
	if oc.SchemaVersion != assess.ObjectivesCatalogSchemaVersion {
		t.Errorf("schema_version = %q, want %q", oc.SchemaVersion, assess.ObjectivesCatalogSchemaVersion)
	}
	if err := oc.VerifyContentHash(); err != nil {
		t.Errorf("vendored catalog fails its own hash: %v", err)
	}
}

// TestObjectivesVendoredCatalogSatisfiesPublishedSchema validates the
// committed file against schema/objectives-catalog-v1.schema.json — a
// DRAFT schema (see that file's own status note), but still the contract an
// external consumer would read if one existed.
func TestObjectivesVendoredCatalogSatisfiesPublishedSchema(t *testing.T) {
	sch := publishedObjectivesSchema(t)

	path := filepath.Join(catalogsDir, "objectives", goldenObjectivesFile)
	data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("%s violates the draft schema:\n%v", path, err)
	}
}

// publishedObjectivesSchema compiles schema/objectives-catalog-v1.schema.json.
func publishedObjectivesSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	const schemaPath = "../../schema/objectives-catalog-v1.schema.json"
	sf, err := os.Open(schemaPath) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("open %s: %v", schemaPath, err)
	}
	defer func() { _ = sf.Close() }()
	schemaDoc, err := jsonschema.UnmarshalJSON(sf)
	if err != nil {
		t.Fatalf("parse %s: %v", schemaPath, err)
	}
	c := jsonschema.NewCompiler()
	if aerr := c.AddResource("objectives-catalog-v1.schema.json", schemaDoc); aerr != nil {
		t.Fatalf("add schema: %v", aerr)
	}
	sch, err := c.Compile("objectives-catalog-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

// TestObjectivesCatalogCoversAllOneHundredTenRequirements pins the
// requirement set: NIST SP 800-171A decomposes exactly the same 110
// requirements as 800-171 Revision 2.
func TestObjectivesCatalogCoversAllOneHundredTenRequirements(t *testing.T) {
	oc := compileObjectivesForTest(t)
	if n := len(oc.Requirements); n != 110 {
		t.Fatalf("compiled %d requirements, want 110", n)
	}
	total := 0
	for _, r := range oc.Requirements {
		total += len(r.Objectives)
	}
	if total != 320 {
		t.Errorf("compiled %d total objectives, want 320 (the NIST SP 800-171A 1.0.0 count)", total)
	}
}

// TestObjectivesCrossReferenceAgainstControlArtifact is the most valuable
// test in this pass: every objective's requirement id must exist in
// catalogs/800-171r2.json, and every 800-171r2 requirement must have at
// least one objective here.
func TestObjectivesCrossReferenceAgainstControlArtifact(t *testing.T) {
	oc := compileObjectivesForTest(t)
	art, err := compileFrom171r2(sourcesDir)
	if err != nil {
		t.Fatalf("compile 800-171r2: %v", err)
	}
	if err := oc.CrossReferenceControlArtifact(art); err != nil {
		t.Errorf("cross-reference failed: %v", err)
	}
}

// TestObjectivesCrossReferenceCatchesAnOrphan proves the cross-reference
// check is not vacuous in either direction.
func TestObjectivesCrossReferenceCatchesAnOrphan(t *testing.T) {
	oc := compileObjectivesForTest(t)
	art, err := compileFrom171r2(sourcesDir)
	if err != nil {
		t.Fatalf("compile 800-171r2: %v", err)
	}

	t.Run("orphan in objectives catalog", func(t *testing.T) {
		mutated := *oc
		mutated.Requirements = append([]assess.RequirementObjectives{}, oc.Requirements...)
		mutated.Requirements = append(mutated.Requirements, assess.RequirementObjectives{
			ID: "9.9.9",
			Objectives: []assess.Objective{
				{ID: "9.9.9", Statement: "an objective naming a requirement that does not exist."},
			},
			AssessmentMethods: assess.AssessmentMethods{Examine: "x", Interview: "y", Test: "z"},
		})
		if err := mutated.CrossReferenceControlArtifact(art); err == nil {
			t.Fatal("cross-reference accepted an objectives entry with no matching control")
		}
	})

	t.Run("orphan in control artifact", func(t *testing.T) {
		mutatedArt := *art
		mutatedArt.Controls = append(artifact.Controls{}, art.Controls...)
		mutatedArt.Controls = append(mutatedArt.Controls, artifact.Control{
			ID:          "9.9.9",
			Title:       "a control with no objectives",
			Enforcement: []artifact.EnforcementClass{artifact.EnforcementProcedural},
			Attestation: &artifact.Attestation{Template: "x.md", Frequency: "annual"},
		})
		if err := oc.CrossReferenceControlArtifact(&mutatedArt); err == nil {
			t.Fatal("cross-reference accepted a control artifact entry with no matching objectives")
		}
	})
}

// TestObjectivesSourceCheckRejectsAShortRequirementList proves the
// invariant that guards the count is not vacuous.
func TestObjectivesSourceCheckRejectsAShortRequirementList(t *testing.T) {
	var doc curatedObjectivesDoc171a
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, sourceObjectivesFile), &doc); err != nil {
		t.Fatalf("read %s: %v", sourceObjectivesFile, err)
	}
	doc.Requirements = doc.Requirements[:len(doc.Requirements)-1]
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted 109 requirements; NIST SP 800-171A decomposes exactly 110")
	}
	if !strings.Contains(err.Error(), "110") {
		t.Errorf("error does not name the expected count: %v", err)
	}
}

// TestObjectivesSourceCheckRejectsEmptyObjectiveStatement proves the
// project's own stated principle — a plausible wrong value is worse than an
// obviously absent one, because it produces output — is enforced at load
// time here too.
func TestObjectivesSourceCheckRejectsEmptyObjectiveStatement(t *testing.T) {
	var doc curatedObjectivesDoc171a
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, sourceObjectivesFile), &doc); err != nil {
		t.Fatalf("read %s: %v", sourceObjectivesFile, err)
	}
	doc.Requirements[0].Objectives[0].Statement = ""
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted an objective with empty statement text")
	}
	if !strings.Contains(err.Error(), "plausible wrong statement") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

// TestObjectivesSourceCheckRejectsDuplicateObjectiveID proves a duplicate
// objective id in the curated source is refused rather than silently
// shadowing an entry.
func TestObjectivesSourceCheckRejectsDuplicateObjectiveID(t *testing.T) {
	var doc curatedObjectivesDoc171a
	if _, err := readJSONAndHash(filepath.Join(sourcesDir, sourceObjectivesFile), &doc); err != nil {
		t.Fatalf("read %s: %v", sourceObjectivesFile, err)
	}
	doc.Requirements[1].Objectives = append(doc.Requirements[1].Objectives, doc.Requirements[0].Objectives[0])
	err := doc.check()
	if err == nil {
		t.Fatal("check() accepted a duplicate objective id across two requirements")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

// TestObjectivesSourceLoaderRequiresUpstreamProvenance mirrors the 800-171r2
// compiler's equivalent test for this catalog's single source block.
func TestObjectivesSourceLoaderRequiresUpstreamProvenance(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*curatedObjectivesDoc171a)
		wantMsg string
	}{
		{"missing upstream hash", func(d *curatedObjectivesDoc171a) { d.Source.SHA256 = "" }, "upstream_sha256"},
		{"malformed upstream hash", func(d *curatedObjectivesDoc171a) { d.Source.SHA256 = "deadbeef" }, "lowercase hex"},
		{"missing uri", func(d *curatedObjectivesDoc171a) { d.Source.URI = "" }, "uri"},
		{"missing retrieved_at", func(d *curatedObjectivesDoc171a) { d.Source.RetrievedAt = "" }, "retrieved_at"},
		{"missing catalog", func(d *curatedObjectivesDoc171a) { d.Source.Catalog = "" }, "catalog"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc curatedObjectivesDoc171a
			if _, err := readJSONAndHash(filepath.Join(sourcesDir, sourceObjectivesFile), &doc); err != nil {
				t.Fatalf("read %s: %v", sourceObjectivesFile, err)
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

// TestObjectivesSourceLoaderRejectsUnknownFields mirrors the 800-171r2
// compiler's equivalent test: a misspelled key in this source must not
// silently drop what it carries.
func TestObjectivesSourceLoaderRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(sourcesDir, sourceObjectivesFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", sourceObjectivesFile, err)
	}
	mangled := strings.Replace(string(data), `"statement"`, `"tatsement"`, 1)
	if mangled == string(data) {
		t.Fatal("test setup: no statement key found to misspell")
	}
	path := filepath.Join(dir, sourceObjectivesFile)
	if werr := os.WriteFile(path, []byte(mangled), 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}

	var doc curatedObjectivesDoc171a
	_, err = readJSONAndHash(path, &doc)
	if err == nil {
		t.Fatal("readJSONAndHash accepted a source file with a misspelled key")
	}
	if !strings.Contains(err.Error(), "tatsement") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// TestObjectivesLoaderRoundTrip proves internal/assess.LoadObjectivesCatalog
// reads back exactly what was compiled: same schema version, same
// requirement count, same first objective.
func TestObjectivesLoaderRoundTrip(t *testing.T) {
	oc := compileObjectivesForTest(t)
	data, err := oc.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "roundtrip.json")
	if werr := os.WriteFile(path, data, 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}

	loaded, err := assess.LoadObjectivesCatalog(path, assess.ObjectivesLoadOptions{})
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if loaded.SchemaVersion != oc.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", loaded.SchemaVersion, oc.SchemaVersion)
	}
	if len(loaded.Requirements) != len(oc.Requirements) {
		t.Errorf("requirements count = %d, want %d", len(loaded.Requirements), len(oc.Requirements))
	}
	req, ok := loaded.Find("3.1.1")
	if !ok {
		t.Fatal("loaded catalog has no entry for 3.1.1")
	}
	if len(req.Objectives) == 0 || req.Objectives[0].ID != "3.1.1[a]" {
		t.Errorf("3.1.1's first objective = %+v, want id 3.1.1[a]", req.Objectives)
	}
}

// TestObjectivesFamilyTitlesMatchCPRTFamilyCount is a sanity check that the
// curated source's family list stayed in step with 800-171r2's 14 families,
// even though ObjectivesCatalog itself does not carry family titles (only
// the source file does, for the requirement-family cross-check at compile
// time).
func TestObjectivesFamilyTitlesMatchCPRTFamilyCount(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sourcesDir, sourceObjectivesFile)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v", sourceObjectivesFile, err)
	}
	var doc curatedObjectivesDoc171a
	if uerr := json.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	if n := len(doc.Families); n != 14 {
		t.Errorf("found %d families, want 14", n)
	}
}
