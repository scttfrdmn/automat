// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/scttfrdmn/automat/internal/artifact"
)

// A vendored catalog is a reviewed, committed file: the golden test is how a
// change to the compiler or to a curated source shows up as a diff a human must
// approve, rather than as a silently different set of controls at vend time.

// updateGolden is an environment variable rather than a -update flag so that
// `go test ./... ` works uniformly: a flag defined in one package makes the same
// command fail in every other package's test binary.
const updateGoldenEnv = "AUTOMAT_UPDATE_GOLDEN"

func updateGolden() bool { return os.Getenv(updateGoldenEnv) == "1" }

const (
	sourcesDir  = "../sources"
	catalogsDir = "../../catalogs"
	goldenFile  = "cmmc-l1.json"
)

func compileForTest(t *testing.T) *artifact.Artifact {
	t.Helper()
	a, err := compileFrom(sourcesDir)
	if err != nil {
		t.Fatalf("compile from %s: %v", sourcesDir, err)
	}
	return a
}

func TestCatalogMatchesGolden(t *testing.T) {
	a := compileForTest(t)
	got, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(catalogsDir, goldenFile)

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
			"vendored content_sha256: %s\nfresh content_sha256:    %s",
			path, sourcesDir, vendoredHash(t, want), a.Meta.ContentHash)
	}
}

// vendoredHash recomputes the content hash of the committed file's controls.
//
// It deliberately does not report the hash the document declares: if the file
// was hand-edited, the declared value is stale and would print as identical to
// the fresh compile, which is the opposite of a useful diagnostic.
func vendoredHash(t *testing.T, data []byte) string {
	t.Helper()
	a, err := artifact.Decode(data, artifact.LoadOptions{SkipHashCheck: true, SkipValidate: true})
	if err != nil {
		return "unparseable"
	}
	h, err := a.ComputeContentHash()
	if err != nil {
		return "unhashable"
	}
	if h != a.Meta.ContentHash {
		return h + " (the file also declares a stale " + a.Meta.ContentHash + ")"
	}
	return h
}

// TestCompileIsDeterministic is the claim that makes the golden file meaningful:
// the same sources always produce the same bytes, including the content hash.
func TestCompileIsDeterministic(t *testing.T) {
	first := compileForTest(t)
	firstBytes, err := first.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := range 3 {
		next := compileForTest(t)
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

// TestVendoredCatalogLoadsAndVerifies exercises the path every other command
// will use: load the committed file, validate it, and check its declared hash
// against its actual controls.
func TestVendoredCatalogLoadsAndVerifies(t *testing.T) {
	path := filepath.Join(catalogsDir, goldenFile)
	a, err := artifact.Load(path, artifact.LoadOptions{})
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if a.Meta.ID != artifactID {
		t.Errorf("artifact id = %q, want %q", a.Meta.ID, artifactID)
	}
	if a.SchemaVersion != artifact.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", a.SchemaVersion, artifact.SchemaVersion)
	}
	if err := a.VerifyContentHash(); err != nil {
		t.Errorf("vendored catalog fails its own hash: %v", err)
	}
}

// TestVendoredCatalogSatisfiesPublishedSchema validates the committed file
// against schema/, not against the Go types that produced it. An external
// consumer reads the schema, so that is the contract the catalog must meet.
func TestVendoredCatalogSatisfiesPublishedSchema(t *testing.T) {
	const schemaPath = "../../schema/control-artifact-v1.schema.json"
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
	if aerr := c.AddResource("control-artifact-v1.schema.json", schemaDoc); aerr != nil {
		t.Fatalf("add schema: %v", aerr)
	}
	sch, err := c.Compile("control-artifact-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	path := filepath.Join(catalogsDir, goldenFile)
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

// TestCatalogCoversAllFifteenRequirements pins the control set itself. CMMC
// Level 1 is exactly the fifteen requirements of FAR 52.204-21(b)(1)(i)-(xv)
// per 32 CFR 170.14(c)(2) — no more, and crucially no fewer, since a dropped
// requirement would make a "born compliant" claim false.
func TestCatalogCoversAllFifteenRequirements(t *testing.T) {
	a := compileForTest(t)

	want := []string{
		"AC.L1-b.1.i", "AC.L1-b.1.ii", "AC.L1-b.1.iii", "AC.L1-b.1.iv",
		"IA.L1-b.1.v", "IA.L1-b.1.vi",
		"MP.L1-b.1.vii",
		"PE.L1-b.1.viii", "PE.L1-b.1.ix",
		"SC.L1-b.1.x", "SC.L1-b.1.xi",
		"SI.L1-b.1.xii", "SI.L1-b.1.xiii", "SI.L1-b.1.xiv", "SI.L1-b.1.xv",
	}
	got := make(map[string]bool, len(a.Controls))
	for _, c := range a.Controls {
		got[c.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("control %s is missing from the compiled catalog", id)
		}
		delete(got, id)
	}
	for id := range got {
		t.Errorf("compiled catalog contains unexpected control %s", id)
	}
	if len(a.Controls) != len(want) {
		t.Errorf("catalog has %d controls, want exactly %d", len(a.Controls), len(want))
	}
}

// TestEnforcementBreakdownIsPinned fixes the enforcement split the human is
// reviewing by hand (gen/MAPPING-NOTES.md). Changing any assignment must fail
// here, because this breakdown is what `verify` prints as the tool's own
// statement of what it does and does not enforce (DESIGN §12).
func TestEnforcementBreakdownIsPinned(t *testing.T) {
	a := compileForTest(t)
	b := a.Breakdown()

	if b.Total != 15 {
		t.Errorf("total = %d, want 15", b.Total)
	}
	// config-rule and procedural sum to more than 15 because the three curated
	// controls carry both: their rules observe a symptom of the requirement, so
	// the attestation stays (see curatedBindings). scp is permanently zero by
	// design — preventive posture for CMMC L1 lives in baseline-protection and
	// profile SCPs, not in this catalog (gen/MAPPING-NOTES.md).
	wantByClass := map[artifact.EnforcementClass]int{
		artifact.EnforcementConfigRule:         12,
		artifact.EnforcementProcedural:         6,
		artifact.EnforcementSCP:                0,
		artifact.EnforcementBaselineProtection: 0,
	}
	for class, want := range wantByClass {
		if got := b.ByClass[class]; got != want {
			t.Errorf("%s = %d, want %d — if an enforcement assignment changed on purpose, "+
				"update gen/MAPPING-NOTES.md and this pin together", class, got, want)
		}
	}

	// Every class must be present in the map even at zero: the breakdown is a
	// statement of limits, and an omitted class reads as "not applicable" rather
	// than "none".
	for _, class := range artifact.AllEnforcementClasses {
		if _, ok := b.ByClass[class]; !ok {
			t.Errorf("breakdown omits class %s; DESIGN §12 requires reporting zero, not silence", class)
		}
	}
}

// TestProceduralControlsAreExactlyTheUnmappedOnes ties the assignment rule to
// the evidence: a control is procedural because AWS maps no Config rule to it,
// not because someone decided it was hard.
//
// Curated bindings do not change that. Three procedural controls carry curated
// rules that observe a symptom of the requirement; they keep their attestation,
// and they must still carry no aws-mapping binding and no AWS mapping id.
func TestProceduralControlsAreExactlyTheUnmappedOnes(t *testing.T) {
	a := compileForTest(t)
	wantProcedural := map[string]bool{
		"AC.L1-b.1.iv":   true, // 800-171 R2 3.1.22
		"MP.L1-b.1.vii":  true, // 3.8.3
		"PE.L1-b.1.viii": true, // 3.10.1
		"PE.L1-b.1.ix":   true, // 3.10.3, 3.10.4, 3.10.5
		"SC.L1-b.1.xi":   true, // 3.13.5
		"SI.L1-b.1.xiv":  true, // 3.14.4
	}
	for _, c := range a.Controls {
		isProcedural := c.Enforces(artifact.EnforcementProcedural)
		if isProcedural != wantProcedural[c.ID] {
			t.Errorf("control %s: procedural = %v, want %v", c.ID, isProcedural, wantProcedural[c.ID])
		}

		var mapped, curated int
		for _, r := range c.ConfigRules {
			switch r.Provenance {
			case artifact.ProvenanceAWSMapping:
				mapped++
			case artifact.ProvenanceCurated:
				curated++
			default:
				t.Errorf("control %s rule %s has provenance %q", c.ID, r.Identifier, r.Provenance)
			}
		}

		switch {
		case isProcedural:
			if c.Attestation == nil {
				t.Errorf("control %s is procedural but has no attestation stub; "+
					"a procedural control with no stub enforces and documents nothing", c.ID)
				continue
			}
			if c.Attestation.Guidance == "" {
				t.Errorf("control %s has an attestation with no guidance; an empty stub is not an attestation", c.ID)
			}
			if mapped != 0 {
				t.Errorf("control %s is procedural but carries %d aws-mapping rules; a control AWS maps "+
					"rules to is not unmapped", c.ID, mapped)
			}
			if _, ok := c.Crosswalk["aws_config_mapping_id"]; ok {
				t.Errorf("control %s is procedural but claims an AWS mapping id; "+
					"if AWS maps rules to it, it should not be procedural", c.ID)
			}
		default:
			if mapped == 0 {
				t.Errorf("control %s is not procedural but carries no aws-mapping config rules", c.ID)
			}
			if curated != 0 {
				t.Errorf("control %s carries %d curated rules; the curated layer exists for controls AWS "+
					"leaves uncovered, so binding one here needs its own review", c.ID, curated)
			}
			if c.Crosswalk["aws_config_mapping_id"] == "" {
				t.Errorf("control %s carries config rules but records no AWS mapping id; "+
					"the join must stay auditable", c.ID)
			}
		}

		if c.Enforces(artifact.EnforcementConfigRule) != (len(c.ConfigRules) > 0) {
			t.Errorf("control %s: config-rule class = %v but carries %d rules",
				c.ID, c.Enforces(artifact.EnforcementConfigRule), len(c.ConfigRules))
		}
	}
}

// TestCuratedBindingsAreExactlyTheReviewedOnes pins the curated layer.
//
// A curated binding is automat asserting an enforcement AWS does not claim, and
// that assertion ends up in an evidence manifest, so the full set is enumerated
// here rather than derived: adding one must fail this test and be reviewed.
func TestCuratedBindingsAreExactlyTheReviewedOnes(t *testing.T) {
	a := compileForTest(t)
	want := map[string][]string{
		"AC.L1-b.1.iv": {
			"s3-account-level-public-access-blocks-periodic",
			"s3-bucket-public-read-prohibited",
			"s3-bucket-public-write-prohibited",
		},
		"SC.L1-b.1.xi":  {"ec2-instance-no-public-ip", "subnet-auto-assign-public-ip-disabled"},
		"SI.L1-b.1.xiv": {"guardduty-enabled-centralized"},
	}
	got := make(map[string][]string)
	for _, c := range a.Controls {
		for _, r := range c.ConfigRules {
			if r.Provenance != artifact.ProvenanceCurated {
				continue
			}
			got[c.ID] = append(got[c.ID], r.Name)
			if r.Rationale == "" {
				t.Errorf("control %s rule %s is curated with no rationale", c.ID, r.Name)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("curated bindings = %v, want %v — a new curated binding is a new claim about what "+
			"automat enforces; review it and update gen/MAPPING-NOTES.md and this test together", got, want)
	}
}

// TestAWSMappingLayerIsMechanical checks that nothing hand-written leaks into
// the generated layer. An aws-mapping binding is vouched for by the mapping's
// sha256 in artifact.sources; a rationale on one would be a jurisdiction error.
func TestAWSMappingLayerIsMechanical(t *testing.T) {
	a := compileForTest(t)
	for _, c := range a.Controls {
		for _, r := range c.ConfigRules {
			if r.Provenance == artifact.ProvenanceAWSMapping && r.Rationale != "" {
				t.Errorf("control %s rule %s is an aws-mapping binding carrying a rationale; the mapping "+
					"vouches for it, and the layer must stay mechanically generated", c.ID, r.Name)
			}
		}
	}
}

// TestEveryControlCarriesItsProvenance checks the crosswalk, which is what lets
// union dedupe one practice across frameworks (DESIGN §9) and what a reader uses
// to trace a control back to its authoritative text.
func TestEveryControlCarriesItsProvenance(t *testing.T) {
	a := compileForTest(t)
	for _, c := range a.Controls {
		if c.Statement == "" {
			t.Errorf("control %s has no verbatim requirement text", c.ID)
		}
		if c.Title == "" {
			t.Errorf("control %s has no title", c.ID)
		}
		for _, key := range []string{"far", "800-171r2"} {
			if c.Crosswalk[key] == "" {
				t.Errorf("control %s is missing crosswalk key %q", c.ID, key)
			}
		}
		if !strings.HasPrefix(c.Crosswalk["far"], "52.204-21(b)(1)(") {
			t.Errorf("control %s has malformed FAR crosswalk %q", c.ID, c.Crosswalk["far"])
		}
	}
}

// TestEveryRuleParameterDeclaresAnOrder guards DESIGN §9's "never guess" rule at
// the point where parameters enter the system.
func TestEveryRuleParameterDeclaresAnOrder(t *testing.T) {
	a := compileForTest(t)
	var seen int
	for _, c := range a.Controls {
		for _, r := range c.ConfigRules {
			if r.Identifier == "" {
				t.Errorf("control %s has a rule with no identifier", c.ID)
			}
			for name, p := range r.Parameters {
				seen++
				valid := false
				for _, o := range artifact.AllParamOrders {
					if p.Order == o {
						valid = true
						break
					}
				}
				if !valid {
					t.Errorf("control %s rule %s parameter %s has order %q, which union cannot resolve",
						c.ID, r.Identifier, name, p.Order)
				}
				if p.Value == "" {
					t.Errorf("control %s rule %s parameter %s has no value", c.ID, r.Identifier, name)
				}
				if p.Order.IsSet() && len(p.Members()) == 0 {
					t.Errorf("control %s rule %s parameter %s is set-valued but has no members in %q",
						c.ID, r.Identifier, name, p.Value)
				}
				if !p.Order.IsSet() && p.SetSeparator != "" {
					t.Errorf("control %s rule %s parameter %s declares a separator on a %s order",
						c.ID, r.Identifier, name, p.Order)
				}
			}
		}
	}
	if seen == 0 {
		t.Error("no rule parameters found; the conformance pack sets defaults for several rules, " +
			"so zero means the parameter join broke")
	}
}

// TestSourcesRecordEveryCuratedInput checks the provenance chain ROADMAP Phase 0
// requires: every input that influenced controls[] appears with a hash.
func TestSourcesRecordEveryCuratedInput(t *testing.T) {
	a := compileForTest(t)
	if len(a.Meta.Sources) < 3 {
		t.Fatalf("artifact records %d sources; the compile joins three curated files", len(a.Meta.Sources))
	}
	var catalogs, mappings int
	for _, s := range a.Meta.Sources {
		switch {
		case s.Catalog != "":
			catalogs++
		case s.Mapping != "":
			mappings++
		}
		if len(s.SHA256) != 64 {
			t.Errorf("source %+v has no usable sha256; provenance without a hash proves nothing", s)
		}
		if s.URI == "" {
			t.Errorf("source %+v has no uri", s)
		}
		if s.Note == "" {
			t.Errorf("source %+v has no note recording what it contributed", s)
		}
	}
	if catalogs < 2 {
		t.Errorf("expected the FAR text and the 32 CFR 170 crosswalk as catalog sources, got %d", catalogs)
	}
	if mappings < 1 {
		t.Errorf("expected at least one AWS mapping source, got %d", mappings)
	}
}

// TestCompiledAtIsDerivedFromSources pins reproducibility: the timestamp must
// come from the sources, never the clock, or `make catalogs` would rewrite the
// file on every run and the golden test would be noise.
func TestCompiledAtIsDerivedFromSources(t *testing.T) {
	s, err := loadSources(sourcesDir)
	if err != nil {
		t.Fatalf("load sources: %v", err)
	}
	stamp, err := compiledAtFrom(s)
	if err != nil {
		t.Fatalf("compiledAtFrom: %v", err)
	}
	a := compileForTest(t)
	if a.Meta.CompiledAt != stamp {
		t.Errorf("compiled_at = %q, want %q (the newest source retrieval time)", a.Meta.CompiledAt, stamp)
	}
}

// TestUnknownParameterIsAnError proves orderFor refuses to default. A new pack
// parameter must stop the compile, not acquire a guessed order.
func TestUnknownParameterIsAnError(t *testing.T) {
	if _, err := orderFor("some-rule", "aParameterNobodyDeclared"); err == nil {
		t.Fatal("orderFor accepted an undeclared parameter; union would then guess which direction is stricter")
	} else if !strings.Contains(err.Error(), "no declared union order") {
		t.Errorf("error does not explain the problem: %v", err)
	}
}

// TestSourceLoaderRejectsUnknownFields proves AUDIT-0 finding H2 is fixed.
//
// A misspelled key in a curated source used to parse cleanly and silently drop
// what it carried: renaming "parameters" to "parmeters" deleted a rule's
// parameter defaults, so the rule would deploy with AWS's defaults instead of
// the conformance pack's — a control loosened by a typo, with a valid-looking
// catalog and a fresh content hash to match.
func TestSourceLoaderRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{farSourceFile, crosswalkSourceFile, awsSourceFile} {
		data, err := os.ReadFile(filepath.Join(sourcesDir, name)) //nolint:gosec // fixed in-repo path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if werr := os.WriteFile(filepath.Join(dir, name), data, 0o600); werr != nil {
			t.Fatalf("write %s: %v", name, werr)
		}
	}
	path := filepath.Join(dir, awsSourceFile)
	data, err := os.ReadFile(path) //nolint:gosec // test-local temp path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	mangled := strings.Replace(string(data), `"parameters"`, `"parmeters"`, 1)
	if mangled == string(data) {
		t.Fatal("test setup: no parameters key found to misspell")
	}
	if werr := os.WriteFile(path, []byte(mangled), 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}

	_, err = loadSources(dir)
	if err == nil {
		t.Fatal("loadSources accepted a source file with a misspelled key; the parameter defaults it " +
			"carried would be silently dropped and the rule would deploy looser than the pack specifies")
	}
	if !strings.Contains(err.Error(), "parmeters") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// TestSourceLoaderRequiresUpstreamProvenance proves AUDIT-0 finding H1 is fixed.
//
// A source whose upstream_sha256 is missing used to compile into an artifact
// whose source note read "(sha256 )" — provenance that looks verified to a
// reviewer while being unverifiable, which is worse than no provenance at all.
func TestSourceLoaderRequiresUpstreamProvenance(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*sourceSet)
		wantMsg string
	}{
		{"missing upstream hash", func(s *sourceSet) { s.far.Source.SHA256 = "" }, "upstream_sha256"},
		{"malformed upstream hash", func(s *sourceSet) { s.far.Source.SHA256 = "deadbeef" }, "lowercase hex"},
		{"missing uri", func(s *sourceSet) { s.crosswalk.Source.URI = "" }, "uri"},
		{"missing retrieved_at", func(s *sourceSet) { s.aws.Sources[0].RetrievedAt = "" }, "retrieved_at"},
		{"no mapping sources at all", func(s *sourceSet) { s.aws.Sources = nil }, "no upstream sources"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := loadSources(sourcesDir)
			if err != nil {
				t.Fatalf("load sources: %v", err)
			}
			tc.mutate(s)
			err = s.check()
			if err == nil {
				t.Fatal("check() accepted a source with incomplete provenance; the compiled artifact would " +
					"claim a source it cannot prove")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error does not name the problem (%q): %v", tc.wantMsg, err)
			}
		})
	}
}

// TestSourceCheckRejectsAShortClauseList proves the invariant that guards the
// count is not vacuous: fourteen requirements must not compile.
func TestSourceCheckRejectsAShortClauseList(t *testing.T) {
	s, err := loadSources(sourcesDir)
	if err != nil {
		t.Fatalf("load sources: %v", err)
	}
	s.far.Clauses = s.far.Clauses[:len(s.far.Clauses)-1]
	err = s.check()
	if err == nil {
		t.Fatal("check() accepted 14 requirement clauses; CMMC Level 1 is exactly fifteen")
	}
	if !strings.Contains(err.Error(), "fifteen") {
		t.Errorf("error does not name the expected count: %v", err)
	}
}
