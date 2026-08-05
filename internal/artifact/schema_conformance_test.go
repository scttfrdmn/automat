// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The files in schema/ are the published compatibility contract; the Go types
// and Validate() in this package are the implementation. These tests keep the
// two honest about each other. Without them the schema and the code can drift
// silently, which is the failure mode that matters most in Phase 0: an external
// consumer trusting schema/ would accept documents automat rejects, or worse,
// automat would accept a document that violates the published contract.

const schemaDir = "../../schema"

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join(schemaDir, name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	c := jsonschema.NewCompiler()
	if aerr := c.AddResource(name, doc); aerr != nil {
		t.Fatalf("add %s: %v", path, aerr)
	}
	sch, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return sch
}

// asGeneric round-trips a value through JSON into the interface{} shape the
// validator expects, so the schema sees exactly the bytes automat would write.
func asGeneric(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestAllSchemasCompile(t *testing.T) {
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatalf("read %s: %v", schemaDir, err)
	}
	var found int
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".schema.json") {
			continue
		}
		found++
		t.Run(e.Name(), func(t *testing.T) { compileSchema(t, e.Name()) })
	}
	if found == 0 {
		t.Fatal("no schemas found; schema/ is the published contract and must not be empty")
	}
}

func TestSampleArtifactSatisfiesPublishedSchema(t *testing.T) {
	sch := compileSchema(t, "control-artifact-v1.schema.json")
	a := sampleArtifact()
	data, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("an artifact this package considers valid violates the published schema:\n%v\n\ndocument:\n%s", err, data)
	}
}

// TestGoAndSchemaAgreeOnRejection is the actual drift detector: for each way of
// breaking an artifact, both the hand-written Go validator and the published
// JSON Schema must reject it. A case only one of them catches is drift.
func TestGoAndSchemaAgreeOnRejection(t *testing.T) {
	sch := compileSchema(t, "control-artifact-v1.schema.json")

	cases := []struct {
		name   string
		mutate func(*testing.T, *Artifact)
	}{
		{"missing schema version", func(_ *testing.T, a *Artifact) { a.SchemaVersion = "" }},
		{"non-semver schema version", func(_ *testing.T, a *Artifact) { a.SchemaVersion = "1.0" }},
		{"bad artifact id", func(_ *testing.T, a *Artifact) { a.Meta.ID = "CMMC L1" }},
		{"missing artifact title", func(_ *testing.T, a *Artifact) { a.Meta.Title = "" }},
		{"sub-second compiled_at", func(_ *testing.T, a *Artifact) { a.Meta.CompiledAt = "2026-08-04T00:00:00.5Z" }},
		{"compiled_at with offset", func(_ *testing.T, a *Artifact) { a.Meta.CompiledAt = "2026-08-04T00:00:00+00:00" }},
		{"empty sources", func(_ *testing.T, a *Artifact) { a.Meta.Sources = Sources{} }},
		{"source with no kind", func(_ *testing.T, a *Artifact) {
			a.Meta.Sources = Sources{{SHA256: strings.Repeat("a", 64)}}
		}},
		{"source with two kinds", func(_ *testing.T, a *Artifact) {
			a.Meta.Sources = Sources{{Catalog: "x", Mapping: "y", SHA256: strings.Repeat("a", 64)}}
		}},
		{"source hash not hex", func(_ *testing.T, a *Artifact) { a.Meta.Sources[0].SHA256 = "not-a-hash" }},
		{"uppercase source hash", func(_ *testing.T, a *Artifact) {
			a.Meta.Sources[0].SHA256 = strings.Repeat("A", 64)
		}},
		{"content hash not hex", func(_ *testing.T, a *Artifact) { a.Meta.ContentHash = "xyz" }},
		{"empty controls", func(_ *testing.T, a *Artifact) { a.Controls = Controls{} }},
		{"missing control id", func(t *testing.T, a *Artifact) { mustControl(t, a, "AA.L1-b.1.a").ID = "" }},
		{"missing control title", func(t *testing.T, a *Artifact) { mustControl(t, a, "AA.L1-b.1.a").Title = "" }},
		{"empty enforcement", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").Enforcement = []EnforcementClass{}
		}},
		{"unknown enforcement class", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").Enforcement = []EnforcementClass{"magic"}
		}},
		{"duplicate enforcement class", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").Enforcement = []EnforcementClass{
				EnforcementBaselineProtection, EnforcementBaselineProtection,
			}
		}},
		{"config-rule class without rules", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").ConfigRules = nil
		}},
		{"procedural class without attestation", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "ZZ.L1-b.1.z").Attestation = nil
		}},
		{"scp class without scp", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").SCP = nil
		}},
		{"lowercase rule identifier", func(t *testing.T, a *Artifact) {
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY").Identifier = "iam-password-policy"
		}},
		{"uppercase rule name", func(t *testing.T, a *Artifact) {
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY").Name = "IamPasswordPolicy"
		}},
		{"parameter missing order", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY")
			r.Parameters["MinimumPasswordLength"] = RuleParameter{Value: "14"}
		}},
		{"parameter bad order", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY")
			r.Parameters["MinimumPasswordLength"] = RuleParameter{Value: "14", Order: "average"}
		}},
		{"binding missing provenance", func(t *testing.T, a *Artifact) {
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY").Provenance = ""
		}},
		{"binding bad provenance", func(t *testing.T, a *Artifact) {
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY").Provenance = "vibes"
		}},
		{"curated binding without rationale", func(t *testing.T, a *Artifact) {
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC").Rationale = ""
		}},
		{"separator on a scalar parameter", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "IAM_PASSWORD_POLICY")
			r.Parameters["MaxPasswordAge"] = RuleParameter{Value: "90", Order: OrderMin, SetSeparator: ";"}
		}},
		{"bad statement effect", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0].Effect = "Maybe"
		}},
		// AUDIT-0 H4: Allow was a Go-side warning the published schema did not
		// share. Both must now reject it.
		{"allow statement effect", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0].Effect = "Allow"
		}},
		// AUDIT-0 H5: an empty set is not a stricter set.
		{"set-intersect parameter with no members", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC")
			r.Parameters["authorizedTcpPorts"] = RuleParameter{Value: "", Order: OrderSetIntersect}
		}},
		{"set-union parameter of only separators", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC")
			r.Parameters["blockedPort1"] = RuleParameter{Value: " , , ", Order: OrderSetUnion}
		}},
		{"non-alphanumeric sid", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0].Sid = "Protect-Recorder"
		}},
		{"bad region code", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").SCP.RegionAllowlist = []string{"US-East-1"}
		}},
		{"bad service namespace", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").SCP.ServiceAllowlist = []string{"Amazon S3"}
		}},
		{"bad attestation frequency", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "ZZ.L1-b.1.z").Attestation.Frequency = "whenever"
		}},
		{"bad attestation template", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "ZZ.L1-b.1.z").Attestation.Template = "Procedural.txt"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := sampleArtifact()
			tc.mutate(t, a)

			goErr := a.Validate()
			schemaErr := sch.Validate(asGeneric(t, a))

			switch {
			case goErr == nil && schemaErr == nil:
				t.Errorf("neither the Go validator nor the schema rejected %q", tc.name)
			case goErr == nil:
				t.Errorf("the published schema rejects %q but internal/artifact accepts it — "+
					"Validate() is missing a check:\n%v", tc.name, schemaErr)
			case schemaErr == nil:
				t.Errorf("internal/artifact rejects %q but the published schema accepts it — "+
					"schema/control-artifact-v1.schema.json is missing a constraint:\n%v", tc.name, goErr)
			}
		})
	}
}

// TestSchemaAcceptsWhatGoAccepts checks the other direction on documents that
// should pass: a valid artifact must not be rejected by either side.
func TestSchemaAcceptsWhatGoAccepts(t *testing.T) {
	sch := compileSchema(t, "control-artifact-v1.schema.json")

	cases := []struct {
		name   string
		mutate func(*testing.T, *Artifact)
	}{
		{"minimal procedural control only", func(_ *testing.T, a *Artifact) {
			a.Controls = Controls{{
				ID:          "MP.L1-b.1.vii",
				Title:       "Sanitize media",
				Enforcement: []EnforcementClass{EnforcementProcedural},
				Attestation: &Attestation{Template: "media-sanitization.md", Frequency: "annual"},
			}}
		}},
		{"no optional metadata", func(_ *testing.T, a *Artifact) {
			a.Meta.Description = ""
			for i := range a.Meta.Sources {
				a.Meta.Sources[i].Version = ""
				a.Meta.Sources[i].URI = ""
				a.Meta.Sources[i].RetrievedAt = ""
				a.Meta.Sources[i].Note = ""
			}
		}},
		{"source with note", func(_ *testing.T, a *Artifact) {
			a.Meta.Sources[0].Note = "mapping is partial; unmapped controls are procedural"
		}},
		{"union-style artifact source", func(_ *testing.T, a *Artifact) {
			a.Meta.Sources = Sources{
				{Artifact: "cmmc-l1", SHA256: strings.Repeat("a", 64)},
				{Artifact: "campus-base", SHA256: strings.Repeat("b", 64)},
			}
		}},
		{"both scp and config-rule on one control", func(t *testing.T, a *Artifact) {
			// DESIGN §8 explicitly allows this combination.
			c := mustControl(t, a, "AA.L1-b.1.a")
			if !c.Enforces(EnforcementSCP) || !c.Enforces(EnforcementConfigRule) {
				t.Fatal("test setup: expected the sample control to carry both classes")
			}
		}},
		{"service allowlist", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").SCP.ServiceAllowlist = []string{"s3", "ec2", "organizations"}
		}},
		{"all attestation frequencies", func(t *testing.T, a *Artifact) {
			mustControl(t, a, "ZZ.L1-b.1.z").Attestation.Frequency = "on-change"
		}},
		{"aws-mapping binding carries no rationale", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "ACCESS_KEYS_ROTATED")
			if r.Provenance != ProvenanceAWSMapping || r.Rationale != "" {
				t.Fatal("test setup: expected an aws-mapping binding with no rationale")
			}
		}},
		{"curated binding with a rationale", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC")
			if r.Provenance != ProvenanceCurated || r.Rationale == "" {
				t.Fatal("test setup: expected a curated binding with a rationale")
			}
		}},
		{"aws-mapping binding may also carry a rationale", func(t *testing.T, a *Artifact) {
			// Only curated bindings *require* one; the schema does not forbid an
			// explanatory note on a mapped binding. gen/ chooses not to emit one
			// (TestAWSMappingLayerIsMechanical), which is a compiler policy, not
			// a schema constraint.
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "ACCESS_KEYS_ROTATED").Rationale = "context for a reader"
		}},
		{"both set orders with the default separator", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC")
			r.Parameters["blockedActionsPatterns"] = RuleParameter{
				Value: "kms:Decrypt,kms:ReEncryptFrom", Order: OrderSetUnion,
			}
			r.Parameters["authorizedTcpPorts"] = RuleParameter{Value: "443", Order: OrderSetIntersect}
		}},
		{"explicit non-default separator on a set order", func(t *testing.T, a *Artifact) {
			r := mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "RESTRICTED_INCOMING_TRAFFIC")
			r.Parameters["blockedActionsPatterns"] = RuleParameter{
				Value: "kms:Decrypt;kms:ReEncryptFrom", Order: OrderSetUnion, SetSeparator: ";",
			}
		}},
		{"resource types on a rule", func(t *testing.T, a *Artifact) {
			mustRule(t, mustControl(t, a, "AA.L1-b.1.a"), "ACCESS_KEYS_ROTATED").ResourceTypes =
				[]string{"AWS::IAM::User"}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := sampleArtifact()
			tc.mutate(t, a)
			if err := a.SetContentHash(); err != nil {
				t.Fatalf("SetContentHash: %v", err)
			}
			if err := a.Validate(); err != nil {
				t.Fatalf("internal/artifact rejects a document that should be valid: %v", err)
			}
			if err := sch.Validate(asGeneric(t, a)); err != nil {
				t.Errorf("the published schema rejects a document internal/artifact accepts — "+
					"schema/control-artifact-v1.schema.json is too strict:\n%v", err)
			}
		})
	}
}

// TestSchemasDeclareStableIdentity guards the fields external consumers key off.
func TestSchemasDeclareStableIdentity(t *testing.T) {
	want := map[string]string{
		"control-artifact-v1.schema.json":  "automat.dev/schema/control-artifact/v1",
		"profile-v1.schema.json":           "automat.dev/schema/profile/v1",
		"evidence-manifest-v1.schema.json": "automat.dev/schema/evidence-manifest/v1",
	}
	for name, wantID := range want {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(schemaDir, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var doc struct {
				Schema string `json:"$schema"`
				ID     string `json:"$id"`
				Title  string `json:"title"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if doc.ID != wantID {
				t.Errorf("$id = %q, want %q; the $id is a published identifier and changing it breaks consumers",
					doc.ID, wantID)
			}
			if doc.Schema == "" {
				t.Error("$schema is missing")
			}
			if doc.Title == "" {
				t.Error("title is missing")
			}
		})
	}
}

// TestNoProductReferences enforces DESIGN §15: no commercial suite, company, or
// upstream product named anywhere in the schema or catalog surface, other than
// AWS.
func TestNoProductReferences(t *testing.T) {
	// Names that would violate the branding rule if they appeared. AWS is
	// permitted; these are not.
	forbidden := []string{
		"control tower",
		"controltower",
		"audit manager",
		"landing zone accelerator",
	}
	dirs := []string{schemaDir, "../../catalogs"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path) //nolint:gosec // test-local path
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			lower := strings.ToLower(string(data))
			for _, bad := range forbidden {
				if strings.Contains(lower, bad) {
					t.Errorf("%s mentions %q; DESIGN §15 forbids product references other than AWS", path, bad)
				}
			}
		}
	}
}
