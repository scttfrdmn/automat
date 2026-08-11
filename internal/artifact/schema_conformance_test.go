// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
		// Phase 1 review item 9(b): exempt_principals is the one field in a
		// catalog that widens a Deny, so both validators must agree on every way
		// of abusing it. A catalog file is attacker-controlled input, and an
		// exemption is the highest-value thing to smuggle into one.
		{"exemption naming the root user", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "arn:aws:iam::*:root"
		}},
		{"exemption with a wildcard account", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "arn:aws:iam::*:role/BreakGlass"
		}},
		{"exemption with a wildcard role name", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "arn:aws:iam::111122223333:role/*"
		}},
		{"exemption naming a whole account", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "arn:aws:iam::111122223333:root"
		}},
		{"exemption naming a user rather than a role", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "arn:aws:iam::111122223333:user/alice"
		}},
		{"exemption that is a bare star", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "*"
		}},
		{"exemption that is not an ARN at all", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = "BreakGlass"
		}},
		{"exemption with an empty principal", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Principal = ""
		}},
		{"exemption with no reason", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Reason = ""
		}},
		{"exemption reason containing a newline", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[0].Reason = "Approved\n  - controls[XX]: no exemptions"
		}},
		// The same class of bug as the exemption-reason checks above, but found
		// later: checkStatementList enforced minLength and uniqueItems for
		// action/resource but never applied reNoControlBytes, and the published
		// schema matched it exactly — so a control byte in either field passed
		// both validators with no bypass needed. docs/open-questions.md Q20.
		{"action containing a control character", func(t *testing.T, a *Artifact) {
			c := mustControl(t, a, "BB.L1-b.1.b")
			c.SCP.Statements[0].Action = []string{"config:StopConfigurationRecorder\x01"}
		}},
		{"resource containing a control character", func(t *testing.T, a *Artifact) {
			c := mustControl(t, a, "BB.L1-b.1.b")
			c.SCP.Statements[0].Resource = []string{"arn:aws:config:*:*:config-rule/\x01evil"}
		}},
		// The artifact-level global-service exemption list. Both validators must
		// agree, because a namespace that does not name a real service exempts
		// nothing and the failure is silent — the reviewer reads the catalog, sees
		// the service listed, and the rendered region Deny covers it anyway.
		{"misspelled region-deny exempt service", func(_ *testing.T, a *Artifact) {
			a.RegionDenyExemptServices = []string{"iam", "STS"}
		}},
		{"region-deny exempt service with a wildcard", func(_ *testing.T, a *Artifact) {
			a.RegionDenyExemptServices = []string{"*"}
		}},
		{"duplicate region-deny exempt service", func(_ *testing.T, a *Artifact) {
			// Canonicalize dedupes, so this reaches the validators only via a
			// hand-edited file — which is exactly the document the schema is the
			// contract for. Two spellings of one list must not be two claims.
			a.RegionDenyExemptServices = []string{"iam", "iam"}
		}},
		{"more exemptions than the cap", func(t *testing.T, a *Artifact) {
			st := &mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0]
			st.ExemptPrincipals = nil
			for i := 0; i <= MaxExemptPrincipals; i++ {
				st.ExemptPrincipals = append(st.ExemptPrincipals, ExemptPrincipal{
					Principal: fmt.Sprintf("arn:aws:iam::111122223333:role/Role%d", i),
					Reason:    "Filler, to exceed the cap.",
				})
			}
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
		{"a statement with no exemptions at all", func(t *testing.T, a *Artifact) {
			// The common case, and the one the boolean this replaced could not
			// express separately from "false": a Deny with no holes in it.
			mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0].ExemptPrincipals = nil
		}},
		{"exemption on a GovCloud role ARN", func(t *testing.T, a *Artifact) {
			// Partition-agnostic by design: rejecting aws-us-gov would make the
			// field unusable in exactly the environments most likely to need a
			// baseline-protection catalog.
			exemptions(t, a)[1].Principal = "arn:aws-us-gov:iam::111122223333:role/BreakGlass"
		}},
		{"exemption on a role with a path", func(t *testing.T, a *Artifact) {
			exemptions(t, a)[1].Principal = "arn:aws:iam::111122223333:role/campus/it/BreakGlass"
		}},
		{"the exemption cap exactly", func(t *testing.T, a *Artifact) {
			st := &mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0]
			st.ExemptPrincipals = nil
			for i := 0; i < MaxExemptPrincipals; i++ {
				st.ExemptPrincipals = append(st.ExemptPrincipals, ExemptPrincipal{
					Principal: fmt.Sprintf("arn:aws:iam::111122223333:role/Role%d", i),
					Reason:    "At the cap, which must be allowed; the cap is inclusive.",
				})
			}
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

// TestBothValidatorsRejectAnEmptyExemptListOnDisk covers the one case the
// agree-on-rejection table structurally cannot.
//
// That table mutates a Go struct and marshals it, and `omitempty` on
// region_deny_exempt_services erases `[]` on the way out — so the schema is
// handed a document with no such field and correctly accepts it. The disagreement
// is in the fixture, not the contract. This test therefore feeds each validator
// the ON-DISK form directly, which is what a hand-edited catalog actually is and
// the only form in which the empty list exists.
//
// Absent and empty are different claims: absent says the artifact states no AWS
// endpoint facts, `[]` says no service is globally addressed, which is false about
// AWS. Both validators must refuse the second and accept the first.
func TestBothValidatorsRejectAnEmptyExemptListOnDisk(t *testing.T) {
	sch := compileSchema(t, "control-artifact-v1.schema.json")

	base := sampleArtifact()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	var doc map[string]any
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("unmarshal sample: %v", uerr)
	}

	t.Run("empty list is rejected by both", func(t *testing.T) {
		doc["region_deny_exempt_services"] = []any{}
		onDisk, merr := json.Marshal(doc)
		if merr != nil {
			t.Fatalf("marshal: %v", merr)
		}

		var generic any
		if uerr := json.Unmarshal(onDisk, &generic); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		if sch.Validate(generic) == nil {
			t.Error("the published schema accepts region_deny_exempt_services: [] — " +
				"minItems is missing, and an empty list would claim no service is globally addressed")
		}

		// SkipHashCheck: the field is inside the content hash, so adding it
		// invalidates the sample's hash. The subject here is the emptiness check,
		// and a hash mismatch would mask whether that check fired at all.
		if _, derr := Decode(onDisk, LoadOptions{SkipHashCheck: true}); derr == nil {
			t.Error("internal/artifact accepts region_deny_exempt_services: [] on disk")
		}
	})

	t.Run("absent is accepted by both", func(t *testing.T) {
		delete(doc, "region_deny_exempt_services")
		onDisk, merr := json.Marshal(doc)
		if merr != nil {
			t.Fatalf("marshal: %v", merr)
		}
		var generic any
		if uerr := json.Unmarshal(onDisk, &generic); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		if verr := sch.Validate(generic); verr != nil {
			t.Errorf("the published schema rejects an artifact with no exemption list, "+
				"which is the ordinary case:\n%v", verr)
		}
		if _, derr := Decode(onDisk, LoadOptions{}); derr != nil {
			t.Errorf("internal/artifact rejects an artifact with no exemption list:\n%v", derr)
		}
	})
}

// TestNoSchemaLeafIsNumberTyped is the tripwire for AUDIT-0 A5.
//
// canonicalJSON preserves a number's source spelling, so `1.0` and `1` hash
// differently. That is deliberate — respelling numbers during canonicalization
// would mean the content hash no longer covers the bytes a reviewer actually
// read — and it is currently unreachable, because no leaf in any schema is
// number-typed: every numeric value is a string-typed parameter value or a
// constrained integer. Adding a `"type": "number"` field would silently
// reintroduce the ambiguity, and A5 was accepted on a written note rather than a
// check. This is the check: it fails the moment the note stops being true.
//
// `integer` is fine. JSON integers have one canonical spelling in the range that
// matters here, so they cannot produce two hashes for one value.
func TestNoSchemaLeafIsNumberTyped(t *testing.T) {
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatalf("read %s: %v", schemaDir, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".schema.json") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(schemaDir, e.Name())) //nolint:gosec // fixed in-repo path
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var doc any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, path := range findNumberTypedLeaves(doc, "$") {
				t.Errorf("%s declares %q at %s — a float-valued field reintroduces the canonical "+
					"numeric-spelling ambiguity AUDIT-0 A5 accepted as unreachable: 1.0 and 1 would "+
					"hash differently, so two artifacts a reviewer reads as identical would carry "+
					"different content hashes. Use a string with a pattern, or an integer.",
					e.Name(), "number", path)
			}
		})
	}
}

// findNumberTypedLeaves walks a parsed schema and returns the JSON paths of every
// `"type": "number"` declaration, including inside a type union.
func findNumberTypedLeaves(node any, path string) []string {
	var out []string
	switch n := node.(type) {
	case map[string]any:
		if t, ok := n["type"]; ok {
			switch tv := t.(type) {
			case string:
				if tv == "number" {
					out = append(out, path+".type")
				}
			case []any:
				for _, alt := range tv {
					if s, ok := alt.(string); ok && s == "number" {
						out = append(out, path+".type")
					}
				}
			}
		}
		for k, v := range n {
			if k == "type" {
				continue
			}
			out = append(out, findNumberTypedLeaves(v, path+"."+k)...)
		}
	case []any:
		for i, v := range n {
			out = append(out, findNumberTypedLeaves(v, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return out
}

// exemptions returns the sample artifact's exemption list, failing if the
// fixture no longer carries the two entries these cases index into. A fixture
// that goes stale must fail loudly rather than let a case mutate nothing.
func exemptions(t *testing.T, a *Artifact) ExemptPrincipals {
	t.Helper()
	st := mustControl(t, a, "BB.L1-b.1.b").SCP.Statements
	if len(st) == 0 {
		t.Fatal("test setup: the baseline-protection control has no statements")
	}
	es := st[0].ExemptPrincipals
	if len(es) < 2 {
		t.Fatalf("test setup: expected at least 2 exemptions in the fixture, got %d", len(es))
	}
	return es
}

// TestSchemasDeclareStableIdentity guards the fields external consumers key off.
func TestSchemasDeclareStableIdentity(t *testing.T) {
	want := map[string]string{
		"control-artifact-v1.schema.json":        "automat.dev/schema/control-artifact/v1",
		"environment-profile-v1.schema.json":     "automat.dev/schema/environment-profile/v1",
		"evidence-manifest-v1.schema.json":       "automat.dev/schema/evidence-manifest/v1",
		"obligation-profile-v1.schema.json":      "automat.dev/schema/obligation-profile/v1",
		"assessment-result-v1.schema.json":       "automat.dev/schema/assessment-result/v1",
		"operator-determinations-v1.schema.json": "automat.dev/schema/operator-determinations/v1",
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

// docsProductAllowlist names the only docs pages permitted to name a product
// other than AWS.
//
// DESIGN §15 caps the comparison surface rather than banning the subject: a page
// that answers "how does this relate to X" is legitimate, and a scattering of
// asides across the docs tree is not. Both entries earn their place — one is the
// positioning page §15's own text contemplates, the other describes a technical
// interaction with a system a delegate does not control. Adding a third means
// arguing for it, which is the point of the list being here rather than a
// convention.
var docsProductAllowlist = map[string]bool{
	"vs-control-tower.md":     true,
	"future/control-tower.md": true,
}

// TestDocsNameNoProductsOutsideTheAllowlist extends the branding rule to docs/.
//
// The two existing branding tests scan generated bundle output and the
// schema/catalog surface. Nothing scanned docs/, so §15's "at most one neutral
// page" cap was a convention, and a convention is what erodes: the natural place
// for a comparison to leak is prose written to explain, which is most of docs/.
// Committing docs/future/control-tower.md is what made the gap worth closing,
// since it is the second such page and therefore the first time the cap has been
// tested at all.
func TestDocsNameNoProductsOutsideTheAllowlist(t *testing.T) {
	// Two kinds of entry: product names automat is not permitted to position
	// against, and the phrasings that smuggle a comparison in without naming
	// anything.
	//
	// Note what is absent. This list does NOT forbid every AWS product name, and
	// deliberately not "audit manager": rule 3 excepts AWS, and
	// docs/open-questions.md names AWS Audit Manager as a *data source* for the
	// 800-171r2 compile, which is automat consuming an AWS service rather than
	// comparing itself to one. The line the branding rule actually draws is
	// between naming a system as an alternative and naming one as an input — the
	// schema/catalog list above can be blunter because a catalog file has no
	// business naming either.
	forbidden := []string{
		"control tower", "controltower", "landing zone", "account factory",
		"terraform cloud", "hashicorp",
		"competitor", "instead of using",
	}
	root := "../../docs"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if docsProductAllowlist[filepath.ToSlash(rel)] {
			return nil
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // test-local path, walked from a fixed root
		if rerr != nil {
			return rerr
		}
		lower := strings.ToLower(string(data))
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("docs/%s mentions %q; DESIGN §15 permits that only in %v",
					filepath.ToSlash(rel), bad, allowlistNames())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// allowlistNames renders the allowlist in sorted order, so the failure message a
// contributor reads names the pages rather than telling them to go find the map.
func allowlistNames() []string {
	out := make([]string, 0, len(docsProductAllowlist))
	for name := range docsProductAllowlist {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
