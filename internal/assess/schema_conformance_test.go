// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schema/obligation-profile-v1.schema.json is the published compatibility
// contract; Profile and Validate() in this package are the implementation.
// These tests keep the two honest about each other — the same discipline
// internal/envprofile's own schema_conformance_test.go established, and the
// one validate.go's own doc comments on reSemver/reSlug/reDate/reSHA256
// have claimed since this package was written
// ("TestValidateAgreesWithTheSchema in this package keeps this copy in step
// with that contract"). AUDIT-5 found that comment describing a test that
// did not exist: internal/artifact/obligation_profile_test.go covers the
// three *shipped* profiles against the schema, which is a different and
// narrower guarantee than this file's — a mutation this package's Validate
// rejects but the schema accepts (or the reverse) never shows up by loading
// documents that are already valid.

func compileObligationSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	return compileNamedSchema(t, "obligation-profile-v1.schema.json")
}

func compileNamedSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("../../schema", name)
	f, err := os.Open(path) //nolint:gosec // fixed in-repo path
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

// asGeneric round-trips a value through JSON into the shape the validator
// expects, so the schema sees exactly the bytes automat would write.
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

func TestSampleProfileSatisfiesPublishedSchema(t *testing.T) {
	sch := compileObligationSchema(t)
	p := validCMMCL1(t)
	if verr := sch.Validate(asGeneric(t, p)); verr != nil {
		t.Errorf("a profile this package considers valid violates the published schema:\n%v", verr)
	}
}

// TestValidateAgreesWithTheSchema is the drift detector this package's own
// comments have named since it was written: for each way of breaking an
// obligation profile, both the hand-written Go validator (Profile.Validate)
// and the published JSON Schema must reject it. A case only one of them
// catches is drift between the two things that check a hand-edited profile.
func TestValidateAgreesWithTheSchema(t *testing.T) {
	sch := compileObligationSchema(t)

	cases := []struct {
		name   string
		mutate func(*testing.T, *Profile)
	}{
		// ---- identity ----
		{"missing schema version", func(_ *testing.T, p *Profile) { p.SchemaVersion = "" }},
		{"non-semver schema version", func(_ *testing.T, p *Profile) { p.SchemaVersion = "1.0" }},
		{"missing profile id", func(_ *testing.T, p *Profile) { p.Meta.ID = "" }},
		{"profile id with spaces", func(_ *testing.T, p *Profile) { p.Meta.ID = "CMMC L1" }},
		{"missing title", func(_ *testing.T, p *Profile) { p.Meta.Title = "" }},
		{"title containing a newline", func(_ *testing.T, p *Profile) {
			p.Meta.Title = "CMMC Level 1\nreviewed-by: nobody"
		}},
		{"missing issuing authority", func(_ *testing.T, p *Profile) { p.Meta.IssuingAuthority = "" }},

		// ---- status / review_by ----
		{"status outside the enum", func(_ *testing.T, p *Profile) { p.Status = "final" }},
		{"missing review date", func(_ *testing.T, p *Profile) { p.ReviewBy = "" }},
		{"review date as a timestamp", func(_ *testing.T, p *Profile) {
			p.ReviewBy = "2027-06-30T00:00:00Z"
		}},

		// ---- citations ----
		{"no citations", func(_ *testing.T, p *Profile) { p.Citations = nil }},
		{"citation with no effective date", func(_ *testing.T, p *Profile) {
			p.Citations[0].EffectiveDate = ""
		}},
		{"citation role outside the enum", func(_ *testing.T, p *Profile) {
			p.Citations[0].Role = "invented"
		}},
		{"citation note with a control character", func(_ *testing.T, p *Profile) {
			p.Citations[0].Note = "See the notice.\x1b[31m"
		}},

		// ---- control_catalogs ----
		{"no control catalogs", func(_ *testing.T, p *Profile) { p.ControlCatalogs = nil }},
		{"revision_policy outside the enum", func(_ *testing.T, p *Profile) {
			p.ControlCatalogs[0].RevisionPolicy = "guessed"
		}},
		{"pinned catalog with no revision", func(_ *testing.T, p *Profile) {
			p.ControlCatalogs[0].RevisionPolicy = "pinned"
			p.ControlCatalogs[0].Revision = ""
		}},
		{"operator-determined catalog carrying a pinned revision", func(_ *testing.T, p *Profile) {
			p.ControlCatalogs[0].RevisionPolicy = RevisionOperatorDetermined
			p.ControlCatalogs[0].Revision = "Revision 2"
		}},
		{"catalog artifact_id with spaces", func(_ *testing.T, p *Profile) {
			p.ControlCatalogs[0].ArtifactID = "cmmc l1"
		}},

		// ---- assessment ----
		{"assessment type outside the enum", func(_ *testing.T, p *Profile) {
			p.Assessment.Type = "peer-reviewed"
		}},
		{"assessment with no signed_by", func(_ *testing.T, p *Profile) {
			p.Assessment.SignedBy = nil
		}},
		{"audited_by_issuer outside the enum", func(_ *testing.T, p *Profile) {
			p.Assessment.AuditedByIssuer = "sometimes"
		}},

		// ---- determinations ----
		// understatement_value outside values is deliberately not in this
		// table — see TestTheSchemaCannotCheckUnderstatementValueAgainstValues.
		{"fewer than two determination values", func(_ *testing.T, p *Profile) {
			p.Determinations.Values = []string{"MET"}
		}},

		// ---- scoring ----
		{"scoring method outside the enum", func(_ *testing.T, p *Profile) {
			p.Scoring.Method = "invented-method"
		}},
		{"weight_table present with method none", func(_ *testing.T, p *Profile) {
			p.Scoring.WeightTable = &HashedReference{ID: "x", SHA256: strings.Repeat("a", 64)}
		}},

		// ---- submission ----
		{"missing submission target", func(_ *testing.T, p *Profile) { p.Submission.Target = "" }},

		// ---- applicability ----
		{"missing applicability trigger", func(_ *testing.T, p *Profile) {
			p.Applicability.Trigger = ""
		}},
		{"declared_by_operator false", func(_ *testing.T, p *Profile) {
			p.Applicability.DeclaredByOperator = false
		}},

		// ---- policy_caveat / sources ----
		{"missing policy caveat", func(_ *testing.T, p *Profile) { p.PolicyCaveat = "" }},
		{"policy caveat with a NUL byte", func(_ *testing.T, p *Profile) {
			p.PolicyCaveat = "automat encodes a technical reading\x00 of policy."
		}},
		{"no sources", func(_ *testing.T, p *Profile) { p.Sources = nil }},
		{"source with a malformed hash", func(_ *testing.T, p *Profile) {
			p.Sources[0].SHA256 = "not-hex"
		}},
		{"source retrieved_at as a bare date", func(_ *testing.T, p *Profile) {
			p.Sources[0].RetrievedAt = "2026-08-01"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validCMMCL1(t)
			tc.mutate(t, p)

			goErr := p.Validate()
			schemaErr := sch.Validate(asGeneric(t, p))

			switch {
			case goErr == nil && schemaErr == nil:
				t.Errorf("neither Profile.Validate nor the schema rejected %q", tc.name)
			case goErr == nil:
				t.Errorf("the published schema rejects %q but internal/assess accepts it — "+
					"Validate() is missing a check:\n%v", tc.name, schemaErr)
			case schemaErr == nil:
				t.Errorf("internal/assess rejects %q but the published schema accepts it — "+
					"schema/obligation-profile-v1.schema.json is missing a constraint:\n%v", tc.name, goErr)
			}
		})
	}
}

// TestTheSchemaCannotCheckUnderstatementValueAgainstValues records a gap the
// table above cannot express, the same way internal/envprofile's own
// schema_conformance_test.go records the gaps neither validator alone can
// state.
//
// determinations.understatement_value must be a member of the sibling array
// determinations.values (docs/assessment-reporting.md, Invariant 2). JSON
// Schema draft 2020-12 has no standard way to constrain one property's value
// against the contents of another property's array in the same object —
// that needs either a hard-coded enum (which would defeat the point of the
// field being data) or the non-standard $data reference some validators
// support and this project's schemas do not use elsewhere. So the schema
// accepts an understatement_value the regime's own vocabulary does not
// contain, and only Profile.Validate refuses it.
func TestTheSchemaCannotCheckUnderstatementValueAgainstValues(t *testing.T) {
	sch := compileObligationSchema(t)
	p := validCMMCL1(t)
	p.Determinations.UnderstatementValue = "PARTIALLY MET"

	if err := p.Validate(); err == nil {
		t.Error("Profile.Validate accepted an understatement_value outside determinations.values, " +
			"want a refusal — Invariant 2 depends on this check existing somewhere")
	}
	if err := sch.Validate(asGeneric(t, p)); err != nil {
		t.Errorf("the published schema unexpectedly rejects an understatement_value outside "+
			"determinations.values on its own — if this now fails, the schema gained a $data "+
			"constraint and this test (and its comment) are stale: %v", err)
	}
}

// TestSchemaAcceptsWhatValidateAccepts is TestValidateAgreesWithTheSchema's
// other direction: confirms the unmutated, valid document — and a couple of
// legitimately different-but-valid shapes — do not trip the schema, so a
// too-strict schema is caught the same way a too-loose one is above.
func TestSchemaAcceptsWhatValidateAccepts(t *testing.T) {
	sch := compileObligationSchema(t)

	for _, name := range []string{"cmmc-l1", "dfars-7012", "nih-cadr-dua"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "catalogs", "obligations", name+".json")
			p, err := LoadProfile(path, LoadOptions{})
			if err != nil {
				t.Fatalf("LoadProfile(%s): %v", path, err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("Profile.Validate rejects the shipped %s profile: %v", name, err)
			}
			if err := sch.Validate(asGeneric(t, p)); err != nil {
				t.Errorf("the published schema rejects a document internal/assess accepts — "+
					"schema/obligation-profile-v1.schema.json is too strict:\n%v", err)
			}
		})
	}
}
