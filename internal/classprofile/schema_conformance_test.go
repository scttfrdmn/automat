// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package classprofile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/scttfrdmn/automat/internal/evidence"
)

// schema/classification-profile-v1.schema.json is the published compatibility contract;
// the Go types and Validate() in this package are the implementation. These tests keep
// the two honest about each other, the way internal/envprofile's do.
//
// The stakes are different here, and higher in one specific way. An environment profile
// is written by the operator who will vend with it, so drift costs them one confusing
// afternoon. A classification profile is FORKED: the whole model is that an institution
// takes automat's reading of its policy, corrects it, and re-attests. Their editor
// validates against the published schema; automat's loader is what decides. If the schema
// is looser, the fork they publish under their own name carries a defect automat would
// have caught. If the schema is stricter, they are told their correction is invalid.

const schemaFile = "classification-profile-v1.schema.json"

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("../../schema", schemaFile)
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
	if aerr := c.AddResource(schemaFile, doc); aerr != nil {
		t.Fatalf("add %s: %v", path, aerr)
	}
	sch, err := c.Compile(schemaFile)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return sch
}

// asGeneric round-trips a value through JSON into the shape the validator expects, so
// the schema sees exactly the bytes automat would write.
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
	sch := compileSchema(t)
	for _, f := range []struct {
		name string
		p    *Profile
	}{
		{"the sample profile", sampleProfile(t)},
		{"the three-level fixture", threeLevelFixture()},
		{"the descending-label fixture", umichFixture()},
		{"the ascending-label fixture", harvardFixture()},
	} {
		t.Run(f.name, func(t *testing.T) {
			data, err := f.p.MarshalIndented()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if verr := sch.Validate(doc); verr != nil {
				t.Errorf("a profile this package considers valid violates the published schema:"+
					"\n%v\n\ndocument:\n%s", verr, data)
			}
		})
	}
}

// TestGoAndSchemaAgreeOnRejection is the drift detector: for each way of breaking a
// classification profile, both the hand-written Go validator and the published JSON
// Schema must reject it. A case only one of them catches is drift.
//
// Cases that only ONE side can express are deliberately absent from this table and
// recorded as their own tests below, so the gap is written down rather than discovered.
func TestGoAndSchemaAgreeOnRejection(t *testing.T) {
	sch := compileSchema(t)

	cases := []struct {
		name   string
		mutate func(*testing.T, *Profile)
	}{
		// ---- identity ----
		{"missing schema version", func(_ *testing.T, p *Profile) { p.SchemaVersion = "" }},
		{"non-semver schema version", func(_ *testing.T, p *Profile) { p.SchemaVersion = "1.0" }},
		{"missing profile id", func(_ *testing.T, p *Profile) { p.Meta.ID = "" }},
		{"profile id with spaces", func(_ *testing.T, p *Profile) { p.Meta.ID = "UC Protection Levels" }},
		{"profile id with a trailing hyphen", func(_ *testing.T, p *Profile) { p.Meta.ID = "uc-levels-" }},
		{"missing title", func(_ *testing.T, p *Profile) { p.Meta.Title = "" }},
		{"title containing a newline", func(_ *testing.T, p *Profile) {
			p.Meta.Title = "Example levels\nreviewed-by: the institution"
		}},
		{"description containing an ANSI escape", func(_ *testing.T, p *Profile) {
			p.Meta.Description = "Levels\x1b[31m"
		}},

		// ---- issuer: rule 8, the id an operator types ----
		{"missing issuer id", func(_ *testing.T, p *Profile) { p.Issuer.ID = "" }},
		{"issuer id with a space", func(_ *testing.T, p *Profile) { p.Issuer.ID = "university of california" }},
		{"issuer id with uppercase", func(_ *testing.T, p *Profile) { p.Issuer.ID = "UC" }},
		{"issuer id with a quote", func(_ *testing.T, p *Profile) { p.Issuer.ID = `uc"` }},
		{"issuer id that is a single character", func(_ *testing.T, p *Profile) { p.Issuer.ID = "u" }},
		{"missing issuer name", func(_ *testing.T, p *Profile) { p.Issuer.Name = "" }},
		{"issuer name with a control character", func(_ *testing.T, p *Profile) {
			p.Issuer.Name = "Example\x00Institution"
		}},

		// ---- status, review, authorship ----
		{"status outside the vocabulary", func(_ *testing.T, p *Profile) { p.Status = "current" }},
		{"missing review date", func(_ *testing.T, p *Profile) { p.ReviewBy = "" }},
		{"review date as a timestamp", func(_ *testing.T, p *Profile) {
			p.ReviewBy = "2027-01-01T00:00:00Z"
		}},
		{"unpadded review date", func(_ *testing.T, p *Profile) { p.ReviewBy = "2027-1-1" }},
		{"authorship outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Authorship = "reviewed-with"
		}},
		{"maintenance outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Maintenance = "best-effort"
		}},
		{"a derived profile claiming to be maintained", func(_ *testing.T, p *Profile) {
			// automat is not the upstream for anybody's classification policy.
			p.Maintenance = MaintenanceShipped
		}},
		{"a derived profile with no interpretation block", func(_ *testing.T, p *Profile) {
			p.Interpretation = nil
		}},
		{"an issuer-authored profile carrying an interpretation", func(_ *testing.T, p *Profile) {
			p.Authorship = AuthorshipIssuer
			p.Maintenance = MaintenanceShipped
		}},
		{"an interpretation with no attribution", func(t *testing.T, p *Profile) {
			interp(t, p).Attribution = ""
		}},
		{"an interpretation with no interpreter", func(t *testing.T, p *Profile) {
			interp(t, p).Interpreter = ""
		}},
		{"an interpretation with no non-endorsement statement", func(t *testing.T, p *Profile) {
			interp(t, p).NonEndorsement = ""
		}},
		{"an interpretation with no source", func(t *testing.T, p *Profile) {
			interp(t, p).SourceID = ""
		}},

		// ---- determination ----
		{"automat determining the level", func(_ *testing.T, p *Profile) {
			// The worst output this tool could produce, pinned const false on both sides.
			p.Determination.AutomatDetermines = true
		}},
		{"no roles named as the determiner", func(_ *testing.T, p *Profile) {
			p.Determination.Roles = []string{}
		}},
		{"a duplicated determination role", func(_ *testing.T, p *Profile) {
			p.Determination.Roles = []string{"Data Stewards", "Data Stewards"}
		}},
		{"a determination role with a newline", func(_ *testing.T, p *Profile) {
			p.Determination.Roles = []string{"Data Stewards\nautomat"}
		}},
		{"more determination roles than the cap", func(_ *testing.T, p *Profile) {
			p.Determination.Roles = nil
			for i := 0; i <= maxRoles; i++ {
				p.Determination.Roles = append(p.Determination.Roles, fmt.Sprintf("Role %d", i))
			}
		}},
		{"no determination process", func(_ *testing.T, p *Profile) { p.Determination.Process = "" }},
		{"no determination citation", func(_ *testing.T, p *Profile) {
			p.Determination.Citation = CitationRef{}
		}},
		{"may_raise outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Determination.MayRaise = "sometimes"
		}},
		{"may_lower permitted outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Determination.MayLower.Permitted = "sometimes"
		}},

		// ---- levels ----
		{"a single level", func(_ *testing.T, p *Profile) {
			// A one-level scheme is not a classification scheme; it has no join.
			p.Levels = p.Levels[:1]
		}},
		{"more levels than the cap", func(_ *testing.T, p *Profile) {
			p.Levels = nil
			for i := 0; i <= MaxLevels; i++ {
				p.Levels = append(p.Levels, Level{
					ID: fmt.Sprintf("level-%d", i), Label: fmt.Sprintf("Level %d", i), Rank: i + 1,
					Definition: "A level.",
					Citation:   CitationRef{SourceID: "example-policy", Section: "Section 3"},
				})
			}
		}},
		{"a level with no id", func(_ *testing.T, p *Profile) { p.Levels[0].ID = "" }},
		{"a level id with a space", func(_ *testing.T, p *Profile) {
			// Rule 8: the most-typed value in the model. Whitespace cannot be
			// double-clicked, so the operator retypes it and gets it wrong.
			p.Levels[0].ID = "protection level 3"
		}},
		{"a level id with uppercase", func(_ *testing.T, p *Profile) { p.Levels[0].ID = "P3" }},
		{"a level id with a quote", func(_ *testing.T, p *Profile) { p.Levels[0].ID = `p3"` }},
		{"a level id with a shell metacharacter", func(_ *testing.T, p *Profile) {
			p.Levels[0].ID = "p3;echo"
		}},
		{"a level id that is a single character", func(_ *testing.T, p *Profile) {
			p.Levels[0].ID = "p"
		}},
		{"a level id longer than the pattern allows", func(_ *testing.T, p *Profile) {
			p.Levels[0].ID = strings.Repeat("p", 33)
		}},
		{"a level with no label", func(_ *testing.T, p *Profile) { p.Levels[0].Label = "" }},
		{"a level label with a newline", func(_ *testing.T, p *Profile) {
			p.Levels[0].Label = "Public\nRestricted"
		}},
		{"a level with no rank", func(_ *testing.T, p *Profile) { p.Levels[1].Rank = 0 }},
		{"a level with a negative rank", func(_ *testing.T, p *Profile) { p.Levels[1].Rank = -1 }},
		{"a rank above the ceiling", func(_ *testing.T, p *Profile) { p.Levels[1].Rank = MaxRank + 1 }},
		{"a level with no definition", func(_ *testing.T, p *Profile) { p.Levels[0].Definition = "" }},
		{"a level with no citation", func(_ *testing.T, p *Profile) { p.Levels[0].Citation = CitationRef{} }},
		{"a duplicated example within a level", func(_ *testing.T, p *Profile) {
			p.Levels[0].Examples = []string{"Press releases", "Press releases"}
		}},
		{"an example with a control character", func(_ *testing.T, p *Profile) {
			p.Levels[0].Examples = []string{"Press releases\x07"}
		}},
		{"more examples than the cap", func(_ *testing.T, p *Profile) {
			p.Levels[0].Examples = nil
			for i := 0; i <= maxExamples; i++ {
				p.Levels[0].Examples = append(p.Levels[0].Examples, fmt.Sprintf("Example %d", i))
			}
		}},

		// ---- controls: gate 4 as a shape ----
		{"a control with no id", func(t *testing.T, p *Profile) { firstControl(t, p).ID = "" }},
		{"a control id with a space", func(t *testing.T, p *Profile) {
			firstControl(t, p).ID = "access review"
		}},
		{"a control with no title", func(t *testing.T, p *Profile) { firstControl(t, p).Title = "" }},
		{"a control with no requirement", func(t *testing.T, p *Profile) {
			firstControl(t, p).Requirement = ""
		}},
		{"a control with no citation", func(t *testing.T, p *Profile) {
			// Where the source is silent the profile is silent; a control with no cited
			// section is automat's opinion wearing an institution's name.
			firstControl(t, p).Citation = CitationRef{}
		}},
		{"a control citing no section", func(t *testing.T, p *Profile) {
			firstControl(t, p).Citation.Section = ""
		}},
		{"automat_enforces outside the vocabulary", func(t *testing.T, p *Profile) {
			firstControl(t, p).AutomatEnforces = "eventually"
		}},
		{"more controls than the cap", func(_ *testing.T, p *Profile) {
			p.Levels[1].Controls = nil
			for i := 0; i <= maxControls; i++ {
				p.Levels[1].Controls = append(p.Levels[1].Controls, Control{
					ID: fmt.Sprintf("control-%d", i), Title: "A control",
					Requirement: "Do the thing.",
					Citation:    CitationRef{SourceID: "example-policy", Section: "Section 4"},
				})
			}
		}},

		// ---- external obligations ----
		{"an external obligation with no name", func(t *testing.T, p *Profile) {
			firstObligation(t, p).Name = ""
		}},
		{"an external obligation automat relates itself", func(t *testing.T, p *Profile) {
			// A level's table naming a regime is not a determination that it applies.
			firstObligation(t, p).Relation = "requires"
		}},
		{"an external obligation not declared by the operator", func(t *testing.T, p *Profile) {
			firstObligation(t, p).DeclaredByOperator = false
		}},
		{"an external obligation with no citation", func(t *testing.T, p *Profile) {
			firstObligation(t, p).Citation = CitationRef{}
		}},

		// ---- composition ----
		{"a second composition rule", func(_ *testing.T, p *Profile) {
			p.Composition.Rule = "lowest-water-mark"
		}},
		{"no composition rule", func(_ *testing.T, p *Profile) { p.Composition.Rule = "" }},
		{"no composition statement", func(_ *testing.T, p *Profile) { p.Composition.Statement = "" }},
		{"no composition citation", func(_ *testing.T, p *Profile) {
			p.Composition.Citation = CitationRef{}
		}},

		// ---- inherits ----
		{"an inherits block with no profile id", func(_ *testing.T, p *Profile) {
			p.Inherits = &Inherits{IssuerID: p.Issuer.ID, Relation: InheritsOverlays}
		}},
		{"an inherits relation outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Inherits = &Inherits{ProfileID: "other", IssuerID: p.Issuer.ID, Relation: "extends"}
		}},
		{"an inherits profile id with a space", func(_ *testing.T, p *Profile) {
			p.Inherits = &Inherits{
				ProfileID: "other profile", IssuerID: p.Issuer.ID, Relation: InheritsOverlays,
			}
		}},

		// ---- unmodeled axes ----
		{"an unmodeled axis with no statement", func(_ *testing.T, p *Profile) {
			p.UnmodeledAxes[0].Statement = ""
		}},
		{"an unmodeled axis with no citation", func(_ *testing.T, p *Profile) {
			p.UnmodeledAxes[0].Citation = CitationRef{}
		}},
		{"more unmodeled axes than the cap", func(_ *testing.T, p *Profile) {
			p.UnmodeledAxes = nil
			for i := 0; i <= maxAxes; i++ {
				p.UnmodeledAxes = append(p.UnmodeledAxes, UnmodeledAxis{
					Name: fmt.Sprintf("Axis %d", i), Statement: "Not modeled here.",
					Citation: CitationRef{SourceID: "example-policy", Section: "Section 3.3"},
				})
			}
		}},

		// ---- citations ----
		{"no citations", func(_ *testing.T, p *Profile) { p.Citations = []Citation{} }},
		{"a citation with no id", func(_ *testing.T, p *Profile) { p.Citations[0].ID = "" }},
		{"a citation with no title", func(_ *testing.T, p *Profile) { p.Citations[0].Title = "" }},
		{"a date_basis outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Citations[0].DateBasis = "approximately"
		}},
		{"an effective-date citation with no date", func(_ *testing.T, p *Profile) {
			p.Citations[0].EffectiveDate = ""
		}},
		{"a retrieved-only citation carrying an effective date", func(_ *testing.T, p *Profile) {
			// The pairing that keeps a retrieval timestamp from being read as publication.
			p.Citations[0].DateBasis = DateRetrievedOnly
		}},
		{"a not-retrieved citation carrying an effective date", func(_ *testing.T, p *Profile) {
			// Automat did not read this document, so it has no date to report.
			p.Citations[0].DateBasis = DateNotRetrieved
		}},
		{"a not-retrieved citation carrying a source_id", func(_ *testing.T, p *Profile) {
			// The exact confusion not-retrieved exists to close: naming a source's hash
			// for a document whose bytes were never fetched.
			p.Citations[0].DateBasis = DateNotRetrieved
			p.Citations[0].EffectiveDate = ""
			p.Citations[0].SourceID = "example-policy"
		}},
		{"an effective date that is a timestamp", func(_ *testing.T, p *Profile) {
			p.Citations[0].EffectiveDate = "2024-06-01T00:00:00Z"
		}},
		{"a citation role outside the vocabulary", func(_ *testing.T, p *Profile) {
			p.Citations[0].Role = "mentions"
		}},

		// ---- policy caveat ----
		{"no policy caveat", func(_ *testing.T, p *Profile) { p.PolicyCaveat = "" }},
		{"a policy caveat with a NUL", func(_ *testing.T, p *Profile) {
			p.PolicyCaveat = samplePolicyCaveat + "\x00"
		}},

		// ---- sources ----
		{"no sources", func(_ *testing.T, p *Profile) { p.Sources = []HashedReference{} }},
		{"a source with no id", func(_ *testing.T, p *Profile) { p.Sources[0].ID = "" }},
		{"a source with no title", func(_ *testing.T, p *Profile) { p.Sources[0].Title = "" }},
		{"a source with no hash", func(_ *testing.T, p *Profile) { p.Sources[0].SHA256 = "" }},
		{"a source hash that is not hex", func(_ *testing.T, p *Profile) {
			p.Sources[0].SHA256 = "sha256:whatever"
		}},
		{"a source hash in uppercase", func(_ *testing.T, p *Profile) {
			p.Sources[0].SHA256 = strings.Repeat("A", 64)
		}},
		{"a source with no retrieval timestamp", func(_ *testing.T, p *Profile) {
			p.Sources[0].RetrievedAt = ""
		}},
		{"a retrieval timestamp with an offset rather than Z", func(_ *testing.T, p *Profile) {
			p.Sources[0].RetrievedAt = "2026-08-06T18:00:00-07:00"
		}},
		{"a retrieval timestamp that is only a date", func(_ *testing.T, p *Profile) {
			p.Sources[0].RetrievedAt = "2026-08-06"
		}},

		// ---- signatures ----
		{"an attestation with no role", func(t *testing.T, p *Profile) { firstSig(t, p).Role = "" }},
		{"an attestation role outside the vocabulary", func(t *testing.T, p *Profile) {
			// No role in the vocabulary means approved, certified, or compliant.
			firstSig(t, p).Role = "approved-by"
		}},
		{"an adopted-by attestation on a derived profile", func(t *testing.T, p *Profile) {
			// In the vocabulary, and still inadmissible here: on a derived reading the
			// only claim automat can make is that it interpreted the source.
			firstSig(t, p).Role = evidence.RoleAdoptedBy
		}},
		{"a reviewed-by attestation on a derived profile", func(t *testing.T, p *Profile) {
			firstSig(t, p).Role = evidence.RoleReviewedBy
		}},
		{"an attestation with no identity", func(t *testing.T, p *Profile) {
			firstSig(t, p).Identity = ""
		}},
		{"an attestation identity that forges a report line", func(t *testing.T, p *Profile) {
			firstSig(t, p).Identity = "automat maintainers\nreviewed-by: the institution"
		}},
		{"an attestation with no statement", func(t *testing.T, p *Profile) {
			firstSig(t, p).Statement = ""
		}},
		{"an attestation with no subject hash", func(t *testing.T, p *Profile) {
			firstSig(t, p).ContentSHA256 = ""
		}},
		{"an attestation subject hash that is not a hash", func(t *testing.T, p *Profile) {
			firstSig(t, p).ContentSHA256 = "sha256:whatever"
		}},
		{"an attestation with no date", func(t *testing.T, p *Profile) {
			firstSig(t, p).AttestedAt = ""
		}},
		{"an attestation date as a timestamp", func(t *testing.T, p *Profile) {
			firstSig(t, p).AttestedAt = "2026-08-06T00:00:00Z"
		}},
		{"a signature with an unknown format", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{Format: "pgp", Value: "QUFBQQ==", KeyID: "k1"}
		}},
		{"a signature value that is not base64", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{
				Format: FormatDetachedEd25519, Value: "not base64!", KeyID: "k1",
			}
		}},
		{"a detached signature with no key id", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{Format: FormatDetachedEd25519, Value: "QUFBQQ=="}
		}},
		{"a detached signature carrying an issuer", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{
				Format: FormatDetachedEd25519, Value: "QUFBQQ==", KeyID: "k1",
				IdentityIssuer: "https://accounts.example.edu",
			}
		}},
		{"a keyless signature with no issuer", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{Format: FormatOIDCBundle, Value: "QUFBQQ=="}
		}},
		{"a keyless signature carrying a key id", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{
				Format: FormatOIDCBundle, Value: "QUFBQQ==", KeyID: "k1",
				IdentityIssuer: "https://accounts.example.edu",
			}
		}},
		{"a fully duplicated attestation", func(t *testing.T, p *Profile) {
			p.Signatures = []Attestation{*firstSig(t, p), *firstSig(t, p)}
		}},
		{"more attestations than the cap", func(t *testing.T, p *Profile) {
			base := *firstSig(t, p)
			p.Signatures = nil
			for i := 0; i <= maxSignatures; i++ {
				a := base
				a.Identity = fmt.Sprintf("Reader %d", i)
				p.Signatures = append(p.Signatures, a)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			withAttestation(t, p)
			tc.mutate(t, p)

			goErr := p.Validate()
			schemaErr := sch.Validate(asGeneric(t, p))

			switch {
			case goErr == nil && schemaErr == nil:
				t.Errorf("neither the Go validator nor the schema rejected %q", tc.name)
			case goErr == nil:
				t.Errorf("the published schema rejects %q but internal/classprofile accepts it — "+
					"Validate() is missing a check, so a fork automat blesses is one the "+
					"institution's editor will call broken:\n%v", tc.name, schemaErr)
			case schemaErr == nil:
				t.Errorf("internal/classprofile rejects %q but the published schema accepts it — "+
					"schema/%s is missing a constraint, so an institution editing against the "+
					"schema is told a document is fine that automat will not load:\n%v",
					tc.name, schemaFile, goErr)
			}
		})
	}
}

// TestSchemaAcceptsWhatGoAccepts checks the other direction on documents that should
// pass: a valid profile must not be rejected by either side.
//
// The direction that matters for the fork path. An institution correcting automat's
// reading of its own policy is the case this model is FOR, and a schema stricter than the
// validator turns their correction into a red editor for no reason. Every case below is a
// shape a real published scheme takes.
func TestSchemaAcceptsWhatGoAccepts(t *testing.T) {
	sch := compileSchema(t)

	cases := []struct {
		name   string
		mutate func(*testing.T, *Profile)
	}{
		{"the minimum a profile can be", func(_ *testing.T, p *Profile) {
			// A two-level scheme defining levels and nothing else. The floor, and the
			// shape a source that defines levels while deferring controls elsewhere
			// takes — which is exactly the UC Standard's shape.
			*p = *fixtureBase("minimal", "somewhere", "Somewhere University", "somewhere-policy")
			p.Levels = fixtureLevels("somewhere-policy",
				[3]string{"open", "Open", "1"},
				[3]string{"closed", "Closed", "2"},
			)
		}},
		{"a level with no controls at all", func(_ *testing.T, p *Profile) {
			for i := range p.Levels {
				p.Levels[i].Controls = nil
			}
		}},
		{"a level with no examples", func(_ *testing.T, p *Profile) {
			for i := range p.Levels {
				p.Levels[i].Examples = nil
			}
		}},
		{"the level cap exactly", func(_ *testing.T, p *Profile) {
			p.Levels = nil
			for i := 0; i < MaxLevels; i++ {
				p.Levels = append(p.Levels, Level{
					ID: fmt.Sprintf("level-%d", i), Label: fmt.Sprintf("Level %d", i), Rank: i + 1,
					Definition: "A level.",
					Citation:   CitationRef{SourceID: "example-policy", Section: "Section 3"},
				})
			}
		}},
		{"the smallest scheme with a join", func(_ *testing.T, p *Profile) {
			p.Levels = p.Levels[:2]
		}},
		{"five levels, which is the widest in the sample", func(_ *testing.T, p *Profile) {
			*p = *harvardFixture()
		}},
		{"level ids that are codes rather than words", func(_ *testing.T, p *Profile) {
			// P1..P4 and DSL 1..5 are both real. An id that is a code must stay legal.
			for i := range p.Levels {
				p.Levels[i].ID = fmt.Sprintf("p%d", i+1)
			}
		}},
		{"a level id at the pattern's full length", func(_ *testing.T, p *Profile) {
			p.Levels[0].ID = "a" + strings.Repeat("b", 30) + "c"
		}},
		{"a level label with interior spaces and a digit", func(_ *testing.T, p *Profile) {
			// "DSL 3", "Protection Level 4". What institutions actually print.
			p.Levels[0].Label = "Protection Level 1"
		}},
		{"no may_lower block", func(_ *testing.T, p *Profile) {
			// Absent because the source is silent, which is different from permitted.
			// Stanford's page states no lowering process at all; a profile that had to
			// pick a value would be inventing one.
			p.Determination.MayLower = nil
		}},
		{"may_raise not stated", func(_ *testing.T, p *Profile) {
			p.Determination.MayRaise = PermissionNotStated
		}},
		{"no may_raise field at all", func(_ *testing.T, p *Profile) {
			p.Determination.MayRaise = ""
		}},
		{"lowering forbidden outright", func(_ *testing.T, p *Profile) {
			p.Determination.MayLower = &MayLower{Permitted: LowerNo}
		}},
		{"lowering permitted with no exception process", func(_ *testing.T, p *Profile) {
			p.Determination.MayLower = &MayLower{Permitted: LowerYes}
		}},
		{"no over-classification block", func(_ *testing.T, p *Profile) {
			p.Composition.OverClassification = nil
		}},
		{"over-classification permitted without documentation", func(_ *testing.T, p *Profile) {
			p.Composition.OverClassification = &OverClassification{
				Permitted: true, DocumentationRequired: false,
			}
		}},
		{"no unmodeled axes", func(_ *testing.T, p *Profile) { p.UnmodeledAxes = nil }},
		{"an unmodeled axis, which is the honest shape for UC's availability levels",
			func(_ *testing.T, p *Profile) {
				p.UnmodeledAxes = []UnmodeledAxis{{
					Name: "Availability",
					Statement: "The Standard defines four Availability Levels alongside the " +
						"Protection Levels. This profile models only the Protection Levels; the " +
						"two axes are not parallel.",
					Citation: CitationRef{SourceID: "example-policy", Section: "Section 3.3"},
				}}
			}},
		{"no inherits block", func(_ *testing.T, p *Profile) { p.Inherits = nil }},
		{"an overlay relation", func(_ *testing.T, p *Profile) {
			p.Inherits = &Inherits{
				ProfileID: "example-levels-research", IssuerID: p.Issuer.ID,
				Relation: InheritsOverlays,
				Note:     "A research overlay sharing this table.",
			}
		}},
		{"a shares-levels-with relation", func(_ *testing.T, p *Profile) {
			p.Inherits = &Inherits{
				ProfileID: "example-levels-hospital", IssuerID: p.Issuer.ID,
				Relation: InheritsSharesLevels,
			}
		}},
		{"a retrieved-only citation, which is what a dateless web page is",
			func(_ *testing.T, p *Profile) {
				// Both Stanford pages are living pages with no published date. A model
				// that required an effective date would force one to be invented.
				p.Citations[0].DateBasis = DateRetrievedOnly
				p.Citations[0].EffectiveDate = ""
			}},
		{"a last-updated-in-document citation", func(_ *testing.T, p *Profile) {
			// The UC PDF's footer date: printed in the document, not necessarily the
			// date the policy took effect.
			p.Citations[0].DateBasis = DateLastUpdated
		}},
		{"a not-retrieved citation, which is what a governing document nobody fetched is",
			func(_ *testing.T, p *Profile) {
				// BFB-IS-3's shape: named because a reader needs to know it governs, never
				// retrieved, so no date and no source_id (AUDIT-2 F5).
				p.Citations[0].DateBasis = DateNotRetrieved
				p.Citations[0].EffectiveDate = ""
				p.Citations[0].SourceID = ""
			}},
		{"a citation reference carrying the source's own words", func(_ *testing.T, p *Profile) {
			// The field that makes a claim checkable at a glance, and the one a reviewer
			// reads first. Optional, because a quote on every control would be a
			// transcription of the source rather than a reading of it.
			p.Levels[0].Citation.Quote = "Institutional Information intended for public release."
			p.Citations[0].Note = "The Standard defers the control list to a separate policy."
		}},
		{"a quote containing the source's own quotation marks", func(_ *testing.T, p *Profile) {
			// Institutional policy quotes itself constantly. A quote field that refused
			// quotation marks would be unusable for the thing it is for.
			p.Levels[0].Citation.Quote = `The Standard's "Exception Process" applies.`
		}},
		{"a multi-paragraph source note", func(_ *testing.T, p *Profile) {
			p.Sources[0].Note = "Retrieved as a PDF.\n\nThe control tables name specific tools; " +
				"this profile transcribes the obligation rather than the tool."
		}},
		{"a source with no version", func(_ *testing.T, p *Profile) { p.Sources[0].Version = "" }},
		{"a source with no media type", func(_ *testing.T, p *Profile) { p.Sources[0].MediaType = "" }},
		{"two sources", func(_ *testing.T, p *Profile) {
			// The Stanford case: a classification page plus a standards page.
			p.Sources = append(p.Sources, HashedReference{
				ID: "example-standards", Title: "Example Minimum Security Standards",
				RetrievedAt: "2026-08-06T18:20:00Z", MediaType: "text/html",
				SHA256: strings.Repeat("c", 64),
			})
		}},
		{"no attestations", func(_ *testing.T, p *Profile) {
			// automat ships no trust anchor, so an unsigned profile is the normal case
			// and always will be. This is the case that must never break.
			p.Signatures = nil
		}},
		{"an interpreted-by attestation with no signature block", func(t *testing.T, p *Profile) {
			withAttestation(t, p)
			firstSig(t, p).Signature = nil
		}},
		{"a detached-key attestation", func(t *testing.T, p *Profile) {
			withAttestation(t, p)
			firstSig(t, p).Signature = &Signature{
				Format: FormatDetachedEd25519, Value: "QUFBQQ==", KeyID: "maintainers-2026",
			}
		}},
		{"a keyless attestation", func(t *testing.T, p *Profile) {
			withAttestation(t, p)
			firstSig(t, p).Signature = &Signature{
				Format: FormatOIDCBundle, Value: "QUFBQQ==",
				IdentityIssuer: "https://accounts.example.edu",
			}
		}},
		{"an issuer-authored profile, which is what a fork becomes", func(_ *testing.T, p *Profile) {
			// The end state the model exists to reach: the institution adopts the
			// document, so the interpretation block goes away and the roles open up.
			p.Authorship = AuthorshipIssuer
			p.Maintenance = MaintenanceShipped
			p.Interpretation = nil
			p.Signatures = []Attestation{{
				Role: evidence.RoleAuthoredBy, Identity: "Example Institution CISO",
				Statement:     "This document states our data classification levels.",
				ContentSHA256: strings.Repeat("0", 64), AttestedAt: "2026-08-06",
			}}
		}},
		{"every role in the vocabulary on an issuer-authored profile", func(_ *testing.T, p *Profile) {
			p.Authorship = AuthorshipIssuer
			p.Maintenance = MaintenanceShipped
			p.Interpretation = nil
			p.Signatures = nil
			for i, r := range evidence.AllRoles {
				p.Signatures = append(p.Signatures, Attestation{
					Role: r, Identity: fmt.Sprintf("Office %d", i),
					Statement:     fmt.Sprintf("Claim %d, in the attester's own words.", i),
					ContentSHA256: strings.Repeat("0", 64), AttestedAt: "2026-08-06",
				})
			}
		}},
		{"a proposed profile", func(_ *testing.T, p *Profile) { p.Status = StatusProposed }},
		{"a superseded profile", func(_ *testing.T, p *Profile) { p.Status = StatusSuperseded }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(t, p)
			// Re-stamp for the same reason envprofile's table does: a mutation to a hashed
			// field moves the subject, and whether the attestations name THIS document is
			// VerifyAttestationSubjects' question rather than Validate's.
			restamp(t, p)

			if err := p.Validate(); err != nil {
				t.Fatalf("internal/classprofile rejects a document that should be valid:\n%v", err)
			}
			if err := sch.Validate(asGeneric(t, p)); err != nil {
				t.Errorf("the published schema rejects a document internal/classprofile accepts — "+
					"schema/%s is too strict:\n%v", schemaFile, err)
			}
		})
	}
}

// TestBothValidatorsRejectAPresentButEmptyArrayOnDisk covers the cases the
// agree-on-rejection table structurally cannot.
//
// That table mutates a Go struct and marshals it, and `omitempty` erases `[]` on the way
// out — so the schema is handed a document with no such field and correctly accepts it.
// The disagreement would be in the fixture rather than the contract. This test therefore
// feeds each validator the ON-DISK form, which is what a forked profile actually is and
// the only form in which the empty array exists.
//
// The stakes are gate 4's. `controls: []` claims the source was consulted and stated no
// controls; an absent `controls` is what a level looks like when the source is silent.
// They render identically to a reader, and the difference is whether automat is asserting
// something about the institution's policy or declining to.
func TestBothValidatorsRejectAPresentButEmptyArrayOnDisk(t *testing.T) {
	sch := compileSchema(t)

	// onDisk rewrites the sample document's JSON, since the struct cannot express `[]`.
	onDisk := func(t *testing.T, edit func(map[string]any)) []byte {
		t.Helper()
		p := sampleProfile(t)
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var doc map[string]any
		if uerr := json.Unmarshal(raw, &doc); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		edit(doc)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}
	level := func(doc map[string]any, i int) map[string]any {
		return doc["levels"].([]any)[i].(map[string]any)
	}

	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"an empty controls array on a level", func(doc map[string]any) {
			level(doc, 0)["controls"] = []any{}
		}},
		{"an empty examples array on a level", func(doc map[string]any) {
			level(doc, 0)["examples"] = []any{}
		}},
		{"an empty external_obligations array on a level", func(doc map[string]any) {
			level(doc, 0)["external_obligations"] = []any{}
		}},
		{"an empty unmodeled_axes array", func(doc map[string]any) {
			doc["unmodeled_axes"] = []any{}
		}},
		{"an empty determination roles array", func(doc map[string]any) {
			doc["determination"].(map[string]any)["roles"] = []any{}
		}},
		{"an empty citations array", func(doc map[string]any) { doc["citations"] = []any{} }},
		{"an empty sources array", func(doc map[string]any) { doc["sources"] = []any{} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := onDisk(t, tc.edit)
			var generic any
			if err := json.Unmarshal(data, &generic); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if sch.Validate(generic) == nil {
				t.Errorf("the published schema accepts %s — minItems is missing, and an empty "+
					"array claims the source was read and said nothing", tc.name)
			}
			// SkipAttestationSubjects: the subject of this test is the emptiness check, and
			// a stale-subject error would mask whether it fired.
			if _, err := Decode(data, LoadOptions{SkipAttestationSubjects: true}); err == nil {
				t.Errorf("internal/classprofile accepts %s on disk", tc.name)
			} else if !strings.Contains(err.Error(), "empty") {
				t.Errorf("the refusal does not say the array is empty, so an operator is sent "+
					"looking for a different defect:\n%v", err)
			}
		})
	}

	// levels: [] is refused by both, and belongs here rather than in the table above
	// because the refusal is a different one. The other arrays are optional, so `[]` is a
	// claim; `levels` is required, so `[]` is a scheme with no levels — and the Go
	// message says a scheme needs at least two rather than that an array is empty. Both
	// are correct refusals; only the wording differs, and asserting the wrong one would
	// have been a test that passed for the wrong reason.
	t.Run("an empty levels array", func(t *testing.T) {
		data := onDisk(t, func(doc map[string]any) { doc["levels"] = []any{} })
		var generic any
		if err := json.Unmarshal(data, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if sch.Validate(generic) == nil {
			t.Error("the published schema accepts levels: [] — minItems is 2, so this cannot " +
				"happen without the contract having been loosened")
		}
		_, err := Decode(data, LoadOptions{SkipAttestationSubjects: true})
		if err == nil {
			t.Fatal("internal/classprofile accepts levels: [] on disk")
		}
		if !strings.Contains(err.Error(), "at least 2") {
			t.Errorf("the refusal does not say how many levels a scheme needs:\n%v", err)
		}
	})

	t.Run("the absent forms are accepted by both", func(t *testing.T) {
		data := onDisk(t, func(doc map[string]any) {
			for i := range doc["levels"].([]any) {
				delete(level(doc, i), "controls")
				delete(level(doc, i), "examples")
				delete(level(doc, i), "external_obligations")
			}
			delete(doc, "unmodeled_axes")
			delete(doc, "inherits")
		})
		var generic any
		if err := json.Unmarshal(data, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := sch.Validate(generic); err != nil {
			t.Errorf("the published schema rejects a profile that states levels and nothing "+
				"else, which is the shape a source defining levels without controls takes:\n%v", err)
		}
		if _, err := Decode(data, LoadOptions{SkipAttestationSubjects: true}); err != nil {
			t.Errorf("internal/classprofile rejects it:\n%v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Gaps one layer cannot express, recorded rather than discovered
// ---------------------------------------------------------------------------

// TestTheSchemaCannotRejectAnUnsupportedMajorVersion records the first asymmetry.
//
// The schema's pattern is any semver, on purpose: a published contract that rejected
// `2.0.0` would make every v2 document invalid against v1 rather than merely unreadable
// by a v1 build, and an archived document would go retroactively malformed. Which majors
// a BUILD understands is a property of the build, so Validate() owns it.
func TestTheSchemaCannotRejectAnUnsupportedMajorVersion(t *testing.T) {
	sch := compileSchema(t)
	p := sampleProfile(t)
	p.SchemaVersion = "2.0.0"

	if err := sch.Validate(asGeneric(t, p)); err != nil {
		t.Fatalf("the schema now rejects a future major version. That is a behaviour change to "+
			"argue for rather than discover:\n%v", err)
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() accepted schema_version 2.0.0; this build cannot know what a v2 " +
			"document's fields mean, and silently acting on one is worse than refusing it")
	}
	if !strings.Contains(err.Error(), "not supported by this build") {
		t.Errorf("the refusal does not say the build is the limit:\n%v", err)
	}
	t.Log("recorded: the schema accepts any semver; the supported-major check is Go-side.")
}

// TestGoOnlyChecksAreTheOnesNoSchemaCanState enumerates every within-document rule that
// depends on comparing two fields, and asserts each one fires.
//
// Held as one list rather than scattered because the list itself is the claim: these are
// the checks a consumer validating against the published schema alone WILL NOT GET. An
// institution forking a profile validates against the schema, so every entry here is a
// defect their editor will call clean.
func TestGoOnlyChecksAreTheOnesNoSchemaCanState(t *testing.T) {
	sch := compileSchema(t)

	cases := []struct {
		name   string
		why    string
		want   string
		mutate func(*testing.T, *Profile)
	}{
		{
			name: "a citation naming a source the document does not carry",
			why: "a citation that resolves to nothing renders exactly as confidently as one that " +
				"resolves to bytes somebody can check. No schema can compare a source_id against " +
				"the sources list",
			want: "names no entry in sources",
			mutate: func(_ *testing.T, p *Profile) {
				p.Levels[0].Citation.SourceID = "a-document-nobody-retrieved"
			},
		},
		{
			name: "two levels at the same rank",
			why: "two levels at one rank have no join, so composition has no answer. uniqueItems " +
				"cannot see it: the entries differ in every other field",
			want:   "duplicates",
			mutate: func(_ *testing.T, p *Profile) { p.Levels[1].Rank = p.Levels[2].Rank },
		},
		{
			name: "a gap in the rank sequence",
			why: "ranks 1, 2, 4 read as a complete three-level scheme, and nothing in the rendering " +
				"says the third level is missing. A schema can bound a rank but cannot see the run",
			want:   "no gaps",
			mutate: func(_ *testing.T, p *Profile) { p.Levels[2].Rank = 4 },
		},
		{
			name: "two levels with the same id",
			why: "the id is what an operator types and what another document references, so two " +
				"levels answering to one id make the reference ambiguous",
			want:   "duplicates",
			mutate: func(_ *testing.T, p *Profile) { p.Levels[1].ID = p.Levels[0].ID },
		},
		{
			name: "two levels with the same label",
			why: "the label is what a person reads in a plan; two levels printing the same name are " +
				"indistinguishable at the point of use even though their ids differ",
			want:   "duplicates",
			mutate: func(_ *testing.T, p *Profile) { p.Levels[1].Label = p.Levels[0].Label },
		},
		{
			name: "a non-endorsement statement that names no institution",
			why: "\"not authored, reviewed, or endorsed by the institution\" is a grammatically " +
				"complete disclaimer that disclaims nobody. A schema can require the field, but " +
				"not that it contains the value of another field",
			want: "does not name",
			mutate: func(_ *testing.T, p *Profile) {
				p.Interpretation.NonEndorsement = strings.ReplaceAll(
					p.Interpretation.NonEndorsement, "Example Institution", "the institution")
			},
		},
		{
			name: "a non-endorsement statement missing the negative claim",
			why: "the phrase list is the substance of the disclaimer, and a reader who sees only " +
				"\"not authored\" concludes the institution reviewed it. A schema could pin the " +
				"wording verbatim, which would enforce formatting instead of meaning",
			want: "not authored, reviewed, or endorsed",
			mutate: func(_ *testing.T, p *Profile) {
				p.Interpretation.NonEndorsement = "This is automat's interpretation of a published " +
					"policy by Example Institution. The institution's own policy governs; verify " +
					"against it."
			},
		},
		{
			name: "an inherits block pointing at another institution",
			why: "inheritance is within one institution's policy set — an enterprise policy and its " +
				"research overlay. Across institutions it would assert an equivalence neither one " +
				"published",
			want: "this profile's issuer is",
			mutate: func(_ *testing.T, p *Profile) {
				p.Inherits = &Inherits{
					ProfileID: "some-other-scheme", IssuerID: "a-different-institution",
					Relation: InheritsOverlays,
				}
			},
		},
		{
			name: "an inherits block pointing at itself",
			why:  "a profile that overlays itself describes no relationship and resolves in a loop",
			want: "names this profile",
			mutate: func(_ *testing.T, p *Profile) {
				p.Inherits = &Inherits{
					ProfileID: p.Meta.ID, IssuerID: p.Issuer.ID, Relation: InheritsOverlays,
				}
			},
		},
		{
			name: "two sources sharing an id",
			why:  "a citation resolving to two different documents resolves to neither",
			want: "duplicates",
			mutate: func(_ *testing.T, p *Profile) {
				p.Sources = append(p.Sources, p.Sources[0])
				p.Sources[1].Title = "A different document under the same id"
				p.Sources[1].SHA256 = strings.Repeat("e", 64)
			},
		},
		{
			name: "two citations sharing an id",
			why:  "same reason, one level up: a reference to the citation id becomes ambiguous",
			want: "duplicates",
			mutate: func(_ *testing.T, p *Profile) {
				p.Citations = append(p.Citations, p.Citations[0])
				p.Citations[1].Title = "A different citation under the same id"
			},
		},
		{
			name: "two controls sharing an id within a level",
			why:  "the id is how a control is referenced, so two answering to one make it ambiguous",
			want: "duplicates",
			mutate: func(_ *testing.T, p *Profile) {
				c := p.Levels[1].Controls[0]
				c.Title = "A different requirement"
				p.Levels[1].Controls = append(p.Levels[1].Controls, c)
			},
		},
		{
			name: "an exception-only lowering rule with no exception process",
			why: "\"only by exception\" with no process named tells an operator a door exists and " +
				"not where it is. Whether the field is required depends on the value of another " +
				"field, which is expressible in a schema only as a conditional nobody will maintain",
			want: "exception_process",
			mutate: func(_ *testing.T, p *Profile) {
				p.Determination.MayLower = &MayLower{Permitted: LowerOnlyByException}
			},
		},
		{
			name: "a retrieved-only citation with no source",
			why: "with no effective date, the retrieval record is the only thing dating the claim, " +
				"so a retrieved-only citation that names no retrieved document dates nothing",
			want: "source_id",
			mutate: func(_ *testing.T, p *Profile) {
				p.Citations[0].DateBasis = DateRetrievedOnly
				p.Citations[0].EffectiveDate = ""
				p.Citations[0].SourceID = ""
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(t, p)

			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate() accepted %q, which it must refuse: %s", tc.name, tc.why)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal for %q does not mention %q, so an operator has to guess "+
					"which of two fields to change:\n%v", tc.name, tc.want, err)
			}
			// Recorded, not asserted as desirable: a consumer holding only the schema does
			// not get this check. If the schema ever grows it, this fails and the case
			// moves into the agreement table.
			if schemaErr := sch.Validate(asGeneric(t, p)); schemaErr != nil {
				t.Errorf("the published schema now rejects %q too. Good news, but it means this "+
					"case belongs in TestGoAndSchemaAgreeOnRejection rather than here:\n%v",
					tc.name, schemaErr)
			}
		})
	}
}

// TestTheSchemaCannotCheckAnAttestationsOwnSubject records the gap
// VerifyAttestationSubjects closes.
//
// content_sha256 names the document an attestation is over, and a schema cannot compute a
// hash — so an attestation can name ANY hash, including one lifted from the profile it
// was forked from. That last case is the one that matters here: a fork inherits the
// interpreted-by attestation, and if nothing recomputed the subject, automat's signature
// would appear to vouch for the institution's edits.
func TestTheSchemaCannotCheckAnAttestationsOwnSubject(t *testing.T) {
	sch := compileSchema(t)
	p := sampleProfile(t)
	withAttestation(t, p)
	// Well-formed, and about the document this one was forked from.
	firstSig(t, p).ContentSHA256 = strings.Repeat("f", 64)

	if err := sch.Validate(asGeneric(t, p)); err != nil {
		t.Fatalf("the schema now rejects an attestation naming another document's hash. If the "+
			"constraint moved, delete this test:\n%v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() must accept it — whether the subject matches is a separate call, so "+
			"that a caller who only wanted a syntax check is not silently given less:\n%v", err)
	}
	err := p.VerifyAttestationSubjects()
	if err == nil {
		t.Fatal("VerifyAttestationSubjects accepted an attestation over a different document. " +
			"On a forked profile that is automat's signature appearing to vouch for somebody " +
			"else's edits.")
	}
	if !strings.Contains(err.Error(), "about something else") {
		t.Errorf("the refusal does not say what a mismatched subject means:\n%v", err)
	}
	t.Log("recorded: the schema cannot compute a hash; the subject check is Go-side.")
}

// TestTheSchemaCannotSeeTheJoinLaws records the last asymmetry, and it is the one worth
// naming explicitly.
//
// A schema constrains a document; it cannot assert that an operation over the document
// behaves. `composition.rule` being pinned to `highest-water-mark` on both sides means
// the DOCUMENT declares the rule — nothing in the schema says Join implements it. The
// laws are asserted in TestJoinHoldsTheUnionLaws; this records that the schema's
// agreement is about the declaration and not the behaviour.
func TestTheSchemaCannotSeeTheJoinLaws(t *testing.T) {
	sch := compileSchema(t)
	p := sampleProfile(t)

	if err := sch.Validate(asGeneric(t, p)); err != nil {
		t.Fatalf("the sample profile fails the schema:\n%v", err)
	}
	// The rank field is what makes the join computable, and its ONLY schema constraint is
	// a range. Ranks that are legal integers in an order the schema cannot object to:
	if err := sch.Validate(asGeneric(t, mustRanks(t, p, 1, 2, 4))); err != nil {
		t.Fatalf("the schema now rejects a gapped rank sequence, which would move the "+
			"density check into the agreement table:\n%v", err)
	}
	t.Log("recorded: the schema pins composition.rule but cannot see whether Join implements " +
		"it; the four union laws are asserted in TestJoinHoldsTheUnionLaws.")
}

func mustRanks(t *testing.T, p *Profile, ranks ...int) *Profile {
	t.Helper()
	if len(ranks) != len(p.Levels) {
		t.Fatalf("test setup: %d ranks for %d levels", len(ranks), len(p.Levels))
	}
	out := *p
	out.Levels = make([]Level, len(p.Levels))
	copy(out.Levels, p.Levels)
	for i, r := range ranks {
		out.Levels[i].Rank = r
	}
	return &out
}

// interp returns the fixture's interpretation block, failing loudly if the fixture
// stopped carrying one — a stale fixture must not let a case mutate nothing.
func interp(t *testing.T, p *Profile) *Interpretation {
	t.Helper()
	if p.Interpretation == nil {
		t.Fatal("test setup: the fixture carries no interpretation block")
	}
	return p.Interpretation
}

// firstControl returns the first control on any level, failing loudly if there is none.
func firstControl(t *testing.T, p *Profile) *Control {
	t.Helper()
	for i := range p.Levels {
		if len(p.Levels[i].Controls) > 0 {
			return &p.Levels[i].Controls[0]
		}
	}
	t.Fatal("test setup: no level in the fixture states a control")
	return nil
}

// firstObligation returns the first external obligation on any level.
func firstObligation(t *testing.T, p *Profile) *ExternalObligation {
	t.Helper()
	for i := range p.Levels {
		if len(p.Levels[i].ExternalObligations) > 0 {
			return &p.Levels[i].ExternalObligations[0]
		}
	}
	t.Fatal("test setup: no level in the fixture names an external obligation")
	return nil
}

// firstSig returns the fixture's first attestation, failing loudly if there is none.
func firstSig(t *testing.T, p *Profile) *Attestation {
	t.Helper()
	if len(p.Signatures) == 0 {
		t.Fatal("test setup: the fixture carries no attestation")
	}
	return &p.Signatures[0]
}

// withAttestation gives a fixture one interpreted-by attestation over its own content,
// which is the only role a derived profile admits.
func withAttestation(t *testing.T, p *Profile) {
	t.Helper()
	hash, err := p.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	p.Signatures = []Attestation{{
		Role:          evidence.RoleInterpretedBy,
		Identity:      "automat maintainers",
		Statement:     "We read the cited source and wrote this reading of it.",
		ContentSHA256: hash,
		AttestedAt:    "2026-08-06",
	}}
}

// restamp recomputes every attestation's subject after a mutation, so a table testing
// Validate does not fail on VerifyAttestationSubjects' question.
func restamp(t *testing.T, p *Profile) {
	t.Helper()
	if len(p.Signatures) == 0 {
		return
	}
	hash, err := p.ContentHash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	for i := range p.Signatures {
		p.Signatures[i].ContentSHA256 = hash
	}
}
