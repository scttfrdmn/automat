// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

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

// schema/environment-profile-v1.schema.json is the published compatibility contract;
// the Go types and Validate() in this package are the implementation. These tests keep
// the two honest about each other.
//
// Without them the schema and the code drift silently, and the drift is worse here than
// for a control artifact: an environment profile is HAND-WRITTEN by an operator, so the
// schema is what their editor validates against and Validate() is what actually decides
// whether a vend proceeds. A gap in either direction means an operator is told a
// document is fine by one of the two things that check it.

const schemaFile = "environment-profile-v1.schema.json"

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
	p := sampleProfile(t)
	data, err := p.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if verr := sch.Validate(doc); verr != nil {
		t.Errorf("a profile this package considers valid violates the published schema:\n%v\n\n"+
			"document:\n%s", verr, data)
	}
}

// TestGoAndSchemaAgreeOnRejection is the drift detector: for each way of breaking an
// environment profile, both the hand-written Go validator and the published JSON Schema
// must reject it. A case only one of them catches is drift.
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
		{"profile id with spaces", func(_ *testing.T, p *Profile) { p.Meta.ID = "Research CUI" }},
		{"profile id with a trailing hyphen", func(_ *testing.T, p *Profile) { p.Meta.ID = "research-" }},
		{"profile id that is a single character", func(_ *testing.T, p *Profile) { p.Meta.ID = "x" }},
		{"missing title", func(_ *testing.T, p *Profile) { p.Meta.Title = "" }},
		{"title containing a newline", func(_ *testing.T, p *Profile) {
			// A prose field rendered into the birth certificate; a newline forges a row.
			p.Meta.Title = "Research CUI\nreviewed-by: NIST"
		}},
		{"title containing an ANSI escape", func(_ *testing.T, p *Profile) {
			p.Meta.Title = "Research CUI\x1b[31m"
		}},
		{"description containing a NUL", func(_ *testing.T, p *Profile) {
			p.Meta.Description = "Vends accounts\x00for CUI"
		}},

		// ---- review_by ----
		{"missing review date", func(_ *testing.T, p *Profile) { p.ReviewBy = "" }},
		{"review date as a timestamp", func(_ *testing.T, p *Profile) {
			p.ReviewBy = "2027-06-30T00:00:00Z"
		}},
		{"unpadded review date", func(_ *testing.T, p *Profile) { p.ReviewBy = "2027-6-3" }},

		// ---- control_sets ----
		{"no control sets", func(_ *testing.T, p *Profile) { p.ControlSets = []string{} }},
		{"control set id with spaces", func(_ *testing.T, p *Profile) {
			p.ControlSets = []string{"CMMC L1"}
		}},
		{"duplicate control set", func(_ *testing.T, p *Profile) {
			p.ControlSets = []string{"cmmc-l1", "cmmc-l1"}
		}},

		// ---- permitted ----
		{"permitted region that is not a region code", func(_ *testing.T, p *Profile) {
			p.Permitted.Regions = []string{"US-East-1"}
		}},
		{"permitted region that is a wildcard", func(_ *testing.T, p *Profile) {
			// The shape a widening attempt arrives in: a set that reads as "all".
			p.Permitted.Regions = []string{"*"}
		}},
		{"duplicate permitted region", func(_ *testing.T, p *Profile) {
			p.Permitted.Regions = []string{"us-east-1", "us-east-1"}
		}},
		{"permitted service that is a display name", func(_ *testing.T, p *Profile) {
			p.Permitted.Services = []string{"Amazon S3"}
		}},
		{"permitted service that is a wildcard", func(_ *testing.T, p *Profile) {
			p.Permitted.Services = []string{"*"}
		}},
		{"duplicate permitted service", func(_ *testing.T, p *Profile) {
			p.Permitted.Services = []string{"s3", "s3"}
		}},

		// ---- obligations ----
		{"obligation with no id", func(_ *testing.T, p *Profile) { p.Obligations[0].ID = "" }},
		{"obligation id with underscores", func(_ *testing.T, p *Profile) {
			p.Obligations[0].ID = "dfars_7012"
		}},
		{"obligation with no content hash", func(_ *testing.T, p *Profile) {
			p.Obligations[0].ContentSHA256 = ""
		}},
		{"obligation content hash not hex", func(_ *testing.T, p *Profile) {
			p.Obligations[0].ContentSHA256 = "sha256:whatever"
		}},
		{"obligation content hash uppercase", func(_ *testing.T, p *Profile) {
			p.Obligations[0].ContentSHA256 = strings.Repeat("A", 64)
		}},
		{"a fully duplicated obligation reference", func(_ *testing.T, p *Profile) {
			p.Obligations = []ObligationRef{p.Obligations[0], p.Obligations[0]}
		}},
		{"more obligations than the cap", func(_ *testing.T, p *Profile) {
			p.Obligations = nil
			for i := 0; i <= maxObligations; i++ {
				p.Obligations = append(p.Obligations, ObligationRef{
					ID:            fmt.Sprintf("obligation-%d", i),
					ContentSHA256: strings.Repeat(fmt.Sprintf("%x", i%16), 64),
				})
			}
		}},
		{"determination with no value", func(t *testing.T, p *Profile) {
			determination(t, p).Value = ""
		}},
		{"determination with no determiner", func(t *testing.T, p *Profile) {
			determination(t, p).DeterminedBy = ""
		}},
		{"determination with no date", func(t *testing.T, p *Profile) {
			determination(t, p).DeterminedAt = ""
		}},
		{"determination date as a timestamp", func(t *testing.T, p *Profile) {
			determination(t, p).DeterminedAt = "2026-07-01T00:00:00Z"
		}},
		{"determination with no statement", func(t *testing.T, p *Profile) {
			// The field that stops a bare value from inviting the reader to supply the
			// justification themselves.
			determination(t, p).Statement = ""
		}},
		{"determination statement containing an escape byte", func(t *testing.T, p *Profile) {
			determination(t, p).Statement = "Built to r2\x1b[2Kper the award."
		}},

		// ---- placement ----
		{"missing target OU", func(_ *testing.T, p *Profile) { p.Placement.TargetOU = "" }},
		{"target OU that is an account id", func(_ *testing.T, p *Profile) {
			p.Placement.TargetOU = "111122223333"
		}},
		{"target OU with uppercase", func(_ *testing.T, p *Profile) {
			p.Placement.TargetOU = "OU-ABCD-11111111"
		}},
		{"OU path deeper than the nesting limit", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = []string{"a", "b", "c", "d", "e", "f"}
		}},
		{"OU path with an empty name", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = []string{"Research CUI", ""}
		}},
		{"OU name with a leading space", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = []string{" Research CUI"}
		}},
		{"OU name with a newline", func(_ *testing.T, p *Profile) {
			// Rendered into the plan `vend` prints before it acts; a plan whose lines
			// can be forged is not a plan an operator can approve.
			p.Placement.OUPath = []string{"Research CUI\nGenomics"}
		}},
		{"OU name with a path separator", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = []string{"Research/CUI"}
		}},

		// ---- account ----
		{"email pattern that is not an address", func(_ *testing.T, p *Profile) {
			p.Account.EmailPattern = "not an address"
		}},
		{"email pattern with a control character", func(_ *testing.T, p *Profile) {
			p.Account.EmailPattern = "admin+\x07{name}@dept.example.edu"
		}},
		{"email pattern over the address length limit", func(_ *testing.T, p *Profile) {
			p.Account.EmailPattern = strings.Repeat("a", 250) + "+{name}@dept.example.edu"
		}},
		{"role name over 64 characters", func(_ *testing.T, p *Profile) {
			p.Account.RoleName = strings.Repeat("R", 65)
		}},
		{"role name with a path separator", func(_ *testing.T, p *Profile) {
			p.Account.RoleName = "campus/it/Access"
		}},
		{"billing access outside the enum", func(_ *testing.T, p *Profile) {
			p.Account.IAMUserAccessToBilling = "MAYBE"
		}},
		{"tag key in the reserved automat prefix", func(_ *testing.T, p *Profile) {
			// AUDIT-1's C1, the writing half: baseline-protection SCPs read automat's
			// own tags in conditions, so a key this document could write at the same
			// scope is one an account could forge to exempt itself.
			p.Account.Tags = map[string]string{AutomatTagPrefix + "profile": "anything"}
		}},
		{"tag key that is empty", func(_ *testing.T, p *Profile) {
			p.Account.Tags = map[string]string{"": "x"}
		}},
		{"tag key with a newline", func(_ *testing.T, p *Profile) {
			p.Account.Tags = map[string]string{"cost\ncenter": "1234"}
		}},
		{"tag key over the length limit", func(_ *testing.T, p *Profile) {
			p.Account.Tags = map[string]string{strings.Repeat("k", maxTagKeyBytes+1): "x"}
		}},
		{"tag value with a control character", func(_ *testing.T, p *Profile) {
			p.Account.Tags = map[string]string{"department": "Genomics\x1b[31m"}
		}},
		{"tag value over the length limit", func(_ *testing.T, p *Profile) {
			p.Account.Tags = map[string]string{"department": strings.Repeat("v", maxTagValueBytes+1)}
		}},
		{"more tags than the cap", func(_ *testing.T, p *Profile) {
			p.Account.Tags = make(map[string]string, maxTags+1)
			for i := 0; i <= maxTags; i++ {
				p.Account.Tags[fmt.Sprintf("key-%d", i)] = "x"
			}
		}},

		// ---- baseline ----
		{"delivery bucket with uppercase", func(_ *testing.T, p *Profile) {
			p.Baseline.ConfigRecorder.DeliveryBucket = "Example-Config-Delivery"
		}},
		{"delivery bucket with an underscore", func(_ *testing.T, p *Profile) {
			p.Baseline.ConfigRecorder.DeliveryBucket = "example_config_delivery"
		}},
		{"baseline home region that is not a region code", func(_ *testing.T, p *Profile) {
			p.Baseline.Regions.Home = "useast1"
		}},
		{"baseline region to enable that is not a region code", func(_ *testing.T, p *Profile) {
			p.Baseline.Regions.Enable = []string{"us-west-2", "everywhere"}
		}},
		{"duplicate baseline region to enable", func(_ *testing.T, p *Profile) {
			p.Baseline.Regions.Enable = []string{"us-west-2", "us-west-2"}
		}},
		{"duplicate baseline region to disable", func(_ *testing.T, p *Profile) {
			p.Baseline.Regions.Disable = []string{"ap-south-1", "ap-south-1"}
		}},
		{"automation role name with a path separator", func(_ *testing.T, p *Profile) {
			p.Baseline.AutomationRole.Name = "campus/automat"
		}},
		{"evidence directory that is absolute", func(_ *testing.T, p *Profile) {
			// The one field in a profile naming somewhere automat WRITES, in a document
			// an operator may have received rather than written.
			p.Baseline.Evidence.LocalDir = "/etc/automat"
		}},
		{"evidence directory escaping the working directory", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.LocalDir = "../../etc/automat"
		}},
		{"evidence directory with an interior parent segment", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.LocalDir = "out/../../etc"
		}},
		{"evidence directory beginning with a tilde", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.LocalDir = "~/evidence"
		}},
		{"attestation directory that is absolute", func(_ *testing.T, p *Profile) {
			p.Baseline.Attestations.LocalDir = "/tmp/compliance"
		}},
		{"a management mirror on the attestations block", func(_ *testing.T, p *Profile) {
			// The management mirror is for evidence manifests (DESIGN §11). A field
			// silently ignored here would read to an operator as a mirror that exists.
			p.Baseline.Attestations.ManagementMirrorBucket = "example-mirror"
		}},
		{"in-account evidence bucket with uppercase", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.InAccountBucket = "Example-Evidence"
		}},
		{"management mirror bucket with uppercase", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.ManagementMirrorBucket = "Example-Mirror"
		}},

		// ---- signatures ----
		{"attestation with no role", func(t *testing.T, p *Profile) { firstSig(t, p).Role = "" }},
		{"attestation role outside the vocabulary", func(t *testing.T, p *Profile) {
			// The shape an approval claim would arrive in. No role in the vocabulary
			// means approved, certified, or compliant.
			firstSig(t, p).Role = "approved-by"
		}},
		{"attestation with no identity", func(t *testing.T, p *Profile) {
			firstSig(t, p).Identity = ""
		}},
		{"attestation identity that forges a report line", func(t *testing.T, p *Profile) {
			firstSig(t, p).Identity = "Research Computing\nreviewed-by: NIST"
		}},
		{"attestation with no statement", func(t *testing.T, p *Profile) {
			firstSig(t, p).Statement = ""
		}},
		{"attestation statement with a NUL", func(t *testing.T, p *Profile) {
			firstSig(t, p).Statement = "Adopted.\x00"
		}},
		{"attestation with no subject hash", func(t *testing.T, p *Profile) {
			firstSig(t, p).ContentSHA256 = ""
		}},
		{"attestation subject hash that is not a hash", func(t *testing.T, p *Profile) {
			firstSig(t, p).ContentSHA256 = "sha256:whatever"
		}},
		{"attestation with no date", func(t *testing.T, p *Profile) {
			firstSig(t, p).AttestedAt = ""
		}},
		{"attestation date as a timestamp", func(t *testing.T, p *Profile) {
			firstSig(t, p).AttestedAt = "2026-08-05T00:00:00Z"
		}},
		{"signature with no format", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature.Format = ""
		}},
		{"signature with an unknown format", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature.Format = "pgp"
		}},
		{"signature with no value", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature.Value = ""
		}},
		{"signature value that is not base64", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature.Value = "not base64!"
		}},
		{"signature value over the length limit", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature.Value = strings.Repeat("A", maxSigValue+1)
		}},
		{"detached signature with no key id", func(t *testing.T, p *Profile) {
			// Unverifiable in the direction that looks fine.
			firstSig(t, p).Signature.KeyID = ""
		}},
		{"detached signature carrying an issuer", func(t *testing.T, p *Profile) {
			// Two trust models in one block; a reader cannot tell which applies.
			firstSig(t, p).Signature.IdentityIssuer = "https://accounts.example.edu"
		}},
		{"keyless signature with no issuer", func(t *testing.T, p *Profile) {
			s := firstSig(t, p).Signature
			s.Format = FormatOIDCBundle
			s.KeyID = ""
		}},
		{"keyless signature carrying a key id", func(t *testing.T, p *Profile) {
			s := firstSig(t, p).Signature
			s.Format = FormatOIDCBundle
			s.IdentityIssuer = "https://accounts.example.edu"
		}},
		{"a fully duplicated attestation", func(t *testing.T, p *Profile) {
			p.Signatures = []Attestation{*firstSig(t, p), *firstSig(t, p)}
		}},
		{"more attestations than the cap", func(t *testing.T, p *Profile) {
			base := *firstSig(t, p)
			p.Signatures = nil
			for i := 0; i <= maxSignatures; i++ {
				a := base
				a.Identity = fmt.Sprintf("Office %d", i)
				p.Signatures = append(p.Signatures, a)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(t, p)

			goErr := p.Validate()
			schemaErr := sch.Validate(asGeneric(t, p))

			switch {
			case goErr == nil && schemaErr == nil:
				t.Errorf("neither the Go validator nor the schema rejected %q", tc.name)
			case goErr == nil:
				t.Errorf("the published schema rejects %q but internal/envprofile accepts it — "+
					"Validate() is missing a check:\n%v", tc.name, schemaErr)
			case schemaErr == nil:
				t.Errorf("internal/envprofile rejects %q but the published schema accepts it — "+
					"schema/%s is missing a constraint:\n%v", tc.name, schemaFile, goErr)
			}
		})
	}
}

// TestSchemaAcceptsWhatGoAccepts checks the other direction on documents that should
// pass: a valid profile must not be rejected by either side.
//
// The direction that matters for an operator's day: a schema stricter than the
// validator makes their editor red on a document that vends fine, and they learn to
// ignore it.
func TestSchemaAcceptsWhatGoAccepts(t *testing.T) {
	sch := compileSchema(t)
	no := false

	cases := []struct {
		name   string
		mutate func(*testing.T, *Profile)
	}{
		{"the minimum a profile can be", func(_ *testing.T, p *Profile) {
			*p = Profile{
				SchemaVersion: SchemaVersion,
				Meta:          Meta{ID: "minimal", Title: "Minimal"},
				ReviewBy:      "2027-01-01",
				ControlSets:   []string{"cmmc-l1"},
				Placement:     Placement{TargetOU: "ou-abcd-11111111"},
				Baseline:      Baseline{ConfigRecorder: ConfigRecorder{Enabled: true}},
			}
		}},
		{"no permitted boundary at all", func(_ *testing.T, p *Profile) {
			// Nil is not the same as permitting everything: the compiled control sets'
			// own allowlists still apply. It must remain the ordinary case.
			p.Permitted = nil
		}},
		{"a boundary on one axis only", func(_ *testing.T, p *Profile) {
			p.Permitted = &Permitted{Regions: []string{"us-east-1"}}
		}},
		{"an empty permitted block", func(_ *testing.T, p *Profile) {
			// Asserts nothing, and Canonicalize drops it; neither validator has grounds
			// to refuse it on the way in.
			p.Permitted = &Permitted{}
		}},
		{"a single-region single-service boundary", func(_ *testing.T, p *Profile) {
			p.Permitted = &Permitted{Regions: []string{"us-gov-west-1"}, Services: []string{"s3"}}
		}},
		{"no obligations", func(_ *testing.T, p *Profile) { p.Obligations = nil }},
		{"an obligation with no determination", func(_ *testing.T, p *Profile) {
			// The pinned-revision case. Whether a determination is required depends on
			// the OTHER document, so neither validator may demand one here.
			p.Obligations = []ObligationRef{{ID: "cmmc-l1", ContentSHA256: strings.Repeat("c", 64)}}
		}},
		{"a multi-line determination statement", func(t *testing.T, p *Profile) {
			determination(t, p).Statement = "The agreement is silent.\n\n" +
				"This institution builds to r2 until its awarding agency states otherwise."
		}},
		{"no account block", func(_ *testing.T, p *Profile) { p.Account = nil }},
		{"an account block with only tags", func(_ *testing.T, p *Profile) {
			p.Account = &Account{Tags: map[string]string{"cost-center": "1234"}}
		}},
		{"a tag key carrying a colon outside the reserved prefix", func(_ *testing.T, p *Profile) {
			// The prefix is reserved, not the character; institutions namespace their
			// own tags this way.
			p.Account.Tags = map[string]string{"example.edu:cost-center": "1234"}
		}},
		{"a tag with an empty value", func(_ *testing.T, p *Profile) {
			// A present key with no value is a legitimate marker tag.
			p.Account.Tags = map[string]string{"reviewed": ""}
		}},
		{"a role name with the characters IAM permits", func(_ *testing.T, p *Profile) {
			p.Account.RoleName = "Campus+Access=Role,v2.0@_-"
		}},
		{"an OU name with interior spaces", func(_ *testing.T, p *Profile) {
			// What an operator actually names an OU. Refusing it would push them to a
			// name they then mistype.
			p.Placement.OUPath = []string{"Research CUI", "Genomics Core"}
		}},
		{"a single-character OU name", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = []string{"X"}
		}},
		{"the OU nesting limit exactly", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = []string{"a", "b", "c", "d", "e"}
		}},
		{"no OU path", func(_ *testing.T, p *Profile) {
			p.Placement.OUPath = nil
			p.Placement.CreateIntermediateOUs = false
		}},
		{"a root as the placement target", func(_ *testing.T, p *Profile) {
			p.Placement.TargetOU = "r-abcd"
		}},
		{"a disabled recorder with no bucket", func(_ *testing.T, p *Profile) {
			p.Baseline.ConfigRecorder = ConfigRecorder{Enabled: false}
		}},
		{"an explicitly narrowed recording scope", func(_ *testing.T, p *Profile) {
			p.Baseline.ConfigRecorder.AllSupportedResources = &no
			p.Baseline.ConfigRecorder.IncludeGlobalResourceTypes = &no
		}},
		{"an automation role the operator made themselves", func(_ *testing.T, p *Profile) {
			// create:false with a name is legitimate — whether the role exists surfaces
			// at pack time, against the ARN the caller supplies for the exemption.
			p.Baseline.AutomationRole = &AutomationRole{Name: "campus-audit", Create: &no}
		}},
		{"no baseline region enablement", func(_ *testing.T, p *Profile) { p.Baseline.Regions = nil }},
		{"a home region with nothing to enable", func(_ *testing.T, p *Profile) {
			p.Baseline.Regions = &BaselineRegions{Home: "us-east-1"}
		}},
		{"a GovCloud region", func(_ *testing.T, p *Profile) {
			// Partition-agnostic by design: this is the environment most likely to need
			// a CUI baseline at all.
			p.Baseline.Regions = &BaselineRegions{Home: "us-gov-west-1"}
			p.Permitted = &Permitted{Regions: []string{"us-gov-west-1"}}
		}},
		{"a nested output directory", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.LocalDir = "out/evidence"
		}},
		{"an output directory named with a dot", func(_ *testing.T, p *Profile) {
			p.Baseline.Evidence.LocalDir = ".automat/evidence"
		}},
		{"no output targets at all", func(_ *testing.T, p *Profile) {
			// A local copy is still written; an absent block means the caller's default
			// rather than "write nothing".
			p.Baseline.Attestations = nil
			p.Baseline.Evidence = nil
		}},
		{"no attestations", func(_ *testing.T, p *Profile) {
			// automat ships no trust anchor, so an unsigned profile is the normal case
			// and always will be. This is the case that must never break.
			p.Signatures = nil
		}},
		{"an attestation with no signature block", func(t *testing.T, p *Profile) {
			// The claim is the attestation; the bytes are evidence for it. An
			// institution asserting authorship of a file it publishes is a real one.
			firstSig(t, p).Signature = nil
		}},
		{"a keyless attestation", func(t *testing.T, p *Profile) {
			firstSig(t, p).Signature = &Signature{
				Format:         FormatOIDCBundle,
				Value:          "QUFBQQ==",
				IdentityIssuer: "https://accounts.example.edu",
			}
		}},
		{"one identity attesting in two capacities", func(t *testing.T, p *Profile) {
			// Legitimate and the reason canonicalization keys on the whole entry rather
			// than on the identity: authored-by and adopted-by are different claims.
			second := *firstSig(t, p)
			second.Role = evidence.RoleAuthoredBy
			second.Statement = "Research Computing wrote this document."
			second.Signature = nil
			p.Signatures = append(p.Signatures, second)
		}},
		{"every role in the vocabulary", func(t *testing.T, p *Profile) {
			base := *firstSig(t, p)
			base.Signature = nil
			p.Signatures = nil
			for i, r := range evidence.AllRoles {
				a := base
				a.Role = r
				a.Statement = fmt.Sprintf("Claim %d, stated in the attester's own words.", i)
				p.Signatures = append(p.Signatures, a)
			}
		}},
		{"the attestation cap exactly", func(t *testing.T, p *Profile) {
			base := *firstSig(t, p)
			base.Signature = nil
			p.Signatures = nil
			for i := 0; i < maxSignatures; i++ {
				a := base
				a.Identity = fmt.Sprintf("Office %d", i)
				p.Signatures = append(p.Signatures, a)
			}
		}},
		{"the obligation cap exactly", func(_ *testing.T, p *Profile) {
			p.Obligations = nil
			for i := 0; i < maxObligations; i++ {
				p.Obligations = append(p.Obligations, ObligationRef{
					ID:            fmt.Sprintf("obligation-%d", i),
					ContentSHA256: strings.Repeat(fmt.Sprintf("%x", i%16), 64),
				})
			}
		}},
		{"the tag cap exactly", func(_ *testing.T, p *Profile) {
			p.Account.Tags = make(map[string]string, maxTags)
			for i := 0; i < maxTags; i++ {
				p.Account.Tags[fmt.Sprintf("key-%d", i)] = "x"
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := sampleProfile(t)
			tc.mutate(t, p)
			// Re-stamp: a mutation to a hashed field moves the subject, and whether the
			// attestations name this document is VerifyAttestationSubjects' question,
			// not Validate's. Leaving them stale would make this table fail for a
			// reason it is not about.
			stampAttestations(t, p)

			if err := p.Validate(); err != nil {
				t.Fatalf("internal/envprofile rejects a document that should be valid: %v", err)
			}
			if err := sch.Validate(asGeneric(t, p)); err != nil {
				t.Errorf("the published schema rejects a document internal/envprofile accepts — "+
					"schema/%s is too strict:\n%v", schemaFile, err)
			}
		})
	}
}

// TestBothValidatorsRejectAPresentButEmptyPermittedSetOnDisk covers the case the
// agree-on-rejection table structurally cannot.
//
// That table mutates a Go struct and marshals it, and `omitempty` on permitted.regions
// erases `[]` on the way out — so the schema is handed a document with no such field
// and correctly accepts it. The disagreement would be in the fixture, not the contract.
// This test therefore feeds each validator the ON-DISK form directly, which is what a
// hand-edited profile actually is and the only form in which the empty list exists.
//
// The stakes are E5's: absent says this profile adds no boundary on that axis, `[]` says
// nothing is permitted — which denies every call in the account including the ones
// automat's own baseline makes, and would be discovered after create and move had
// already succeeded. Both validators must refuse the second and accept the first.
func TestBothValidatorsRejectAPresentButEmptyPermittedSetOnDisk(t *testing.T) {
	sch := compileSchema(t)

	onDisk := func(t *testing.T, permitted any) []byte {
		t.Helper()
		raw, err := json.Marshal(sampleProfile(t))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var doc map[string]any
		if uerr := json.Unmarshal(raw, &doc); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		if permitted == nil {
			delete(doc, "permitted")
		} else {
			doc["permitted"] = permitted
		}
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}
	validateBytes := func(t *testing.T, data []byte) error {
		t.Helper()
		var generic any
		if err := json.Unmarshal(data, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return sch.Validate(generic)
	}

	for _, tc := range []struct {
		name      string
		permitted map[string]any
	}{
		{"an empty region set", map[string]any{"regions": []any{}, "services": []any{"s3"}}},
		{"an empty service set", map[string]any{"regions": []any{"us-east-1"}, "services": []any{}}},
		{"both sets empty", map[string]any{"regions": []any{}, "services": []any{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := onDisk(t, tc.permitted)
			if validateBytes(t, data) == nil {
				t.Errorf("the published schema accepts %s — minItems is missing, and an empty "+
					"allowlist is not a strict policy but a DENY-ALL", tc.name)
			}
			// SkipAttestationSubjects: the subject is the emptiness check, and a
			// stale-subject error would mask whether it fired.
			if _, err := Decode(data, LoadOptions{SkipAttestationSubjects: true}); err == nil {
				t.Errorf("internal/envprofile accepts %s on disk", tc.name)
			} else if !strings.Contains(err.Error(), "present but empty") {
				t.Errorf("the refusal does not say the set is present but empty, so an operator is "+
					"sent to reconcile two documents when one is malformed:\n%v", err)
			}
		})
	}

	t.Run("an absent permitted block is accepted by both", func(t *testing.T) {
		data := onDisk(t, nil)
		if err := validateBytes(t, data); err != nil {
			t.Errorf("the published schema rejects a profile with no permitted block, which is the "+
				"ordinary case:\n%v", err)
		}
		if _, err := Decode(data, LoadOptions{SkipAttestationSubjects: true}); err != nil {
			t.Errorf("internal/envprofile rejects a profile with no permitted block:\n%v", err)
		}
	})
}

// TestBothValidatorsRejectAPresentButEmptyObligationListOnDisk is the same structural
// case for the other field where `[]` and absent are different claims.
//
// An empty list and an absent one read the same to a person and differently to a
// schema, which is the ambiguity worth refusing in a document an auditor reads.
func TestBothValidatorsRejectAPresentButEmptyObligationListOnDisk(t *testing.T) {
	sch := compileSchema(t)

	raw, err := json.Marshal(sampleProfile(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	doc["obligations"] = []any{}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var generic any
	if uerr := json.Unmarshal(data, &generic); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	if sch.Validate(generic) == nil {
		t.Error("the published schema accepts obligations: [] — minItems is missing")
	}
	if _, derr := Decode(data, LoadOptions{SkipAttestationSubjects: true}); derr == nil {
		t.Error("internal/envprofile accepts obligations: [] on disk")
	}
}

// ---------------------------------------------------------------------------
// Gaps one layer cannot express, recorded rather than discovered
// ---------------------------------------------------------------------------

// TestTheSchemaCannotRejectAnUnsupportedMajorVersion records the first asymmetry.
//
// The schema's pattern is any semver, on purpose: a published contract that rejected
// `2.0.0` would make every v2 document invalid against v1 rather than merely
// unreadable by a v1 build, and an archived document would go retroactively malformed.
// Which majors a BUILD understands is a property of the build, so Validate() owns it.
func TestTheSchemaCannotRejectAnUnsupportedMajorVersion(t *testing.T) {
	sch := compileSchema(t)
	p := sampleProfile(t)
	p.SchemaVersion = "2.0.0"

	if err := sch.Validate(asGeneric(t, p)); err != nil {
		t.Fatalf("the schema now rejects a future major version. That is a behaviour change to "+
			"argue for rather than discover: it makes a v2 document invalid against v1 rather than "+
			"unreadable by a v1 build:\n%v", err)
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
// the checks a consumer validating against the published schema alone WILL NOT GET, and
// a new one added to Validate() without a line here is a rule automat enforces and does
// not advertise.
func TestGoOnlyChecksAreTheOnesNoSchemaCanState(t *testing.T) {
	sch := compileSchema(t)

	cases := []struct {
		name   string
		why    string
		want   string
		mutate func(*testing.T, *Profile)
	}{
		{
			name: "an OU path nobody will create",
			why: "the path is either ensured or it is decoration, and a profile naming OUs automat " +
				"will not create describes a placement that does not happen",
			want: "create_intermediate_ous is false",
			mutate: func(_ *testing.T, p *Profile) {
				p.Placement.OUPath = []string{"Research CUI"}
				p.Placement.CreateIntermediateOUs = false
			},
		},
		{
			name: "an email pattern with no placeholder",
			why: "every account needs a globally unique email (DESIGN §3, fact 11), so this produces " +
				"one address for every account and the second vend fails after the first exists",
			want: "placeholder",
			mutate: func(_ *testing.T, p *Profile) {
				p.Account.EmailPattern = "research-admin@dept.example.edu"
			},
		},
		{
			name: "an email pattern with two placeholders",
			why:  "substituting a name twice produces an address nobody intended",
			want: "more than one",
			mutate: func(_ *testing.T, p *Profile) {
				p.Account.EmailPattern = "admin+{name}+{name}@dept.example.edu"
			},
		},
		{
			name: "a delivery bucket for a recorder that is off",
			why: "the bucket would never be written to, and a profile naming one reads as though the " +
				"detective baseline were deployed",
			want: "recorder is disabled",
			mutate: func(_ *testing.T, p *Profile) {
				p.Baseline.ConfigRecorder.Enabled = false
			},
		},
		{
			name: "a region both enabled and disabled",
			why: "both are Account Management API calls in the same baseline step, so whichever ran " +
				"last would decide, and automat will not pick an order",
			want: "also appears in baseline.regions.enable",
			mutate: func(_ *testing.T, p *Profile) {
				p.Baseline.Regions.Disable = append(p.Baseline.Regions.Disable, "us-west-2")
			},
		},
		{
			name: "two obligation references to one profile",
			why: "two entries for one obligation could carry two different determinations, and this " +
				"validator will not choose between them. uniqueItems cannot see it: the entries " +
				"differ in their hashes",
			want: "duplicates obligations[0]",
			mutate: func(_ *testing.T, p *Profile) {
				p.Obligations = []ObligationRef{
					{ID: "dfars-7012", ContentSHA256: strings.Repeat("a", 64)},
					{ID: "dfars-7012", ContentSHA256: strings.Repeat("b", 64)},
				}
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
				t.Errorf("the refusal for %q does not mention %q, so an operator has to guess which "+
					"of two fields to change:\n%v", tc.name, tc.want, err)
			}
			// Recorded, not asserted as desirable: a consumer holding only the schema
			// does not get this check. If the schema ever grows it, this fails and the
			// case moves into the agreement table.
			if schemaErr := sch.Validate(asGeneric(t, p)); schemaErr != nil {
				t.Errorf("the published schema now rejects %q too. Good news, but it means this case "+
					"belongs in TestGoAndSchemaAgreeOnRejection rather than here:\n%v", tc.name, schemaErr)
			}
		})
	}
}

// TestTheSchemaCannotCheckAnAttestationsOwnSubject records the gap
// VerifyAttestationSubjects closes.
//
// content_sha256 names the document an attestation is over, and a schema cannot compute
// a hash — so an attestation can name ANY hash, including one lifted from a different
// document. Unlike the artifact case, automat DOES close this one: the assertion below
// is that the schema does not, and that Go does.
func TestTheSchemaCannotCheckAnAttestationsOwnSubject(t *testing.T) {
	sch := compileSchema(t)
	p := sampleProfile(t)
	// Well-formed, and about some other document entirely.
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
		t.Fatal("VerifyAttestationSubjects accepted an attestation over a different document. An " +
			"attestation whose subject does not match is not a weaker attestation, it is one about " +
			"something else.")
	}
	if !strings.Contains(err.Error(), "this document's content hashes to") {
		t.Errorf("the refusal does not name the hash this document actually has, so an operator "+
			"cannot tell whether to re-attest or to revert an edit:\n%v", err)
	}
}

// determination returns the fixture's operator determination, failing loudly if the
// fixture stopped carrying one — a stale fixture must not let a case mutate nothing.
func determination(t *testing.T, p *Profile) *Determination {
	t.Helper()
	for i := range p.Obligations {
		if d := p.Obligations[i].RevisionDetermination; d != nil {
			return d
		}
	}
	t.Fatal("test setup: no obligation in the fixture carries a revision determination")
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
