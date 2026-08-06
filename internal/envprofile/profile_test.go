// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package envprofile

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/evidence"
)

// sampleProfile returns a valid environment profile exercising every optional block,
// with each attestation's subject stamped to the document's actual content hash.
//
// Deliberately NOT in canonical form: ControlSets is unsorted and the OU path is in
// tree order rather than sorted order, so a test that asks whether canonicalization
// does anything has something to observe. The hash is defined over canonical form, so
// the stamped subject is stable regardless.
func sampleProfile(t *testing.T) *Profile {
	t.Helper()
	p := unstampedSampleProfile()
	stampAttestations(t, p)
	return p
}

func unstampedSampleProfile() *Profile {
	yes := true
	return &Profile{
		SchemaVersion: SchemaVersion,
		Meta: Meta{
			ID:          "research-cui",
			Title:       "Research CUI environment",
			Description: "Vends accounts rated to hold CUI under a departmental award.",
		},
		ReviewBy: "2027-06-30",
		Signatures: []Attestation{{
			Role:     evidence.RoleAdoptedBy,
			Identity: "Research Computing, Example University",
			Statement: "Research Computing adopted this environment profile for its own use.\n\n" +
				"This says nothing about whether it suits anyone else.",
			AttestedAt: "2026-08-05",
			Signature: &Signature{
				Format: FormatDetachedEd25519,
				Value:  "QUFBQQ==",
				KeyID:  "local-key-1",
			},
		}},
		// Unsorted on purpose; see the doc comment.
		ControlSets: []string{"cmmc-l1", "campus-base"},
		Permitted: &Permitted{
			Regions:  []string{"us-east-1", "us-west-2"},
			Services: []string{"batch", "s3"},
		},
		Obligations: []ObligationRef{
			{ID: "dfars-7012", ContentSHA256: strings.Repeat("a", 64)},
			{
				ID:            "nih-cadr-dua",
				ContentSHA256: strings.Repeat("b", 64),
				RevisionDetermination: &Determination{
					Value:        "800-171r2",
					DeterminedBy: "Office of Research Compliance",
					DeterminedAt: "2026-07-01",
					Statement: "The agreement does not name a revision. This institution builds to " +
						"r2 until its awarding agency states otherwise.",
				},
			},
		},
		Placement: Placement{
			TargetOU:              "ou-abcd-11111111",
			CreateIntermediateOUs: true,
			OUPath:                []string{"Research CUI", "Genomics"},
		},
		Account: &Account{
			EmailPattern:           "research-admin+{name}@dept.example.edu",
			RoleName:               "OrganizationAccountAccessRole",
			IAMUserAccessToBilling: BillingAccessDeny,
			Tags:                   map[string]string{"cost-center": "1234", "department": "Genomics"},
		},
		Baseline: Baseline{
			ConfigRecorder: ConfigRecorder{
				Enabled:                    true,
				AllSupportedResources:      &yes,
				IncludeGlobalResourceTypes: &yes,
				DeliveryBucket:             "example-config-delivery",
			},
			Regions: &BaselineRegions{
				Home:    "us-east-1",
				Enable:  []string{"us-west-2"},
				Disable: []string{"ap-south-1"},
			},
			AutomationRole:                &AutomationRole{Name: DefaultAutomationRoleName, Create: &yes},
			DisableOrgAccessRoleAfterVend: true,
			Attestations: &OutputTargets{
				LocalDir:        "compliance",
				InAccountBucket: "example-attestations",
			},
			Evidence: &OutputTargets{
				LocalDir:               "evidence",
				InAccountBucket:        "example-evidence",
				ManagementMirrorBucket: "example-evidence-mirror",
			},
		},
	}
}

// stampAttestations sets every attestation's subject to the document's own content
// hash, which is what VerifyAttestationSubjects demands and what a real signer would
// have done.
//
// Safe to do after the fact only because Signatures is outside the hash — which is
// itself one of the properties asserted below. If that ever stopped being true this
// helper would not converge, and the test that says so would fail first.
func stampAttestations(t *testing.T, p *Profile) {
	t.Helper()
	h, err := p.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	for i := range p.Signatures {
		p.Signatures[i].ContentSHA256 = h
	}
}

// TestEveryProfileFieldIsClassifiedForHashCoverage makes forgetting a hash-coverage
// decision a build failure.
//
// The same test internal/artifact carries, for the same reason and against a document
// where the stakes are higher: an environment profile field outside the hash can be
// edited without invalidating any attestation over it or any evidence record naming
// it. That is correct for the id and catastrophic for anything deciding what gets
// built — a permitted-region set silently outside the hash would mean an account's
// birth certificate attests to a boundary nobody can check.
func TestEveryProfileFieldIsClassifiedForHashCoverage(t *testing.T) {
	classified := make(map[string]string, len(HashCoveredFields)+len(HashExcludedFields))
	for _, n := range HashCoveredFields {
		classified[n] = "covered"
	}
	for _, n := range HashExcludedFields {
		if prior, dup := classified[n]; dup {
			t.Errorf("field %q is listed as both %s and excluded; it is one or the other", n, prior)
		}
		classified[n] = "excluded"
	}

	profileFields := fieldSet(Profile{})
	payloadFields := fieldSet(contentPayload{})

	for _, name := range sortedKeys(profileFields) {
		if _, ok := classified[name]; !ok {
			t.Errorf("Profile field %q is in neither HashCoveredFields nor HashExcludedFields.\n"+
				"Decide whether the content hash covers it and say so in one of those lists, with the "+
				"reason. A field outside the hash can be edited without invalidating any attestation "+
				"over this document or any evidence record naming it — which is what the exclusions are "+
				"for, and is exactly wrong for anything that decides what gets built.", name)
		}
	}
	for _, n := range HashCoveredFields {
		if !profileFields[n] {
			t.Errorf("HashCoveredFields names %q, which is not a field on Profile", n)
		}
		if !payloadFields[n] {
			t.Errorf("HashCoveredFields names %q, which is not a field on contentPayload — "+
				"so it is documented as hashed and is not in fact hashed", n)
		}
	}
	for _, n := range sortedKeys(payloadFields) {
		if classified[n] != "covered" {
			t.Errorf("contentPayload has field %q, which HashCoveredFields does not name — "+
				"it is hashed and undocumented as such", n)
		}
	}
	for _, n := range HashExcludedFields {
		if !profileFields[n] {
			t.Errorf("HashExcludedFields names %q, which is not a field on Profile", n)
		}
		if payloadFields[n] {
			t.Errorf("HashExcludedFields names %q, which contentPayload also carries — the field is "+
				"documented as outside the hash and is inside it", n)
		}
	}
}

// TestTheHashCoverageListsAreTheTruthRatherThanADescription checks the lists against
// behavior rather than against the struct.
//
// The reflection test above proves contentPayload and the lists agree; it cannot prove
// either one describes what ContentHash actually does. So each covered field is mutated
// and the hash must move, and each excluded field is mutated and it must not. This is
// the assertion an operator's trust in the hash rests on, and it is cheap.
func TestTheHashCoverageListsAreTheTruthRatherThanADescription(t *testing.T) {
	hashOf := func(t *testing.T, p *Profile) string {
		t.Helper()
		h, err := p.ContentHash()
		if err != nil {
			t.Fatalf("ContentHash: %v", err)
		}
		return h
	}

	covered := []struct {
		field  string
		mutate func(*Profile)
	}{
		{"ReviewBy", func(p *Profile) { p.ReviewBy = "2099-01-01" }},
		{"ControlSets", func(p *Profile) { p.ControlSets = append(p.ControlSets, "800-171r2") }},
		{"Permitted", func(p *Profile) { p.Permitted.Regions = []string{"us-east-1"} }},
		{"Obligations", func(p *Profile) { p.Obligations = p.Obligations[:1] }},
		{"Placement", func(p *Profile) { p.Placement.TargetOU = "ou-abcd-22222222" }},
		{"Account", func(p *Profile) { p.Account.IAMUserAccessToBilling = BillingAccessAllow }},
		{"Baseline", func(p *Profile) { p.Baseline.ConfigRecorder.Enabled = false }},
	}
	// Every name in HashCoveredFields must have a case here, or a field could be
	// listed as covered, be absent from contentPayload's effect, and nobody notice.
	if len(covered) != len(HashCoveredFields) {
		t.Fatalf("this table has %d cases but HashCoveredFields names %d fields; a covered field with "+
			"no case here is one whose coverage is asserted only by reflection",
			len(covered), len(HashCoveredFields))
	}
	for _, tc := range covered {
		t.Run("covered/"+tc.field, func(t *testing.T) {
			base := sampleProfile(t)
			before := hashOf(t, base)
			tc.mutate(base)
			if after := hashOf(t, base); after == before {
				t.Errorf("mutating %s did not change the content hash, but HashCoveredFields says it "+
					"is covered. A field that decides what gets built and sits outside the hash can be "+
					"edited under an attestation that still verifies.", tc.field)
			}
		})
	}

	excluded := []struct {
		field  string
		mutate func(*Profile)
	}{
		{"SchemaVersion", func(p *Profile) { p.SchemaVersion = "1.9.9" }},
		{"Meta", func(p *Profile) { p.Meta.ID = "renamed"; p.Meta.Title = "Renamed" }},
		{"Signatures", func(p *Profile) { p.Signatures = nil }},
	}
	if len(excluded) != len(HashExcludedFields) {
		t.Fatalf("this table has %d cases but HashExcludedFields names %d fields",
			len(excluded), len(HashExcludedFields))
	}
	for _, tc := range excluded {
		t.Run("excluded/"+tc.field, func(t *testing.T) {
			base := sampleProfile(t)
			before := hashOf(t, base)
			tc.mutate(base)
			if after := hashOf(t, base); after != before {
				t.Errorf("mutating %s changed the content hash, but HashExcludedFields says it does "+
					"not.\nbefore: %s\nafter:  %s\n\nEach exclusion buys something specific — renaming "+
					"a profile must not invalidate the attestations over it, and a second identity must "+
					"be able to attest without breaking the first's signature. Covering one of these "+
					"fields takes that away.", tc.field, before, after)
			}
		})
	}
}

// TestRefRecordsAnEmptyVerifiedSetRatherThanTheDocumentsOwnClaims is the honesty rule
// on the field most likely to be filled in by wishful thinking.
//
// automat verifies nothing in v1, so Ref records the empty set as an ANSWER: empty and
// non-nil. Copying the document's own Signatures across would manufacture assurance
// out of a document's claims about itself, and a nil slice would blur "nothing was
// verified" into "the question was never asked" — the one distinction an evidence
// record must not lose.
func TestRefRecordsAnEmptyVerifiedSetRatherThanTheDocumentsOwnClaims(t *testing.T) {
	p := sampleProfile(t)
	if len(p.Signatures) == 0 {
		t.Fatal("test setup: the fixture must carry an attestation for this to mean anything")
	}
	hash, err := p.ContentHash()
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}

	ref := p.Ref(hash)
	if ref.VerifiedSignatures == nil {
		t.Error("Ref returned a nil verified-signature set. Empty and nil are different claims: " +
			"empty says nothing verified, nil says the question was never asked, and automat's answer " +
			"in v1 is the first one.")
	}
	if len(ref.VerifiedSignatures) != 0 {
		t.Errorf("Ref copied %d signature(s) out of the document. automat verifies none of them in "+
			"v1, and a record listing signatures it did not check manufactures assurance out of a "+
			"document's own claims about itself (DESIGN §11a).", len(ref.VerifiedSignatures))
	}
	if ref.ID != p.Meta.ID || ref.ContentSHA256 != hash ||
		ref.SchemaVersion != p.SchemaVersion || ref.ReviewBy != p.ReviewBy {
		t.Errorf("Ref = %+v, which does not name the document it was built from", ref)
	}
}

// TestRefTakesTheHashItIsGivenRatherThanRecomputing pins the argument's purpose.
//
// The caller controls which bytes the record attests to, because the bytes on disk are
// what a later `verify` re-reads — not whatever a struct in memory has become since.
func TestRefTakesTheHashItIsGivenRatherThanRecomputing(t *testing.T) {
	p := sampleProfile(t)
	const asLoaded = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := p.Ref(asLoaded).ContentSHA256; got != asLoaded {
		t.Errorf("Ref recomputed the hash (%s) instead of recording the one it was given (%s); the "+
			"caller holds the bytes a later verify will re-read", got, asLoaded)
	}
}

// TestDefaultsAreReportedRatherThanGuessed covers the accessors that exist because a
// plain bool cannot distinguish "the profile said false" from "the profile said
// nothing" — and where the wrong reading of an absent field silently records less than
// the operator asked for.
func TestDefaultsAreReportedRatherThanGuessed(t *testing.T) {
	no, yes := false, true

	t.Run("recorder scope defaults to the wider reading", func(t *testing.T) {
		var c ConfigRecorder
		if !c.RecordsAllSupportedResources() || !c.RecordsGlobalResourceTypes() {
			t.Error("an absent recording scope must default to true, matching the schema. Defaulting " +
				"to the narrower reading would silently reduce what is recorded, and the operator " +
				"would find out from a gap in the evidence rather than from the document.")
		}
		c = ConfigRecorder{AllSupportedResources: &no, IncludeGlobalResourceTypes: &no}
		if c.RecordsAllSupportedResources() || c.RecordsGlobalResourceTypes() {
			t.Error("an explicit false must be honored")
		}
		c = ConfigRecorder{AllSupportedResources: &yes, IncludeGlobalResourceTypes: &yes}
		if !c.RecordsAllSupportedResources() || !c.RecordsGlobalResourceTypes() {
			t.Error("an explicit true must be honored")
		}
	})

	t.Run("automation role", func(t *testing.T) {
		var nilRole *AutomationRole
		if got := nilRole.RoleName(); got != DefaultAutomationRoleName {
			t.Errorf("nil role name = %q, want %q", got, DefaultAutomationRoleName)
		}
		if !nilRole.ShouldCreate() {
			t.Error("an absent automation_role block must still create the role: the " +
				"baseline-protection SCP exemptions name that principal, and an exemption pointing at " +
				"a role that does not exist is a hole in a Deny nobody can use and nobody can see")
		}
		if got := (&AutomationRole{}).RoleName(); got != DefaultAutomationRoleName {
			t.Errorf("empty name = %q, want %q", got, DefaultAutomationRoleName)
		}
		if !(&AutomationRole{}).ShouldCreate() {
			t.Error("an absent create must default to true")
		}
		if (&AutomationRole{Create: &no}).ShouldCreate() {
			t.Error("an explicit create:false must be honored")
		}
		if got := (&AutomationRole{Name: "campus-audit"}).RoleName(); got != "campus-audit" {
			t.Errorf("named role = %q", got)
		}
	})

	t.Run("output directory", func(t *testing.T) {
		var nilTargets *OutputTargets
		if got := nilTargets.Dir(DefaultEvidenceDir); got != DefaultEvidenceDir {
			t.Errorf("nil targets dir = %q, want %q", got, DefaultEvidenceDir)
		}
		if got := (&OutputTargets{}).Dir(DefaultAttestationDir); got != DefaultAttestationDir {
			t.Errorf("empty dir = %q, want %q", got, DefaultAttestationDir)
		}
		if got := (&OutputTargets{LocalDir: "out/evidence"}).Dir(DefaultEvidenceDir); got != "out/evidence" {
			t.Errorf("explicit dir = %q", got)
		}
	})
}

// fieldSet returns the exported field names of a struct value.
func fieldSet(v any) map[string]bool {
	typ := reflect.TypeOf(v)
	out := make(map[string]bool, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.IsExported() {
			out[f.Name] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
