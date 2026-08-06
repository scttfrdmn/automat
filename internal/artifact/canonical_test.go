// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestEveryArtifactFieldIsClassifiedForHashCoverage is the test that makes
// forgetting a hash-coverage decision a build failure.
//
// Adding a field to Artifact is a decision about whether the content hash covers
// it, and the failure mode of getting it wrong is silent: the field exists, the
// document validates, signatures verify, and an edit to the field changes what a
// vended account permits without changing any hash that anyone checks. That is
// how region_deny_exempt_services nearly landed outside the hash — the one field
// in the artifact that decides whether a region Deny covers IAM.
//
// So: every exported field of Artifact must appear in exactly one of
// HashCoveredFields or HashExcludedFields, and each name in HashCoveredFields
// must be a real field on both Artifact and the content payload. A new field
// fails here until someone writes down which it is and why.
func TestEveryArtifactFieldIsClassifiedForHashCoverage(t *testing.T) {
	fieldNames := func(v any) []string {
		typ := reflect.TypeOf(v)
		out := make([]string, 0, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.IsExported() {
				out = append(out, f.Name)
			}
		}
		sort.Strings(out)
		return out
	}

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

	for _, name := range fieldNames(Artifact{}) {
		if _, ok := classified[name]; !ok {
			t.Errorf("Artifact field %q is in neither HashCoveredFields nor HashExcludedFields.\n"+
				"Decide whether the content hash covers it and say so in one of those lists, with the reason.\n"+
				"A field outside the hash can be edited without invalidating any signature over the artifact — "+
				"which is fine for compiled_at and catastrophic for anything that changes what an account permits.",
				name)
		}
	}

	artifactFields := make(map[string]bool)
	for _, n := range fieldNames(Artifact{}) {
		artifactFields[n] = true
	}
	payloadFields := make(map[string]bool)
	for _, n := range fieldNames(contentPayload{}) {
		payloadFields[n] = true
	}
	for _, n := range HashCoveredFields {
		if !artifactFields[n] {
			t.Errorf("HashCoveredFields names %q, which is not a field on Artifact", n)
		}
		if !payloadFields[n] {
			t.Errorf("HashCoveredFields names %q, which is not a field on contentPayload — "+
				"so it is documented as hashed and is not in fact hashed", n)
		}
	}
	for _, n := range fieldNames(contentPayload{}) {
		if classified[n] != "covered" {
			t.Errorf("contentPayload has field %q, which HashCoveredFields does not name — "+
				"it is hashed and undocumented as such", n)
		}
	}
	for _, n := range HashExcludedFields {
		if !artifactFields[n] {
			t.Errorf("HashExcludedFields names %q, which is not a field on Artifact", n)
		}
	}
}

// sampleArtifact returns a valid artifact exercising every enforcement class.
//
// The content hash is set, so a mutation in a validation table produces exactly
// the one problem it intends and nothing else.
func sampleArtifact() *Artifact {
	a := unhashedSampleArtifact()
	if err := a.SetContentHash(); err != nil {
		panic("sampleArtifact: " + err.Error())
	}
	return a
}

func unhashedSampleArtifact() *Artifact {
	return &Artifact{
		SchemaVersion: SchemaVersion,
		Meta: Meta{
			ID:         "test-set",
			Title:      "Test Control Set",
			CompiledAt: "2026-08-04T00:00:00Z",
			Sources: Sources{
				{Catalog: "FAR 52.204-21", Version: "Nov 2021", SHA256: strings.Repeat("a", 64)},
				{Mapping: "aws-config-conformance-pack", SHA256: strings.Repeat("b", 64)},
			},
		},
		Controls: Controls{
			{
				ID:          "ZZ.L1-b.1.z",
				Title:       "Procedural control",
				Enforcement: []EnforcementClass{EnforcementProcedural},
				Attestation: &Attestation{Template: "procedural.md", Frequency: "annual"},
			},
			{
				ID:          "AA.L1-b.1.a",
				Title:       "Detective and preventive control",
				Statement:   "Do the thing.",
				Crosswalk:   map[string]string{"800-171r2": "3.1.1", "far": "52.204-21(b)(1)(i)"},
				Enforcement: []EnforcementClass{EnforcementConfigRule, EnforcementSCP},
				SCP: &SCP{
					Statements: []SCPStatement{{
						Sid:      "DenyPublic",
						Effect:   "Deny",
						Action:   []string{"s3:PutBucketPolicy", "s3:PutBucketAcl"},
						Resource: []string{"*"},
						Condition: Condition{
							"StringNotEquals": {"aws:PrincipalArn": {"arn:aws:iam::*:role/automat-automation"}},
						},
					}},
					RegionAllowlist: []string{"us-west-2", "us-east-1"},
				},
				ConfigRules: []ConfigRule{
					{
						Identifier: "IAM_PASSWORD_POLICY",
						Name:       "iam-password-policy",
						Provenance: ProvenanceAWSMapping,
						Parameters: map[string]RuleParameter{
							"MinimumPasswordLength": {Value: "14", Order: OrderMax},
							"MaxPasswordAge":        {Value: "90", Order: OrderMin},
						},
					},
					{
						Identifier: "ACCESS_KEYS_ROTATED",
						Name:       "access-keys-rotated",
						Provenance: ProvenanceAWSMapping,
					},
					{
						Identifier: "RESTRICTED_INCOMING_TRAFFIC",
						Name:       "restricted-common-ports",
						Provenance: ProvenanceCurated,
						Rationale:  "Bound by this project, not by an upstream mapping, to exercise both provenances.",
						Parameters: map[string]RuleParameter{
							"blockedPort1":       {Value: "3389", Order: OrderSetUnion},
							"authorizedTcpPorts": {Value: "443,22", Order: OrderSetIntersect},
						},
					},
				},
			},
			{
				ID:          "BB.L1-b.1.b",
				Title:       "Baseline protection control",
				Enforcement: []EnforcementClass{EnforcementBaselineProtection},
				SCP: &SCP{Statements: []SCPStatement{{
					Sid:      "ProtectRecorder",
					Effect:   "Deny",
					Action:   []string{"config:StopConfigurationRecorder"},
					Resource: []string{"*"},
					ExemptPrincipals: ExemptPrincipals{
						{Principal: AutomationRolePlaceholder, Reason: "automat's own baseline apply must be able to configure the recorder."},
						{Principal: "arn:aws:iam::111122223333:role/BreakGlass", Reason: "Exercises the literal-ARN form alongside the placeholder."},
					},
				}}},
			},
		},
	}
}

func TestRoundTripPreservesContentHash(t *testing.T) {
	orig := sampleArtifact()
	if err := orig.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := orig.Validate(); err != nil {
		t.Fatalf("sample artifact must be valid: %v", err)
	}

	for _, tc := range []struct {
		name    string
		marshal func(*Artifact) ([]byte, error)
	}{
		{"canonical", (*Artifact).MarshalCanonical},
		{"indented", (*Artifact).MarshalIndented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.marshal(orig)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got, err := Decode(data, LoadOptions{})
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Meta.ContentHash != orig.Meta.ContentHash {
				t.Errorf("content hash changed across round trip: got %s want %s",
					got.Meta.ContentHash, orig.Meta.ContentHash)
			}
			// Re-marshalling must be byte-identical, or the golden files and
			// the atomic catalog write are both unstable.
			again, err := tc.marshal(got)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if string(again) != string(data) {
				t.Errorf("re-marshal is not byte-identical:\n--- first ---\n%s\n--- second ---\n%s", data, again)
			}
		})
	}
}

func TestContentHashIsOrderIndependent(t *testing.T) {
	a := sampleArtifact()
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	want := a.Meta.ContentHash

	// Shuffle every set-valued member, then rehash. Canonicalization must
	// absorb all of it: this hash lands in account tags and evidence records,
	// so a reordering that changed it would break `verify` for no reason.
	b := sampleArtifact()
	b.Controls[0], b.Controls[2] = b.Controls[2], b.Controls[0]
	b.Meta.Sources[0], b.Meta.Sources[1] = b.Meta.Sources[1], b.Meta.Sources[0]
	for i := range b.Controls {
		c := &b.Controls[i]
		if len(c.Enforcement) == 2 {
			c.Enforcement[0], c.Enforcement[1] = c.Enforcement[1], c.Enforcement[0]
		}
		if c.SCP != nil {
			for j := range c.SCP.Statements {
				st := &c.SCP.Statements[j]
				reverse(st.Action)
				reverse(st.Resource)
			}
			reverse(c.SCP.RegionAllowlist)
		}
		for j, k := 0, len(c.ConfigRules)-1; j < k; j, k = j+1, k-1 {
			c.ConfigRules[j], c.ConfigRules[k] = c.ConfigRules[k], c.ConfigRules[j]
		}
		// Set-valued parameter members are a set, so respelling one must not
		// move the hash either.
		for j := range c.ConfigRules {
			for name, param := range c.ConfigRules[j].Parameters {
				if !param.Order.IsSet() {
					continue
				}
				members := param.Members()
				reverse(members)
				param.Value = strings.Join(members, " , ")
				c.ConfigRules[j].Parameters[name] = param
			}
		}
	}
	if err := b.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if b.Meta.ContentHash != want {
		t.Errorf("reordering changed the content hash: got %s want %s", b.Meta.ContentHash, want)
	}
}

func TestContentHashIgnoresArtifactMetadata(t *testing.T) {
	a := sampleArtifact()
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	// Recompiling the same controls at a different time, with a different
	// title, must yield the same content hash — otherwise every recompile
	// invalidates the tags and manifests that reference the artifact.
	b := sampleArtifact()
	b.Meta.CompiledAt = "2027-01-01T12:34:56Z"
	b.Meta.Title = "Renamed"
	b.Meta.Description = "Added later"
	b.Meta.Sources = append(b.Meta.Sources, Source{Mapping: "another", SHA256: strings.Repeat("c", 64)})
	if err := b.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if b.Meta.ContentHash != a.Meta.ContentHash {
		t.Errorf("metadata changed the content hash: got %s want %s", b.Meta.ContentHash, a.Meta.ContentHash)
	}
}

func TestContentHashChangesWithControls(t *testing.T) {
	base := sampleArtifact()
	if err := base.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	// Mutations address controls by id, not index: canonicalization sorts
	// controls, so an index would silently point at the wrong one.
	mutations := map[string]func(*testing.T, *Artifact){
		"add action": func(t *testing.T, a *Artifact) {
			c := mustControl(t, a, "AA.L1-b.1.a")
			c.SCP.Statements[0].Action = append(c.SCP.Statements[0].Action, "s3:DeleteBucket")
		},
		"narrow region allowlist": func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").SCP.RegionAllowlist = []string{"us-east-1"}
		},
		"change parameter value": func(t *testing.T, a *Artifact) {
			c := mustControl(t, a, "AA.L1-b.1.a")
			mustRule(t, c, "IAM_PASSWORD_POLICY").Parameters["MinimumPasswordLength"] = RuleParameter{Value: "16", Order: OrderMax}
		},
		"change parameter order": func(t *testing.T, a *Artifact) {
			c := mustControl(t, a, "AA.L1-b.1.a")
			mustRule(t, c, "IAM_PASSWORD_POLICY").Parameters["MinimumPasswordLength"] = RuleParameter{Value: "14", Order: OrderExact}
		},
		"drop a control": func(_ *testing.T, a *Artifact) {
			a.Controls = a.Controls[:2]
		},
		"change enforcement class": func(t *testing.T, a *Artifact) {
			c := mustControl(t, a, "ZZ.L1-b.1.z")
			c.Enforcement = []EnforcementClass{EnforcementConfigRule}
			c.Attestation = nil
			c.ConfigRules = []ConfigRule{{Identifier: "SOME_RULE"}}
		},
		"drop an exemption": func(t *testing.T, a *Artifact) {
			st := &mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0]
			st.ExemptPrincipals = st.ExemptPrincipals[:1]
		},
		"add an exemption": func(t *testing.T, a *Artifact) {
			st := &mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0]
			st.ExemptPrincipals = append(st.ExemptPrincipals, ExemptPrincipal{
				Principal: "arn:aws:iam::111122223333:role/Auditor",
				Reason:    "A third principal, so the hash must move.",
			})
		},
		"change an exempted principal": func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0].
				ExemptPrincipals[1].Principal = "arn:aws:iam::111122223333:role/SomeoneElse"
		},
		// The reason is part of the hash, not annotation. Two artifacts that
		// exempt the same principals for different stated reasons are different
		// artifacts: the reason is the reviewable half of an exemption, and a
		// hash that ignored it would let the justification be rewritten under a
		// signature that still verified.
		"change an exemption reason": func(t *testing.T, a *Artifact) {
			mustControl(t, a, "BB.L1-b.1.b").SCP.Statements[0].
				ExemptPrincipals[0].Reason = "A different reason for the same hole."
		},
		"change crosswalk": func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").Crosswalk["800-171r3"] = "03.01.01"
		},
		"change statement text": func(t *testing.T, a *Artifact) {
			mustControl(t, a, "AA.L1-b.1.a").Statement = "Do a different thing."
		},
		// The artifact-level global-service exemption list is inside the hash, and
		// these three cases are why it has to be. The list decides which service
		// namespaces a rendered region Deny does NOT cover, so every edit to it
		// widens or narrows the holes in that Deny. Outside the hash, adding `s3`
		// here would pass VerifyContentHash and every signature over the artifact
		// unremarked, and the operator's only evidence that the Deny changed shape
		// would be an account that behaves differently.
		"add a region-deny exemption list": func(_ *testing.T, a *Artifact) {
			a.RegionDenyExemptServices = []string{"iam", "sts"}
		},
		"widen a region-deny exemption list": func(_ *testing.T, a *Artifact) {
			a.RegionDenyExemptServices = []string{"iam", "sts", "s3"}
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			a := sampleArtifact()
			mutate(t, a)
			if err := a.SetContentHash(); err != nil {
				t.Fatalf("SetContentHash: %v", err)
			}
			if a.Meta.ContentHash == base.Meta.ContentHash {
				t.Errorf("mutation %q did not change the content hash (%s); the hash is not covering it",
					name, a.Meta.ContentHash)
			}
		})
	}
}

func TestContentHashIsStable(t *testing.T) {
	// A literal expected hash. If this changes, canonicalization changed, and
	// every previously written tag, SCP tag, and evidence record that names an
	// artifact hash is now unverifiable. Treat a diff here as a schema-breaking
	// change requiring a version bump and a note in schema/CHANGELOG.md.
	//
	// Moved from 9d80614f… when exempt_automation_role became exempt_principals
	// (Phase 1 review item 9b). The fixture's own contents changed, so this is
	// the pin following the sample rather than canonicalization drifting under
	// it — the distinction is why this constant exists, and it is the reason no
	// published catalog needed rehashing: nothing had shipped with the boolean,
	// and no catalog in catalogs/ carries an exemption at all.
	//
	// It moved a second time within that same change, for editing one fixture
	// exemption's *reason* text and nothing else. That is the field working as
	// designed: the reason is the reviewable half of an exemption, so it is
	// inside the hash. A hash that ignored it would let the stated
	// justification for a hole in a Deny be rewritten under a signature that
	// still verified.
	//
	// It moved a third time when the content hash stopped covering a bare
	// controls[] array and started covering a content payload OBJECT
	// (HashCoveredFields), so that the artifact-level
	// region_deny_exempt_services list is inside the hash. That list decides
	// whether a rendered region Deny covers IAM; outside the hash, an edit adding
	// a service to it — widening the holes in the Deny — would pass
	// VerifyContentHash unremarked. Every artifact hash moved, which cost nothing
	// because no schema has been published and no catalog had shipped, and would
	// have cost a great deal later.
	const want = "cd27800083c55774c7c65d27b6bbe81f084ffa331b183b74330d64e4a9b06776"

	a := sampleArtifact()
	got, err := a.ComputeContentHash()
	if err != nil {
		t.Fatalf("ComputeContentHash: %v", err)
	}
	if got != want {
		t.Errorf("canonical hash of the sample artifact changed:\n got %s\nwant %s\n"+
			"If this change is intentional, bump the schema version and add a migration note "+
			"in schema/CHANGELOG.md, then update this constant.", got, want)
	}
}

// TestCanonicalizeKeepsAnEmptyExemptListDistinguishableFromAbsent guards the one
// place the empty/absent distinction has to survive.
//
// Canonicalize runs before Write validates, so if it turned `[]` into nil the
// invalid document would become a valid one on the way to disk and the error the
// author needed to see would never be raised. The content hash is allowed to
// conflate the two — no valid document carries `[]`, because both the schema's
// minItems and Validate reject it — but canonicalization is upstream of that
// rejection and must not launder it.
func TestCanonicalizeKeepsAnEmptyExemptListDistinguishableFromAbsent(t *testing.T) {
	empty := unhashedSampleArtifact()
	empty.RegionDenyExemptServices = []string{}
	empty.Canonicalize()
	if empty.RegionDenyExemptServices == nil {
		t.Error("Canonicalize turned an empty region_deny_exempt_services into absent; " +
			"Write validates AFTER canonicalizing, so this would silently repair an invalid " +
			"artifact into a valid one instead of telling the author the list is empty")
	}

	absent := unhashedSampleArtifact()
	absent.Canonicalize()
	if absent.RegionDenyExemptServices != nil {
		t.Errorf("Canonicalize invented a region_deny_exempt_services where the artifact had none: %v",
			absent.RegionDenyExemptServices)
	}

	// And it still sorts and dedupes, like every other set-valued member: order in
	// the source file must not reach the hash.
	unsorted := unhashedSampleArtifact()
	unsorted.RegionDenyExemptServices = []string{"sts", "iam", "sts", "organizations"}
	unsorted.Canonicalize()
	want := []string{"iam", "organizations", "sts"}
	if !reflect.DeepEqual(unsorted.RegionDenyExemptServices, want) {
		t.Errorf("Canonicalize did not sort and dedupe the exempt list:\n got %v\nwant %v",
			unsorted.RegionDenyExemptServices, want)
	}
}

func TestCanonicalizeIsIdempotent(t *testing.T) {
	a := sampleArtifact()
	a.Canonicalize()
	first, err := a.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	a.Canonicalize()
	a.Canonicalize()
	second, err := a.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("Canonicalize is not idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestCanonicalizeNormalizesEmptyCollections(t *testing.T) {
	// `[]` and absent must hash identically, or a compiler that emits an empty
	// slice produces a different hash than one that omits the field for the
	// same controls.
	withEmpty := sampleArtifact()
	detective := mustControl(t, withEmpty, "AA.L1-b.1.a")
	detective.SCP.ServiceAllowlist = []string{}
	mustRule(t, detective, "ACCESS_KEYS_ROTATED").ResourceTypes = []string{}
	protection := mustControl(t, withEmpty, "BB.L1-b.1.b")
	protection.SCP.RegionAllowlist = []string{}
	protection.SCP.Statements[0].Condition = Condition{}
	mustControl(t, withEmpty, "ZZ.L1-b.1.z").Crosswalk = map[string]string{}

	withAbsent := sampleArtifact()

	hEmpty, err := withEmpty.ComputeContentHash()
	if err != nil {
		t.Fatalf("ComputeContentHash: %v", err)
	}
	hAbsent, err := withAbsent.ComputeContentHash()
	if err != nil {
		t.Fatalf("ComputeContentHash: %v", err)
	}
	if hEmpty != hAbsent {
		t.Errorf("empty collections hash differently from absent ones: %s vs %s", hEmpty, hAbsent)
	}
}

func TestCanonicalizeDedupes(t *testing.T) {
	a := sampleArtifact()
	target := mustControl(t, a, "AA.L1-b.1.a")
	target.SCP.Statements[0].Action = []string{"s3:PutBucketAcl", "s3:PutBucketPolicy", "s3:PutBucketAcl"}
	target.SCP.RegionAllowlist = []string{"us-east-1", "us-east-1", "us-west-2"}
	target.Enforcement = []EnforcementClass{EnforcementSCP, EnforcementConfigRule, EnforcementSCP}
	a.Canonicalize()

	// Canonicalize reorders controls, so look the control up again by id.
	got := mustControl(t, a, "AA.L1-b.1.a")
	if act := got.SCP.Statements[0].Action; len(act) != 2 {
		t.Errorf("duplicate actions not removed: %v", act)
	}
	if regions := got.SCP.RegionAllowlist; len(regions) != 2 {
		t.Errorf("duplicate regions not removed: %v", regions)
	}
	if classes := got.Enforcement; len(classes) != 2 {
		t.Errorf("duplicate enforcement classes not removed: %v", classes)
	}
}

// mustControl returns a pointer to the control with the given id, failing the
// test if it is absent.
func mustControl(t *testing.T, a *Artifact, id string) *Control {
	t.Helper()
	for i := range a.Controls {
		if a.Controls[i].ID == id {
			return &a.Controls[i]
		}
	}
	t.Fatalf("control %q not found in artifact %q", id, a.Meta.ID)
	return nil
}

// mustRule returns a pointer to the named Config rule within a control, failing
// the test if it is absent. Addressing rules by identifier rather than index
// keeps tests correct across canonicalization, which sorts them.
func mustRule(t *testing.T, c *Control, identifier string) *ConfigRule {
	t.Helper()
	for i := range c.ConfigRules {
		if c.ConfigRules[i].Identifier == identifier {
			return &c.ConfigRules[i]
		}
	}
	t.Fatalf("config rule %q not found in control %q", identifier, c.ID)
	return nil
}

func TestCanonicalEnforcementOrder(t *testing.T) {
	// Fixed order, not alphabetical: preventive, then detective, then
	// procedural, then baseline-protection.
	a := &Artifact{Controls: Controls{{
		Enforcement: []EnforcementClass{
			EnforcementProcedural, EnforcementBaselineProtection, EnforcementConfigRule, EnforcementSCP,
		},
	}}}
	a.Canonicalize()
	want := []EnforcementClass{EnforcementSCP, EnforcementConfigRule, EnforcementProcedural, EnforcementBaselineProtection}
	got := a.Controls[0].Enforcement
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestCanonicalJSONSortsKeysAndDoesNotEscapeHTML(t *testing.T) {
	in := map[string]any{
		"z":   1,
		"a":   map[string]any{"nested": "a<b&c>d"},
		"m":   []any{3, 1, 2},
		"big": json.Number("123456789012345678901234567890"),
	}
	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := `{"a":{"nested":"a<b&c>d"},"big":123456789012345678901234567890,"m":[3,1,2],"z":1}`
	if string(got) != want {
		t.Errorf("canonicalJSON:\n got %s\nwant %s", got, want)
	}
}

func TestVerifyContentHashDetectsTampering(t *testing.T) {
	a := sampleArtifact()
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Widen an SCP action list without recompiling: exactly the edit an
	// attacker or a careless hand-edit would make.
	tampered := strings.Replace(string(data), `"s3:PutBucketAcl",`, ``, 1)
	if tampered == string(data) {
		t.Fatal("test setup: expected to modify the document")
	}
	_, err = Decode([]byte(tampered), LoadOptions{})
	if err == nil {
		t.Fatal("expected a content hash mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "content hash mismatch") {
		t.Errorf("error should name the mismatch, got: %v", err)
	}
	if !strings.Contains(err.Error(), "make catalogs") {
		t.Errorf("error should tell the operator how to fix it, got: %v", err)
	}
}

// TestRejectDuplicateKeysFindsTheSecondCopyAndNothingElse covers both halves of the
// check, and the second half is the one that has already been wrong once.
//
// A duplicate key is a second document hiding inside the first: encoding/json takes the
// LAST occurrence silently, so appending a copy of a hashed field changes what automat
// loaded while the original line stays visible and inert.
//
// The accept cases exist because the first draft of this scanner guessed key-vs-value by
// alternation and refused a valid artifact — `the key "scp" appears twice`, "scp" being
// an enforcement class, a value, appearing once per control in an array. A load-path
// check that rejects real documents does not fail safe; it fails closed on everything.
func TestRejectDuplicateKeysFindsTheSecondCopyAndNothingElse(t *testing.T) {
	refused := []struct {
		name  string
		json  string
		where string
	}{
		{
			name:  "at the top level",
			json:  `{"review_by":"2027-06-30","x":1,"review_by":"2099-12-31"}`,
			where: "the top-level object",
		},
		{
			name:  "inside a nested object",
			json:  `{"meta":{"issuer":"a","issuer":"b"}}`,
			where: "meta",
		},
		{
			name:  "inside an object in an array, named by position",
			json:  `{"controls":[{"id":"1"},{"id":"2","id":"3"}]}`,
			where: "controls[1]",
		},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectDuplicateKeys([]byte(tc.json))
			if err == nil {
				t.Fatalf("accepted a document with a duplicate key: %s", tc.json)
			}
			if !strings.Contains(err.Error(), tc.where) {
				t.Errorf("the refusal does not name %q, so an operator cannot find the offending "+
					"object:\n%v", tc.where, err)
			}
			if !strings.Contains(err.Error(), "last occurrence") {
				t.Errorf("the refusal does not say which copy won, which is the whole hazard:\n%v", err)
			}
		})
	}

	accepted := []struct {
		name string
		json string
	}{
		{
			// The regression: repeated string values in arrays, which is what
			// enforcement classes look like across a real catalog.
			name: "a repeated string value in an array",
			json: `{"a":["scp","config"],"b":["scp","config"],"c":["scp"]}`,
		},
		{
			name: "an odd number of strings in an array",
			json: `{"a":["x","y","z"],"b":"x"}`,
		},
		{
			name: "the same key in sibling objects",
			json: `{"one":{"id":"a"},"two":{"id":"b"}}`,
		},
		{
			name: "a key equal to a sibling's value",
			json: `{"kind":"kind"}`,
		},
		{
			name: "nested arrays of strings",
			json: `{"a":[["p","q"],["p","q"]]}`,
		},
		{
			name: "an array of arrays of objects",
			json: `{"a":[[{"k":1}],[{"k":2}]]}`,
		},
		{
			name: "scalars of every kind as values",
			json: `{"a":1,"b":true,"c":null,"d":"s","e":1.5}`,
		},
		{
			name: "a top-level array",
			json: `[{"k":1},{"k":2},"k","k"]`,
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if err := RejectDuplicateKeys([]byte(tc.json)); err != nil {
				t.Errorf("refused a valid document — this is the false-positive direction, which "+
					"breaks the load path for real files:\n%s\n%v", tc.json, err)
			}
		})
	}

	// Malformed input is the caller's to report: decodeError gives an offset and a type,
	// and a duplicate-key message about a file that does not parse would misdirect.
	t.Run("malformed JSON is left to the caller", func(t *testing.T) {
		for _, bad := range []string{`{`, `{"a":}`, `{"a":1,,}`, `not json`, ``} {
			if err := RejectDuplicateKeys([]byte(bad)); err != nil {
				t.Errorf("RejectDuplicateKeys reported on malformed input %q, pre-empting the "+
					"decoder's better message: %v", bad, err)
			}
		}
	})
}

// TestEveryShippedCatalogPassesTheDuplicateKeyScan is the false-positive guard against
// real documents rather than hand-written ones.
//
// The scanner runs on every load, so a bug in it takes the catalogs offline. The unit
// cases above are the shapes I thought of; this one is the shapes that actually ship.
func TestEveryShippedCatalogPassesTheDuplicateKeyScan(t *testing.T) {
	a := sampleArtifact()
	if err := a.SetContentHash(); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := a.MarshalIndented()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := RejectDuplicateKeys(data); err != nil {
		t.Errorf("refused an artifact automat itself just wrote: %v", err)
	}
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
