// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package compilesets

import (
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Tests for the allowlist reader.
//
// The requirement these discharge: the shape the packer chose for region and
// service restrictions must be CHECKABLE, not merely emittable, because `verify`
// has to compare what is attached against the environment profile and say which
// region or service moved. A shape that only renders leaves `verify` diffing whole
// documents.
//
// So the load-bearing test here is the round trip, and it is a property rather than
// a table: the claim is about everything the packer can emit, and the packer's
// output shape depends on the merge, the bin packing, and the statement splitter.

// TestPackedAllowlistsRoundTrip is E7 stated as a property.
//
// Pack a generated control set, hand the rendered documents back to ReadAllowlists,
// and require the recovered allowlists to be exactly the merged ones. Exactly, not
// approximately: a reader that recovered a superset would let `verify` pass an
// account whose attached policy permits a region the profile does not, and a reader
// that recovered a subset would report drift on a correct account, which is the
// finding that teaches an operator to ignore the tool.
func TestPackedAllowlistsRoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := drawRenderable(rt, "a")
		p, err := Pack(m, packOpts())
		if err != nil {
			// The refusals; nothing is attached, so there is nothing to read back.
			return
		}
		docs := make([]string, 0, len(p.Policies))
		for _, pol := range p.Policies {
			docs = append(docs, pol.Document)
		}

		got, rerr := ReadAllowlists(docs...)
		if rerr != nil {
			rt.Fatalf("the packer's own output does not read back: %v\n%s", rerr, describe("input", m))
		}

		exempt := m.RegionDenyExemptServices.Members

		if want := pickMembers(m.RegionAllowlist); !equalSets(got.Regions, want) {
			rt.Fatalf("the region allowlist did not survive the round trip: packed %v, read back %v.\n"+
				"`verify` compares the attached policy against the environment profile through this "+
				"reader, so a shape that does not round-trip cannot be verified", want, got.Regions)
		}

		switch {
		case m.ServiceAllowlist == nil:
			if got.Services != nil {
				rt.Fatalf("the reader found a service allowlist %v where the input constrained no "+
					"services; nil and empty are different findings and this conflates them", got.Services)
			}
		case m.RegionAllowlist == nil:
			// The inseparable case: nothing in the document carries the exemption
			// list on its own, so the recovered set is the union and the flag must
			// say so. The union is what the round trip can assert here.
			if !got.ServicesIncludeExemptions {
				rt.Fatal("a service restriction with no region restriction read back as separable; " +
					"there is nothing in the document carrying the exemption list alone")
			}
			want := append(append([]string(nil), m.ServiceAllowlist.Members...), exempt...)
			if !equalSets(got.Services, want) {
				rt.Fatalf("the service statement's spared set did not survive the round trip: "+
					"packed %v, read back %v", want, got.Services)
			}
		default:
			if got.ServicesIncludeExemptions {
				rt.Fatalf("the service allowlist could not be separated from the exemption list even "+
					"though a region allowlist is present (%v)", pickMembers(m.RegionAllowlist))
			}
			if want := m.ServiceAllowlist.Members; !equalSets(got.Services, want) {
				rt.Fatalf("the service allowlist did not survive the round trip: packed %v, read back %v",
					want, got.Services)
			}
		}

		// The exemption list is recoverable exactly when a region statement carries
		// it alone. That is a real limit of the shape rather than of the reader, and
		// stating it as an assertion is what keeps it from being discovered by
		// `verify` reporting nothing.
		if m.RegionAllowlist == nil {
			if got.ExemptServices != nil {
				rt.Fatalf("the reader recovered an exemption list %v from a document with no region "+
					"statement; there is nothing in it that carries the list alone", got.ExemptServices)
			}
			return
		}
		if !equalSets(got.ExemptServices, exempt) {
			rt.Fatalf("the global-service exemption list did not survive the round trip: packed %v, "+
				"read back %v. It is the list whose entries are holes in the Deny, so `verify` not "+
				"being able to read it is `verify` not being able to check the widest thing in the policy",
				exempt, got.ExemptServices)
		}
	})
}

// TestTheReaderAgreesWithTheBehavioralModel.
//
// The round trip proves the reader recovers the SETS. This proves the sets mean what
// the policy does, by checking the reader's two predicates against Denies over the
// same rendered statements.
//
// Worth having separately because the round trip would pass on a reader that
// recovered both lists perfectly and a PermitsRegion that had the membership test
// inverted — and PermitsRegion is what `verify` will actually call.
func TestTheReaderAgreesWithTheBehavioralModel(t *testing.T) {
	m := withGlobalExemptions(&Merged{
		RegionAllowlist:  newAllowSet([]string{"us-east-1", "us-west-2"}, "set:regions"),
		ServiceAllowlist: newAllowSet([]string{"s3", "batch"}, "set:services"),
	})
	packed := mustPack(t, m, packOpts())
	sts := packedStatements(packed)

	docs := []string{packed.Policies[0].Document}
	got, err := ReadAllowlists(docs...)
	if err != nil {
		t.Fatalf("ReadAllowlists: %v", err)
	}

	// A region-scoped service, so the region axis is the only thing varying.
	for _, region := range []string{"us-east-1", "us-west-2", "eu-west-1", "ap-south-1"} {
		denied := Denies(sts, Request{
			Principal: breakGlass, Action: "s3:GetObject", Resource: "*", Region: region,
		})
		if got.PermitsRegion(region) == denied {
			t.Errorf("PermitsRegion(%q) = %v but the policy %s an allowlisted service there; the reader "+
				"and the policy disagree, so `verify` would report the opposite of the truth",
				region, got.PermitsRegion(region), deniedWord(denied))
		}
	}

	// And the service axis, inside an allowlisted region so the region statement
	// does not decide the outcome.
	for _, tc := range []struct{ ns, action string }{
		{"s3", "s3:GetObject"},
		{"batch", "batch:SubmitJob"},
		{"sagemaker", "sagemaker:CreateDomain"},
		{"iam", "iam:CreateRole"},
		{"organizations", "organizations:ListAccounts"},
	} {
		denied := Denies(sts, Request{
			Principal: breakGlass, Action: tc.action, Resource: "*", Region: "us-east-1",
		})
		if got.PermitsService(tc.ns) == denied {
			t.Errorf("PermitsService(%q) = %v but the policy %s %s in an allowlisted region",
				tc.ns, got.PermitsService(tc.ns), deniedWord(denied), tc.action)
		}
	}
}

func deniedWord(denied bool) string {
	if denied {
		return "denies"
	}
	return "permits"
}

// TestTheReaderIntersectsAcrossAttachedPolicies.
//
// Two SCPs at one target each restricting regions permit only what both permit,
// because each denies everything outside its own list. A reader that took the last
// document's answer, or unioned them, would report an account as compliant with a
// profile the attached pair does not actually allow work under.
//
// This is also the multi-document pack: automat splits one control set across
// documents when it does not fit, and the split can put the region statement in a
// different document from the service one.
func TestTheReaderIntersectsAcrossAttachedPolicies(t *testing.T) {
	a := mustPack(t, withGlobalExemptions(&Merged{
		RegionAllowlist: newAllowSet([]string{"us-east-1", "us-west-2"}, "set:a"),
	}), packOpts())
	b := mustPack(t, withGlobalExemptions(&Merged{
		RegionAllowlist: newAllowSet([]string{"us-west-2", "eu-west-1"}, "set:b"),
	}), packOpts())

	got, err := ReadAllowlists(a.Policies[0].Document, b.Policies[0].Document)
	if err != nil {
		t.Fatalf("ReadAllowlists: %v", err)
	}
	if !equalSets(got.Regions, []string{"us-west-2"}) {
		t.Errorf("two attached region restrictions read back as %v, want [us-west-2]: each denies every "+
			"region outside its own list, so together they permit only the overlap", got.Regions)
	}
	if got.PermitsRegion("us-east-1") {
		t.Error("the reader reports us-east-1 permitted, but the second attached policy denies every " +
			"region outside [us-west-2, eu-west-1]")
	}
}

// TestTheReaderReportsARestrictionThatPermitsNothing.
//
// The packer refuses to create this, but `verify` runs against an organization
// automat does not exclusively control: a hand-edited SCP, or two attached policies
// with disjoint region lists, produces an account where nothing can run. It must
// read back as an empty non-nil allowlist — a distinguishable finding — rather than
// as nil, which means unrestricted and would be reported as healthy.
func TestTheReaderReportsARestrictionThatPermitsNothing(t *testing.T) {
	a := mustPack(t, withGlobalExemptions(&Merged{
		RegionAllowlist: newAllowSet([]string{"us-east-1"}, "set:a"),
	}), packOpts())
	b := mustPack(t, withGlobalExemptions(&Merged{
		RegionAllowlist: newAllowSet([]string{"eu-west-1"}, "set:b"),
	}), packOpts())

	got, err := ReadAllowlists(a.Policies[0].Document, b.Policies[0].Document)
	if err != nil {
		t.Fatalf("ReadAllowlists: %v", err)
	}
	if got.Regions == nil {
		t.Fatal("two attached policies with disjoint region lists read back as an unrestricted account; " +
			"nil means nobody restricted regions, and reporting this state as nil hides an account " +
			"where no region-scoped call can succeed")
	}
	if len(got.Regions) != 0 {
		t.Errorf("disjoint region restrictions read back as %v, want an empty (non-nil) list", got.Regions)
	}
	if got.PermitsRegion("us-east-1") || got.PermitsRegion("eu-west-1") {
		t.Error("the reader reports a permitted region for an intersection that is empty")
	}
}

// TestTheReaderIgnoresPoliciesItDoesNotUnderstand.
//
// An institutional SCP attached alongside automat's is the normal case (DESIGN §3
// reserves a slot for exactly that), and ordinary Denies are checked against the
// compiled statements elsewhere. So a document carrying no NotAction Deny must
// contribute nothing rather than being read as a restriction of some kind.
func TestTheReaderIgnoresPoliciesItDoesNotUnderstand(t *testing.T) {
	institutional := `{"Version":"2012-10-17","Statement":[
		{"Sid":"NoRootKeys","Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"},
		{"Sid":"Allow","Effect":"Allow","Action":"*","Resource":"*"}]}`

	got, err := ReadAllowlists(institutional)
	if err != nil {
		t.Fatalf("ReadAllowlists: %v", err)
	}
	if got.Regions != nil || got.Services != nil || got.ExemptServices != nil {
		t.Errorf("a policy with no allowlist read back as one (regions=%v services=%v exempt=%v)",
			got.Regions, got.Services, got.ExemptServices)
	}

	// And alongside a real one, it must not narrow the answer: an intersection
	// seeded by a document that restricts nothing would collapse to empty.
	packed := mustPack(t, withGlobalExemptions(&Merged{
		RegionAllowlist: newAllowSet([]string{"us-west-2"}, "set:a"),
	}), packOpts())
	got, err = ReadAllowlists(institutional, packed.Policies[0].Document)
	if err != nil {
		t.Fatalf("ReadAllowlists: %v", err)
	}
	if !equalSets(got.Regions, []string{"us-west-2"}) {
		t.Errorf("an institutional policy attached alongside automat's changed the recovered region "+
			"allowlist to %v", got.Regions)
	}
}

// TestTheReaderAcceptsTheScalarFormIAMAllows.
//
// automat emits arrays; AWS accepts a bare string for a single-element Action,
// NotAction, Resource, or condition value, and the console writes that form. A
// reader that failed to parse it would report a finding about automat rather than
// about the account.
func TestTheReaderAcceptsTheScalarFormIAMAllows(t *testing.T) {
	scalar := `{"Version":"2012-10-17","Statement":[{
		"Sid":"AutomatDenyRegionsOutsideAllowlist","Effect":"Deny",
		"NotAction":"iam:*","Resource":"*",
		"Condition":{"StringNotEquals":{"aws:RequestedRegion":"us-west-2"}}}]}`

	got, err := ReadAllowlists(scalar)
	if err != nil {
		t.Fatalf("the scalar form AWS accepts did not parse: %v", err)
	}
	if !equalSets(got.Regions, []string{"us-west-2"}) {
		t.Errorf("regions read back as %v, want [us-west-2]", got.Regions)
	}
	if !equalSets(got.ExemptServices, []string{"iam"}) {
		t.Errorf("exempt services read back as %v, want [iam]", got.ExemptServices)
	}
}

// TestAServiceRestrictionWithoutARegionOneSaysSo.
//
// The one case the reader cannot separate: with no region statement there is
// nothing carrying the exemption list alone, so the service statement's NotAction
// is the union and the flag has to be set. Reporting the union as "the service
// allowlist" would show an operator namespaces nobody put in a profile.
func TestAServiceRestrictionWithoutARegionOneSaysSo(t *testing.T) {
	packed := mustPack(t, withGlobalExemptions(&Merged{
		ServiceAllowlist: newAllowSet([]string{"s3", "batch"}, "set:services"),
	}), packOpts())

	got, err := ReadAllowlists(packed.Policies[0].Document)
	if err != nil {
		t.Fatalf("ReadAllowlists: %v", err)
	}
	if !got.ServicesIncludeExemptions {
		t.Error("a service restriction with no region restriction read back as a separable service " +
			"allowlist; there is no region statement to supply the exemption list, so Services is the " +
			"union and a caller told otherwise would diff it against a profile and report every " +
			"globally addressed namespace as drift")
	}
	// The union is still usable for the question `verify` asks.
	for _, ns := range []string{"s3", "batch", "iam", "sts"} {
		if !got.PermitsService(ns) {
			t.Errorf("PermitsService(%q) = false, but the attached policy spares it", ns)
		}
	}
	if got.PermitsService("sagemaker") {
		t.Error("PermitsService reports a namespace the attached policy denies")
	}
}

// TestAnUnreadablePolicyIsAnErrorWithRemediation.
//
// Not a silent skip: a document automat cannot parse is a document whose effect on
// the account is unknown, and reporting the account as verified against the rest
// would be a false clean bill. Rule 7 makes the remediation part of that.
func TestAnUnreadablePolicyIsAnErrorWithRemediation(t *testing.T) {
	_, err := ReadAllowlists(`{"Version":"2012-10-17","Statement":`)
	if err == nil {
		t.Fatal("a truncated policy document parsed successfully")
	}
	var pe *PackError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a *PackError with remediation text, got %T", err)
	}
	if pe.Remediation == "" {
		t.Error("the error has no remediation text (CLAUDE.md rule 7)")
	}
	if !strings.Contains(pe.Reason, "1") {
		t.Errorf("the error does not say which of the attached documents failed to parse: %v", pe.Reason)
	}
}

func equalSets(a, b []string) bool {
	as, bs := sortedUnique(a), sortedUnique(b)
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
