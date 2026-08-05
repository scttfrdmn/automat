// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"strings"
	"testing"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

// -----------------------------------------------------------------------------
// Ownership. The security half of this package.
// -----------------------------------------------------------------------------

// TestEnsurePolicyRefusesToAdoptAnUntaggedPolicy is AUDIT-1's C1 applied to
// automat itself.
//
// A policy with the right name but without automat's owner tag is central IT's,
// and the delegation policy gates every SCP modification on that exact resource
// tag (internal/bundle's scpModifyActions). So "tag it and then rewrite it" is
// precisely the escalation the resource-tag reading exists to prevent — performed
// by automat, on its own behalf, against the institution's own floor. Nothing in
// AWS stops it in the MANAGEMENT state, which is why the refusal has to be here.
//
// The assertion is on the recorder as well as the error: an implementation that
// errored *after* calling TagResource would pass an error-text check and still
// have claimed the policy.
func TestEnsurePolicyRefusesToAdoptAnUntaggedPolicy(t *testing.T) {
	f := newFixture(t)
	// Central IT's policy, under the name automat's artifact would produce. No
	// owner tag, because automat did not create it.
	central := f.State.SeedPolicy("automat-cui-1", scpDocOther, nil)

	_, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-cui-1", Document: scpDoc})
	mustErr(t, err,
		"does not carry automat:managed-by=automat",
		"will not modify it",
		"rename the existing policy")

	if f.Policy.CallCount("TagResource") != 0 {
		t.Error("automat tagged a policy it did not create, which is how it would claim ownership")
	}
	if f.Policy.CallCount("UpdatePolicy") != 0 {
		t.Error("automat rewrote a policy it does not own")
	}
	if got := f.State.PolicyContent(central); got != scpDocOther {
		t.Errorf("the untagged policy's content changed to %q", got)
	}
}

// TestEnsurePolicyRefusesToAdoptAnUntaggedPolicyThatAppearsInTheWindow is the same
// refusal on the tolerate path. A policy that appeared under this name in the last
// moment is no more automat's than one that was there all along, and the duplicate
// path is exactly where an implementation would be tempted to skip the check
// because it "just" lost a race.
func TestEnsurePolicyRefusesToAdoptAnUntaggedPolicyThatAppearsInTheWindow(t *testing.T) {
	f := newFixture(t)
	f.State.Before = map[string]func() error{
		"CreatePolicy": func() error {
			f.State.SeedPolicy("automat-cui-1", scpDocOther, nil)
			return nil
		},
	}
	_, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-cui-1", Document: scpDoc})
	mustErr(t, err, "appeared between automat's read and its create", "will not modify or adopt it")
	if f.Policy.CallCount("TagResource") != 0 {
		t.Error("automat tagged a policy that appeared in the TOCTOU window")
	}
}

// TestEnsurePolicyAdoptsItsOwnPolicyFromTheWindow: the same race, but the policy
// that appeared carries automat's tag — a concurrent vend of the same artifact.
// Both runs want the same policy, so this is adopted rather than failed.
func TestEnsurePolicyAdoptsItsOwnPolicyFromTheWindow(t *testing.T) {
	f := newFixture(t)
	var raced string
	f.State.Before = map[string]func() error{
		"CreatePolicy": func() error {
			if raced == "" {
				raced = f.seedOwnedPolicy("automat-cui-1", scpDoc)
			}
			return nil
		},
	}
	id, act, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-cui-1", Document: scpDoc})
	if err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	if id != raced {
		t.Errorf("returned %q, want the policy from the window %q", id, raced)
	}
	if act.Verb != VerbUnchanged || act.Applied {
		t.Errorf("action = %s, want an unapplied unchanged", act)
	}
}

// TestUnreadableTagsAreNotTreatedAsNotOwned. A missing ListTagsForResource grant
// must not be reported as "somebody else owns this policy": that is a confident
// false statement about the organization, and it would send the operator to rename
// a policy that is theirs.
func TestUnreadableTagsAreNotTreatedAsNotOwned(t *testing.T) {
	f := newFixture(t)
	f.seedOwnedPolicy("automat-cui-1", scpDoc)
	f.State.Errs["ListTagsForResource"] = awsfake.AccessDenied("organizations:ListTagsForResource")

	_, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-cui-1", Document: scpDoc})
	mustErr(t, err, "organizations:ListTagsForResource")
	if strings.Contains(err.Error(), "does not carry") {
		t.Error("an unreadable tag list was reported as somebody else's ownership")
	}
}

// -----------------------------------------------------------------------------
// Content.
// -----------------------------------------------------------------------------

// TestEnsurePolicyCreatesWithTheOwnerTagAtCreation. The owner tag can only be
// applied at creation, through the request tag: the delegation policy gates every
// later tag write on the tag already being present, so a policy created without it
// could never acquire it.
func TestEnsurePolicyCreatesWithTheOwnerTagAtCreation(t *testing.T) {
	f := newFixture(t)
	id, act, err := f.E.EnsurePolicy(ctx(), PolicySpec{
		Name: "automat-cui-1", Document: scpDoc,
		Tags: map[string]string{"automat:artifact-id": "cmmc-l1"},
	})
	if err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	if act.Verb != VerbCreate || !act.Applied {
		t.Errorf("action = %s, want an applied create", act)
	}
	tags := f.State.TagsOf(id)
	if tags[OwnerTagKey] != OwnerTagValue {
		t.Errorf("the created policy does not carry %s=%s: %v", OwnerTagKey, OwnerTagValue, tags)
	}
	if tags["automat:artifact-id"] != "cmmc-l1" {
		t.Errorf("the spec's tags were not applied: %v", tags)
	}
	// One call, not create-then-tag: a separate TagResource would be refused by the
	// delegation policy, since the policy does not yet carry the tag being read.
	if f.Policy.CallCount("TagResource") != 0 {
		t.Error("the owner tag was applied by a separate TagResource, which the delegation policy refuses")
	}
}

// TestEnsurePolicyUpdatesWhenContentDiffers, and does NOT update when the service
// merely reformatted the document. The second case is the one that decides whether
// this package is idempotent: nothing documents that Organizations returns a
// document byte-for-byte as submitted, so a byte comparison would call
// UpdatePolicy on every run and fail run-twice while looking correct.
func TestEnsurePolicyUpdatesWhenContentDiffers(t *testing.T) {
	tests := []struct {
		name       string
		attached   string
		want       string
		wantUpdate bool
	}{
		{"identical", scpDoc, scpDoc, false},
		{"reformatted by the service", scpDocReformatted, scpDoc, false},
		{"genuinely different", scpDocOther, scpDoc, true},
		{"unparseable in the organization", "not a policy at all", scpDoc, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			id := f.seedOwnedPolicy("automat-cui-1", tt.attached)

			_, act, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-cui-1", Document: tt.want})
			if err != nil {
				t.Fatalf("EnsurePolicy: %v", err)
			}
			gotUpdate := f.Policy.CallCount("UpdatePolicy") > 0
			if gotUpdate != tt.wantUpdate {
				t.Errorf("UpdatePolicy called = %v, want %v (action was %s)", gotUpdate, tt.wantUpdate, act)
			}
			if tt.wantUpdate {
				if act.Verb != VerbUpdate || !act.Applied {
					t.Errorf("action = %s, want an applied update", act)
				}
				if got := f.State.PolicyContent(id); got != tt.want {
					t.Errorf("content = %q, want %q", got, tt.want)
				}
			} else if act.Verb != VerbUnchanged || act.Applied {
				t.Errorf("action = %s, want an unapplied unchanged", act)
			}
		})
	}
}

// TestEnsurePolicyDoesNotRename. The policy was found BY name, so resending it is
// a no-op at best; a rename would produce a policy no later run can find, and
// every run would then create another one.
func TestEnsurePolicyDoesNotRename(t *testing.T) {
	f := newFixture(t)
	id := f.seedOwnedPolicy("automat-cui-1", scpDocOther)

	if _, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{
		Name: "automat-cui-1", Document: scpDoc,
	}); err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	if got := f.State.PolicyIDByName("automat-cui-1"); got != id {
		t.Errorf("the policy is no longer findable by its name: %q", got)
	}
}

// TestEnsurePolicyMalformedDocumentIsParkableAndSaysSo. This arrives at
// CreatePolicy or UpdatePolicy in vend step 4, AFTER the account exists and has
// been moved. The natural response to a failed vend is to run `vend` again, which
// creates a second account — so the message has to say --resume, and Parkable has
// to agree.
func TestEnsurePolicyMalformedDocumentIsParkableAndSaysSo(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "on create"
		if existing {
			name = "on update"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			op := "CreatePolicy"
			if existing {
				f.seedOwnedPolicy("automat-cui-1", scpDocOther)
				op = "UpdatePolicy"
			}
			f.State.Errs[op] = &awsfake.APIError{
				Code:    "MalformedPolicyDocumentException",
				Message: "Syntax errors in policy.",
			}

			_, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{Name: "automat-cui-1", Document: scpDoc})
			mustErr(t, err,
				"malformed",
				"duplicate Sid",
				"--resume",
				"would create a second one")
			if !Parkable(err) {
				t.Error("a malformed document mid-vend is not parkable, but the account already exists")
			}
		})
	}
}

// TestEnsurePolicyValidation.
func TestEnsurePolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		spec   PolicySpec
		wantIn string
	}{
		{"no name", PolicySpec{Document: scpDoc}, "only handle"},
		{"name too long", PolicySpec{Name: strings.Repeat("a", 129), Document: scpDoc}, "128"},
		{"empty document", PolicySpec{Name: "automat-x-1"}, "empty document"},
		{
			// A packer bug, not a catalog one, and the message says so — otherwise
			// an operator edits a policy by hand and automat overwrites it.
			"unparseable document", PolicySpec{Name: "automat-x-1", Document: "not json"},
			"bug in automat's packer",
		},
		{
			"tag outside the namespace",
			PolicySpec{Name: "automat-x-1", Document: scpDoc, Tags: map[string]string{"Cost": "1"}},
			"aws:TagKeys",
		},
		{
			// The owner tag with the wrong value would make every downstream
			// condition read false while looking present.
			"owner tag with the wrong value",
			PolicySpec{Name: "automat-x-1", Document: scpDoc,
				Tags: map[string]string{OwnerTagKey: "someone-else"}},
			"must be \"automat\"",
		},
		{
			"owner tag restated correctly is fine",
			PolicySpec{Name: "automat-x-1", Document: scpDoc,
				Tags: map[string]string{OwnerTagKey: OwnerTagValue}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.validate()
			if tt.wantIn == "" {
				if err != nil {
					t.Errorf("validate = %v, want nil", err)
				}
				return
			}
			mustErr(t, err, tt.wantIn)
		})
	}
}

// -----------------------------------------------------------------------------
// Attachment.
// -----------------------------------------------------------------------------

// TestEnsurePolicyAttachmentToleratesADuplicate is Q12 on the attachment: read
// ListPoliciesForTarget first, and also treat DuplicatePolicyAttachment as
// success.
func TestEnsurePolicyAttachmentToleratesADuplicate(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	pid := f.seedOwnedPolicy("automat-cui-1", scpDoc)

	// The read half.
	f.State.SeedAttachment(pid, ou)
	act, err := f.E.EnsurePolicyAttachment(ctx(), pid, "automat-cui-1", ou)
	if err != nil {
		t.Fatalf("EnsurePolicyAttachment: %v", err)
	}
	if act.Verb != VerbUnchanged || f.Policy.CallCount("AttachPolicy") != 0 {
		t.Errorf("re-attached an attached policy: %s", act)
	}

	// The tolerate half: the attachment appears in the window.
	f2 := newFixture(t)
	ou2 := f2.State.SeedOU("Regulated", testRoot)
	pid2 := f2.seedOwnedPolicy("automat-cui-1", scpDoc)
	f2.State.Before = map[string]func() error{
		"AttachPolicy": func() error {
			f2.State.SeedAttachment(pid2, ou2)
			return nil
		},
	}
	act, err = f2.E.EnsurePolicyAttachment(ctx(), pid2, "automat-cui-1", ou2)
	if err != nil {
		t.Fatalf("EnsurePolicyAttachment lost the race: %v", err)
	}
	if act.Verb != VerbUnchanged {
		t.Errorf("verb = %s, want unchanged", act.Verb)
	}
	if !strings.Contains(act.Detail, "between") {
		t.Errorf("the action does not say the attachment appeared in the window: %s", act.Detail)
	}
}

// TestAttachedPoliciesPaginates. Reading only the first page would conclude a
// policy is not attached, call AttachPolicy, and get DuplicatePolicyAttachment —
// which this package tolerates, so the bug would be invisible except as a target
// one slot closer to the five-policy limit than the plan said.
func TestAttachedPoliciesPaginates(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	f.State.PoliciesPerTarget = 0 // unlimited, so the fixture can exceed a page
	var last string
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		last = f.seedOwnedPolicy("automat-"+n, scpDoc)
		f.State.SeedAttachment(last, ou)
	}

	act, err := f.E.EnsurePolicyAttachment(ctx(), last, "automat-e", ou)
	if err != nil {
		t.Fatalf("EnsurePolicyAttachment: %v", err)
	}
	if act.Verb != VerbUnchanged {
		t.Errorf("verb = %s: the attachment past the first page was not seen", act.Verb)
	}
	if f.Policy.CallCount("ListPoliciesForTarget") < 2 {
		t.Error("only one page was read; the pagination is not being exercised")
	}
}

// TestAttachmentQuotaNamesTheOccupantsAndWhoOwnsThem is the five-per-target limit.
//
// AWS's own message says the limit was exceeded and never says by what, and the
// operator's options — attach at a parent OU, or compile fewer sets — depend
// entirely on which slots are taken and by whom. Naming which are automat's is the
// load-bearing part: a policy that is not automat's is the institution's floor,
// and it is the one thing nobody should be advised to detach.
func TestAttachmentQuotaNamesTheOccupantsAndWhoOwnsThem(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	// Five slots taken: central IT's floor plus four of automat's.
	f.State.SeedAttachment(f.State.SeedPolicy("institutional-floor", scpDocOther, nil), ou)
	for _, n := range []string{"a", "b", "c", "d"} {
		f.State.SeedAttachment(f.seedOwnedPolicy("automat-"+n, scpDoc), ou)
	}
	overflow := f.seedOwnedPolicy("automat-overflow", scpDoc)

	_, err := f.E.EnsurePolicyAttachment(ctx(), overflow, "automat-overflow", ou)
	mustErr(t, err,
		"maximum number of service control policies",
		"institutional-floor (not automat's)",
		"automat-a (automat's)",
		"attached at a PARENT OU are inherited",
		"Do not detach a policy automat did not create",
		"--resume")
	if !Parkable(err) {
		t.Error("the attachment quota is not parkable, but the account already exists by then")
	}
}

// TestAttachmentWithoutTheSCPTypeEnabledIsRefusedLoudly.
//
// The dangerous shape of this failure is the opposite one: an organization in ALL
// features mode with the SCP policy type disabled, where CreatePolicy and
// AttachPolicy both SUCCEED and nothing is enforced. Here AWS refuses, which is
// the good case — and the message has to explain that until the type is on, no
// preventive control in any catalog does anything.
func TestAttachmentWithoutTheSCPTypeEnabledIsRefusedLoudly(t *testing.T) {
	f := newFixture(t)
	f.State.SCPEnabled = false
	ou := f.State.SeedOU("Regulated", testRoot)
	pid := f.seedOwnedPolicy("automat-cui-1", scpDoc)

	_, err := f.E.EnsurePolicyAttachment(ctx(), pid, "automat-cui-1", ou)
	mustErr(t, err,
		"not enabled on this organization's root",
		"no preventive control in any catalog does anything",
		"automat init",
		"--resume")
	if !Parkable(err) {
		t.Error("PolicyTypeNotEnabled is not parkable, but it stops a vend after the account exists")
	}
}

// TestEnsurePolicyAttachmentRefusesAnEmptyPolicyID: in a plan the policy does not
// exist yet, and the caller must report the attachment as unknown rather than
// attach to "".
func TestEnsurePolicyAttachmentRefusesAnEmptyPolicyID(t *testing.T) {
	f := newFixture(t)
	_, err := f.E.EnsurePolicyAttachment(ctx(), "", "automat-cui-1", "ou-exam-1")
	mustErr(t, err, "no policy id was given", "report the attachment as unknown")

	_, err = f.E.EnsurePolicyAttachment(ctx(), "p-auto0001", "automat-cui-1", "")
	mustErr(t, err, "no target was given")
}

// -----------------------------------------------------------------------------
// The set.
// -----------------------------------------------------------------------------

// TestEnsurePolicySetDoesContentBeforeAttachments.
//
// The five-per-target quota is checked at attach, so interleaving would leave a
// set half attached when the sixth policy is refused — a target carrying two of
// four control policies is a state with no name, whereas a target carrying none is
// simply not yet done.
func TestEnsurePolicySetDoesContentBeforeAttachments(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	specs := []PolicySpec{
		{Name: "automat-cui-1", Document: scpDoc},
		{Name: "automat-cui-region", Document: scpDocOther},
		{Name: "automat-baseline-protection", Document: scpDoc},
	}
	res, err := f.E.EnsurePolicySet(ctx(), ou, specs)
	if err != nil {
		t.Fatalf("EnsurePolicySet: %v", err)
	}
	if len(res.IDs) != 3 {
		t.Fatalf("got %d ids, want 3", len(res.IDs))
	}
	// Every CreatePolicy must precede every AttachPolicy in the call log.
	var lastCreate, firstAttach = -1, -1
	for i, c := range f.Policy.Calls() {
		switch c {
		case "CreatePolicy":
			lastCreate = i
		case "AttachPolicy":
			if firstAttach == -1 {
				firstAttach = i
			}
		}
	}
	if firstAttach == -1 || lastCreate == -1 {
		t.Fatalf("expected both creates and attaches: %v", f.Policy.Calls())
	}
	if lastCreate > firstAttach {
		t.Errorf("an attach was interleaved with the creates: %v", f.Policy.Calls())
	}
}

// TestEnsurePolicySetEmptyIsNormal. A control set with no preventive statements
// packs to zero policies — cmmc-l1 is exactly that, permanently and by design —
// and the vend proceeds, because a catalog whose controls are all detective still
// has a recorder, a conformance pack, and a manifest to produce.
func TestEnsurePolicySetEmptyIsNormal(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	res, err := f.E.EnsurePolicySet(ctx(), ou, nil)
	if err != nil {
		t.Fatalf("an empty control set was an error: %v", err)
	}
	if len(res.IDs) != 0 || len(res.Actions) != 0 {
		t.Errorf("an empty set produced %d ids and %d actions", len(res.IDs), len(res.Actions))
	}
	if len(f.writeCalls()) != 0 {
		t.Errorf("an empty set issued writes: %v", f.writeCalls())
	}
}

// TestEnsurePolicySetRefusesDuplicateNames. Two specs with one name would find
// each other's policy, decide the content differs, and overwrite it — so each vend
// overwrites one document with the other and both runs report a change forever.
// The run-twice criterion would fail with no failing call anywhere.
func TestEnsurePolicySetRefusesDuplicateNames(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	_, err := f.E.EnsurePolicySet(ctx(), ou, []PolicySpec{
		{Name: "automat-cui-1", Document: scpDoc},
		{Name: "automat-cui-1", Document: scpDocOther},
	})
	mustErr(t, err, "entries 0 and 1 are both named", "overwrite each other's content on every run")
	if len(f.writeCalls()) != 0 {
		t.Errorf("the duplicate check ran after writes: %v", f.writeCalls())
	}
}

// TestEnsurePolicySetReportsOrphansAndCannotRemoveThem.
//
// A narrowed artifact leaves the previous vend's policies attached, because no
// write interface in awsapi has DetachPolicy. That is the safe direction — the
// leftover is a Deny, so keeping it is stricter than asked — and the alternative is
// worse: a vend against a mistyped artifact id would silently widen an OU that was
// compliant this morning. Reporting is what lets a human with DetachPolicy decide.
func TestEnsurePolicySetReportsOrphansAndCannotRemoveThem(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	// Last vend's policy, automat's, no longer in the set.
	stale := f.seedOwnedPolicy("automat-old-1", scpDocOther)
	f.State.SeedAttachment(stale, ou)
	// Central IT's floor, which must NOT be reported as automat's leftover.
	floor := f.State.SeedPolicy("institutional-floor", scpDoc, nil)
	f.State.SeedAttachment(floor, ou)
	// And a policy whose name merely looks like automat's.
	lookalike := f.State.SeedPolicy("automat-lookalike", scpDoc, nil)
	f.State.SeedAttachment(lookalike, ou)

	res, err := f.E.EnsurePolicySet(ctx(), ou, []PolicySpec{{Name: "automat-cui-1", Document: scpDoc}})
	if err != nil {
		t.Fatalf("EnsurePolicySet: %v", err)
	}
	if len(res.Orphans) != 1 || !strings.Contains(res.Orphans[0], "automat-old-1") {
		t.Errorf("orphans = %v, want exactly automat-old-1", res.Orphans)
	}
	for _, o := range res.Orphans {
		if strings.Contains(o, "institutional-floor") {
			t.Error("central IT's policy was reported as automat's leftover")
		}
		if strings.Contains(o, "lookalike") {
			t.Error("an untagged policy with an automat-shaped name was reported as automat's")
		}
	}
	// And nothing was detached, because nothing can be.
	if got := f.State.AttachedTo(ou); len(got) != 4 {
		t.Errorf("attachments changed: %v", got)
	}
}

// TestEnsurePolicySetPlanReportsUnknownAttachments. A policy that does not exist
// yet cannot be looked up on the target, and silently omitting the attachment
// would make a plan for a first vend look like it attaches nothing.
func TestEnsurePolicySetPlanReportsUnknownAttachments(t *testing.T) {
	f := newFixture(t)
	f.E.Mode = ModePlan
	ou := f.State.SeedOU("Regulated", testRoot)

	res, err := f.E.EnsurePolicySet(ctx(), ou, []PolicySpec{{Name: "automat-cui-1", Document: scpDoc}})
	if err != nil {
		t.Fatalf("EnsurePolicySet: %v", err)
	}
	var sawUnknownAttachment bool
	for _, a := range res.Actions {
		if a.Kind == "policy attachment" && a.Verb == VerbUnknown {
			sawUnknownAttachment = true
			if !strings.Contains(a.Detail, "does not exist yet") {
				t.Errorf("the unknown attachment does not explain itself: %s", a.Detail)
			}
		}
	}
	if !sawUnknownAttachment {
		t.Errorf("a plan for a first vend reported no attachment at all: %v", res.Actions)
	}
}

// TestEnsurePolicySetTagsAreEnsuredWithoutRemovingOthers. The cost-allocation keys
// of DESIGN §14 are the operator's to set, and an ensure that removed unrecognized
// tags would delete an institution's chargeback labels on every vend.
func TestEnsurePolicySetTagsAreEnsuredWithoutRemovingOthers(t *testing.T) {
	f := newFixture(t)
	id := f.seedOwnedPolicy("automat-cui-1", scpDoc)
	f.State.SeedTags(id, map[string]string{"automat:cost-center": "chem-1234"})

	if _, _, err := f.E.EnsurePolicy(ctx(), PolicySpec{
		Name: "automat-cui-1", Document: scpDoc,
		Tags: map[string]string{"automat:artifact-sha256": "abc123"},
	}); err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	tags := f.State.TagsOf(id)
	if tags["automat:cost-center"] != "chem-1234" {
		t.Errorf("an operator's tag was removed: %v", tags)
	}
	if tags["automat:artifact-sha256"] != "abc123" {
		t.Errorf("the spec's tag was not written: %v", tags)
	}
}

// -----------------------------------------------------------------------------
// init.
// -----------------------------------------------------------------------------

// TestEnsureSCPEnabledToleratesAlreadyEnabled. AWS's usual shape for an idempotent
// call it does not implement idempotently.
func TestEnsureSCPEnabledToleratesAlreadyEnabled(t *testing.T) {
	f := newFixture(t)
	f.State.SCPEnabled = false

	act, err := f.E.EnsureSCPEnabled(ctx(), testRoot)
	if err != nil {
		t.Fatalf("EnsureSCPEnabled: %v", err)
	}
	if act.Verb != VerbEnable || !act.Applied {
		t.Errorf("action = %s, want an applied enable", act)
	}
	if !strings.Contains(act.Detail, "enforces nothing") {
		t.Errorf("the action does not say why this matters: %s", act.Detail)
	}

	f.resetCalls()
	act, err = f.E.EnsureSCPEnabled(ctx(), testRoot)
	if err != nil {
		t.Fatalf("second EnsureSCPEnabled: %v", err)
	}
	if act.Verb != VerbUnchanged || act.Applied {
		t.Errorf("action = %s, want an unapplied unchanged", act)
	}
}

// TestEnsureSCPEnabledRequiresTheInitClient. Only `automat init` enables a policy
// type, and it is the only command that should hold that capability — so an
// Ensurer without the init client says so rather than nil-panicking.
func TestEnsureSCPEnabledRequiresTheInitClient(t *testing.T) {
	e := &Ensurer{Mode: ModeApply}
	_, err := e.EnsureSCPEnabled(ctx(), testRoot)
	mustErr(t, err, "no organization-init client", "automat init")
}

// TestEnsureOrganizationAdoptsAnExistingOrg. Nearly every institution already has
// one; `init` exists mostly to make that discoverable and to enable the policy
// type.
func TestEnsureOrganizationAdoptsAnExistingOrg(t *testing.T) {
	f := newFixture(t)
	info, act, err := f.E.EnsureOrganization(ctx(), f.Read)
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if info.ID != testOrgID || !info.PreExisting {
		t.Errorf("info = %+v, want the existing org marked PreExisting", info)
	}
	if act.Verb != VerbUnchanged || act.Applied {
		t.Errorf("action = %s, want an unapplied unchanged", act)
	}
	if f.Init.CallCount("CreateOrganization") != 0 {
		t.Error("called CreateOrganization against an account already in an organization")
	}
	if !strings.Contains(act.Detail, "did not create it") {
		t.Errorf("the action does not distinguish finding from creating: %s", act.Detail)
	}
}

// TestEnsureOrganizationCreatesWhenStandalone, and says the SCP policy type is not
// enabled by the create — the trap in DESIGN §3 fact 8, where everything reports
// fine and no control is live.
func TestEnsureOrganizationCreatesWhenStandalone(t *testing.T) {
	f := newFixture(t)
	f.Read.InOrg = false

	info, act, err := f.E.EnsureOrganization(ctx(), f.Read)
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if info.ID == "" || info.PreExisting {
		t.Errorf("info = %+v, want a created org", info)
	}
	if info.FeatureSet != string(orgtypes.OrganizationFeatureSetAll) {
		t.Errorf("feature set = %q, want ALL", info.FeatureSet)
	}
	if act.Verb != VerbCreate || !act.Applied {
		t.Errorf("action = %s, want an applied create", act)
	}
	if !strings.Contains(act.Detail, "NOT enabled") {
		t.Errorf("the action does not warn that the policy type is still off: %s", act.Detail)
	}
	// And the fake agrees: a fresh organization has SCPs off.
	if f.State.SCPEnabled {
		t.Error("the fake enabled SCPs on create, which would hide a forgotten EnablePolicyType")
	}
}

// TestEnsureOrganizationRefusesConsolidatedBilling. SCPs do not exist in that mode
// (DESIGN §3 fact 8), so every preventive control in every catalog is
// unenforceable — and automat cannot fix it, because leaving that feature set
// requires every member account to accept a handshake.
func TestEnsureOrganizationRefusesConsolidatedBilling(t *testing.T) {
	f := newFixture(t)
	f.Read.FeatureSet = orgtypes.OrganizationFeatureSetConsolidatedBilling

	_, _, err := f.E.EnsureOrganization(ctx(), f.Read)
	mustErr(t, err,
		"CONSOLIDATED_BILLING",
		"DESIGN §3, fact 8",
		"automat cannot change this",
		"accept an invitation",
		testMgmtAcct)
}

// TestEnsureOrganizationToleratesAlreadyInOrganization: the create is refused
// because the account joined an organization in the window, and the re-read is
// required because that error does not carry the feature set — which is the one
// thing automat has to know.
func TestEnsureOrganizationToleratesAlreadyInOrganization(t *testing.T) {
	f := newFixture(t)
	f.Read.InOrg = false
	f.State.Before = map[string]func() error{
		"CreateOrganization": func() error {
			f.Read.InOrg = true
			return &orgtypes.AlreadyInOrganizationException{}
		},
	}
	info, act, err := f.E.EnsureOrganization(ctx(), f.Read)
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	if !info.PreExisting || info.ID != testOrgID {
		t.Errorf("info = %+v, want the org it joined", info)
	}
	if act.Verb != VerbUnchanged {
		t.Errorf("verb = %s, want unchanged", act.Verb)
	}
}

// TestEnsureOrganizationWillNotCreateBlind. A create automat did not need is the
// one call in this package that cannot be undone by re-running, so it never
// happens without a read first.
func TestEnsureOrganizationWillNotCreateBlind(t *testing.T) {
	f := newFixture(t)
	_, _, err := f.E.EnsureOrganization(ctx(), nil)
	mustErr(t, err, "no read client", "cannot be undone by re-running")
	if f.Init.CallCount("CreateOrganization") != 0 {
		t.Error("CreateOrganization was called without a preceding read")
	}
}

// TestRootID refuses to guess when the invariant breaks. An organization has
// exactly one root; a wrong answer here silently attaches an institution's
// controls to the wrong half of its organization.
func TestRootID(t *testing.T) {
	f := newFixture(t)
	got, err := RootID(ctx(), f.Read)
	if err != nil || got != testRoot {
		t.Fatalf("RootID = %q, %v; want %q, nil", got, err, testRoot)
	}

	f.Read.InOrg = false
	if _, err := RootID(ctx(), f.Read); err == nil {
		t.Error("RootID succeeded against a standalone account")
	}
}

// TestSCPEnabledCountsOnlyEnabled. PENDING_ENABLE and PENDING_DISABLE are both
// states in which enforcement is not yet a fact, and reading either as "on" would
// be automat asserting a control is live while AWS is still deciding.
func TestSCPEnabledCountsOnlyEnabled(t *testing.T) {
	tests := []struct {
		status orgtypes.PolicyTypeStatus
		want   bool
	}{
		{orgtypes.PolicyTypeStatusEnabled, true},
		{orgtypes.PolicyTypeStatusPendingEnable, false},
		{orgtypes.PolicyTypeStatusPendingDisable, false},
		{"", false}, // the root reports no policy types at all
	}
	for _, tt := range tests {
		name := string(tt.status)
		if name == "" {
			name = "no policy types listed"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.Read.SCPStatus = tt.status
			got, err := SCPEnabled(ctx(), f.Read)
			if err != nil {
				t.Fatalf("SCPEnabled: %v", err)
			}
			if got != tt.want {
				t.Errorf("SCPEnabled = %v, want %v", got, tt.want)
			}
		})
	}
}
