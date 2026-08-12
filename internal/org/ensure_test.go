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
// Run twice = no diff. The Phase 2 acceptance criterion.
// -----------------------------------------------------------------------------

// TestRunTwiceWritesNothingTheSecondTime is ROADMAP Phase 2's acceptance
// criterion for this package, and CLAUDE.md rule 4 in observable form.
//
// The whole pipeline's Organizations half runs twice against one organization.
// The first pass creates; the second must issue no mutating call at all — not a
// tolerated duplicate, not a redundant UpdatePolicy, nothing. Asserting on the
// recorder rather than on the resulting state is what makes the difference
// visible: a second pass that re-attached everything and swallowed
// DuplicatePolicyAttachment would leave the organization identical and still be
// wrong, because on a real account it is four writes and four audit-log entries
// per vend.
func TestRunTwiceWritesNothingTheSecondTime(t *testing.T) {
	f := newFixture(t)

	run := func() {
		ouID, _, err := f.E.EnsureOUPath(ctx(), testRoot, []string{"Regulated", "CUI"})
		if err != nil {
			t.Fatalf("EnsureOUPath: %v", err)
		}
		res, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
			Name: "lab-alpha", Email: testEmail,
			Tags:          map[string]string{"automat:vended-by": "automat", "automat:ou": "CUI"},
			SearchParents: []string{testRoot, ouID},
		})
		if err != nil {
			t.Fatalf("EnsureAccount: %v", err)
		}
		if _, err := f.E.EnsurePlacement(ctx(), res.ID, ouID); err != nil {
			t.Fatalf("EnsurePlacement: %v", err)
		}
		if _, err := f.E.EnsurePolicySet(ctx(), ouID, []PolicySpec{
			{Name: "automat-cui-1", Document: scpDoc},
			{Name: "automat-cui-region", Document: scpDocOther},
		}); err != nil {
			t.Fatalf("EnsurePolicySet: %v", err)
		}
	}

	run()
	if !f.E.Changed() {
		t.Fatal("the first run reported no change against an empty organization")
	}
	first := f.writeCalls()
	for _, want := range []string{"CreateAccount", "CreateOrganizationalUnit", "CreatePolicy",
		"AttachPolicy", "MoveAccount"} {
		if !containsCall(first, want) {
			t.Errorf("the first run never called %s: %v", want, first)
		}
	}

	f.resetCalls()
	run()

	if got := f.writeCalls(); len(got) != 0 {
		t.Errorf("the second run issued mutating calls: %v", got)
	}
	if f.E.Changed() {
		t.Error("the second run reported Changed() = true")
	}
	for _, a := range f.E.Actions() {
		if a.Verb != VerbUnchanged {
			t.Errorf("the second run produced a non-unchanged action: %s", a)
		}
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// OUs.
// -----------------------------------------------------------------------------

// TestEnsureOUFindsWhatIsAlreadyThere is the read half: the OU exists, so no
// create is issued at all.
func TestEnsureOUFindsWhatIsAlreadyThere(t *testing.T) {
	f := newFixture(t)
	existing := f.State.SeedOU("Regulated", testRoot)

	id, act, err := f.E.EnsureOU(ctx(), testRoot, "Regulated")
	if err != nil {
		t.Fatalf("EnsureOU: %v", err)
	}
	if id != existing {
		t.Errorf("EnsureOU returned %q, want the existing OU %q", id, existing)
	}
	if act.Verb != VerbUnchanged {
		t.Errorf("verb = %s, want unchanged", act.Verb)
	}
	if f.Vend.CallCount("CreateOrganizationalUnit") != 0 {
		t.Error("EnsureOU created an OU that already existed")
	}
}

// TestEnsureOUAdoptsAnOUCreatedInTheTOCTOUWindow is the tolerate half, driven
// through the fake's real refusal (Q12).
//
// The OU is seeded from inside the Before hook on CreateOrganizationalUnit, which
// is precisely the window: automat has read (nothing there), and by the time its
// create lands, a concurrent vend or a console click has made the OU. The fake
// then produces a genuine DuplicateOrganizationalUnitException from its own
// name-uniqueness check, so what is under test is automat's handling of AWS's
// behavior rather than of a hand-built error.
//
// The re-read is the part worth asserting: without it, tolerating the exception
// would return no id at all, and the caller would go on to attach policies to "".
func TestEnsureOUAdoptsAnOUCreatedInTheTOCTOUWindow(t *testing.T) {
	f := newFixture(t)
	var raced string
	f.State.Before = map[string]func() error{
		"CreateOrganizationalUnit": func() error {
			if raced == "" {
				raced = f.State.SeedOU("Regulated", testRoot)
			}
			return nil
		},
	}

	id, act, err := f.E.EnsureOU(ctx(), testRoot, "Regulated")
	if err != nil {
		t.Fatalf("EnsureOU: %v", err)
	}
	if id != raced {
		t.Errorf("EnsureOU returned %q, want the OU that appeared in the window, %q", id, raced)
	}
	if act.Verb != VerbUnchanged {
		t.Errorf("verb = %s, want unchanged: the desired state holds either way", act.Verb)
	}
	if act.Applied {
		t.Error("an adopted OU is reported as applied, so a run-twice check would see a change")
	}
	if !strings.Contains(act.Detail, "concurrently") {
		t.Errorf("the action does not say what happened: %s", act.Detail)
	}
}

// TestEnsureOUReportsAnInvisibleDuplicate: AWS says the name is taken and the
// re-read cannot see it. Reporting that as an ordinary failure would send the
// operator looking for an OU that is not under that parent, so the message names
// the situation instead.
func TestEnsureOUReportsAnInvisibleDuplicate(t *testing.T) {
	f := newFixture(t)
	f.State.Before = map[string]func() error{
		"CreateOrganizationalUnit": func() error {
			return &awsfake.APIError{
				Code:    "DuplicateOrganizationalUnitException",
				Message: "An OU with the same name already exists.",
			}
		},
	}
	_, _, err := f.E.EnsureOU(ctx(), testRoot, "Regulated")
	mustErr(t, err, "the name is already taken", "no such OU is visible under that parent")
}

// TestEnsureOUDenialIsParkable. An AccessDenied while looking for an OU leaves a
// vend mid-change — the account may already exist — so it must be a resumable
// parked state rather than a fatal error, and it must name the grant.
func TestEnsureOUDenialIsParkable(t *testing.T) {
	f := newFixture(t)
	f.State.Errs["ListOrganizationalUnitsForParent"] =
		awsfake.AccessDenied("organizations:ListOrganizationalUnitsForParent")

	_, _, err := f.E.EnsureOU(ctx(), testRoot, "Regulated")
	mustErr(t, err, "organizations:ListOrganizationalUnitsForParent")
	if !Parkable(err) {
		t.Error("an AccessDenied while looking for an OU is not parkable, but it leaves a vend mid-change")
	}
}

// TestEnsureOUPathRefusesTooDeepBeforeCreatingAnything is the depth check's real
// requirement: it must run BEFORE the first create.
//
// A path one level too deep that is checked lazily fails halfway and leaves the
// shallow levels behind — the account then lands in an OU carrying none of the
// policies the environment profile asked for, which is the parked case with extra steps and no
// name. The assertion is therefore on the call recorder, not on the error.
func TestEnsureOUPathRefusesTooDeepBeforeCreatingAnything(t *testing.T) {
	tests := []struct {
		name   string
		depth  int // pre-existing OU levels below the root
		names  []string
		wantIn string
	}{
		{
			name: "path alone exceeds the limit", depth: 0,
			names:  []string{"a", "b", "c", "d", "e", "f"},
			wantIn: "levels deep",
		},
		{
			name: "path fits alone but not under this parent", depth: 3,
			names:  []string{"a", "b", "c"},
			wantIn: "already 3 levels below the root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			parent := testRoot
			for i := 0; i < tt.depth; i++ {
				parent = f.State.SeedOU(string(rune('A'+i)), parent)
			}
			_, _, err := f.E.EnsureOUPath(ctx(), parent, tt.names)
			mustErr(t, err, tt.wantIn, "DESIGN §3")
			if f.Vend.CallCount("CreateOrganizationalUnit") != 0 {
				t.Error("the depth refusal came after a create, leaving OUs behind")
			}
		})
	}
}

// TestEnsureOUPathRefusesAnUnknownParent. `vend` resolves the root first, so this
// is not reachable from the CLI — but an empty parent would make the whole path a
// create at an unspecified location, and the OUs would land wherever
// CreateOrganizationalUnit puts a request with no ParentId. Refusing is cheap; the
// alternative is an account carrying an institution's controls in the wrong branch.
func TestEnsureOUPathRefusesAnUnknownParent(t *testing.T) {
	f := newFixture(t)
	_, _, err := f.E.EnsureOUPath(ctx(), "", []string{"Regulated", "CUI"})
	mustErr(t, err, "Regulated/CUI", "no parent was given", "unknown location")
	if len(f.writeCalls()) != 0 {
		t.Errorf("the refusal came after a write: %v", f.writeCalls())
	}
}

// TestEnsureOUPathPlanReportsWhatItCannotKnow: once a level would be created,
// nothing below it can be read, and the plan says so rather than asserting the
// deeper levels are absent. A plan that claimed to know would be wrong whenever a
// concurrent vend got there first.
func TestEnsureOUPathPlanReportsWhatItCannotKnow(t *testing.T) {
	f := newFixture(t)
	f.E.Mode = ModePlan

	id, acts, err := f.E.EnsureOUPath(ctx(), testRoot, []string{"Regulated", "CUI", "Level3"})
	if err != nil {
		t.Fatalf("EnsureOUPath: %v", err)
	}
	if id != "" {
		t.Errorf("a plan returned an OU id it cannot know: %q", id)
	}
	if len(acts) != 3 {
		t.Fatalf("expected one action per level, got %d", len(acts))
	}
	if acts[0].Verb != VerbCreate {
		t.Errorf("level 1 verb = %s, want create", acts[0].Verb)
	}
	for i, a := range acts[1:] {
		if a.Verb != VerbUnknown {
			t.Errorf("level %d verb = %s, want unknown: nothing below a planned create can be read",
				i+2, a.Verb)
		}
		if !strings.Contains(a.Detail, "does not exist yet") {
			t.Errorf("level %d detail does not explain why it is unknown: %s", i+2, a.Detail)
		}
	}
}

// TestFindOUPaginates: awsfake.OrgState.PageSize defaults to 2, so an OU beyond
// the first page is only found by a caller that follows NextToken. A caller that
// stops at page one concludes the OU does not exist, creates a duplicate, and is
// refused by AWS — turning a missing token into a vend that cannot proceed.
func TestFindOUPaginates(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"Alpha", "Beta", "Gamma", "Delta", "Epsilon"} {
		f.State.SeedOU(name, testRoot)
	}
	// Epsilon sorts to a later page by id, since the fake pages on sorted ids and
	// they are assigned in seed order.
	id, act, err := f.E.EnsureOU(ctx(), testRoot, "Epsilon")
	if err != nil {
		t.Fatalf("EnsureOU: %v", err)
	}
	if id == "" || act.Verb != VerbUnchanged {
		t.Errorf("did not find an OU past the first page: id=%q verb=%s", id, act.Verb)
	}
	if f.Vend.CallCount("ListOrganizationalUnitsForParent") < 2 {
		t.Error("only one page was read; the pagination is not being exercised")
	}
	if f.Vend.CallCount("CreateOrganizationalUnit") != 0 {
		t.Error("created an OU that exists past the first page")
	}
}

func TestValidOUName(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		wantIn string // empty means valid
	}{
		{"plain", "Regulated", ""},
		{"interior space", "Research Computing", ""},
		{"dots and dashes", "cui-l2.research_1", ""},
		{"empty", "", "empty name"},
		{"too long", strings.Repeat("a", 129), "129 characters"},
		{"leading space", " Regulated", "leading or trailing whitespace"},
		{"trailing space", "Regulated ", "leading or trailing whitespace"},
		{"newline", "Reg\nulated", "control character"},
		{"tab", "Reg\tulated", "control character"},
		{"del", "Reg\x7fulated", "control character"},
		{"double quote", `Reg"ulated`, "terminate a string"},
		{"single quote", "Reg'ulated", "terminate a string"},
		{"backslash", `Reg\ulated`, "terminate a string"},
		{"brace", "Reg{ulated}", "terminate a string"},
		{"bracket", "Reg[0]", "terminate a string"},
		{"dollar", "Reg$ulated", "terminate a string"},
		{"backtick", "Reg`ulated`", "terminate a string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validOUName(tt.in)
			if tt.wantIn == "" {
				if err != nil {
					t.Errorf("validOUName(%q) = %v, want nil", tt.in, err)
				}
				return
			}
			mustErr(t, err, tt.wantIn)
		})
	}
}

// -----------------------------------------------------------------------------
// Accounts.
// -----------------------------------------------------------------------------

// TestEnsureAccountPollsAndLandsUnderTheRoot holds DESIGN §3 facts 4 and 6
// together: creation is asynchronous, and the account materializes under the ROOT
// rather than in the destination OU. That second fact is the entire reason
// EnsurePlacement exists as a separate step.
func TestEnsureAccountPollsAndLandsUnderTheRoot(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)

	res, act, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail,
		Tags:          map[string]string{"automat:vended-by": "automat"},
		SearchParents: []string{testRoot, ou},
	})
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if res.ID == "" {
		t.Fatal("no account id")
	}
	if res.RequestID == "" {
		t.Error("no request id: without it a resume is impossible and the operator has an account " +
			"they cannot find")
	}
	if res.Parent != testRoot {
		t.Errorf("the account landed under %q, want the root: DESIGN §3 fact 4", res.Parent)
	}
	if act.Verb != VerbCreate || !act.Applied {
		t.Errorf("action = %s, want an applied create", act)
	}
	if n := f.Vend.CallCount("DescribeCreateAccountStatus"); n < 2 {
		t.Errorf("polled %d times; the fake defaults to 2 in-progress polls, so a single check means "+
			"the asynchronous path is not being exercised", n)
	}
}

// TestEnsureAccountAdoptsByEmailNotByName. AWS permits two accounts with the same
// name, so a name match would let a second vend adopt an unrelated account and
// attach somebody else's policies to it. The email is unique across all of AWS.
func TestEnsureAccountAdoptsByEmailNotByName(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	existing := f.State.SeedAccount("lab-alpha", testEmail, ou)
	// A same-named account with a DIFFERENT email, in the same container. Adopting
	// this one would be the bug.
	f.State.SeedAccount("lab-alpha", "someone-else@example.edu", ou)

	res, act, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail,
		SearchParents: []string{testRoot, ou},
	})
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if res.ID != existing {
		t.Errorf("adopted %q, want the account with the matching email %q", res.ID, existing)
	}
	if act.Verb != VerbUnchanged || act.Applied {
		t.Errorf("action = %s, want an unapplied unchanged", act)
	}
	if f.Vend.CallCount("CreateAccount") != 0 {
		t.Error("created a second account for an email that already has one")
	}
}

// TestEnsureAccountEmailMatchIsCaseInsensitive. RFC 5321 makes the local part
// case-sensitive; AWS treats the whole address as one account key. An ensure
// operation that decided Lab@ and lab@ were different accounts would create the
// second one and then be told by AWS that they are the same.
func TestEnsureAccountEmailMatchIsCaseInsensitive(t *testing.T) {
	f := newFixture(t)
	existing := f.State.SeedAccount("lab-alpha", "Lab-Alpha@Example.edu", testRoot)

	res, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: "lab-alpha@example.edu",
		SearchParents: []string{testRoot},
	})
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if res.ID != existing {
		t.Errorf("adopted %q, want %q: the address differs only in case", res.ID, existing)
	}
}

// TestEnsureAccountResumeDoesNotCreate is `vend --resume`: a request id is polled
// rather than replayed. Re-running the create is the one mistake that costs an
// account from the organization's quota and cannot be undone.
func TestEnsureAccountResumeDoesNotCreate(t *testing.T) {
	f := newFixture(t)
	first, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail, SearchParents: []string{testRoot},
	})
	if err != nil {
		t.Fatalf("first EnsureAccount: %v", err)
	}
	f.resetCalls()

	res, act, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail, RequestID: first.RequestID,
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.ID != first.ID {
		t.Errorf("resume returned %q, want the original account %q", res.ID, first.ID)
	}
	if f.Vend.CallCount("CreateAccount") != 0 {
		t.Error("a resume created a second account")
	}
	if act.Verb != VerbUnchanged || act.Applied {
		t.Errorf("action = %s, want an unapplied unchanged", act)
	}
}

// TestEnsureAccountPlanDoesNotWaitOnAnInFlightCreate. A plan that blocked for five
// minutes on somebody else's create would not be a plan; VerbWait says so.
func TestEnsureAccountPlanDoesNotWaitOnAnInFlightCreate(t *testing.T) {
	f := newFixture(t)
	// A create that stays in flight past what the first run is willing to wait for.
	// This is the real shape of the case: a vend gave up (or was killed) while AWS
	// was still working, and the operator comes back with the request id.
	f.State.CreateAccountPolls = 50
	f.E.MaxPolls = 2
	first, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail, SearchParents: []string{testRoot},
	})
	mustErr(t, err, "did not finish within", "--resume")
	reqID := first.RequestID
	if reqID == "" {
		t.Fatal("no request id travelled with the timeout, so the operator cannot resume")
	}

	f.E.Mode = ModePlan
	f.resetCalls()
	res, act, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail, RequestID: reqID,
	})
	if err != nil {
		t.Fatalf("plan resume: %v", err)
	}
	if act.Verb != VerbWait {
		t.Errorf("verb = %s, want wait", act.Verb)
	}
	if res.RequestID != reqID {
		t.Errorf("the plan dropped the request id: %q", res.RequestID)
	}
	if n := f.Vend.CallCount("DescribeCreateAccountStatus"); n != 1 {
		t.Errorf("a plan polled %d times; it must read the status once and report", n)
	}
}

// TestEnsureAccountRequestIDTravelsWithTheError. The request id must reach the
// caller even when the vend fails: a run killed mid-poll has already consumed the
// account quota, and without the id the operator has an account they cannot find.
func TestEnsureAccountRequestIDTravelsWithTheError(t *testing.T) {
	f := newFixture(t)
	f.State.FailNextCreateWith = orgtypes.CreateAccountFailureReasonInvalidEmail

	res, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "lab-alpha", Email: testEmail, SearchParents: []string{testRoot},
	})
	mustErr(t, err, "root email")
	if res.RequestID == "" {
		t.Error("the request id did not travel with the error, so the operator cannot resume or " +
			"even name what AWS did")
	}
}

// TestCreateFailedRemediationPerReason: CLAUDE.md rule 7 across the whole
// CreateAccountFailureReason enum. Each reason gets its own sentence because the
// owners differ completely — an email collision is the operator's to fix in
// seconds, an account limit is a support ticket with days of lead time, and a
// payment instrument belongs to whoever owns the AWS bill.
func TestCreateFailedRemediationPerReason(t *testing.T) {
	tests := []struct {
		reason orgtypes.CreateAccountFailureReason
		wants  []string
	}{
		{orgtypes.CreateAccountFailureReasonEmailAlreadyExists, []string{"already exists"}},
		{orgtypes.CreateAccountFailureReasonInvalidEmail, []string{"root email", "deliverable mailbox"}},
		{orgtypes.CreateAccountFailureReasonAccountLimitExceeded,
			[]string{"L-E619E033", "quota increase", "request-service-quota-increase"}},
		{orgtypes.CreateAccountFailureReasonMissingPaymentInstrument,
			[]string{"payment method", "owns the AWS bill"}},
		{orgtypes.CreateAccountFailureReasonInvalidPaymentInstrument,
			[]string{"payment method", "owns the AWS bill"}},
		{orgtypes.CreateAccountFailureReasonConcurrentAccountModification,
			[]string{"retry", "re-run the vend"}},
		{orgtypes.CreateAccountFailureReasonInternalFailure, []string{"internal AWS error", "support"}},
		{"", []string{"no reason", "will not guess"}},
		{"SOME_FUTURE_REASON", []string{"SOME_FUTURE_REASON", "API reference"}},
	}
	e := &Ensurer{}
	spec := AccountSpec{Name: "lab-alpha", Email: testEmail}
	for _, tt := range tests {
		name := string(tt.reason)
		if name == "" {
			name = "no reason at all"
		}
		t.Run(name, func(t *testing.T) {
			st := &orgtypes.CreateAccountStatus{
				Id:            strPtr("car-exam0001"),
				FailureReason: tt.reason,
			}
			err := e.createFailed(st, spec)
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tt.wants {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("remediation is missing %q:\n%v", w, err)
				}
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// TestEnsureAccountValidation refuses the specs that would create a second
// account on a re-run.
func TestEnsureAccountValidation(t *testing.T) {
	tests := []struct {
		name   string
		spec   AccountSpec
		wantIn string
	}{
		{"no name", AccountSpec{Email: testEmail, SearchParents: []string{testRoot}}, "no name"},
		{"no email", AccountSpec{Name: "lab", SearchParents: []string{testRoot}}, "fact 11"},
		{
			// The dangerous one: with nowhere to look, a re-run creates a second
			// account rather than finding the first.
			"no search parents", AccountSpec{Name: "lab", Email: testEmail},
			"nowhere to look",
		},
		{
			"tag outside the namespace",
			AccountSpec{Name: "lab", Email: testEmail, SearchParents: []string{testRoot},
				Tags: map[string]string{"CostCenter": "1234"}},
			"outside automat's",
		},
		{
			// This subtest used to be named "resume needs nothing else" and assert
			// nil, which is AUDIT-2's critical finding written down as an
			// expectation. The request id does identify the create at AWS — that
			// part was never wrong — but it does not say whose create it is, and it
			// is printed on the birth certificate and recorded in the manifest, so
			// it is not a secret either. A resume must therefore still carry the
			// email checkResumedAccount compares against.
			"resume without the email", AccountSpec{RequestID: "car-exam0001"}, "fact 11",
		},
		{
			// A resume needs the email and NOT the name or the search parents: the
			// name is not a key (two accounts may share one), and a resume reads the
			// account's parent rather than hunting for it.
			"resume with the email alone",
			AccountSpec{RequestID: "car-exam0001", Email: testEmail}, "",
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
// Placement: Q12's both-readings requirement.
// -----------------------------------------------------------------------------

// TestEnsurePlacementSurvivesBothReadingsOfMoveToSamePlace is docs/open-questions
// Q12 as a test.
//
// Whether MoveAccount into the parent an account already sits in succeeds or
// returns DuplicateAccountException is not documented and cannot be settled from
// fakes, so the code does both things: it reads ListParents first and skips, and
// it treats DuplicateAccountException as success. This runs the placement under
// both fake settings and requires unchanged-and-not-applied from each.
//
// Neither half alone is enough, and the failure modes are different: with only the
// read, a TOCTOU loss fails a vend that has already done the right thing; with
// only the tolerance, automat's ordinary success path depends on undocumented
// behavior.
func TestEnsurePlacementSurvivesBothReadingsOfMoveToSamePlace(t *testing.T) {
	for _, samePlaceErrors := range []bool{false, true} {
		name := "move to same place succeeds"
		if samePlaceErrors {
			name = "move to same place returns DuplicateAccountException"
		}
		t.Run(name, func(t *testing.T) {
			// The read half: the account is already in the destination, so no move
			// is issued and the undocumented behavior never comes up.
			t.Run("read first", func(t *testing.T) {
				f := newFixture(t)
				f.State.MoveToSamePlaceErrors = samePlaceErrors
				ou := f.State.SeedOU("Regulated", testRoot)
				acct := f.State.SeedAccount("lab", testEmail, ou)

				act, err := f.E.EnsurePlacement(ctx(), acct, ou)
				if err != nil {
					t.Fatalf("EnsurePlacement: %v", err)
				}
				if act.Verb != VerbUnchanged || act.Applied {
					t.Errorf("action = %s, want an unapplied unchanged", act)
				}
				if f.Vend.CallCount("MoveAccount") != 0 {
					t.Error("moved an account that was already in the destination")
				}
			})

			// The tolerate half: the account is moved into the destination from
			// inside the Before hook, so automat's move lands on an account that is
			// already there. Under the harsher reading AWS refuses with
			// DuplicateAccountException; under the other it succeeds. Both mean the
			// desired state holds, and automat must not fail either way.
			t.Run("tolerate the window", func(t *testing.T) {
				f := newFixture(t)
				f.State.MoveToSamePlaceErrors = samePlaceErrors
				ou := f.State.SeedOU("Regulated", testRoot)
				other := f.State.SeedOU("Other", testRoot)
				acct := f.State.SeedAccount("lab", testEmail, other)

				moved := false
				f.State.Before = map[string]func() error{
					"MoveAccount": func() error {
						if moved {
							return nil
						}
						moved = true
						// Somebody else got there first, between automat's
						// ListParents and this call.
						f.State.Reparent(acct, ou)
						return nil
					},
				}

				act, err := f.E.EnsurePlacement(ctx(), acct, ou)
				if err != nil {
					t.Fatalf("EnsurePlacement lost the TOCTOU race: %v", err)
				}
				// The verb differs between the two readings and both are honest: if
				// AWS accepted the redundant move, automat did issue one and says so;
				// if AWS refused it as a duplicate, automat reports unchanged. What
				// must not differ is the outcome.
				if act.Verb != VerbMove && act.Verb != VerbUnchanged {
					t.Errorf("verb = %s, want move or unchanged", act.Verb)
				}
				if f.State.ParentOf(acct) != ou {
					t.Errorf("the account ended up under %q, want %q", f.State.ParentOf(acct), ou)
				}
			})
		})
	}
}

// TestEnsurePlacementRemediationNamesTheRightFix. A bad destination is a config
// error, and the message has to say where the account actually is — because it is
// now somewhere carrying policies the environment profile did not ask for.
func TestEnsurePlacementRemediationNamesTheRightFix(t *testing.T) {
	f := newFixture(t)
	acct := f.State.SeedAccount("lab", testEmail, testRoot)

	_, err := f.E.EnsurePlacement(ctx(), acct, "ou-does-not-exist")
	mustErr(t, err, "no root or OU with id ou-does-not-exist", "config file", testRoot)

	_, err = f.E.EnsurePlacement(ctx(), acct, "")
	mustErr(t, err, "fact 4", "parked")
}

// -----------------------------------------------------------------------------
// depthOf: undetermined is not an error.
// -----------------------------------------------------------------------------

// TestDepthOfUndeterminedIsNotAnError. A member account is frequently denied
// ListParents on an OU it may nonetheless vend into; refusing to vend because
// automat could not count would make the delegation useless.
func TestDepthOfUndeterminedIsNotAnError(t *testing.T) {
	f := newFixture(t)
	ou := f.State.SeedOU("Regulated", testRoot)
	f.State.Errs["ListParents"] = awsfake.AccessDenied("organizations:ListParents")

	depth, err := f.E.depthOf(ctx(), ou)
	if err != nil {
		t.Fatalf("depthOf returned an error for an unreadable parent: %v", err)
	}
	if depth != -1 {
		t.Errorf("depth = %d, want -1 for undetermined", depth)
	}

	// And the path still proceeds, because -1 skips the budget check rather than
	// failing it.
	f.E.Mode = ModePlan
	if _, _, err := f.E.EnsureOUPath(ctx(), ou, []string{"CUI"}); err != nil {
		t.Errorf("EnsureOUPath refused to plan because the depth was unknown: %v", err)
	}
}

func TestDepthOfRootIsZero(t *testing.T) {
	f := newFixture(t)
	depth, err := f.E.depthOf(ctx(), testRoot)
	if err != nil || depth != 0 {
		t.Errorf("depthOf(root) = %d, %v; want 0, nil", depth, err)
	}
	if f.Vend.CallCount("ListParents") != 0 {
		t.Error("the root's depth was read from the API; it is known from the id prefix")
	}
}
