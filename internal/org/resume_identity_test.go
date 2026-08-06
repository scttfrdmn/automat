// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

// The resumed create-account request checked against the identity the caller claims
// (AUDIT-2, critical).
//
// Rather than editing the fix out of account.go — which is the one thing a security
// counter-check must not do — the first test reproduces the PRE-FIX SEQUENCE call by
// call: pollCreate, parentOf, EnsurePlacement, with nothing between them. It asserts
// that sequence does the damage, and logs it. Then it runs the same attack through the
// real EnsureAccount and asserts it is refused. Same fake, same request id, same two
// profiles' worth of specs.

func TestResumePreFixSequenceMovesSomebodyElsesAccount(t *testing.T) {
	f := newFixture(t)
	victimOU := f.State.SeedOUWithID("ou-vict-victim001", "Victim", f.State.RootID)
	attackerOU := f.State.SeedOUWithID("ou-atck-attack001", "Attacker", f.State.RootID)

	// The victim vends.
	victim := AccountSpec{
		Name: "genomics", Email: "victim@dept.example.edu",
		SearchParents: []string{f.State.RootID},
	}
	res, _, err := f.E.EnsureAccount(ctx(), victim)
	if err != nil {
		t.Fatalf("the victim's create: %v", err)
	}
	if _, perr := f.E.EnsurePlacement(ctx(), res.ID, victimOU); perr != nil {
		t.Fatalf("the victim's placement: %v", perr)
	}
	if got := f.State.ParentOf(res.ID); got != victimOU {
		t.Fatalf("setup: the victim's account is under %s, want %s", got, victimOU)
	}
	reqID := res.RequestID
	if reqID == "" {
		t.Fatal("no create-account request id, so there is nothing to attack with")
	}

	// The attacker's spec: their own name, their own email, the victim's request id.
	attacker := AccountSpec{
		Name: "attacker-lab", Email: "attacker@other.example.edu", RequestID: reqID,
		SearchParents: []string{f.State.RootID},
	}

	// PRE-FIX: what resumeAccount used to do. pollCreate the caller-supplied id,
	// read the parent, and hand the id to the placement. No identity check exists
	// between any two of these lines, which was the whole finding.
	id, err := f.E.pollCreate(ctx(), attacker.RequestID, attacker)
	if err != nil {
		t.Fatalf("pre-fix poll: %v", err)
	}
	if _, perr := f.E.parentOf(ctx(), id); perr != nil {
		t.Fatalf("pre-fix parentOf: %v", perr)
	}
	if _, perr := f.E.EnsurePlacement(ctx(), id, attackerOU); perr != nil {
		t.Fatalf("pre-fix placement: %v", perr)
	}
	if got := f.State.ParentOf(id); got == attackerOU {
		t.Logf("CONFIRMED PRE-FIX HIJACK: account %s (the victim's, email victim@dept.example.edu) "+
			"moved from %s to %s on a resume that named neither. Every SCP attached at %s no longer "+
			"applies to it.", id, victimOU, attackerOU, victimOU)
	} else {
		t.Fatalf("the pre-fix sequence did NOT move the account (parent %s) — the counter-check is "+
			"not exercising what the finding describes", got)
	}

	// Put it back, so the post-fix half starts from the same world.
	if _, rerr := f.E.EnsurePlacement(ctx(), id, victimOU); rerr != nil {
		t.Fatalf("restoring the victim: %v", rerr)
	}

	// POST-FIX: the same attack through the real entry point.
	f.E.ResetActions()
	_, _, err = f.E.EnsureAccount(ctx(), attacker)
	if err == nil {
		t.Fatalf("EnsureAccount accepted another spec's request id; the account is under %s",
			f.State.ParentOf(id))
	}
	for _, want := range []string{
		"victim@dept.example.edu", "attacker@other.example.edu", "exactly one parent", reqID,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if got := f.State.ParentOf(id); got != victimOU {
		t.Errorf("the victim's account is under %s despite the refusal, want %s", got, victimOU)
	}
	t.Logf("refused: %v", err)
}

// The plan path must refuse too, and must refuse BEFORE it reports anything about
// somebody else's account.
func TestResumeRefusesInPlanModeToo(t *testing.T) {
	f := newFixture(t)
	res, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "genomics", Email: "victim@dept.example.edu",
		SearchParents: []string{f.State.RootID},
	})
	if err != nil {
		t.Fatalf("the victim's create: %v", err)
	}
	f.E.Mode = ModePlan
	f.E.ResetActions()
	_, act, err := f.E.EnsureAccount(ctx(), AccountSpec{
		Name: "attacker-lab", Email: "attacker@other.example.edu", RequestID: res.RequestID,
		SearchParents: []string{f.State.RootID},
	})
	if err == nil {
		t.Fatalf("the plan accepted another spec's request id and reported %+v", act)
	}
	if !strings.Contains(err.Error(), "victim@dept.example.edu") {
		t.Errorf("the plan's refusal does not name the account's real email: %v", err)
	}
	t.Logf("plan refused: %v", err)
}

// The two cases that must still WORK: a genuine resume of one's own request, in both
// modes, with the email differing only in case.
func TestResumeOfOnesOwnRequestStillWorks(t *testing.T) {
	for _, mode := range []Mode{ModeApply, ModePlan} {
		f := newFixture(t)
		spec := AccountSpec{
			Name: "genomics", Email: "Lab@Dept.Example.Edu",
			SearchParents: []string{f.State.RootID},
		}
		res, _, err := f.E.EnsureAccount(ctx(), spec)
		if err != nil {
			t.Fatalf("mode %v: create: %v", mode, err)
		}
		f.E.Mode = mode
		f.E.ResetActions()
		// Same account, address typed back in a different case, no name at all.
		got, _, err := f.E.EnsureAccount(ctx(), AccountSpec{
			RequestID: res.RequestID, Email: "lab@dept.example.edu",
		})
		if err != nil {
			t.Fatalf("mode %v: a genuine resume must be allowed: %v", mode, err)
		}
		if got.ID != res.ID {
			t.Errorf("mode %v: the resume returned account %s, want %s", mode, got.ID, res.ID)
		}
	}
}

// An in-flight request has no account id and nothing to check. It must report a wait
// rather than a refusal — a resume of one's own still-running create is the ordinary
// case the whole flag exists for.
func TestResumeOfAnInFlightRequestReportsAWait(t *testing.T) {
	f := newFixture(t)
	f.State.CreateAccountPolls = 1000
	// Straight at the fake, because an in-flight create is a state EnsureAccount
	// cannot leave behind: apply-mode polls to completion and plan-mode never starts.
	out, err := f.Vend.CreateAccount(ctx(), &organizations.CreateAccountInput{
		AccountName: aws.String("genomics"), Email: aws.String("lab@dept.example.edu"),
	})
	if err != nil {
		t.Fatalf("seeding an in-flight create: %v", err)
	}
	reqID := aws.ToString(out.CreateAccountStatus.Id)
	f.E.Mode = ModePlan
	f.E.ResetActions()
	_, act, err := f.E.EnsureAccount(ctx(), AccountSpec{
		RequestID: reqID, Email: "someone-else@other.example.edu",
	})
	if err != nil {
		t.Fatalf("an in-flight resume must report a wait, not refuse: %v", err)
	}
	if act == nil || act.Verb != VerbWait {
		t.Errorf("want a wait action, got %+v", act)
	}
}
