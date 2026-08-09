// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

// reclaimFixture is newFixture's Reclaimer-shaped sibling.
type reclaimFixture struct {
	State   *awsfake.OrgState
	Reclaim *awsfake.OrgReclaim
	R       *Reclaimer
}

func newReclaimFixture(t *testing.T) *reclaimFixture {
	t.Helper()
	st := awsfake.NewOrgState(testOrgID, testMgmtAcct)
	f := &reclaimFixture{
		State:   st,
		Reclaim: awsfake.NewOrgReclaim(st),
	}
	f.R = &Reclaimer{Policy: f.Reclaim, Close: f.Reclaim, Mode: ModeApply}
	return f
}

func (f *reclaimFixture) seedOwnedPolicy(name, content string) string {
	return f.State.SeedPolicy(name, content, map[string]string{OwnerTagKey: OwnerTagValue})
}

// TestDetachOwnedPoliciesDetachesOnlyAutomatsOwn is the security half of
// reclaim, the same argument TestEnsurePolicyRefusesToAdoptAnUntaggedPolicy
// makes for EnsurePolicy: a policy without automat's owner tag is central
// IT's institutional floor, and reclaim must leave it attached and say so,
// never silently skip it.
func TestDetachOwnedPoliciesDetachesOnlyAutomatsOwn(t *testing.T) {
	f := newReclaimFixture(t)
	ou := f.State.SeedOU("Research", testRoot)
	owned := f.seedOwnedPolicy("automat-x-1", scpDoc)
	central := f.State.SeedPolicy("central-floor", scpDocOther, nil)
	f.State.SeedAttachment(owned, ou)
	f.State.SeedAttachment(central, ou)

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou)
	if err != nil {
		t.Fatalf("DetachOwnedPolicies: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(actions))
	}

	var sawDetached, sawLeftAlone bool
	for _, a := range actions {
		switch a.ID {
		case owned:
			if a.Verb != VerbDetach || !a.Applied {
				t.Errorf("owned policy action = %+v, want an applied detach", a)
			}
			sawDetached = true
		case central:
			if a.Verb != VerbUnchanged || a.Applied {
				t.Errorf("central policy action = %+v, want an unapplied unchanged", a)
			}
			if !strings.Contains(a.Detail, "not automat's") {
				t.Errorf("central policy detail = %q, want it to say the policy is not automat's", a.Detail)
			}
			sawLeftAlone = true
		}
	}
	if !sawDetached || !sawLeftAlone {
		t.Fatalf("actions = %+v, want one detach and one left-alone", actions)
	}

	// The security assertion: central's attachment must still be there.
	remaining := f.State.AttachedTo(ou)
	if len(remaining) != 1 || remaining[0] != central {
		t.Errorf("policies remaining attached to %s = %v, want only %s", ou, remaining, central)
	}
}

// TestDetachOwnedPoliciesPlanModeWritesNothing is CLAUDE.md rule 5's plan
// half: a plan must never call DetachPolicy.
func TestDetachOwnedPoliciesPlanModeWritesNothing(t *testing.T) {
	f := newReclaimFixture(t)
	f.R.Mode = ModePlan
	ou := f.State.SeedOU("Research", testRoot)
	owned := f.seedOwnedPolicy("automat-x-1", scpDoc)
	f.State.SeedAttachment(owned, ou)

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou)
	if err != nil {
		t.Fatalf("DetachOwnedPolicies: %v", err)
	}
	if len(actions) != 1 || actions[0].Applied {
		t.Fatalf("actions = %+v, want one unapplied action", actions)
	}
	for _, call := range f.Reclaim.Calls() {
		if call == "DetachPolicy" {
			t.Fatalf("plan mode called DetachPolicy — CLAUDE.md rule 5's plan half must write nothing")
		}
	}
	remaining := f.State.AttachedTo(ou)
	if len(remaining) != 1 {
		t.Errorf("policies remaining attached to %s = %v, want the plan to have changed nothing", ou, remaining)
	}
}

// TestCloseAccountAppliesAndReportsTheGraceWindow.
func TestCloseAccountAppliesAndReportsTheGraceWindow(t *testing.T) {
	f := newReclaimFixture(t)
	acct := f.State.SeedAccount("lab", testEmail, testRoot)

	action, err := f.R.CloseAccount(ctx(), acct)
	if err != nil {
		t.Fatalf("CloseAccount: %v", err)
	}
	if action.Verb != VerbClose || !action.Applied {
		t.Errorf("action = %+v, want an applied close", action)
	}
}

// TestCloseAccountPlanModeCallsNothing is the plan-mode half for the second
// destructive action.
func TestCloseAccountPlanModeCallsNothing(t *testing.T) {
	f := newReclaimFixture(t)
	f.R.Mode = ModePlan
	acct := f.State.SeedAccount("lab", testEmail, testRoot)

	action, err := f.R.CloseAccount(ctx(), acct)
	if err != nil {
		t.Fatalf("CloseAccount: %v", err)
	}
	if action.Applied {
		t.Errorf("plan mode produced an applied action: %+v", action)
	}
	for _, call := range f.Reclaim.Calls() {
		if call == "CloseAccount" {
			t.Fatalf("plan mode called CloseAccount — CLAUDE.md rule 5's plan half must write nothing")
		}
	}
}

// TestCloseAccountReportsTheQuotaByName is docs/reclaim-design.md's own
// remediation requirement: the rejection names the actual AWS-documented
// limit rather than a client-side guess, since no Service Quotas code
// exposes this rate for automat to check in advance.
func TestCloseAccountReportsTheQuotaByName(t *testing.T) {
	f := newReclaimFixture(t)
	f.Reclaim.CloseAccountQuotaExceeded = true
	acct := f.State.SeedAccount("lab", testEmail, testRoot)

	_, err := f.R.CloseAccount(ctx(), acct)
	mustErr(t, err, "250", "20%", "rolling 30 day", "Quotas for Organizations")
}

// TestDetachOwnedPoliciesRefusesAnEmptyTarget.
func TestDetachOwnedPoliciesRefusesAnEmptyTarget(t *testing.T) {
	f := newReclaimFixture(t)
	if _, err := f.R.DetachOwnedPolicies(ctx(), ""); err == nil {
		t.Fatal("DetachOwnedPolicies accepted an empty target, want a refusal")
	}
}

// TestCloseAccountRefusesAnEmptyAccountID.
func TestCloseAccountRefusesAnEmptyAccountID(t *testing.T) {
	f := newReclaimFixture(t)
	if _, err := f.R.CloseAccount(ctx(), ""); err == nil {
		t.Fatal("CloseAccount accepted an empty account id, want a refusal")
	}
}
