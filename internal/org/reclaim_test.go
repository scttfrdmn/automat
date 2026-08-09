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

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou, "")
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

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou, "")
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
	if _, err := f.R.DetachOwnedPolicies(ctx(), "", ""); err == nil {
		t.Fatal("DetachOwnedPolicies accepted an empty target, want a refusal")
	}
}

// TestDetachOwnedPoliciesLeavesAPolicyAttachedWhenALiveSiblingSharesTheOU is
// AUDIT-6 C1's security assertion: an SCP is attached at the OU, not the
// account (DESIGN §5, §8), so an OU can hold more than one account. Detaching
// the account being reclaimed's OWN account id must not be enough to detach
// its OU's shared policy while another account under that same OU is still
// ACTIVE — doing so would strip that sibling's guardrails as a side effect
// of reclaiming a completely different account.
func TestDetachOwnedPoliciesLeavesAPolicyAttachedWhenALiveSiblingSharesTheOU(t *testing.T) {
	f := newReclaimFixture(t)
	ou := f.State.SeedOU("Research", testRoot)
	owned := f.seedOwnedPolicy("automat-x-1", scpDoc)
	f.State.SeedAttachment(owned, ou)

	reclaiming := f.State.SeedAccount("lab-a", "lab-a@example.edu", ou)
	sibling := f.State.SeedAccount("lab-b", "lab-b@example.edu", ou)

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou, reclaiming)
	if err != nil {
		t.Fatalf("DetachOwnedPolicies: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(actions))
	}
	if actions[0].Verb != VerbUnchanged || actions[0].Applied {
		t.Errorf("action = %+v, want an unapplied unchanged", actions[0])
	}
	if !strings.Contains(actions[0].Detail, sibling) {
		t.Errorf("detail = %q, want it to name the live sibling %s", actions[0].Detail, sibling)
	}

	// The security assertion: the shared policy must still be attached.
	remaining := f.State.AttachedTo(ou)
	if len(remaining) != 1 || remaining[0] != owned {
		t.Errorf("policies remaining attached to %s = %v, want %s still attached (sibling %s is still "+
			"ACTIVE)", ou, remaining, owned, sibling)
	}
	for _, call := range f.Reclaim.Calls() {
		if call == "DetachPolicy" {
			t.Fatal("DetachPolicy was called despite a live sibling sharing the OU")
		}
	}
}

// TestDetachOwnedPoliciesDetachesWhenTheOnlyOtherAccountUnderTheOUIsNotActive
// is the other half: a sibling that is SUSPENDED (already reclaimed, or
// otherwise not ACTIVE) does not block the detach, because it has no
// guardrails left to strip.
func TestDetachOwnedPoliciesDetachesWhenTheOnlyOtherAccountUnderTheOUIsNotActive(t *testing.T) {
	f := newReclaimFixture(t)
	ou := f.State.SeedOU("Research", testRoot)
	owned := f.seedOwnedPolicy("automat-x-1", scpDoc)
	f.State.SeedAttachment(owned, ou)

	reclaiming := f.State.SeedAccount("lab-a", "lab-a@example.edu", ou)
	alreadyClosed := f.State.SeedAccount("lab-b", "lab-b@example.edu", ou)
	if _, err := f.R.CloseAccount(ctx(), alreadyClosed); err != nil {
		t.Fatalf("seed close of the sibling: %v", err)
	}

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou, reclaiming)
	if err != nil {
		t.Fatalf("DetachOwnedPolicies: %v", err)
	}
	if len(actions) != 1 || actions[0].Verb != VerbDetach || !actions[0].Applied {
		t.Fatalf("actions = %+v, want one applied detach (the only other account under the OU is not "+
			"ACTIVE)", actions)
	}
	remaining := f.State.AttachedTo(ou)
	if len(remaining) != 0 {
		t.Errorf("policies remaining attached to %s = %v, want none", ou, remaining)
	}
}

// TestDetachOwnedPoliciesDetachesWhenNoSiblingSharesTheOU is the ordinary
// case's own regression guard: the common shape, one account per OU, must
// keep working exactly as it did before the sibling check was added.
func TestDetachOwnedPoliciesDetachesWhenNoSiblingSharesTheOU(t *testing.T) {
	f := newReclaimFixture(t)
	ou := f.State.SeedOU("Research", testRoot)
	owned := f.seedOwnedPolicy("automat-x-1", scpDoc)
	f.State.SeedAttachment(owned, ou)
	reclaiming := f.State.SeedAccount("lab-a", "lab-a@example.edu", ou)

	actions, err := f.R.DetachOwnedPolicies(ctx(), ou, reclaiming)
	if err != nil {
		t.Fatalf("DetachOwnedPolicies: %v", err)
	}
	if len(actions) != 1 || actions[0].Verb != VerbDetach || !actions[0].Applied {
		t.Fatalf("actions = %+v, want one applied detach", actions)
	}
}

// TestCloseAccountRefusesAnEmptyAccountID.
func TestCloseAccountRefusesAnEmptyAccountID(t *testing.T) {
	f := newReclaimFixture(t)
	if _, err := f.R.CloseAccount(ctx(), ""); err == nil {
		t.Fatal("CloseAccount accepted an empty account id, want a refusal")
	}
}

// TestDetachPolicyDeniedInBrokeredStateBlamesTheDelegationPolicyNotTheVendorRole
// is AUDIT-6 H2: DetachPolicy (and the three read methods DetachOwnedPolicies
// calls) run on r.Policy, which the type's own doc says is NEVER brokered —
// in MEMBER state it is the caller's own delegated identity, gated by
// delegation-policy.json, not by the vendor role CloseAccount uses. A
// Reclaimer built for MEMBER state sets Credential to Brokered because
// CloseAccount needs that word; before this fix, denied() read only that one
// field and told every denial — including this one — to widen the vendor
// role, a file that cannot grant a policy action at all.
func TestDetachPolicyDeniedInBrokeredStateBlamesTheDelegationPolicyNotTheVendorRole(t *testing.T) {
	f := newReclaimFixture(t)
	f.R.Credential = Brokered
	ou := f.State.SeedOU("Research", testRoot)
	owned := f.seedOwnedPolicy("automat-x-1", scpDoc)
	f.State.SeedAttachment(owned, ou)
	f.Reclaim.State.Errs["DetachPolicy"] = awsfake.AccessDenied("organizations:DetachPolicy")

	_, err := f.R.DetachOwnedPolicies(ctx(), ou, "")
	mustErr(t, err, "delegation-policy.json")
	if strings.Contains(err.Error(), "vendor-role") {
		t.Errorf("a DetachPolicy denial pointed at the vendor role, which cannot grant a policy "+
			"action: %v", err)
	}
}

// TestCloseAccountDeniedInBrokeredStateStillBlamesTheVendorRole is the other
// half: CloseAccount itself must still be attributed to the vendor role in
// MEMBER state, unchanged by the fix above.
func TestCloseAccountDeniedInBrokeredStateStillBlamesTheVendorRole(t *testing.T) {
	f := newReclaimFixture(t)
	f.R.Credential = Brokered
	acct := f.State.SeedAccount("lab", testEmail, testRoot)
	f.Reclaim.State.Errs["CloseAccount"] = awsfake.AccessDenied("organizations:CloseAccount")

	_, err := f.R.CloseAccount(ctx(), acct)
	mustErr(t, err, "vendor-role")
	if strings.Contains(err.Error(), "delegation-policy") {
		t.Errorf("a CloseAccount denial pointed at the delegation policy, which cannot grant "+
			"account closure: %v", err)
	}
}
