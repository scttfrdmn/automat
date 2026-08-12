// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"context"
	"strings"
	"testing"
	"time"

	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"

	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/envprofile"
	"github.com/scttfrdmn/automat/internal/org"
)

func newRegionsFixture(mode org.Mode) (*Ensurer, *awsfake.Account) {
	acct := awsfake.NewAccount()
	return &Ensurer{
		Account:   acct,
		Mode:      mode,
		Principal: "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/automat-baseline",
		// No real sleep in a unit test: the poll count is what the code under
		// test is proven against, not a real wait.
		Sleep: func(context.Context, time.Duration) error { return nil },
	}, acct
}

// TestEnsureRegionsPlanWritesNothing is CLAUDE.md rule 5: a plan must issue no
// mutating call.
func TestEnsureRegionsPlanWritesNothing(t *testing.T) {
	e, acct := newRegionsFixture(org.ModePlan)

	actions, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Enable: []string{"ap-south-1"}})
	if err != nil {
		t.Fatalf("EnsureRegions: %v", err)
	}
	for _, op := range []string{"EnableRegion", "DisableRegion"} {
		if n := acct.CallCount(op); n != 0 {
			t.Errorf("plan mode called %s %d times; a plan must write nothing", op, n)
		}
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbEnable || actions[0].Applied {
		t.Fatalf("want one unapplied enable action, got %+v", actions)
	}
}

// TestEnsureRegionsAppliesEnableAndDisable is the apply-mode counterpart:
// both an enable and a disable, on regions that need it, must actually
// happen and must poll GetRegionOptStatus to the terminal state.
func TestEnsureRegionsAppliesEnableAndDisable(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)
	// Seed a region already ENABLED so there is something to disable.
	acct.Regions["ap-south-1"] = accounttypes.RegionOptStatusEnabled

	actions, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{
		Enable:  []string{"ap-northeast-1"},
		Disable: []string{"ap-south-1"},
	})
	if err != nil {
		t.Fatalf("EnsureRegions: %v", err)
	}
	if acct.CallCount("EnableRegion") != 1 {
		t.Errorf("EnableRegion called %d times, want 1", acct.CallCount("EnableRegion"))
	}
	if acct.CallCount("DisableRegion") != 1 {
		t.Errorf("DisableRegion called %d times, want 1", acct.CallCount("DisableRegion"))
	}
	if got := acct.Regions["ap-northeast-1"]; got != accounttypes.RegionOptStatusEnabled {
		t.Errorf("ap-northeast-1 status = %s, want ENABLED", got)
	}
	if got := acct.Regions["ap-south-1"]; got != accounttypes.RegionOptStatusDisabled {
		t.Errorf("ap-south-1 status = %s, want DISABLED", got)
	}
	if len(actions) != 2 {
		t.Fatalf("want 2 actions, got %+v", actions)
	}
	for _, a := range actions {
		if !a.Applied {
			t.Errorf("action not marked Applied: %+v", a)
		}
	}
}

// TestEnsureRegionsIdempotent is CLAUDE.md rule 4: a second apply against
// regions already in the wanted state must issue no write.
func TestEnsureRegionsIdempotent(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)
	acct.Regions["ap-south-1"] = accounttypes.RegionOptStatusEnabled

	spec := envprofile.BaselineRegions{Enable: []string{"ap-northeast-1"}, Disable: []string{"ap-south-1"}}
	if _, err := e.EnsureRegions(ctx(), spec); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	acct.Reset()

	actions, err := e.EnsureRegions(ctx(), spec)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	for _, op := range []string{"EnableRegion", "DisableRegion"} {
		if n := acct.CallCount(op); n != 0 {
			t.Errorf("the second ensure called %s %d times; a re-run must write nothing", op, n)
		}
	}
	if len(actions) != 2 {
		t.Fatalf("want 2 actions, got %+v", actions)
	}
	for _, a := range actions {
		if a.Verb != org.VerbUnchanged || a.Applied {
			t.Errorf("want an unapplied unchanged action, got %+v", a)
		}
	}
}

// TestEnsureRegionsAlreadyEnabledByDefaultIsUnchanged confirms a region named
// in Enable that AWS already turns on for every account (the fixture's own
// seeded set) produces VerbUnchanged rather than an EnableRegion call the
// real API would refuse as redundant.
func TestEnsureRegionsAlreadyEnabledByDefaultIsUnchanged(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)

	actions, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Enable: []string{"us-east-1"}})
	if err != nil {
		t.Fatalf("EnsureRegions: %v", err)
	}
	if acct.CallCount("EnableRegion") != 0 {
		t.Error("EnableRegion was called against an already-enabled-by-default region")
	}
	if len(actions) != 1 || actions[0].Verb != org.VerbUnchanged || actions[0].Applied {
		t.Fatalf("want one unapplied unchanged action, got %+v", actions)
	}
}

// TestEnsureRegionsRefusesDisablingAnEnabledByDefaultRegion is the plan-time
// refusal the task's scope statement asks for: baseline.regions.disable
// naming a region AWS never allows disabling must be refused before any
// DisableRegion call, with remediation naming the field to fix — not
// surfaced as a raw AWS ConflictException.
func TestEnsureRegionsRefusesDisablingAnEnabledByDefaultRegion(t *testing.T) {
	for _, mode := range []org.Mode{org.ModePlan, org.ModeApply} {
		e, acct := newRegionsFixture(mode)

		_, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Disable: []string{"us-east-1"}})
		if err == nil {
			t.Fatalf("[%s] want an error when baseline.regions.disable names an enabled-by-default region", mode)
		}
		if !strings.Contains(err.Error(), "us-east-1") {
			t.Errorf("[%s] error does not name the region: %v", mode, err)
		}
		if !strings.Contains(err.Error(), "enables by default") {
			t.Errorf("[%s] error does not explain why: %v", mode, err)
		}
		if acct.CallCount("DisableRegion") != 0 {
			t.Errorf("[%s] DisableRegion was called even though the refusal should have happened first", mode)
		}
	}
}

// TestEnsureRegionsPollsMultipleTimesBeforeTerminal exercises the
// bounded-poll loop against a fake that reports the transitional state
// (ENABLING) twice before landing on ENABLED — the injected-sleep pattern
// internal/org's own account creation tests use for the identical property.
func TestEnsureRegionsPollsMultipleTimesBeforeTerminal(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)
	acct.EnablePollsLeft["ap-northeast-1"] = 2

	var slept int
	e.Sleep = func(context.Context, time.Duration) error {
		slept++
		return nil
	}

	actions, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Enable: []string{"ap-northeast-1"}})
	if err != nil {
		t.Fatalf("EnsureRegions: %v", err)
	}
	if slept != 2 {
		t.Errorf("slept %d times, want 2 (matching EnablePollsLeft)", slept)
	}
	if got := acct.Regions["ap-northeast-1"]; got != accounttypes.RegionOptStatusEnabled {
		t.Errorf("ap-northeast-1 status = %s, want ENABLED", got)
	}
	if len(actions) != 1 || !actions[0].Applied {
		t.Fatalf("want one applied action, got %+v", actions)
	}
}

// TestEnsureRegionsGivesUpAfterMaxPolls confirms a region that never reaches
// a terminal state within MaxPolls produces an error naming the region and
// action, rather than hanging or silently reporting success — the same
// "still in flight, re-run" wording internal/org's own pollCreate gives for
// the identical shape of asynchronous completion.
func TestEnsureRegionsGivesUpAfterMaxPolls(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)
	e.MaxPolls = 2
	acct.EnablePollsLeft["ap-northeast-1"] = 100

	_, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Enable: []string{"ap-northeast-1"}})
	if err == nil {
		t.Fatal("want an error when the region never reaches a terminal state within MaxPolls")
	}
	if !strings.Contains(err.Error(), "ap-northeast-1") {
		t.Errorf("error does not name the region: %v", err)
	}
	if !strings.Contains(err.Error(), "re-run") {
		t.Errorf("error carries no re-run guidance: %v", err)
	}
}

// TestEnsureRegionsHomeIsInformationalOnly confirms spec.Home drives no call
// at all: there is no AWS API to change an account's home region after the
// fact (see the method doc), so a profile naming only Home and no
// Enable/Disable members must produce zero actions and zero calls.
func TestEnsureRegionsHomeIsInformationalOnly(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)

	actions, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Home: "us-east-1"})
	if err != nil {
		t.Fatalf("EnsureRegions: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("want no actions for a Home-only spec, got %+v", actions)
	}
	if len(acct.Calls()) != 0 {
		t.Errorf("want no calls at all for a Home-only spec, got %v", acct.Calls())
	}
}

// TestEnsureRegionsRefusesWithNoAccountClient is a narrow input check: this
// Ensurer must not silently no-op when Account was never set.
func TestEnsureRegionsRefusesWithNoAccountClient(t *testing.T) {
	e := &Ensurer{Mode: org.ModeApply}
	if _, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Enable: []string{"ap-south-1"}}); err == nil {
		t.Fatal("want an error when Account is nil")
	}
}

// TestEnsureRegionsListRegionsDenialIsRemediated confirms a denied read is
// wrapped as an awsapi.PermissionError with remediation, not a bare AWS
// error — CLAUDE.md rule 7.
func TestEnsureRegionsListRegionsDenialIsRemediated(t *testing.T) {
	e, acct := newRegionsFixture(org.ModeApply)
	acct.ListRegionsErr = awsfake.AccessDenied("account:ListRegions")

	_, err := e.EnsureRegions(ctx(), envprofile.BaselineRegions{Enable: []string{"ap-south-1"}})
	if err == nil {
		t.Fatal("want an error when ListRegions is denied")
	}
	if !strings.Contains(err.Error(), "account:ListRegions") {
		t.Errorf("error does not name the denied action: %v", err)
	}
	if !strings.Contains(err.Error(), "grant") {
		t.Errorf("error carries no remediation: %v", err)
	}
}
