// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
)

// TestListShowsVendedAccountAndOU vends one account and confirms `list`
// reports both the OU it was moved into and the account itself.
func TestListShowsVendedAccountAndOU(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)
	accountID := vendThenVerify(t, g, f, profile)

	out, _, err := runCLI(t, g, "list", "--ou", f.State.RootID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, testVendOU) {
		t.Errorf("list did not show the OU %s:\n%s", testVendOU, out)
	}
	if !strings.Contains(out, accountID) {
		t.Errorf("list did not show the vended account %s:\n%s", accountID, out)
	}
}

// TestListShowsNothingBeforeAnyVend is the state right after `automat init`:
// an OU exists, nothing has been vended, and `list` must say "none" rather
// than error.
func TestListShowsNothingBeforeAnyVend(t *testing.T) {
	g, f := vendWorld(t)

	out, _, err := runCLI(t, g, "list", "--ou", f.State.RootID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "Accounts:\n  none") {
		t.Errorf("list did not report no accounts:\n%s", out)
	}
	if !strings.Contains(out, "Parked accounts") {
		t.Errorf("list did not print a parked-accounts section:\n%s", out)
	}
}

// TestListDefaultsToOrgRootWithNoConfiguredOU: absent both --ou and a config
// `ou`, list must find *some* root to walk rather than refusing outright —
// DESIGN §13 describes list as an inventory command, and an inventory with
// no destination configured yet should still show the whole org.
func TestListDefaultsToOrgRootWithNoConfiguredOU(t *testing.T) {
	g, _ := vendWorld(t)
	// vendWorld's chdirTemp + fakeSet wiring does not set orgCtx.OU by
	// default (no config file was written), so this exercises the
	// ListRoots fallback path directly.
	out, _, err := runCLI(t, g, "list")
	if err != nil {
		t.Fatalf("list with no --ou and no configured ou: %v", err)
	}
	if !strings.Contains(out, "Organizational units:") {
		t.Errorf("list did not print its OU section:\n%s", out)
	}
}

// TestListReportsParkedAccount is the property the plan's Task 2 scope
// exists for: a parked account is invisible to the OU walk (it may not have
// moved anywhere), and only the local evidence manifest says it needs
// attention.
func TestListReportsParkedAccount(t *testing.T) {
	g, f := vendWorld(t)
	profile := vendProfileJSON(t, nil)

	// A denied CreatePolicy after the account is created and moved is the
	// real parked path TestVendParksWhenAPolicyFailsAfterTheAccountExists
	// (vend_test.go) exercises directly; reused here as the fixture for
	// `list`'s parked-accounts inventory.
	f.State.Errs["CreatePolicy"] = awsfake.AccessDenied("organizations:CreatePolicy")

	_, _, err := runCLI(t, g, vendArgs(profile)...)
	if err == nil {
		t.Fatal("vend succeeded despite a denied CreatePolicy, want a parked failure")
	}

	out, _, lerr := runCLI(t, g, "list", "--ou", f.State.RootID)
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	if !strings.Contains(out, "parked") && !strings.Contains(out, "Parked accounts") {
		t.Errorf("list did not report the parked account:\n%s", out)
	}
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("vend produced %d accounts, want exactly 1 parked account", len(accounts))
	}
	if !strings.Contains(out, accounts[0]) {
		t.Errorf("list's parked section does not name account %s:\n%s", accounts[0], out)
	}
}

func TestListRefusesAMalformedOUFlag(t *testing.T) {
	g, _ := vendWorld(t)
	if _, _, err := runCLI(t, g, "list", "--ou", "not-an-ou-id"); err == nil {
		t.Error("list with a malformed --ou succeeded, want a refusal")
	}
}
