// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/scttfrdmn/automat/internal/awsfake"
	"github.com/scttfrdmn/automat/internal/config"
	"github.com/scttfrdmn/automat/internal/evidence"
	"github.com/scttfrdmn/automat/internal/org"
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
	accounts := f.State.AccountIDs()
	if len(accounts) != 1 {
		t.Fatalf("vend produced %d accounts, want exactly 1 parked account", len(accounts))
	}

	// Assert against the "Parked accounts" section specifically, not the
	// whole output: the account also appears in the OU walk's "Accounts:"
	// section (it was created and moved before the policy step parked),
	// so a naive substring check on the whole output would pass even if
	// the parked-accounts inventory itself reported nothing.
	idx := strings.Index(out, "Parked accounts")
	if idx < 0 {
		t.Fatalf("list did not print a parked-accounts section:\n%s", out)
	}
	parkedSection := out[idx:]
	if strings.Contains(parkedSection, "none") {
		t.Errorf("the parked-accounts section reports none, want account %s: %s",
			accounts[0], parkedSection)
	}
	if !strings.Contains(parkedSection, accounts[0]) {
		t.Errorf("list's parked section does not name account %s: %s", accounts[0], parkedSection)
	}
}

// TestListReportQuotesEveryVariableField is AUDIT-4 M2. None of these values is
// automat's own: ids and emails are whatever AWS returned, and a parked entry's
// id is whatever preceded ".json" in a filename (evidence.Dir.ListAccountIDs
// deliberately does not validate it) while its message came out of a manifest on
// disk. A newline in any of them forges a line of the inventory an operator reads
// to decide which account to act on.
//
// Rendered directly rather than through runCLI: the fakes will not produce an
// account whose email contains a newline, and the property under test is the
// renderer's, not the walk's.
func TestListReportQuotesEveryVariableField(t *testing.T) {
	tree := &org.Tree{
		OUs: []org.TreeOU{{ID: "ou-aaaa-11111111\n  ou-forged-11111111 \"forged\" (under r-aaaa)",
			Name: "n", ParentID: "r-aaaa"}},
		Accounts: []org.TreeAccount{{ID: "111122223333", Name: "n",
			Email:      "a@example.edu\n  999988887777 \"forged\" <b@example.edu> (under r-aaaa)",
			ParentOUID: "r-aaaa"}},
	}
	parked := []parkedAccount{{
		AccountID: "444455556666\n  777788889999: verify at 2026-01-01T00:00:00Z — clean",
		Record: evidence.Record{Operation: evidence.OpAccountCreate, Timestamp: "2026-01-01T00:00:00Z",
			Err: &evidence.RecordError{Message: "stopped\n  and here is a forged line"}},
	}}

	var sb strings.Builder
	if err := renderListReport(&sb, config.Context{}, tree, parked); err != nil {
		t.Fatalf("renderListReport: %v", err)
	}
	for _, forged := range []string{"ou-forged-11111111", "999988887777", "777788889999",
		"here is a forged line"} {
		for _, line := range strings.Split(sb.String(), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), forged) {
				t.Errorf("a hostile value began its own line of the report, so it can forge one:\n%s",
					sb.String())
			}
		}
	}
}

func TestListRefusesAMalformedOUFlag(t *testing.T) {
	g, _ := vendWorld(t)
	if _, _, err := runCLI(t, g, "list", "--ou", "not-an-ou-id"); err == nil {
		t.Error("list with a malformed --ou succeeded, want a refusal")
	}
}
