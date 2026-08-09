// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"sort"
	"testing"
)

func TestWalkTreeCollectsEveryAccountAndOU(t *testing.T) {
	f := newFixture(t)
	// root
	//  ├─ acct-1
	//  └─ ou-a
	//      ├─ acct-2
	//      └─ ou-b
	//          └─ acct-3
	acct1 := f.State.SeedAccount("Alpha", "alpha@example.edu", f.State.RootID)
	ouA := f.State.SeedOU("A", f.State.RootID)
	acct2 := f.State.SeedAccount("Beta", "beta@example.edu", ouA)
	ouB := f.State.SeedOU("B", ouA)
	acct3 := f.State.SeedAccount("Gamma", "gamma@example.edu", ouB)

	tree, err := f.E.WalkTree(ctx(), f.State.RootID)
	if err != nil {
		t.Fatalf("WalkTree: %v", err)
	}

	gotOUs := map[string]string{}
	for _, ou := range tree.OUs {
		gotOUs[ou.ID] = ou.ParentID
	}
	if gotOUs[ouA] != f.State.RootID {
		t.Errorf("ouA parent = %q, want root", gotOUs[ouA])
	}
	if gotOUs[ouB] != ouA {
		t.Errorf("ouB parent = %q, want ouA", gotOUs[ouB])
	}
	if len(tree.OUs) != 2 {
		t.Errorf("found %d OUs, want 2: %+v", len(tree.OUs), tree.OUs)
	}

	gotAccounts := map[string]string{}
	for _, a := range tree.Accounts {
		gotAccounts[a.ID] = a.ParentOUID
	}
	if gotAccounts[acct1] != f.State.RootID {
		t.Errorf("acct1 parent = %q, want root", gotAccounts[acct1])
	}
	if gotAccounts[acct2] != ouA {
		t.Errorf("acct2 parent = %q, want ouA", gotAccounts[acct2])
	}
	if gotAccounts[acct3] != ouB {
		t.Errorf("acct3 parent = %q, want ouB", gotAccounts[acct3])
	}
	if len(tree.Accounts) != 3 {
		t.Errorf("found %d accounts, want 3: %+v", len(tree.Accounts), tree.Accounts)
	}
}

func TestWalkTreeEmptySubtree(t *testing.T) {
	f := newFixture(t)
	ouEmpty := f.State.SeedOU("Empty", f.State.RootID)

	tree, err := f.E.WalkTree(ctx(), ouEmpty)
	if err != nil {
		t.Fatalf("WalkTree: %v", err)
	}
	if len(tree.OUs) != 0 || len(tree.Accounts) != 0 {
		t.Errorf("tree = %+v, want empty", tree)
	}
}

func TestWalkTreeNoRoot(t *testing.T) {
	f := newFixture(t)
	if _, err := f.E.WalkTree(ctx(), ""); err == nil {
		t.Fatal("WalkTree with no root succeeded, want a refusal")
	}
}

func TestWalkTreePagination(t *testing.T) {
	// PageSize defaults to 2, so five siblings force multiple pages through
	// both ListOrganizationalUnitsForParent and ListAccountsForParent — the
	// same truncated-read bug findOU's own callers guard against.
	f := newFixture(t)
	var wantOUs, wantAccounts []string
	for i := 0; i < 5; i++ {
		wantOUs = append(wantOUs, f.State.SeedOU("ou", f.State.RootID))
		wantAccounts = append(wantAccounts, f.State.SeedAccount("acct", treeTestEmail(i), f.State.RootID))
	}

	tree, err := f.E.WalkTree(ctx(), f.State.RootID)
	if err != nil {
		t.Fatalf("WalkTree: %v", err)
	}
	if len(tree.OUs) != 5 {
		t.Errorf("found %d OUs, want 5", len(tree.OUs))
	}
	if len(tree.Accounts) != 5 {
		t.Errorf("found %d accounts, want 5", len(tree.Accounts))
	}

	var gotOUs, gotAccounts []string
	for _, ou := range tree.OUs {
		gotOUs = append(gotOUs, ou.ID)
	}
	for _, a := range tree.Accounts {
		gotAccounts = append(gotAccounts, a.ID)
	}
	sort.Strings(gotOUs)
	sort.Strings(wantOUs)
	sort.Strings(gotAccounts)
	sort.Strings(wantAccounts)
	for i := range wantOUs {
		if gotOUs[i] != wantOUs[i] {
			t.Errorf("OU[%d] = %q, want %q", i, gotOUs[i], wantOUs[i])
		}
	}
	for i := range wantAccounts {
		if gotAccounts[i] != wantAccounts[i] {
			t.Errorf("account[%d] = %q, want %q", i, gotAccounts[i], wantAccounts[i])
		}
	}
}

func treeTestEmail(i int) string {
	return "acct" + string(rune('0'+i)) + "@example.edu"
}
